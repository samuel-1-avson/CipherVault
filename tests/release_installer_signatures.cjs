// Exercise both trusted local bootstrap verifiers without network or installation.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repo = path.resolve(__dirname, '..');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-release-signatures-'));
const pinnedKey = 'b625994c0c3f53a6c40b0eadebe7ba1f5199e9f829a4bf20e064ae7aaab22c1e';
const pinnedId = pinnedKey.slice(0, 16);
const seed = Buffer.alloc(32, 0x31);
const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
const keyId = publicKey.slice(0, 16);
const tag = 'v9.9.9';
const sums = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  ciphervault-v9.9.9-x86_64-unknown-linux-gnu.tar.gz\n';
const message = Buffer.from(`CIPHERVAULT-RELEASE-SIG-V2\ntag: ${tag}\n${sums}`);
const signature = crypto.sign(null, message, privateKey).toString('hex');
const envelope = `CIPHERVAULT-RELEASE-SIG-V2\ntag: ${tag}\nkey-id: ${keyId}\nsignature: ${signature}\n`;
const fixtureSignature = 'ed0b77b87e8194636f04dcf90268a0142f1c6380bc4bbb58ba7f84592019d8e8d4699befb5ea2bd09f76badfeeea33a0fbec7522fd1e760e22bd93a47d72c303';
const v1 = `CIPHERVAULT-RELEASE-SIG-V1\ntag: ${tag}\nkey-id: ${pinnedId}\nsignature: ${fixtureSignature}\n`;

function executable(candidates) {
  for (const candidate of candidates) {
    const test = spawnSync(candidate, candidate.toLowerCase().includes('powershell') || candidate === 'pwsh' ? ['-NoProfile', '-Command', '$PSVersionTable.PSVersion.ToString()'] : ['--version'], { encoding: 'utf8' });
    if (!test.error && test.status === 0) return candidate;
  }
  return null;
}

const bash = executable(process.platform === 'win32' ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'bash'] : ['bash']);
const powershell = executable(['pwsh', 'powershell.exe']);
assert(bash, 'Bash is required for the installer verifier contract');
let checked = 0;
try {
  for (const [suffix, runtime] of [['sh', bash], ['ps1', powershell]]) {
    if (!runtime) { console.log(`Skipping ${suffix}: runtime is unavailable on this host`); continue; }
    const original = fs.readFileSync(path.join(repo, 'dist', 'scripts', `install.${suffix}`), 'utf8');
    // The test trust root is substituted in this isolated temporary copy only.
    // Production scripts retain the independently pinned release key.
    const trustedFixture = original.replaceAll(pinnedKey, publicKey).replaceAll(pinnedId, keyId);
    for (const [name, source, checksums, signed, expectedTag, legacy, shouldPass] of [
      ['valid V2', trustedFixture, sums, envelope, tag, false, true],
      ['tampered archive/checksums', trustedFixture, sums.replace('9f86', '0000'), envelope, tag, false, false],
      ['rewritten signed tag', trustedFixture, sums, envelope.replaceAll(tag, 'v9.9.10'), 'v9.9.10', false, false],
      ['wrong trust key', original, sums, envelope, tag, false, false],
      ['unsigned', trustedFixture, sums, '', tag, false, false],
      ['legacy rejected by default', original, sums, v1, tag, false, false],
      ['explicit historical V1', original, sums, v1, tag, true, true],
    ]) {
      const script = path.join(scratch, `install.${suffix}`);
      const sumsFile = path.join(scratch, 'SHA256SUMS.txt');
      const signatureFile = path.join(scratch, 'SHA256SUMS.txt.sig');
      fs.writeFileSync(script, source.replaceAll('\r\n', '\n'));
      fs.writeFileSync(sumsFile, checksums); fs.writeFileSync(signatureFile, signed);
      const env = { ...process.env, CIPHERVAULT_INSTALLER_VERIFY_ONLY:'1', CIPHERVAULT_VERIFY_SUMS:sumsFile, CIPHERVAULT_VERIFY_SIGNATURE:signatureFile,
        CIPHERVAULT_VERIFY_TAG:expectedTag, CIPHERVAULT_VERIFY_SCRATCH:scratch, CIPHERVAULT_ALLOW_LEGACY_RELEASE_SIGNATURE:legacy ? '1' : '', CIPHERVAULT_VERSION:legacy ? tag : '' };
      if (process.platform === 'win32') {
        for (const key of Object.keys(env)) if (key.toLowerCase() === 'path') delete env[key];
        env.PATH = `C:\\Program Files\\Git\\usr\\bin;C:\\Program Files\\Git\\mingw64\\bin;${process.env.PATH}`;
      }
      const args = suffix === 'sh' ? [script] : ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script];
      const result = spawnSync(runtime, args, { env, encoding:'utf8', timeout:30000 });
      assert.equal(result.status === 0, shouldPass, `${suffix}: ${name}: ${result.error || result.stderr || result.stdout}`);
      checked++;
    }
    const verificationCall = suffix === 'sh' ? 'verify_release_signature "$TMP_DIR/SHA256SUMS.txt"' : 'Assert-CipherVaultReleaseSignature -SumsPath $sumsPath';
    const extraction = suffix === 'sh' ? 'tar -xzf "$TMP_DIR/$PKG_NAME"' : 'Expand-Archive -LiteralPath $archive';
    assert(original.indexOf(verificationCall) >= 0 && original.indexOf(verificationCall) < original.indexOf(extraction), `${suffix} must authenticate before extraction`);
  }
  console.log(`Passed ${checked} independent bootstrap signature cases`);
} finally {
  fs.rmSync(scratch, { recursive:true, force:true });
}
