// Run the actual release packaging step against isolated multi-role archives.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repo = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(repo, '.github/workflows/release.yml'), 'utf8');
const match = workflow.match(/- name: Compute SHA256 Checksums[\s\S]*?run: \|\r?\n([\s\S]*?)\r?\n      - name:/);
assert(match, 'release packaging step must exist');
const script = 'set -euo pipefail\n' + match[1].replace(/^          /gm, '').replaceAll('${{ github.ref_name }}', 'v9.9.9');
const bash = process.platform === 'win32' ? 'C:\\Program Files\\Git\\bin\\bash.exe' : 'bash';
const python = process.platform === 'win32' ? 'python' : 'python3';
const fixture = String.raw`
import io,pathlib,sys,tarfile,zipfile
root=pathlib.Path(sys.argv[1]); missing=sys.argv[2]=='missing'
targets=['x86_64-pc-windows-msvc','x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-unknown-linux-musl','x86_64-apple-darwin','aarch64-apple-darwin']
for target in targets:
 for role in ['', '-dev', '-node']:
  stem=f'ciphervault{role}-v9.9.9-{target}'
  directory=root/'release-assets'/target;directory.mkdir(parents=True,exist_ok=True)
  member=f'{stem}/bin/ciphervault'+('.exe' if 'windows' in target else '')
  payload=f'CLI:{role or "full"}:{target}'.encode()
  if missing and not role and target=='x86_64-unknown-linux-gnu':member=f'{stem}/README.md'
  if 'windows' in target:
   with zipfile.ZipFile(directory/f'{stem}.zip','w') as z:z.writestr(member,payload)
  else:
   with tarfile.open(directory/f'{stem}.tar.gz','w:gz') as t:
    info=tarfile.TarInfo(member);info.size=len(payload);info.mode=0o755;t.addfile(info,io.BytesIO(payload))
`;
for (const scenario of ['valid', 'missing']) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-release-packaging-'));
  try {
    const setup = spawnSync(python, ['-c', fixture, scratch, scenario], { encoding: 'utf8', timeout: 30000 });
    assert.equal(setup.status, 0, setup.stderr || setup.error?.message);
    const result = spawnSync(bash, ['-c', script], { cwd: scratch, encoding: 'utf8', timeout: 30000 });
    if (scenario === 'missing') {
      assert.notEqual(result.status, 0, 'missing executable must fail before checksums/publication');
      assert(!fs.existsSync(path.join(scratch, 'dist-release', 'SHA256SUMS.txt')));
      continue;
    }
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    for (const [name, target] of [
      ['ciphervault.exe', 'x86_64-pc-windows-msvc'],
      ['ciphervault-linux-amd64', 'x86_64-unknown-linux-gnu'],
      ['ciphervault-linux-arm64', 'aarch64-unknown-linux-gnu'],
      ['ciphervault-linux-amd64-musl', 'x86_64-unknown-linux-musl'],
      ['ciphervault-macos-amd64', 'x86_64-apple-darwin'],
      ['ciphervault-macos-arm64', 'aarch64-apple-darwin'],
    ]) {
      assert.equal(fs.readFileSync(path.join(scratch, 'dist-release', name), 'utf8'), `CLI:full:${target}`);
    }
    const sums = fs.readFileSync(path.join(scratch, 'dist-release', 'SHA256SUMS.txt'), 'utf8').trim().split('\n');
    assert.equal(sums.length, 24, 'all 18 archives and six standalone binaries must be checksummed');
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
console.log('Release packaging verified: exact full bundles, all checksums, missing executable rejection.');
