// Execute the production validator/loader with local fixtures and no cloud calls.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repo = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(repo, 'deploy/gcp/startup-web.sh'), 'utf8').replaceAll('\r\n', '\n');
const start = source.indexOf('validate_local_kek_file() {');
const end = source.indexOf('\nfetch_totp_key() {', start);
assert(start >= 0 && end > start, 'production key-loader functions must be present');
assert(source.includes('"$LOCAL_KEK_FILE" \'account local KEK\' local-kek'), 'only local KEK opts into versioned JSON');
const functions = source.slice(start, end);
const bash = process.platform === 'win32' ? 'C:\\Program Files\\Git\\bin\\bash.exe' : 'bash';
const jq = process.env.CIPHERVAULT_JQ || 'jq';
const slash = value => process.platform === 'win32' ? value.replaceAll('\\', '/') : value;
const available = spawnSync(jq, ['--version'], { encoding: 'utf8' });
assert.equal(available.status, 0, 'jq is required; set CIPHERVAULT_JQ to its executable');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-web-secret-bootstrap-'));
const key = 'ab'.repeat(32);
const second = 'cd'.repeat(32);
const ring = JSON.stringify({ active_version: 'v2', keys: { legacy: key, v2: second } }, null, 2);
const label64 = 'v'.repeat(64);
const keys = count => Object.fromEntries(Array.from({ length: count }, (_, i) => [`v${i}`, key]));
const cases = [
  ['legacy', key, 'local-kek', true],
  ['legacy surrounding whitespace', ` \t${key}\r\n`, 'local-kek', true],
  ['versioned multiline JSON', ring, 'local-kek', true],
  ['32 retained versions', JSON.stringify({ active_version: 'v0', keys: keys(32) }), 'local-kek', true],
  ['64-character version', JSON.stringify({ active_version: label64, keys: { [label64]: key } }), 'local-kek', true],
  ['unknown root field', JSON.stringify({ active_version: 'v1', keys: { v1: key }, extra: key }), 'local-kek', false],
  ['missing active version', JSON.stringify({ keys: { v1: key } }), 'local-kek', false],
  ['active key absent', JSON.stringify({ active_version: 'v2', keys: { v1: key } }), 'local-kek', false],
  ['empty keyring', JSON.stringify({ active_version: 'v1', keys: {} }), 'local-kek', false],
  ['33 retained versions', JSON.stringify({ active_version: 'v0', keys: keys(33) }), 'local-kek', false],
  ['invalid version label', JSON.stringify({ active_version: 'v/1', keys: { 'v/1': key } }), 'local-kek', false],
  ['empty version label', JSON.stringify({ active_version: '', keys: { '': key } }), 'local-kek', false],
  ['65-character version', JSON.stringify({ active_version: `${label64}v`, keys: { [`${label64}v`]: key } }), 'local-kek', false],
  ['short hex key', JSON.stringify({ active_version: 'v1', keys: { v1: key.slice(2) } }), 'local-kek', false],
  ['invalid hex key', JSON.stringify({ active_version: 'v1', keys: { v1: 'zz'.repeat(32) } }), 'local-kek', false],
  ['non-string key', JSON.stringify({ active_version: 'v1', keys: { v1: 7 } }), 'local-kek', false],
  ['non-string active version', JSON.stringify({ active_version: 1, keys: { v1: key } }), 'local-kek', false],
  ['array', `[${ring}]`, 'local-kek', false],
  ['multiple JSON documents', `${ring}\n${ring}`, 'local-kek', false],
  ['duplicate active field', `{"active_version":"v1","active_version":"v1","keys":{"v1":"${key}"}}`, 'local-kek', false],
  ['duplicate root keyring', `{"active_version":"v1","keys":{"old":"${key}"},"keys":{"v1":"${key}"}}`, 'local-kek', false],
  ['duplicate version label', `{"active_version":"v1","keys":{"v1":"${second}","v1":"${key}"}}`, 'local-kek', false],
  ['literal newline in JSON string', `{"active_version":"v1","keys":{"v1":"${key.slice(0, 32)}\n${key.slice(32)}"}}`, 'local-kek', false],
  ['malformed JSON', `{"active_version":"v1","keys":{"v1":"${key}"}`, 'local-kek', false],
  ['oversized JSON', `${ring}${' '.repeat(65537)}`, 'local-kek', false],
  ['empty', '', 'local-kek', false],
  ['non-KEK legacy', `${key}\r\n`, 'hex', true],
  ['non-KEK JSON rejected', ring, 'hex', false],
  ['non-KEK whitespace rejected', ` ${key} `, 'hex', false],
  ['unknown format', key, 'unsupported', false],
];

try {
  const script = path.join(scratch, 'bootstrap-test.sh');
  fs.writeFileSync(script, `#!/usr/bin/env bash\nset -euo pipefail\n${functions}\n` +
    `jq() { "$JQ_EXECUTABLE" ${process.platform === 'win32' ? '--binary ' : ''}"$@"; }\n` +
    'curl() {\n case "${@: -1}" in\n' +
    '  *service-accounts/default/token) printf \'{"access_token":"synthetic-offline-token"}\';;\n' +
    '  *secretmanager.googleapis.com*) cat "$PAYLOAD_RESPONSE";;\n' +
    '  *) echo "unexpected cloud request" >&2; return 91;;\n esac\n}\n' +
    'install() {\n if [[ "$1" == -d ]]; then mkdir -p "${@: -1}"; return; fi\n' +
    ' cp "${@: -2:1}" "${@: -1}"\n}\n' +
    'SECRETS_DIR="$TEST_SECRETS_DIR"\nfetch_hex_secret project secret "$TEST_DESTINATION" synthetic "$TEST_FORMAT"\n');
  const syntax = spawnSync(bash, ['-n', script], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  for (const [label, payload, format, accepted] of cases) {
    const response = path.join(scratch, 'response.json');
    const destination = path.join(scratch, 'protected-existing-key');
    fs.writeFileSync(response, JSON.stringify({ payload: { data: Buffer.from(payload).toString('base64') } }));
    fs.writeFileSync(destination, 'existing-key-must-survive');
    const result = spawnSync(bash, [script], { encoding: 'utf8', timeout: 10000, env: {
      ...process.env, JQ_EXECUTABLE: slash(jq), PAYLOAD_RESPONSE: slash(response),
      TEST_DESTINATION: slash(destination), TEST_SECRETS_DIR: slash(path.join(scratch, 'secrets')),
      TEST_FORMAT: format,
    }});
    assert.equal(result.status === 0, accepted, `${label}: ${result.error || result.stderr || result.stdout}`);
    assert(!result.stdout.includes(key) && !result.stderr.includes(key), `${label}: secret payload was printed`);
    assert.equal(fs.readFileSync(destination, 'utf8'), accepted ? (format === 'hex' ? payload.replaceAll('\r', '').replaceAll('\n', '') : payload) : 'existing-key-must-survive', `${label}: destination changed incorrectly`);
  }
  console.log(`Passed ${cases.length} isolated web secret-bootstrap cases without cloud calls`);
} finally {
  const resolved = path.resolve(scratch);
  assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
  assert(path.basename(resolved).startsWith('cv-web-secret-bootstrap-'));
  fs.rmSync(scratch, { recursive: true, force: true });
}
