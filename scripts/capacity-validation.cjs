#!/usr/bin/env node
'use strict';

// Isolated, bounded TCP capacity probe. Node 24+; no npm dependencies.
// Every measured request targets a service this process starts itself.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const exec = promisify(execFile);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const rounded = value => Math.round(value * 100) / 100;
const children = new Set();

function argumentsFor(argv) {
  const args = { concurrency: [1, 8, 32, 64], requests: 240, secrets: 50,
    objectBytes: 65536, p99Ms: 2000, overload: 128, overloadBytes: 1048576 };
  const numbers = { '--requests': 'requests', '--secrets': 'secrets',
    '--object-bytes': 'objectBytes', '--p99-ms': 'p99Ms', '--overload': 'overload',
    '--overload-bytes': 'overloadBytes' };
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === '--require-overload-rejection') args.requireRejection = true;
    else if (key === '--require-enforced-mfa') args.requireMfa = true;
    else if (key === '--skip-default-limiter') args.skipLimiter = true;
    else if (key === '--concurrency') {
      args.concurrency = String(argv[++i]).split(',').map(Number);
    } else if (key in numbers) args[numbers[key]] = Number(argv[++i]);
    else if (['--account-bin', '--operator-bin', '--output'].includes(key)) {
      args[key.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = argv[++i];
    } else throw new Error(`Unknown argument: ${key}`);
  }
  for (const key of ['accountBin', 'operatorBin', 'output']) {
    assert(args[key], `Required: --${key.replace(/[A-Z]/g, c => '-' + c.toLowerCase())}`);
    args[key] = path.resolve(args[key]);
  }
  for (const key of ['requests', 'secrets', 'objectBytes', 'p99Ms', 'overload', 'overloadBytes']) {
    assert(Number.isSafeInteger(args[key]) && args[key] > 0, `${key} must be a positive integer`);
  }
  assert(args.requests <= 2000 && args.secrets >= 5 && args.secrets <= 200, 'Bounded requests/secrets required');
  assert(args.concurrency.length <= 8 && args.concurrency.every(c => Number.isSafeInteger(c) && c >= 1 && c <= 256), 'Concurrency must be 1..256 (at most eight phases)');
  assert(new Set(args.concurrency).size === args.concurrency.length, 'Concurrency phases must be distinct');
  assert(args.overload <= 256 && args.objectBytes <= 1048576 && args.overloadBytes <= 2097152, 'Bounded object/overload sizes required');
  assert(!fs.existsSync(args.output), 'Output must be a new file; existing evidence is never overwritten');
  return args;
}

function summarize(samples, elapsedMs) {
  const sorted = samples.map(s => s.ms).sort((a, b) => a - b);
  const percentile = p => sorted[Math.max(0, Math.ceil(sorted.length * p / 100) - 1)] || 0;
  const statuses = {};
  for (const sample of samples) statuses[sample.status] = (statuses[sample.status] || 0) + 1;
  const rejected = samples.filter(s => s.rejected).length;
  const failures = samples.filter(s => !s.ok && !s.rejected).length;
  const successes = samples.length - rejected - failures;
  return { requests: samples.length, successes, rejected, failures, statuses,
    failure_percent: rounded(failures * 100 / Math.max(1, samples.length)),
    rejection_percent: rounded(rejected * 100 / Math.max(1, samples.length)),
    elapsed_ms: rounded(elapsedMs), requests_per_second: rounded(samples.length * 1000 / elapsedMs),
    successes_per_second: rounded(successes * 1000 / elapsedMs),
    p50_ms: rounded(percentile(50)), p95_ms: rounded(percentile(95)), p99_ms: rounded(percentile(99)),
    max_ms: rounded(sorted.at(-1) || 0), errors: samples.filter(s => s.error).slice(0, 5).map(s => s.error) };
}

async function parallel(count, concurrency, operation) {
  let next = 0;
  const samples = [];
  const started = performance.now();
  await Promise.all(Array.from({ length: Math.min(count, concurrency) }, async (_, worker) => {
    for (;;) {
      const index = next++;
      if (index >= count) break;
      samples.push(await operation(index, worker));
    }
  }));
  return { samples, ...summarize(samples, performance.now() - started) };
}

async function request(base, route, { method = 'GET', token, headers = {}, json, body, validate,
  admission = false, expectedStatuses } = {}) {
  const started = performance.now();
  let response;
  try {
    const outgoing = { ...headers };
    if (token) outgoing.authorization = `Bearer ${token}`;
    if (json !== undefined) { outgoing['content-type'] = 'application/json'; body = JSON.stringify(json); }
    response = await fetch(base + route, { method, headers: outgoing, body,
      signal: AbortSignal.timeout(30000), redirect: 'error' });
    const bytes = Buffer.from(await response.arrayBuffer());
    const status = response.status;
    const isAdmission = status === 503 && /(?:IO_CAPACITY_EXHAUSTED|Operator I\/O capacity exhausted)/.test(bytes.toString());
    const rejected = admission && (status === 429 || isAdmission);
    const ok = (expectedStatuses ? expectedStatuses.includes(status) : response.ok) && (!validate || validate(bytes, response));
    return { status, ms: performance.now() - started, ok, rejected,
      error: ok || rejected ? undefined : `HTTP ${status}: ${response.ok ? 'response integrity/contract mismatch' : bytes.toString().slice(0, 180)}` };
  } catch (error) {
    return { status: response?.status || 0, ms: performance.now() - started, ok: false,
      rejected: false, error: String(error) };
  }
}

async function jsonRequest(base, route, options) {
  let result;
  const sample = await request(base, route, { ...options,
    validate: bytes => { result = JSON.parse(bytes.toString()); return true; } });
  assert(sample.ok, `${route}: ${sample.error}`);
  return result;
}

async function port() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}

function isolatedEnvironment() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(CIPHERVAULT_|ARBITRUM_|GOOGLE_APPLICATION_CREDENTIALS$)/i.test(key)) delete env[key];
  }
  return env;
}

function start(binary, args, env) {
  const child = spawn(binary, args, { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child);
  let logs = '';
  const capture = data => { logs = (logs + data.toString()).slice(-8192); };
  child.stdout.on('data', capture); child.stderr.on('data', capture);
  child.on('error', capture);
  child.once('exit', () => children.delete(child));
  child.recentLogs = () => logs;
  return child;
}

async function stop(child) {
  if (child.exitCode !== null || !children.has(child)) return;
  child.kill();
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), sleep(5000)]);
  if (children.has(child)) { child.kill('SIGKILL'); await sleep(250); }
}

async function ready(child, base, route) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`Service exited: ${child.recentLogs()}`);
    try {
      if ((await fetch(base + route, { signal: AbortSignal.timeout(1000) })).ok) return;
    } catch {}
    await sleep(100);
  }
  throw new Error(`Service did not become ready: ${child.recentLogs()}`);
}

async function resources(child) {
  if (process.platform === 'win32') {
    const { stdout } = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      `$p = Get-Process -Id ${child.pid} -ErrorAction Stop; [pscustomobject]@{rss_bytes=$p.WorkingSet64;peak_rss_bytes=$p.PeakWorkingSet64;cpu_seconds=$p.TotalProcessorTime.TotalSeconds} | ConvertTo-Json -Compress`], { windowsHide: true });
    return JSON.parse(stdout);
  }
  if (process.platform === 'linux') {
    const text = fs.readFileSync(`/proc/${child.pid}/status`, 'utf8');
    const read = name => Number(text.match(new RegExp(`^${name}:\\s+(\\d+)`, 'm'))?.[1] || 0) * 1024;
    return { rss_bytes: read('VmRSS'), peak_rss_bytes: read('VmHWM') };
  }
  const { stdout } = await exec('ps', ['-o', 'rss=', '-p', String(child.pid)]);
  return { rss_bytes: Number(stdout.trim()) * 1024, peak_rss_bytes: null };
}

function disk(directory) {
  let bytes = 0; let files = 0;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) { const child = disk(target); bytes += child.bytes; files += child.files; }
    else if (entry.isFile()) { bytes += fs.statSync(target).size; files++; }
  }
  return { bytes, files };
}

function signDomain(key, context, message) {
  return crypto.sign(null, Buffer.concat([Buffer.from(`CipherVault-Ed25519-v1:${context}:`), message]), key).toString('hex');
}

async function accountSetup(base, dataDir, args) {
  const actors = [];
  for (let i = 0; i < 16; i++) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicHex = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
    const account = await jsonRequest(base, '/v1/accounts', { method: 'POST',
      json: { display_name: `Capacity fixture ${i}`, account_public_key_hex: publicHex } });
    const challenge = await jsonRequest(base, '/v1/sessions/challenge', { method: 'POST',
      json: { account_id: account.account_id } });
    const signingBytes = Buffer.from(JSON.stringify([account.account_id, null, null, challenge.challenge_id, challenge.nonce_hex]));
    const session = await jsonRequest(base, '/v1/sessions', { method: 'POST', json: {
      challenge_id: challenge.challenge_id, signature_hex: signDomain(privateKey, 'account_login', signingBytes) } });
    actors.push({ id: account.account_id, token: session.token, privateKey });
  }
  const tenant = crypto.randomBytes(16).toString('hex');
  const project = crypto.randomBytes(16).toString('hex');
  const environment = crypto.randomBytes(16).toString('hex');
  const workspace = crypto.randomBytes(16).toString('hex');
  const db = new DatabaseSync(path.join(dataDir, 'accounts.sqlite3'));
  db.exec('PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; BEGIN IMMEDIATE');
  db.prepare('INSERT INTO organizations(tenant_id,name,created_at_utc) VALUES(?,?,?)').run(tenant, 'capacity', 1);
  db.prepare('INSERT INTO workspaces(workspace_id,tenant_id,name,created_at_utc) VALUES(?,?,?,?)').run(workspace, tenant, 'capacity', 1);
  db.prepare('INSERT INTO projects(project_id,tenant_id,workspace_id,slug,name,created_at_utc) VALUES(?,?,?,?,?,?)').run(project, tenant, workspace, 'capacity', 'Capacity fixture', 1);
  // Tier 2 also exercises the existing fresh-key production policy gate.
  db.prepare('INSERT INTO environments(environment_id,tenant_id,project_id,slug,tier,created_at_utc) VALUES(?,?,?,?,?,?)').run(environment, tenant, project, 'production-fixture', 2, 1);
  for (const actor of actors) db.prepare('INSERT INTO project_members(project_id,principal_id,role,granted_by,granted_at_utc) VALUES(?,?,?,?,?)').run(project, `account:${actor.id}`, 'admin', 'capacity-fixture', 1);
  db.exec('COMMIT'); db.close();
  for (const actor of actors.slice(0, 2)) {
    actor.scope = (await jsonRequest(base, '/v1/scope-tokens', { method: 'POST', token: actor.token,
      json: { project_id: project, ttl_seconds: 600 } })).token;
  }
  const secrets = [];
  const value = 'capacity-synthetic-' + 'x'.repeat(1005);
  for (let i = 0; i < args.secrets; i++) {
    const secret = await jsonRequest(base, `/v1/projects/${project}/environments/${environment}/secrets`,
      { method: 'POST', token: actors[i % actors.length].token, json: { name: `CAPACITY_${String(i).padStart(4, '0')}`, value } });
    secrets.push({ name: secret.name, id: secret.secret_id });
  }
  return { actors, project, environment, secrets };
}

function accountOperation(base, fixture, phase) {
  const { actors, project, environment, secrets } = fixture;
  return async index => {
    const actor = actors[(index + Math.floor(index / 20)) % actors.length];
    const secret = secrets[index % secrets.length];
    const baseRoute = `/v1/projects/${project}/environments/${environment}`;
    const kind = index % 20;
    let options = { token: actor.token };
    let route; let label;
    if (kind < 8) {
      label = 'value_read'; route = `${baseRoute}/secrets/${secret.name}`;
      options.validate = bytes => JSON.parse(bytes).value.startsWith('capacity-');
    } else if (kind < 13) {
      label = 'materialize_5'; route = `${baseRoute}/materialize`;
      const names = Array.from({ length: 5 }, (_, j) => secrets[(index + j) % secrets.length].name);
      options = { ...options, method: 'POST', json: { names }, validate: bytes => {
        const value = JSON.parse(bytes);
        return value.values.length === 5 && value.values.every(v => names.includes(v.name) && v.value.startsWith('capacity-'));
      } };
    } else if (kind < 17) {
      label = 'manual_rotation'; route = `/v1/projects/${project}/secrets/${secret.id}/rotate`;
      options = { ...options, method: 'POST', json: { new_value: `capacity-rotation-${phase}-${index}`,
        idempotency_key: `capacity-${phase}-${index}`, reason: 'Synthetic capacity probe' },
      validate: bytes => { const value = JSON.parse(bytes); return value.secret_id === secret.id && value.provider_verified === false; } };
    } else if (kind < 19) {
      label = 'metadata_list'; route = `/v1/projects/${project}/secrets?environment=${environment}&limit=100`;
      options.validate = bytes => {
        const value = JSON.parse(bytes);
        return value.secrets.length === secrets.length && /^[0-9a-f]{64}$/.test(value.revision);
      };
    } else {
      label = 'audit_export'; route = `/v1/projects/${project}/audit/export`;
      const other = actor.id === actors[0].id ? actors[1] : actors[0];
      options.headers = { 'x-step-up-authorization': `Bearer ${other.scope}` };
      options.validate = (bytes, response) => bytes.toString().trim().split('\n').length === Number(response.headers.get('x-audit-events'));
    }
    return { label, ...await request(base, route, options) };
  };
}

async function operatorSetup(base, serviceToken) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const publicHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
  const vault = crypto.randomBytes(32).toString('hex');
  const enrolled = await request(base, '/v1/identities', { method: 'POST',
    headers: { 'x-ciphervault-service-token': serviceToken }, json: { vault_id_hex: vault, public_key_hex: publicHex } });
  assert(enrolled.ok, enrolled.error);
  const challenge = await jsonRequest(base, '/v1/challenges', { method: 'POST', json: { vault_id_hex: vault, public_key_hex: publicHex } });
  const session = await jsonRequest(base, '/v1/sessions', { method: 'POST', json: {
    challenge_id: challenge.challenge_id, public_key_hex: publicHex,
    signature_hex: signDomain(privateKey, 'operator_challenge', Buffer.from(challenge.nonce_hex, 'hex')) } });
  return { token: session.token, headers: { 'x-ciphervault-id': vault } };
}

function payload(index, size, phase) {
  const bytes = Buffer.alloc(size, 0x5a);
  Buffer.from(`capacity-${phase}-${index}`).copy(bytes);
  return bytes;
}

function totpCode(secretBase32, step) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0; let accumulator = 0; const bytes = [];
  for (const character of secretBase32.replace(/=+$/, '').toUpperCase()) {
    const value = alphabet.indexOf(character);
    assert(value >= 0, 'Invalid synthetic TOTP seed');
    accumulator = (accumulator << 5) | value; bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const digest = crypto.createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
  const offset = digest.at(-1) & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

async function enforcedMfaPhase(base, fixture, args) {
  const capabilities = await jsonRequest(base, '/v1/capabilities');
  if (capabilities.scoped_auth?.enforced_account_mfa_policy !== true) {
    assert(!args.requireMfa, 'Fresh enforced MFA capability is required for this run');
    return { skipped: true, reason: 'Measured binary does not implement enforced account MFA policy' };
  }
  const actor = fixture.actors[0]; const route = `/v1/accounts/${actor.id}`;
  const device = crypto.generateKeyPairSync('ed25519');
  const deviceId = crypto.randomBytes(32).toString('hex');
  const devicePublic = device.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
  const deviceChallenge = await jsonRequest(base, `${route}/devices/challenge`, { method: 'POST', token: actor.token,
    json: { device_id_hex: deviceId, public_key_hex: devicePublic, label: 'Capacity MFA device' } });
  await jsonRequest(base, `${route}/devices`, { method: 'POST', token: actor.token, json: {
    device_id_hex: deviceId, public_key_hex: devicePublic, label: 'Capacity MFA device',
    challenge_id: deviceChallenge.challenge_id,
    proof_signature_hex: signDomain(actor.privateKey, 'account_device_enrollment', Buffer.from(JSON.stringify([
      actor.id, deviceId, devicePublic, deviceChallenge.challenge_id, deviceChallenge.nonce_hex]))) } });
  const deviceLogin = await jsonRequest(base, '/v1/sessions/challenge', { method: 'POST',
    json: { account_id: actor.id, device_id_hex: deviceId } });
  actor.token = (await jsonRequest(base, '/v1/sessions', { method: 'POST', json: {
    challenge_id: deviceLogin.challenge_id, signature_hex: signDomain(device.privateKey, 'account_login',
      Buffer.from(JSON.stringify([actor.id, deviceId, null, deviceLogin.challenge_id, deviceLogin.nonce_hex]))) } })).token;
  await jsonRequest(base, `${route}/recovery/codes`, { method: 'POST', token: actor.token, json: { count: 4 } });
  const enrollment = await jsonRequest(base, `${route}/totp/enrollment`, { method: 'POST', token: actor.token });
  const enrolledStep = Math.floor(Date.now() / 30000);
  await jsonRequest(base, `${route}/totp/enrollment/verify`, { method: 'POST', token: actor.token,
    json: { code: totpCode(enrollment.secret_base32, enrolledStep) } });
  // Enrollment consumed that time-step. Exercise replay-safe real TOTP
  // step-up with the next current code, not a synthetic proof-row insert.
  const waitMs = Math.max(0, (enrolledStep + 1) * 30000 + 100 - Date.now());
  console.log(`MFA capacity fixture: waiting ${waitMs}ms for the next current authenticator code.`);
  await sleep(waitMs);
  await jsonRequest(base, '/v1/sessions/mfa/totp', { method: 'POST', token: actor.token,
    json: { code: totpCode(enrollment.secret_base32, Math.floor(Date.now() / 30000)) } });
  await jsonRequest(base, `${route}/mfa`, { method: 'PATCH', token: actor.token, json: { required: true } });
  const valueRoute = `/v1/projects/${fixture.project}/environments/${fixture.environment}/secrets/${fixture.secrets[0].name}`;
  const measured = await parallel(120, 8, () => request(base, valueRoute, { token: actor.token,
    validate: bytes => JSON.parse(bytes).value.startsWith('capacity-') }));
  const { samples, ...summary } = measured;
  // A real new primary login must not inherit the first session's proof.
  const challenge = await jsonRequest(base, '/v1/sessions/challenge', { method: 'POST',
    json: { account_id: actor.id, device_id_hex: deviceId } });
  const signingBytes = Buffer.from(JSON.stringify([actor.id, deviceId, null, challenge.challenge_id, challenge.nonce_hex]));
  const renewed = await jsonRequest(base, '/v1/sessions', { method: 'POST', json: {
    challenge_id: challenge.challenge_id, signature_hex: signDomain(device.privateKey, 'account_login', signingBytes) } });
  const denied = await request(base, valueRoute, { token: renewed.token, expectedStatuses: [403, 404],
    validate: bytes => !Object.hasOwn(JSON.parse(bytes), 'value') });
  assert(denied.ok, 'MFA-required fresh primary without second factor must not return a value');
  console.log(JSON.stringify({ phase: 'account-enforced-mfa-read-c8', ...summary }));
  return { skipped: false, real_enrollment_and_step_up: true, next_code_wait_ms: waitMs,
    accounts_with_required_mfa: 1, service: 'account', name: 'account-enforced-mfa-read-c8', concurrency: 8,
    ...summary, proofless_new_primary_denial: { status: denied.status, ms: rounded(denied.ms), no_value_returned: denied.ok } };
}

async function run(args) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ciphervault-capacity-'));
  const accountDir = path.join(root, 'account'); const operatorDir = path.join(root, 'operator');
  const report = { format_version: 1, started_at_utc: new Date().toISOString(),
    scope: 'isolated local TCP; synthetic fixtures; no production or cloud calls',
    host: { os: `${os.type()} ${os.release()}`, arch: os.arch(), logical_cpus: os.cpus().length,
      total_memory_bytes: os.totalmem(), node: process.version },
    configuration: { ...args, accountBin: undefined, operatorBin: undefined, output: undefined },
    binaries: {}, phases: [], gates: {}, artifacts_retained: false };
  let resourceTimer;
  try {
    for (const [name, binary] of [['account', args.accountBin], ['operator', args.operatorBin]]) {
      // Pin exact executable bytes; concurrent development builds cannot
      // change the measured program or hit a Windows running-image file lock.
      const bytes = fs.readFileSync(binary);
      const executable = path.join(root, `${name}-service${process.platform === 'win32' ? '.exe' : ''}`);
      fs.writeFileSync(executable, bytes, { flag: 'wx', mode: 0o700 });
      const { stdout } = await exec(executable, ['--version'], { windowsHide: true });
      report.binaries[name] = { version: stdout.trim(), sha256: sha(bytes),
        binary_path: binary, profile_hint: path.basename(path.dirname(binary)) };
      args[`${name}Bin`] = executable;
    }
    const accountPort = await port(); const operatorPort = await port();
    const accountBase = `http://127.0.0.1:${accountPort}`; const operatorBase = `http://127.0.0.1:${operatorPort}`;
    const accountEnv = { ...isolatedEnvironment(), CIPHERVAULT_ACCOUNT_DATA_DIR: accountDir,
      CIPHERVAULT_ACCOUNT_BIND: `127.0.0.1:${accountPort}`, CIPHERVAULT_ACCOUNT_LOCAL_KEK: crypto.randomBytes(32).toString('hex'),
      CIPHERVAULT_ACCOUNT_TOTP_KEY: crypto.randomBytes(32).toString('hex'),
      CIPHERVAULT_ACCOUNT_SCOPE_TOKEN_KEY: crypto.randomBytes(32).toString('hex') };
    const serviceToken = crypto.randomBytes(32).toString('hex');
    const operatorEnv = { ...isolatedEnvironment(), CIPHERVAULT_OPERATOR_STRICT_AUTH: 'true',
      CIPHERVAULT_OPERATOR_REQUIRE_ENROLLMENT: 'true', CIPHERVAULT_OPERATOR_SERVICE_TOKEN: serviceToken,
      CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN: '100000' };
    const { stdout: help } = await exec(args.operatorBin, ['--help'], { windowsHide: true });
    const operatorArgs = ['--port', String(operatorPort), '--data-dir', operatorDir, '--operator-id', 'capacity-isolated'];
    report.operator_bind = help.includes('--bind-address') ? '127.0.0.1' : '0.0.0.0 (legacy binary; authenticated; requests remain loopback)';
    if (help.includes('--bind-address')) operatorArgs.push('--bind-address', '127.0.0.1');
    const account = start(args.accountBin, [], accountEnv);
    let operator = start(args.operatorBin, operatorArgs, operatorEnv);
    await Promise.all([ready(account, accountBase, '/v1/capabilities'), ready(operator, operatorBase, '/healthz')]);
    report.resource_samples = [];
    let sampling = false;
    const sampleResources = async () => {
      if (sampling) return;
      sampling = true;
      try { report.resource_samples.push({ at_utc: new Date().toISOString(),
        account: await resources(account), operator: await resources(operator) }); } catch {}
      finally { sampling = false; }
    };
    await sampleResources();
    resourceTimer = setInterval(sampleResources, 2000);
    const fixture = await accountSetup(accountBase, accountDir, args);
    let operatorAuth = await operatorSetup(operatorBase, serviceToken);
    const seedObjects = Array.from({ length: 16 }, (_, i) => payload(i, args.objectBytes, 'seed'));
    for (const bytes of seedObjects) assert((await request(operatorBase, `/v1/objects/${sha(bytes)}`,
      { ...operatorAuth, method: 'PUT', body: bytes })).ok, 'Object seed must succeed');
    for (const concurrency of args.concurrency) {
      const phaseName = `account-mixed-c${concurrency}`;
      // Wait until a minimum prefix has completed so the backup overlaps measured writes.
      let completed = 0;
      const operation = accountOperation(accountBase, fixture, phaseName);
      const load = parallel(args.requests, concurrency, async i => { const sample = await operation(i); completed++; return sample; });
      while (completed < Math.min(8, args.requests)) await sleep(5);
      const backupDir = path.join(root, `backup-${concurrency}-${report.phases.length}`);
      const backupStart = performance.now();
      const backup = exec(args.accountBin, ['backup', '--data-dir', accountDir, '--output-dir', backupDir], { env: accountEnv, windowsHide: true, timeout: 130000 })
        .then(({ stdout }) => ({ receipt: JSON.parse(stdout), elapsedMs: performance.now() - backupStart,
          requestsCompleted: completed }));
      const result = await load;
      const backupResult = await backup;
      const backupReceipt = backupResult.receipt;
      const operations = {};
      for (const label of new Set(result.samples.map(s => s.label))) {
        operations[label] = summarize(result.samples.filter(s => s.label === label), result.elapsed_ms);
      }
      const { samples, ...summary } = result;
      const phase = { name: phaseName, service: 'account', concurrency, ...summary, operations,
        backup: { elapsed_ms: rounded(backupResult.elapsedMs), requests_completed_when_backup_finished: backupResult.requestsCompleted,
          overlapped_requests: backupResult.requestsCompleted > 8 && backupResult.requestsCompleted < args.requests,
          audit_chains_checked: backupReceipt.audit_chains_checked,
          database_bytes: backupReceipt.database_bytes, table_rows: backupReceipt.table_rows }, disk: disk(accountDir) };
      report.phases.push(phase); console.log(JSON.stringify({ phase: phase.name, ...summary }));
      const operatorResult = await parallel(args.requests, concurrency, async i => {
        if (i % 3 === 0) {
          const bytes = payload(i, args.objectBytes, `c${concurrency}`);
          return { label: 'unique_write', ...await request(operatorBase, `/v1/objects/${sha(bytes)}`,
            { ...operatorAuth, method: 'PUT', body: bytes, admission: true }) };
        }
        const bytes = seedObjects[i % seedObjects.length];
        return { label: 'verified_read', ...await request(operatorBase, `/v1/objects/${sha(bytes)}`,
          { ...operatorAuth, admission: true, validate: value => value.equals(bytes) }) };
      });
      const { samples: operatorSamples, ...operatorSummary } = operatorResult;
      report.phases.push({ name: `operator-mixed-c${concurrency}`, service: 'operator', concurrency,
        ...operatorSummary, disk: disk(operatorDir), operations: Object.fromEntries(['unique_write', 'verified_read'].map(label =>
          [label, summarize(operatorSamples.filter(s => s.label === label), operatorResult.elapsed_ms)])) });
      console.log(JSON.stringify({ phase: `operator-mixed-c${concurrency}`, ...operatorSummary }));
      await sampleResources();
    }
    report.enforced_mfa = await enforcedMfaPhase(accountBase, fixture, args);
    if (!report.enforced_mfa.skipped) report.phases.push(report.enforced_mfa);
    const overloadResult = await parallel(args.overload, args.overload, async i => {
      const bytes = payload(i, args.overloadBytes, 'overload');
      return request(operatorBase, `/v1/objects/${sha(bytes)}`, { ...operatorAuth, method: 'PUT', body: bytes, admission: true });
    });
    const { samples: overloadSamples, ...overload } = overloadResult;
    report.phases.push({ name: 'operator-overload', service: 'operator', concurrency: args.overload, ...overload, disk: disk(operatorDir) });
    console.log(JSON.stringify({ phase: 'operator-overload', ...overload }));
    report.overload_resources = { account: await resources(account), operator: await resources(operator) };
    const objectFiles = fs.readdirSync(path.join(operatorDir, 'objects'));
    report.operator_object_integrity = { objects_checked: objectFiles.length,
      valid: objectFiles.every(name => name === sha(fs.readFileSync(path.join(operatorDir, 'objects', name)))) };
    if (!args.skipLimiter) {
      await stop(operator);
      const limiterEnv = { ...operatorEnv }; delete limiterEnv.CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN;
      operator = start(args.operatorBin, operatorArgs, limiterEnv);
      await ready(operator, operatorBase, '/healthz');
      const limiter = await parallel(640, 16, () => request(operatorBase, '/v1/info', { admission: true }));
      const { samples: limiterSamples, ...limiterSummary } = limiter;
      report.default_operator_limiter = { ...limiterSummary, configured_per_minute: 600 };
      assert(limiter.rejected > 0 && limiter.failures === 0, 'Default limiter must reject floods with429');
    }
    const db = new DatabaseSync(path.join(accountDir, 'accounts.sqlite3'), { readOnly: true });
    report.account_database = { integrity_check: db.prepare('PRAGMA integrity_check').get().integrity_check,
      journal_mode: db.prepare('PRAGMA journal_mode').get().journal_mode,
      observer_synchronous: db.prepare('PRAGMA synchronous').get().synchronous,
      durability_evidence: 'Service source opens WAL and never changes SQLite default FULL; observer pragma is connection-local, not direct telemetry of service connection',
      secret_versions: db.prepare('SELECT count(*) AS n FROM secret_versions').get().n,
      access_events: db.prepare('SELECT count(*) AS n FROM secret_access_events').get().n };
    db.close();
    await sampleResources();
    report.gates = { no_unexpected_failures: report.phases.every(p => p.failures === 0),
      account_no_rejections: report.phases.filter(p => p.service === 'account').every(p => p.rejected === 0),
      p99_within_budget: report.phases.every(p => p.p99_ms <= args.p99Ms),
      sqlite_integrity_ok: report.account_database.integrity_check === 'ok',
      operator_object_integrity_ok: report.operator_object_integrity.valid,
      backup_audit_checks_passed: report.phases.filter(p => p.backup).every(p => p.backup.audit_chains_checked > 0),
      overload_rejected_when_required: !args.requireRejection || overload.rejected > 0 };
    report.passed = Object.values(report.gates).every(Boolean);
  } catch (error) {
    report.passed = false; report.harness_error = String(error.stack || error);
  } finally {
    clearInterval(resourceTimer);
    for (const child of [...children]) await stop(child);
    // Only delete the exact mkdtemp directory owned by this invocation.
    const absolute = path.resolve(root);
    assert(path.dirname(absolute) === path.resolve(os.tmpdir()) && path.basename(absolute).startsWith('ciphervault-capacity-'));
    try { fs.rmSync(absolute, { recursive: true, force: false }); }
    catch (error) { report.artifacts_retained = true; report.artifact_directory = absolute; report.cleanup_error = String(error); }
    report.completed_at_utc = new Date().toISOString();
    fs.mkdirSync(path.dirname(args.output), { recursive: true });
    fs.writeFileSync(args.output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  }
  console.log(`Capacity probe ${report.passed ? 'PASS' : 'FAIL'}; evidence: ${args.output}`);
  if (!report.passed) process.exitCode = 1;
  return report;
}

if (require.main === module) {
  run(argumentsFor(process.argv.slice(2))).catch(error => { console.error(error); process.exitCode = 1; });
}
module.exports = { argumentsFor, summarize, totpCode };
