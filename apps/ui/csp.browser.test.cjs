// Run against actual dashboard assets with the production CSP and synthetic APIs.
// Requires a Chromium browser; set CIPHERVAULT_TEST_BROWSER for CI/custom installs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const candidates = [process.env.CIPHERVAULT_TEST_BROWSER,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].filter(Boolean);
const browser = candidates.find(candidate => fs.existsSync(candidate));
assert(browser, 'A Chromium browser is required; set CIPHERVAULT_TEST_BROWSER.');
const router = fs.readFileSync(path.join(root, 'apps/cli/src/dashboard/router.rs'), 'utf8');
const csp = router.match(/const UI_SHELL_CSP: &str = "([^"]+)"/)[1];
assert(!csp.includes('unsafe-inline'), 'Production CSP must remain strict.');
const markup = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const script = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
assert(!/\b(?:style|on\w+)\s*=\s*["']/.test(markup), 'Static HTML contains inline styles or event attributes.');
assert(!/\b(?:style|on\w+)\s*=\s*["']/.test(script), 'Generated markup contains inline styles or event attributes.');

const harness = `
const cspViolations = [], scriptErrors = [];
document.addEventListener('securitypolicyviolation', e => cspViolations.push(e.effectiveDirective));
window.addEventListener('error', e => scriptErrors.push(e.message));
document.addEventListener('DOMContentLoaded', () => setTimeout(async () => {
  const result = {};
  try {
    await fetchAllData();
    state.accessMode = 'local_private';
    applyAccessContext({mode:'local_private'});
    let diffClicks = 0, pushClicks = 0;
    const diff = document.getElementById('btn-run-diff');
    diff.disabled = false;
    diff.addEventListener('click', () => diffClicks++, {capture:true});
    document.querySelector('[data-click-target="btn-run-diff"]').click();
    const push = document.getElementById('btn-open-create-snapshot');
    push.disabled = false;
    push.addEventListener('click', () => pushClicks++, {capture:true});
    renderSnapshots([]);
    document.querySelector('[data-click-target="btn-open-create-snapshot"]').click();
    result.diffClicks = diffClicks; result.pushClicks = pushClicks;
    result.pushModalOpen = document.getElementById('modal-create-snapshot').classList.contains('open');
    renderLatencyBars([{status:'online', latency_ms:120, operator_id:'synthetic'}]);
    const latency = document.querySelector('.latency-bar-fill');
    result.latencyWidth = latency && latency.style.width;
    result.latencyColor = latency && getComputedStyle(latency).backgroundColor;
    openSnapshotInspector({snapshot_id_hex:'aa', parent_ids_hex:[], signature_verified:false});
    result.unverifiedLabel = document.getElementById('modal-inspector-body').textContent;
    openSnapshotInspector({snapshot_id_hex:'aa', parent_ids_hex:[], signature_verified:true});
    result.verifiedLabel = document.getElementById('modal-inspector-body').textContent;
    result.initiallyHidden = getComputedStyle(document.querySelector('.sidebar-category-filter')).display;
    handleTelemetryPacket({token_attached:null, pending_uploads:{count:3, failed_count:1, oldest_created_at_utc:1700000000}});
    const backlog = document.getElementById('pending-upload-status');
    result.backlogText = backlog.textContent;
    result.backlogRole = backlog.getAttribute('role');
    result.backlogLive = backlog.getAttribute('aria-live');
    result.tokenUnknown = document.getElementById('sse-token-status').textContent;
    handleTelemetryPacket({pending_uploads:{count:0, failed_count:0, oldest_created_at_utc:null}});
    result.backlogEmpty = backlog.textContent;
    closeSseStream(); clearInterval(state.pollTimer);
    await new Promise(resolve => setTimeout(resolve, 50));
  } catch (error) { result.error = String(error.stack || error); }
  result.cspViolations = cspViolations; result.scriptErrors = scriptErrors;
  document.body.setAttribute('data-csp-test', btoa(JSON.stringify(result)));
}, 150));
`;

const server = http.createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');
  response.setHeader('Content-Security-Policy', csp);
  response.setHeader('Cache-Control', 'no-store');
  if (url.pathname === '/') {
    response.setHeader('Content-Type', 'text/html');
    response.end(markup.replace('</body>', '<script src="/test-harness.js"></script></body>'));
  } else if (url.pathname === '/test-harness.js') {
    response.setHeader('Content-Type', 'application/javascript'); response.end(harness);
  } else if (url.pathname === '/app.js' || url.pathname === '/styles.css') {
    response.setHeader('Content-Type', url.pathname.endsWith('.css') ? 'text/css' : 'application/javascript');
    response.end(fs.readFileSync(path.join(__dirname, url.pathname.slice(1))));
  } else if (url.pathname.startsWith('/api/')) {
    response.setHeader('Content-Type', 'application/json');
    const payload = url.pathname === '/api/context' ? {mode:'local_private'}
      : url.pathname === '/api/snapshots' ? {snapshots:[]}
      : url.pathname === '/api/operators' ? {operators:[]}
      : url.pathname === '/api/events' ? null : {};
    if (payload === null) { response.statusCode = 204; response.end(); }
    else response.end(JSON.stringify(payload));
  } else { response.statusCode = 404; response.end(); }
});

(async () => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-csp-browser-'));
  let child;
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = 'http://127.0.0.1:' + server.address().port;
    child = spawn(browser, ['--headless=new', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check',
      '--disable-extensions', '--disable-background-networking', '--user-data-dir=' + profile,
      '--virtual-time-budget=2500', '--dump-dom', url], {windowsHide:true});
    let output = '', diagnostics = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { diagnostics += data; });
    const timer = setTimeout(() => child.kill(), 25000);
    const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('exit', resolve); });
    clearTimeout(timer);
    assert.equal(code, 0, 'Browser failed: ' + diagnostics.slice(-1500));
    const encoded = output.match(/data-csp-test="([^"]+)"/);
    assert(encoded, 'Browser test did not complete: ' + diagnostics.slice(-1500));
    const result = JSON.parse(Buffer.from(encoded[1], 'base64').toString());
    assert(!result.error, result.error);
    assert.deepEqual(result.scriptErrors, [], 'Actual browser script errors');
    assert.deepEqual(result.cspViolations, [], 'Production CSP violations');
    assert.equal(result.diffClicks, 1, 'Diff empty-state control must forward a click');
    assert.equal(result.pushClicks, 1, 'Initial push control must forward a click');
    assert.equal(result.pushModalOpen, true, 'Initial push must open the existing capture modal');
    assert.equal(result.latencyWidth, '100%');
    assert.notEqual(result.latencyColor, 'rgba(0, 0, 0, 0)');
    assert(result.unverifiedLabel.includes('Signature not verified'));
    assert(!result.unverifiedLabel.includes('Ed25519 signature verified'));
    assert(result.verifiedLabel.includes('Ed25519 signature verified'));
    assert.equal(result.initiallyHidden, 'none', 'Stylesheet must preserve initially hidden layouts');
    assert(result.backlogText.includes('3 pending upload(s), 1 with recorded failed attempts'));
    assert.equal(result.backlogRole, 'status');
    assert.equal(result.backlogLive, 'polite');
    assert.equal(result.tokenUnknown, 'Smartcard Probe Unavailable');
    assert(result.backlogEmpty.includes('no pending uploads in the last observation'));
    console.log('Actual Chromium dashboard CSP regression passed: forwarded controls, layout, truthful signatures, zero policy violations.');
  } finally {
    child?.kill(); server.close();
    await new Promise(resolve => setTimeout(resolve, 150));
    fs.rmSync(profile, {recursive:true, force:true});
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
