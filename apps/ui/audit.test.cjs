const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map();
const getElementById = id => {
  if (!elements.has(id)) elements.set(id, { textContent: '', style: {}, innerHTML: '' });
  return elements.get(id);
};
let response;
const context = vm.createContext({
  document: { addEventListener() {}, getElementById },
  console: { warn() {}, error() {} },
  fetch: async () => response,
});
vm.runInContext(fs.readFileSync(`${__dirname}/app.js`, 'utf8'), context);
(async () => {
  // Reachable operators cannot independently establish durability.
  vm.runInContext("state.operators = [{status:'online'}, {status:'online'}, {status:'online'}]", context);
  response = { ok: true, json: async () => ({ report: { healthy: false, recoverable_operators: ['one', 'two'], objects: { lost_count: 1 } } }) };
  await vm.runInContext('fetchAudit()', context);
  assert.equal(getElementById('badge-durability-state').textContent, 'Degraded');
  assert.equal(getElementById('durability-ratio').textContent, '2/3');
  response = { ok: true, json: async () => ({ report: { healthy: true, recoverable_operators: ['one','two','three'], objects: { lost_count: 0 } } }) };
  await vm.runInContext('fetchAudit()', context);
  assert.equal(getElementById('badge-durability-state').textContent, 'Verified');
  // An unavailable audit must clear a previously healthy state.
  response = { ok: false };
  await vm.runInContext('fetchAudit()', context);
  assert.equal(getElementById('badge-durability-state').textContent, 'Unverified');
  assert.equal(getElementById('durability-ratio').textContent, '--/3');
  vm.runInContext("renderTrackedFiles([{path:'never-uploaded', file_id_hex:'abcd', size_bytes:1}])", context);
  assert(!getElementById('table-files-body').innerHTML.includes('Replicas Verified'));
  console.log('Dashboard audit regressions passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
