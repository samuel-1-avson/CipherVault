const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map();
const getElementById = id => {
  if (!elements.has(id)) {
    const classes = new Set();
    const attrs = new Map();
    elements.set(id, {
      id,
      textContent: '',
      style: {},
      innerHTML: '',
      querySelectorAll: () => [],
      querySelector: () => null,
      getAttribute: (k) => attrs.get(k) || null,
      setAttribute: (k, v) => attrs.set(k, String(v)),
      addEventListener: () => {},
      focus: () => {},
      classList: {
        add: (c) => classes.add(c),
        remove: (c) => classes.delete(c),
        contains: (c) => classes.has(c),
      }
    });
  }
  return elements.get(id);
};
let response;
const context = vm.createContext({
  document: { addEventListener() {}, getElementById, querySelectorAll: () => [], activeElement: null },
  window: { addEventListener() {} },
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

  // Regression tests for Threshold Guardians
  vm.runInContext(`renderGuardians({
    active_threshold: 3,
    total_guardians: 5,
    sheets: [{
      share_index: 1,
      guardian_name: 'Guardian 1',
      threshold: 3,
      total_shares: 5,
      recovery_signing_pk: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      recovery_encrypt_pk: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
      recovery_locator: 'loc123456789',
      crc32: '9ABCDEF0',
      sheet_text: 'TEST-SHEET'
    }]
  })`, context);
  assert.equal(getElementById('badge-tab-guardians').textContent, '3-of-5');
  assert.equal(getElementById('quorum-circle-badge').textContent, '3 / 5');
  assert(getElementById('guardians-grid').innerHTML.includes('card-guardian-1'));

  // Regression tests for L2 Relayer & Checkpoints
  vm.runInContext(`renderRelayerCheckpoints({
    relayer_status: { operational: true, mode: 'auto_relayer', target_network: 'Arbitrum One / Sepolia' },
    checkpoints: [{
      block_number: 123456,
      tx_hash: '0xdeadbeef1234567890abcdef',
      status: 'SequencerConfirmed',
      commitment: '0x112233445566778899aabbcc',
      explorer_url: 'https://sepolia.arbiscan.io/tx/0xdeadbeef1234567890abcdef'
    }]
  })`, context);
  assert.equal(getElementById('relayer-mode-display').textContent, 'Automated L2 Relayer: Active');
  assert(getElementById('table-checkpoints-body').innerHTML.includes('123,456'));
  assert(getElementById('table-checkpoints-body').innerHTML.includes('arbiscan.io'));

  // Regression tests for Maintenance Fleet
  vm.runInContext(`renderFleet({
    fleet_summary: { total_tracked_vaults: 2, active_operators: 3, avg_latency_ms: 14, audits_completed: 7 },
    vaults: [{ vault_id: 'vault_alpha', head_cid: 'cid_123', storage_allowance_bytes: 1048576, registered_at: '2026-09-12' }],
    operator_nodes: [{ operator_id: 'op-1', endpoint: 'http://127.0.0.1:8081', status: 'Online', latency_ms: 12, last_heartbeat: '2026-09-12' }],
    audit_history: [{ id: 1, vault_id: 'vault_alpha', status: 'Healthy', healthy_objects: 5, degraded_objects: 0, repaired_objects: 0, duration_ms: 18, timestamp: '2026-09-12' }]
  })`, context);
  assert.equal(getElementById('fleet-kpi-vaults').textContent, '2');
  assert.equal(getElementById('fleet-kpi-operators').textContent, '3 / 3');
  assert.equal(getElementById('fleet-kpi-latency').textContent, '14 ms');
  assert.equal(getElementById('fleet-kpi-audits').textContent, '7');
  assert(getElementById('fleet-operators-grid').innerHTML.includes('op-1'));
  assert(getElementById('table-fleet-vaults-body').innerHTML.includes('vault_alph'));
  assert(getElementById('table-fleet-audits-body').innerHTML.includes('Healthy'));

  // Regression tests for Live SSE Telemetry Stream
  vm.runInContext(`handleTelemetryPacket({
    timestamp: '2026-09-12T12:00:00Z',
    operators: [
      { endpoint: 'http://operator-1:8201', online: true, latency_ms: 12 },
      { endpoint: 'http://operator-2:8202', online: true, latency_ms: 18 },
      { endpoint: 'http://operator-3:8203', online: false, latency_ms: 999 }
    ],
    token_attached: true
  })`, context);
  assert.equal(getElementById('sse-op1-lat').textContent, '12 ms');
  assert.equal(getElementById('sse-op2-lat').textContent, '18 ms');
  assert.equal(getElementById('sse-op3-lat').textContent, 'OFFLINE');
  assert(getElementById('sse-token-status').textContent.includes('Slot 9C/9D Ready'));

  // Regression tests for FastCDC Inspector & Slicing
  vm.runInContext(`renderFastCdcResults({
    config: { min_size: 4096, avg_size: 16384, max_size: 65536 },
    metrics: {
      total_bytes: 65536,
      total_chunks: 4,
      unique_chunks: 3,
      duplicate_chunks: 1,
      unique_bytes: 49152,
      saved_bytes: 16384,
      dedup_savings_pct: 25.0,
      fixed_chunks_count: 4,
      boundary_shift_resilient: true
    },
    chunks: [
      {
        index: 0,
        offset: 0,
        length: 16384,
        cid_hex: 'a1b2c3d4e5f600112233445566778899aabbccddeeff00112233445566778899',
        gear_fingerprint: '0x1234567890abcdef',
        entropy: 5.432,
        is_duplicate: false,
        preview: '{"timestamp":"2026-09-12T12:00:00Z"}'
      },
      {
        index: 1,
        offset: 16384,
        length: 16384,
        cid_hex: 'b2c3d4e5f6a100112233445566778899aabbccddeeff00112233445566778899',
        gear_fingerprint: '0xabcdef1234567890',
        entropy: 7.891,
        is_duplicate: false,
        preview: 'data_stream_high_entropy'
      }
    ]
  })`, context);
  assert.equal(getElementById('f-metric-total-chunks').textContent, '4');
  assert.equal(getElementById('f-metric-savings-pct').textContent, '25.0%');
  assert.equal(getElementById('badge-tab-fastcdc').textContent, '4 Chunks');
  assert(getElementById('chunk-blocks-container').innerHTML.includes('chunk-block'));

  // Test selecting chunk 1
  vm.runInContext('selectChunk(1)', context);
  assert.equal(getElementById('detail-chunk-index').textContent, '1');
  assert.equal(getElementById('detail-chunk-gear').textContent, '0xabcdef1234567890');
  assert.equal(getElementById('detail-chunk-cid').textContent, 'b2c3d4e5f6a100112233445566778899aabbccddeeff00112233445566778899');

  // Regression tests for backend-emitted Guardian Split and Fleet responses (Contract reconciliation)
  vm.runInContext(`renderGuardians({
    status: 'ok',
    success: true,
    is_drill_demo: true,
    active_threshold: 3,
    total_guardians: 5,
    threshold: 3,
    total_shares: 5,
    shares_count: 1,
    sheets: [{
      share_index: 1,
      guardian_index: 1,
      guardian_name: 'Guardian 1',
      threshold: 3,
      total_shares: 5,
      vault_id_hex: '00112233',
      recovery_signing_pk: 'aabbccdd',
      recovery_encrypt_pk: '11223344',
      recovery_locator: 'loc1234',
      crc32: '0x12345678',
      checksum_hex: '0x12345678',
      sheet_text: 'TEST-RECONCILED-SHEET',
      printable_sheet: 'TEST-RECONCILED-SHEET'
    }]
  })`, context);
  assert.equal(getElementById('badge-tab-guardians').textContent, '3-of-5');

  // =========================================================================
  // P2.4 Accessibility (WCAG 2.1 AA) & Protocol Assurance Tests
  // =========================================================================
  const htmlContent = fs.readFileSync(`${__dirname}/index.html`, 'utf8');

  // 1. Verify Skip Link for keyboard navigation
  assert(
    htmlContent.includes('<a href="#main-content" class="skip-link">Skip to main content</a>'),
    'index.html must include accessible skip navigation link'
  );

  // 2. Verify Main Landmark
  assert(
    htmlContent.includes('<main id="main-content" tabindex="-1">'),
    'index.html must include accessible main landmark with tabindex=-1'
  );

  // 3. Verify Tablist & Tabpanel Semantics
  assert(
    htmlContent.includes('role="tablist"'),
    'Tab navigation must have role="tablist"'
  );
  assert(
    htmlContent.includes('role="tab"'),
    'Tab buttons must have role="tab"'
  );
  assert(
    htmlContent.includes('role="tabpanel"'),
    'Tab content sections must have role="tabpanel"'
  );

  // 4. Verify Live Status Indicators
  assert(
    htmlContent.includes('id="cluster-status-indicator" role="status" aria-live="polite"'),
    'Cluster status indicator must have role="status" and aria-live="polite"'
  );
  assert(
    htmlContent.includes('id="sse-stream-indicator" role="status" aria-live="polite"'),
    'SSE telemetry indicator must have role="status" and aria-live="polite"'
  );

  // 5. Verify Modal Accessibility State Transitions
  vm.runInContext(`
    const testModal = document.getElementById('modal-test-acc');
    const testTrigger = document.getElementById('btn-test-trigger');
    openModal(testModal, testTrigger);
  `, context);
  const testModal = getElementById('modal-test-acc');
  assert.equal(testModal.getAttribute('aria-hidden'), 'false');
  assert(testModal.classList.contains('open'));

  vm.runInContext(`
    closeModal(testModal);
  `, context);
  assert.equal(testModal.getAttribute('aria-hidden'), 'true');
  assert(!testModal.classList.contains('open'));

  // 6. Verify Truthful Arbitrum L2 Settlement Rendering
  vm.runInContext(`renderRelayerCheckpoints({
    relayer_status: { operational: true, mode: 'auto_relayer', target_network: 'Arbitrum One / Sepolia' },
    checkpoints: [{
      block_number: 0,
      tx_hash: '',
      status: 'QueuedForRelay',
      commitment: '0x33445566778899aabbccddeeff',
      explorer_url: ''
    }]
  })`, context);
  const checkpointHtml = getElementById('table-checkpoints-body').innerHTML;
  assert(checkpointHtml.includes('QueuedForRelay'), 'Unmined checkpoint must truthfully report QueuedForRelay');
  assert(!checkpointHtml.includes('arbiscan.io/tx/'), 'Unmined checkpoint must not fabricate explorer link');

  console.log('Dashboard audit regressions & WCAG 2.1 AA accessibility checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });

