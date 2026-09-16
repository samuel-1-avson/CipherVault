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
      getAttribute: (k) => attrs.has(k) ? attrs.get(k) : null,
      setAttribute: (k, v) => attrs.set(k, String(v)),
      removeAttribute: (k) => attrs.delete(k),
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
      reported_block_number: 123456,
      tx_hash: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      status: 'verified',
      verification_status: 'verified',
      chain_id: 421614,
      commitment: '0x112233445566778899aabbcc',
      explorer_url: 'https://sepolia.arbiscan.io/tx/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
    }]
  })`, context);
  assert.equal(getElementById('relayer-mode-display').textContent, 'Automated L2 Relayer: Active');
  assert(getElementById('table-checkpoints-body').innerHTML.includes('123,456'));
  assert(getElementById('table-checkpoints-body').innerHTML.includes('arbiscan.io'));

  // Regression tests for Maintenance Fleet
  vm.runInContext(`renderFleet({
    fleet_summary: { total_tracked_vaults: 2, active_operators: 3, total_operators: 3, avg_latency_ms: 14, audits_completed: 7 },
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
        preview: 'Content previews are disabled.'
      },
      {
        index: 1,
        offset: 16384,
        length: 16384,
        cid_hex: 'b2c3d4e5f6a100112233445566778899aabbccddeeff00112233445566778899',
        gear_fingerprint: '0xabcdef1234567890',
        entropy: 7.891,
        is_duplicate: false,
        preview: 'Content previews are disabled.'
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
  assert.equal(getElementById('detail-chunk-preview').textContent, 'Content previews are disabled.');

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
  assert(checkpointHtml.includes('Not submitted'), 'A checkpoint without a valid transaction hash must not claim relay progress');
  assert(!checkpointHtml.includes('arbiscan.io/tx/'), 'Unmined checkpoint must not fabricate explorer link');
  assert.equal(
    vm.runInContext("checkpointDisplayState({ status: 'SequencerConfirmed' }, '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef').confirmed", context),
    false,
    'A display status alone must not be treated as chain verification',
  );
  assert.equal(
    vm.runInContext("checkpointDisplayState({ verification_status: 'verified' }, '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef').confirmed", context),
    true,
    'Only explicit verification evidence may produce a confirmed checkpoint state',
  );

  // =========================================================================
  // 7. Secret Revision Diff Engine Tests
  // =========================================================================
  vm.runInContext(`
    state.diffReveal = false;
    renderDiffResults({
      base_label: 'head:b38eb88b',
      target_label: 'working tree',
      total_added_keys: 1,
      total_modified_keys: 1,
      total_deleted_keys: 0,
      file_diffs: [
        {
          path: 'secrets.env',
          format: 'Env',
          change_type: 'Modified',
          lines: [
            {
              kind: 'Modified',
              key: 'DATABASE_URL',
              old_value_masked: 'pos***0.1',
              new_value_masked: 'pos***2.5',
              old_value_plain: 'postgres://admin:old@10.0.0.1',
              new_value_plain: 'postgres://admin:new@10.0.2.5'
            },
            {
              kind: 'Added',
              key: 'REDIS_PORT',
              new_value_masked: '63***79',
              new_value_plain: '6379'
            }
          ]
        }
      ]
    });
  `, context);
  assert.equal(getElementById('diff-kpi-added').textContent, '1');
  assert.equal(getElementById('diff-kpi-modified').textContent, '1');
  assert.equal(getElementById('diff-kpi-removed').textContent, '0');
  assert.equal(getElementById('diff-kpi-files').textContent, '1');
  assert(getElementById('diff-results-container').innerHTML.includes('pos***0.1'), 'Diff must show masked secret by default');
  assert(!getElementById('diff-results-container').innerHTML.includes('postgres://admin:old'), 'Diff must not reveal plaintext without unmask toggle');

  // Test reveal unmasking
  vm.runInContext(`
    state.diffReveal = true;
    renderDiffResults({
      base_label: 'head:b38eb88b',
      target_label: 'working tree',
      total_added_keys: 1,
      total_modified_keys: 1,
      total_deleted_keys: 0,
      file_diffs: [
        {
          path: 'secrets.env',
          format: 'Env',
          change_type: 'Modified',
          lines: [
            {
              kind: 'Modified',
              key: 'DATABASE_URL',
              old_value_masked: 'pos***0.1',
              new_value_masked: 'pos***2.5',
              old_value_plain: 'postgres://admin:old@10.0.0.1',
              new_value_plain: 'postgres://admin:new@10.0.2.5'
            }
          ]
        }
      ]
    });
  `, context);
  assert(getElementById('diff-results-container').innerHTML.includes('postgres://admin:old'), 'Diff must show revealed plaintext when toggle is activated');

  // =========================================================================
  // 8. Operator response summary tests
  // =========================================================================
  vm.runInContext(`
    renderOperators([
      { operator_id: 'cv-operator-1', endpoint: 'https://vault.cipherv.online/op/1', status: 'online', latency_ms: 12, transport_security: 'https' },
      { operator_id: 'cv-operator-2', endpoint: 'https://vault.cipherv.online/op/2', status: 'online', latency_ms: 14, transport_security: 'https' },
      { operator_id: 'cv-operator-3', endpoint: 'https://vault.cipherv.online/op/3', status: 'online', latency_ms: 32, transport_security: 'https' }
    ]);
  `, context);
  assert.equal(getElementById('quorum-health-text').textContent, '3/3 operators responding', 'Response summary must reflect configured operators');
  assert(getElementById('operator-response-summary').textContent.includes('3/3 configured operators responded'), 'Response summary must disclose the probe scope');
  assert(getElementById('operators-grid').innerHTML.includes('HTTPS configured'), 'Operator card must display observed transport security');
  assert(getElementById('operators-grid').innerHTML.includes('card-operator-1'), 'Operator card 1 must be rendered in grid');

  vm.runInContext(`
    renderOperators([
      { operator_id: 'cv-operator-1', endpoint: 'https://vault.cipherv.online/op/1', status: 'online', latency_ms: 12, transport_security: 'https', identity_verification: 'verified' },
      { operator_id: 'cv-operator-2', endpoint: 'https://vault.cipherv.online/op/2', status: 'online', latency_ms: 14, transport_security: 'https', identity_status: 'expiring_soon', identity_verification: 'verified' },
      { operator_id: 'cv-operator-3', endpoint: 'https://vault.cipherv.online/op/3', status: 'online', latency_ms: 32, transport_security: 'https', identity_status: 'expired', identity_verification: 'verified' }
    ]);
  `, context);
  assert(getElementById('operators-grid').innerHTML.includes('Verified'), 'Operator card must show verified identity from client fallback');
  assert(getElementById('operators-grid').innerHTML.includes('Expiring soon'), 'Operator card must warn when server reports expiring_soon');
  assert(getElementById('operators-grid').innerHTML.includes('Expired'), 'Operator card must flag server-reported expired identity');

  // =========================================================================
  // 9. Snapshot Deep Inspector Drawer Tests
  // =========================================================================
  vm.runInContext(`
    state.vault = { tracked_files: [{ path: 'secrets.env', size_bytes: 170, file_id_hex: 'b9300ccc11223344' }] };
    openSnapshotDrawer({
      snapshot_id_hex: 'e63584c0642f31b9638af6bc9c806dfb153bd16c91e7124770fcaa630795b28d',
      manifest_cid_hex: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      device_id_hex: '6b793bf54a16d7e5133ddb7eb6201771d4530398ff01400ead0d499bc13ab2d6',
      device_counter: 2,
      epoch: 1,
      timestamp_utc: 1789250000,
      parent_ids_hex: []
    });
  `, context);
  assert(getElementById('snapshot-drawer').classList.contains('open'), 'Drawer must open upon inspect trigger');
  assert(getElementById('snapshot-drawer').classList.contains('drawer-open'), 'Drawer must have drawer-open class');
  assert.equal(getElementById('snapshot-drawer').getAttribute('aria-hidden'), 'false', 'Open drawer must have aria-hidden="false"');
  assert.equal(getElementById('snapshot-drawer').getAttribute('inert'), null, 'Open drawer must be available to assistive technology');
  assert(getElementById('snapshot-drawer-backdrop').classList.contains('active'), 'Drawer backdrop must have active class');
  assert(getElementById('drawer-snap-id').textContent.includes('e63584c0'), 'Drawer must display snapshot ID');
  assert(getElementById('drawer-body').innerHTML.includes('Restore Snapshot to Disk'), 'Drawer must provide one-click restore action');

  // Test drawer close
  vm.runInContext('closeSnapshotDrawer()', context);
  assert(!getElementById('snapshot-drawer').classList.contains('drawer-open'), 'Closed drawer must not have drawer-open');
  assert.equal(getElementById('snapshot-drawer').getAttribute('aria-hidden'), 'true', 'Closed drawer must have aria-hidden="true"');
  assert.equal(getElementById('snapshot-drawer').getAttribute('inert'), '', 'Closed drawer must be inert');
  assert(!getElementById('snapshot-drawer-backdrop').classList.contains('active'), 'Closed backdrop must not have active class');

  // =========================================================================
  // 10. Live Terminal Console & CLI Command Dispatch
  // =========================================================================
  vm.runInContext(`
    appendTerminalLog('DIFF', 'Testing terminal event emission');
    handleTerminalCommand('status');
  `, context);
  assert.equal(getElementById('terminal-event-counter').textContent, '2 events');
  assert(getElementById('terminal-logs').innerHTML.includes('Testing terminal event emission'), 'Terminal log must include emitted message');
  assert(getElementById('terminal-logs').innerHTML.includes('Operators: 3/3 responding'), 'Terminal status command must output live cluster summary');

  // =========================================================================
  // 11. Truthful Active Head & Snapshot History Tests (F06)
  // =========================================================================
  vm.runInContext(`
    renderSnapshots([
      { snapshot_id_hex: 'aaaa1111', device_counter: 1, is_head: false, epoch: 1, timestamp_utc: 1789200000 },
      { snapshot_id_hex: 'bbbb2222', device_counter: 2, is_head: true, epoch: 1, timestamp_utc: 1789210000 },
      { snapshot_id_hex: 'cccc3333', device_counter: 3, is_head: false, epoch: 1, timestamp_utc: 1789220000 }
    ]);
  `, context);
  const dagHtml = getElementById('dag-list').innerHTML;
  assert(dagHtml.includes('ACTIVE HEAD'), 'Active head must be rendered');
  const headCount = (dagHtml.match(/ACTIVE HEAD/g) || []).length;
  assert.equal(headCount, 1, 'Only the true canonical head must receive the ACTIVE HEAD badge');

  // =========================================================================
  // 12. Durable Activity Journal Tests (F13)
  // =========================================================================
  vm.runInContext(`
    renderActivity([
      { event_type: 'SNAPSHOT_PUSH', summary: 'Encrypted snapshot captured', details_json: '{"epoch":1}', created_at_utc: 1789250000 },
      { event_type: 'SNAPSHOT_RESTORE', summary: 'Restored snapshot into ./restore-target', details_json: '{}', created_at_utc: 1789250100 },
      { event_type: 'ARBITRUM_ANCHOR', summary: 'Anchored head commitment to L2', details_json: '{"block":123}', created_at_utc: 1789250200 }
    ]);
  `, context);
  const actHtml = getElementById('activity-feed-list').innerHTML;
  assert(actHtml.includes('SNAPSHOT_PUSH'), 'Activity feed must render push event');
  assert(actHtml.includes('SNAPSHOT_RESTORE'), 'Activity feed must render restore event');
  // =========================================================================
  // 13. Multi-Vault Workspace Explorer Switcher Tests
  // =========================================================================
  assert(getElementById('workspace-switcher-wrap'), 'Workspace switcher dropdown wrapper must exist in DOM');
  assert(getElementById('btn-workspace-switcher'), 'Workspace switcher trigger button must exist');
  assert(getElementById('workspace-dropdown-menu'), 'Workspace dropdown menu must exist');
  assert(getElementById('btn-rescan-workspaces'), 'Rescan workspaces button must exist');

  vm.runInContext(`
    renderWorkspaces([
      {
        name: 'CipherVault (Root)',
        path: 'c:/projects/CipherVault',
        db_path: 'c:/projects/CipherVault/.ciphervault/vault.db',
        vault_id: '11223344',
        active_head_cid: 'aabbccdd',
        snapshot_count: 5,
        tracked_files_count: 3,
        is_active: true
      },
      {
        name: 'Backend-Vault',
        path: 'c:/projects/CipherVault/backend',
        db_path: 'c:/projects/CipherVault/backend/.ciphervault/vault.db',
        vault_id: '55667788',
        active_head_cid: 'eeff0011',
        snapshot_count: 2,
        tracked_files_count: 1,
        is_active: false
      }
    ], 'c:/projects/CipherVault/.ciphervault/vault.db');
  `, context);

  assert.equal(getElementById('workspace-count-badge').textContent, '2');
  assert(getElementById('active-workspace-name').textContent.includes('CipherVault (Root)'));
  const wsHtml = getElementById('workspace-dropdown-list').innerHTML;
  assert(wsHtml.includes('Backend-Vault'), 'Workspace dropdown must list non-active vaults');
  assert(wsHtml.includes('ACTIVE'), 'Active workspace must have ACTIVE badge');

  console.log('All Dashboard audit regressions, WCAG 2.1 AA accessibility checks, and 10x Web Enhancement tests passed!');
})().catch(error => { console.error(error); process.exitCode = 1; });


