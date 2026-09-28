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
  console: { warn() {}, error() {}, debug() {} },
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

  // Regression: the explorer anchors strip never renders a dead href="#.
  vm.runInContext(`state.anchors = [
    { tx_hash_hex: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', chain_id: 421614, reported_block_number: 312389514, finality_status: 'confirmed' },
    { tx_hash_hex: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', chain_id: 999999, reported_block_number: 1, finality_status: 'confirmed' }
  ]`, context);
  vm.runInContext('renderExplorerAnchors()', context);
  const stripHtml = getElementById('explorer-anchors-strip').innerHTML;
  assert(stripHtml.includes('https://sepolia.arbiscan.io/tx/0xaaaa'));
  assert(!stripHtml.includes('href="#'));
  assert(stripHtml.includes('<span title="0xbbbb'));

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

  vm.runInContext(`renderRelayerCheckpoints({
    relayer_status: { public_read_only: true, target_network: 'Arbitrum One', canary_status: 'stale', newest_checkpoint_at_utc: 1 },
    checkpoints: []
  })`, context);
  assert(getElementById('relayer-canary-display').textContent.includes('STALE'), 'Stale canary must raise a visible alarm');
  vm.runInContext(`renderRelayerCheckpoints({
    relayer_status: { public_read_only: true, target_network: 'Arbitrum One', canary_status: 'ok', newest_checkpoint_at_utc: 1999999999 },
    checkpoints: []
  })`, context);
  assert(getElementById('relayer-canary-display').textContent.includes('fresh'), 'Fresh canary must clear the alarm');

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

  // =========================================================================
  // 14. Team Role Matrix + Approval Queue Tests (R14)
  // =========================================================================
  vm.runInContext('renderRoleMatrix()', context);
  const matrixHtml = getElementById('table-role-matrix-body').innerHTML;
  assert(matrixHtml.includes('Invite members'), 'Role matrix must list the invite capability');
  assert(matrixHtml.includes('Editor or below'), 'Role matrix must show the admin grant ceiling');
  assert(matrixHtml.includes('Link vault'), 'Role matrix must list the vault-link capability');

  vm.runInContext(`state.accessMode = 'local_private';`, context);
  response = { ok: true, json: async () => ({ operators: [
    { endpoint: 'op-1', status: 'online', challenges: [{
      challenge_id: 'abcdef1234567890abcdef1234567890',
      action: 'EmergencyRecovery',
      vault_id_hex: 'vv'.repeat(32),
      requester_device_id_hex: 'dd'.repeat(32),
      created_at_utc: 1789250000,
      expires_at_utc: 1789260000,
      details: 'Lost device recovery',
    }] },
    { endpoint: 'op-2', status: 'unavailable', error: 'connection refused', challenges: [] },
  ] }) };
  await vm.runInContext('fetchApprovals()', context);
  const queueHtml = getElementById('table-approvals-body').innerHTML;
  assert(queueHtml.includes('EmergencyRecovery'), 'Approval queue must render the challenge action');
  assert(queueHtml.includes('abcdef123456'), 'Approval queue must render the truncated challenge id');
  assert(queueHtml.includes('op-2'), 'Approval queue must surface unavailable operators');
  assert(!queueHtml.includes('No pending approval challenges.'), 'Non-empty queue must not show the empty state');

  response = { ok: true, json: async () => ({ operators: [] }) };
  await vm.runInContext('fetchApprovals()', context);
  assert(getElementById('table-approvals-body').innerHTML.includes('No pending approval challenges.'), 'Empty queue must show the empty state');

  // =========================================================================
  // 15. Checkpoint Reorg Alarm Tests
  // =========================================================================
  const reorgState = vm.runInContext(
    `checkpointDisplayState({ finality_status: 'reorg_suspected' }, '0x${'ab'.repeat(32)}')`,
    context
  );
  assert.equal(reorgState.label, 'Reorg suspected — deeply-confirmed receipt regressed');
  assert.equal(reorgState.confirmed, false);

  vm.runInContext(`renderRelayerCheckpoints({
    relayer_status: { public_read_only: true, reorg_suspected: true, reorg_suspect_tx_hashes: ['0xaaa', '0xbbb'] },
    checkpoints: []
  })`, context);
  assert.equal(getElementById('relayer-reorg-display').textContent, 'Reorg suspected (2)');

  vm.runInContext(`renderRelayerCheckpoints({
    relayer_status: { public_read_only: true, reorg_suspected: false },
    checkpoints: []
  })`, context);
  assert.equal(getElementById('relayer-reorg-display').textContent, 'No reorg detected');

  // =========================================================================
  // 16. Watcher Event Log Tests (R15)
  // =========================================================================
  vm.runInContext(`renderActivity([{ event_type: 'WATCH_SNAPSHOT', summary: 'Watcher captured snapshot abc123', details_json: '{"files":1,"chunks":4}', created_at_utc: 1789250000 }])`, context);
  const watchHtml = getElementById('activity-feed-list').innerHTML;
  assert(watchHtml.includes('WATCH_SNAPSHOT'), 'Activity feed must render watcher snapshot events');
  assert(watchHtml.includes('Watcher captured snapshot abc123'), 'Activity feed must render the watcher summary');

  // =========================================================================
  // 17. Explorer Search Classification Tests
  // =========================================================================
  const classifyObject = vm.runInContext(`classifyExplorerQuery('${'ab'.repeat(32)}')`, context);
  assert.equal(classifyObject.kind, 'object');
  assert.equal(classifyObject.cid, 'ab'.repeat(32));
  const classifyUpper = vm.runInContext(`classifyExplorerQuery('${'AB'.repeat(32)}')`, context);
  assert.equal(classifyUpper.cid, 'ab'.repeat(32));
  const classifyTx = vm.runInContext(`classifyExplorerQuery('0x${'cd'.repeat(32)}')`, context);
  assert.equal(classifyTx.kind, 'anchor-tx');
  vm.runInContext(`state.operators = [{ operator_id: 'op_alpha_1', display_name: 'Operator 1' }]`, context);
  const classifyOp = vm.runInContext(`classifyExplorerQuery('alpha')`, context);
  assert.equal(classifyOp.kind, 'operator');
  assert.equal(classifyOp.index, 0);
  const classifyUnknown = vm.runInContext(`classifyExplorerQuery('---')`, context);
  assert.equal(classifyUnknown.kind, 'unknown');

  vm.runInContext(`state.explorerObject = { cid: '${'ab'.repeat(32)}', checked_at_utc: 'now', quorum: { present: 3, checked: 3, required: 3, satisfied: true }, replicas: [{ endpoint: 'http://op1:8201', status: 'present', operator_id: 'op_8201', size_bytes: 1024, latency_ms: 12 }] }; renderExplorerObject()`, context);
  const explorerHtml = getElementById('explorer-result').innerHTML;
  assert(explorerHtml.includes('QUORUM 3/3'), 'Explorer must render the quorum badge');
  assert(explorerHtml.includes('op_8201'), 'Explorer must render replica operator ids');

  // =========================================================================
  // 18. Output-Encoding Edge Cases (escapeHtml quotes, formatBytes clamp)
  // =========================================================================
  assert.equal(vm.runInContext(`escapeHtml("a'b\\"c<d>e&f")`, context), 'a&#39;b&quot;c&lt;d&gt;e&amp;f');
  assert.equal(vm.runInContext(`formatBytes(-5)`, context), '--');
  assert.equal(vm.runInContext(`formatBytes(NaN)`, context), '--');
  assert.equal(vm.runInContext(`formatBytes(undefined)`, context), '--');
  assert.equal(vm.runInContext(`formatBytes(0)`, context), '0 B');
  assert.equal(vm.runInContext(`formatBytes(1024)`, context), '1 KiB');
  assert.equal(vm.runInContext(`formatBytes('2048')`, context), '2 KiB');
  assert.equal(vm.runInContext(`formatBytes(5 * 1024 ** 4)`, context), '5 TiB');

  // =========================================================================
  // 19. My Data Overview rendering (private local surface)
  // =========================================================================
  vm.runInContext(`
    renderOverview({
      vault_id_hex: '${'aa'.repeat(32)}',
      device_id_hex: '${'bb'.repeat(32)}',
      current_epoch: 1,
      snapshots: [{ snapshot_id_hex: '${'cc'.repeat(32)}', epoch: 1, advisory_timestamp_utc: 1000000 }],
      active_head_hex: '${'cc'.repeat(32)}',
      tracked_files: 2,
      tracked_bytes_on_disk: 42,
      operators: ['https://op1.cipherv.online'],
      leases: [{ lease_id: 'lease-9', operator: 'https://op1.cipherv.online', bytes: 100, expires_at_utc: 2000000, expired: false }],
      anchors: [{ tx_hash_hex: '${'dd'.repeat(32)}', block_number: 7, chain_id: 42161, timestamp_utc: 1000001 }],
      recent_activity: [{ event_type: 'push', summary: 'snapshot captured', created_at_utc: 1000002 }]
    });
  `, context);
  assert(getElementById('overview-metrics').innerHTML.includes('Storage Leases'), 'Overview must render metric cards');
  assert(getElementById('table-overview-snapshots-body').innerHTML.includes('ccccc'), 'Overview must list snapshots');
  assert(getElementById('table-overview-leases-body').innerHTML.includes('lease-9'), 'Overview must list leases');
  assert(getElementById('table-overview-activity-body').innerHTML.includes('snapshot captured'), 'Overview must list activity');

  vm.runInContext(`renderOverview(null);`, context);
  assert(getElementById('table-overview-snapshots-body').innerHTML.includes('No vault initialized'), 'Overview must degrade honestly without a vault');

  vm.runInContext(`renderOverview({ vault_id_hex: 'ee', snapshots: [], leases: [], anchors: [], recent_activity: [] });`, context);
  assert(getElementById('table-overview-leases-body').innerHTML.includes('ciphervault lease create'), 'Overview must guide toward lease creation when empty');

  // My Data tab must be a private surface (hidden on the public explorer).
  const shellHtml = fs.readFileSync(`${__dirname}/index.html`, 'utf8');
  assert(shellHtml.match(/id="tab-btn-overview"[^>]*data-private-surface/), 'My Data tab button must carry data-private-surface');
  assert(shellHtml.match(/id="tab-overview"[^>]*data-private-surface/), 'My Data tab panel must carry data-private-surface');

  // =========================================================================
  // 20. Enhanced Productivity Suite: Command Palette, Secret Health & Filter
  // =========================================================================
  // Command Palette build and search
  vm.runInContext(`
    state.overview = {
      tracked_files: [{ path: '.env.production', size_bytes: 512 }, { path: 'certs/server.crt', size_bytes: 2048 }],
      snapshots: [{ snapshot_id_hex: '${'ff'.repeat(32)}', epoch: 2, timestamp_utc: Math.floor(Date.now() / 1000) }]
    };
    buildPaletteItems('');
  `, context);
  const paletteItemsAll = vm.runInContext('state.paletteItems', context);
  assert(paletteItemsAll.some(i => i.title.includes('Go to Storage Operators')), 'Command palette must include navigation targets');
  assert(paletteItemsAll.some(i => i.title.includes('Push Snapshot')), 'Command palette must include quick actions');
  assert(paletteItemsAll.some(i => i.title.includes('.env.production')), 'Command palette must index tracked secret files');

  // Command Palette query filtering
  vm.runInContext(`buildPaletteItems('.env'); renderPaletteResults();`, context);
  const filteredItems = vm.runInContext('state.paletteItems', context);
  assert(filteredItems.every(i => i.title.toLowerCase().includes('.env') || i.category.toLowerCase().includes('.env')), 'Filtering must prune non-matching items');

  // Command Palette execution
  let executedAction = false;
  context.testActionRan = () => { executedAction = true; };
  vm.runInContext(`
    state.paletteItems = [{ title: 'Test Action', action: testActionRan }];
    executePaletteItem(0);
  `, context);
  assert(executedAction, 'Executing palette item must trigger its action callback');

  // Secret Health & Hygiene analysis verification
  vm.runInContext(`
    renderSecretHealth({
      tracked_files: [
        { path: '.env.production', size_bytes: 1024 },
        { path: 'certs/tls.crt', size_bytes: 2048 }
      ],
      snapshots: [{ timestamp_utc: Math.floor(Date.now() / 1000) - 86400 }]
    });
  `, context);
  assert.equal(getElementById('val-health-score').textContent, '100%', 'Clean recently updated secrets must have 100% hygiene');
  assert(getElementById('card-health-certs').classList.contains('ok'), 'Certificate detection must report valid');

  // Staleness degradation check (>90 days old)
  vm.runInContext(`
    renderSecretHealth({
      tracked_files: [{ path: '.env.production', size_bytes: 1024 }],
      snapshots: [{ timestamp_utc: Math.floor(Date.now() / 1000) - (95 * 86400) }]
    });
  `, context);
  assert(getElementById('val-health-score').textContent !== '100%', 'Stale secrets over 90 days must degrade hygiene score');
  assert(getElementById('card-health-staleness').classList.contains('warn'), 'Stale secrets must flag warning status');

  // Accessibility checks for new elements
  assert(shellHtml.match(/id="btn-open-command-palette"[^>]*aria-label/), 'Command Palette button must have aria-label');
  assert(shellHtml.match(/id="modal-command-palette"[^>]*role="dialog"/), 'Command Palette modal must have role=dialog');
  assert(shellHtml.match(/id="command-palette-results"[^>]*role="listbox"/), 'Palette results must have role=listbox');
  assert(shellHtml.match(/id="card-secret-health"[^>]*data-private-surface/), 'Secret Health card must carry data-private-surface');

  // 21. Minimal Design & Light/Dark Theme Engine verification
  assert(shellHtml.match(/id="btn-theme-toggle"[^>]*aria-label/), 'Theme toggle button must have aria-label');
  assert(shellHtml.includes('icon-theme-sun') && shellHtml.includes('icon-theme-moon'), 'Theme toggle button must include both sun and moon SVG icons');

  const cssContent = fs.readFileSync(`${__dirname}/styles.css`, 'utf8');
  assert(cssContent.includes('html[data-theme="light"]'), 'styles.css must contain light theme variables');
  assert(cssContent.includes('html[data-theme="dark"]') || cssContent.includes(':root'), 'styles.css must contain dark theme variables');
  assert(!cssContent.includes('#0b0a08'), 'styles.css must not use harsh pitch-black #0b0a08');

  // Verify theme functions in VM
  vm.runInContext(`
    document.documentElement = {
      attrs: {},
      setAttribute(k, v) { this.attrs[k] = String(v); },
      getAttribute(k) { return this.attrs[k] || null; }
    };
    applyTheme('light');
  `, context);
  assert.equal(vm.runInContext("document.documentElement.getAttribute('data-theme')", context), 'light');
  assert.equal(getElementById('btn-theme-toggle').getAttribute('aria-label'), 'Switch to Dark Mode');

  vm.runInContext("applyTheme('dark')", context);
  assert.equal(vm.runInContext("document.documentElement.getAttribute('data-theme')", context), 'dark');
  assert.equal(getElementById('btn-theme-toggle').getAttribute('aria-label'), 'Switch to Light Mode');

  const toggledTheme = vm.runInContext("toggleTheme()", context);
  assert.equal(toggledTheme, 'light');
  assert.equal(vm.runInContext("document.documentElement.getAttribute('data-theme')", context), 'light');

  // Command palette includes theme toggle
  const paletteThemeItem = vm.runInContext("buildPaletteItems('').find(i => i.title.includes('Theme'))", context);
  assert(paletteThemeItem, 'Command Palette must contain theme toggle action');
  assert.equal(paletteThemeItem.category, 'Actions');

  // Scoped explorer banner (T-703): shows project/env, degrades honestly.
  response = { ok: true, json: async () => ({ status: 'ok', project_slug: 'shop', project_source: 'env', environment_slug: 'staging' }) };
  await vm.runInContext('fetchScopeBanner()', context);
  assert.equal(getElementById('scope-banner-text').textContent, 'Scope: shop/staging');
  assert(getElementById('scope-banner').classList.contains('is-ok'));
  assert(!getElementById('scope-banner').classList.contains('is-unset'));
  response = { ok: true, json: async () => ({ status: 'ok', project_slug: 'shop', environment_slug: null }) };
  await vm.runInContext('fetchScopeBanner()', context);
  assert.equal(getElementById('scope-banner-text').textContent, 'Scope: shop');
  response = { ok: true, json: async () => ({ status: 'unconfigured', hint: 'Set CIPHERVAULT_SCOPE_TOKEN' }) };
  await vm.runInContext('fetchScopeBanner()', context);
  assert.equal(getElementById('scope-banner-text').textContent, 'Scope: not configured');
  assert(getElementById('scope-banner').classList.contains('is-unset'));
  assert(!getElementById('scope-banner').classList.contains('is-ok'));
  response = { ok: false };
  await vm.runInContext('fetchScopeBanner()', context);
  assert.equal(getElementById('scope-banner-text').textContent, 'Scope: not configured');

  // 22. The public explorer must not offer device-key sign-in: the ceremony
  // signs with the local vault keystore, which a remote browser cannot
  // reach. Local workspaces keep the option.
  vm.runInContext(`applyAccessContext({ mode: 'public_explorer' })`, context);
  assert.equal(getElementById('btn-signin-device').hidden, true);
  assert.equal(getElementById('btn-signin-device').getAttribute('aria-hidden'), 'true');
  vm.runInContext(`applyAccessContext({ mode: 'local_private' })`, context);
  assert.equal(getElementById('btn-signin-device').hidden, false);
  assert.equal(getElementById('btn-signin-device').getAttribute('aria-hidden'), 'false');

  // 23. Local-vault tabs stay off the public explorer, and local-only
  // actions never touch the network there (no 403 error walls).
  for (const tab of ['diff', 'dag', 'files', 'activity', 'guardians', 'fleet', 'fastcdc']) {
    assert(shellHtml.match(new RegExp(`id="tab-btn-${tab}"[^>]*data-private-surface`)), `tab-btn-${tab} must carry data-private-surface`);
    assert(shellHtml.match(new RegExp(`id="tab-${tab}"[^>]*data-private-surface`)), `tab-${tab} must carry data-private-surface`);
  }
  assert(shellHtml.match(/id="workspace-switcher-wrap"[^>]*data-private-surface/), 'Workspace switcher must carry data-private-surface');
  assert(shellHtml.match(/id="scope-banner"[^>]*data-private-surface/), 'Scope banner must carry data-private-surface');

  let publicFetchCount = 0;
  const stockFetch = context.fetch;
  context.fetch = async () => { publicFetchCount++; return { ok: false, status: 403, json: async () => ({}) }; };
  vm.runInContext(`state.accessMode = 'public_explorer';`, context);
  await vm.runInContext('runDiffComparison()', context);
  assert.equal(publicFetchCount, 0, 'diff must not fetch on the public explorer');
  await vm.runInContext('fetchApprovals()', context);
  assert.equal(publicFetchCount, 0, 'approvals must not fetch on the public explorer');
  assert.equal(getElementById('approvals-status').textContent, 'Approval queue is available only in a local private workspace.');
  context.fetch = stockFetch;

  console.log('All Dashboard audit regressions, WCAG 2.1 AA accessibility checks, and 10x Web Enhancement tests passed!');
})().catch(error => { console.error(error); process.exitCode = 1; });



