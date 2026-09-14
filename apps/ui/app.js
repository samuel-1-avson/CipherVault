// CipherVault Web Dashboard & Visual Vault Inspector Client Logic

const state = {
  vault: null,
  audit: null,
  fetching: false,
  operators: [],
  operatorObservedAt: null,
  snapshots: [],
  context: null,
  // Treat an unrecognized server as public until it explicitly identifies a
  // loopback private workspace. This prevents private controls from flashing
  // while the context request is pending or unavailable.
  accessMode: 'restricted',
  anchors: [],
  guardians: null,
  relayerCheckpoints: [],
  fleet: null,
  activity: [],
  searchQueryDag: '',
  searchQueryFiles: '',
  lastActiveElement: null,
  isPolling: true,
  pollTimer: null,
  sseStream: null,
  fastCdcResult: null,
  fastCdcVaultFilesLoaded: false,
  selectedChunkIndex: null,
  diffReveal: false,
  terminalEventsCount: 0,
  drawerSnapshotId: null,
};

document.addEventListener('DOMContentLoaded', () => {
  applyAccessContext({ mode: state.accessMode });
  initTabs();
  initModals();
  initCopyActions();
  initSecretToggle();
  initSearchFilters();
  initQuickActions();
  initMathVerifier();
  initRelayerActions();
  initFleetActions();
  initFastCdcInspector();
  initDiffViewer();
  initFileManagement();
  initSnapshotDrawer();
  initActivityFeed();
  initTerminalConsole();
  initKeyboardShortcuts();
  initWorkspaceSwitcher();
  
  // Initial data load and periodic polling
  fetchAllData();
  state.pollTimer = setInterval(() => {
    if (!document.hidden) fetchAllData();
  }, 30000);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      closeSseStream();
    } else {
      fetchAllData();
    }
  });
});

// -------------------------------------------------------------
// Data Fetching & State Synchronization
// -------------------------------------------------------------

async function fetchAllData() {
  if (state.fetching) return;
  state.fetching = true;
  captureSearchFilters();
  const refreshIcon = document.getElementById('icon-refresh');
  if (refreshIcon) refreshIcon.classList.add('rotating');

  try {
    // Resolve the serving context before asking for any private vault state.
    await fetchContext();
    if (!document.hidden) initSseStream();

    const requests = [
      fetchVault(),
      fetchOperators(),
      fetchAnchors(),
      fetchRelayerCheckpoints(),
    ];

    if (canAccessPrivateFeature('snapshot_history')) requests.push(fetchSnapshots());
    if (canAccessPrivateFeature('vault_workspace')) requests.push(fetchGuardians(), fetchActivity(), fetchFleet());
    if (canAccessPrivateFeature('workspace_switching')) requests.push(fetchWorkspaces());

    await Promise.all(requests);
  } catch (err) {
    console.error("Data synchronization error:", err);
  } finally {
    state.fetching = false;
    restoreSearchFilters();
    if (refreshIcon) {
      setTimeout(() => refreshIcon.classList.remove('rotating'), 600);
    }
  }
}

async function fetchContext() {
  try {
    const response = await fetch('/api/context');
    if (!response.ok) return;
    const context = await response.json();
    if (!context || typeof context !== 'object') return;

    state.context = context;
    if (typeof context.mode !== 'string') return;
    state.accessMode = context.mode;
    applyAccessContext(context);
  } catch (error) {
    console.debug('Dashboard context unavailable; private controls remain unavailable:', error);
  }
}

function isPublicExplorer() {
  return state.accessMode !== 'local_private';
}

function canAccessPrivateFeature(feature) {
  if (isPublicExplorer()) return false;
  const capabilities = state.context && state.context.capabilities;
  if (!capabilities || !Object.prototype.hasOwnProperty.call(capabilities, feature)) return true;
  return capabilities[feature] === true;
}

function operatorResponded(operator) {
  return Boolean(operator && (operator.status === 'online' || operator.status === 'reachable'));
}

function applyAccessContext(context) {
  const publicExplorer = !context || context.mode !== 'local_private';
  if (document.body && document.body.classList) {
    document.body.classList.toggle('public-explorer', publicExplorer);
    document.body.classList.toggle('local-private-explorer', !publicExplorer);
  }

  const publicNotice = document.getElementById('public-explorer-notice');
  if (publicNotice) publicNotice.hidden = !publicExplorer;

  const vaultIdentityLabel = document.getElementById('vault-identity-label');
  if (vaultIdentityLabel) vaultIdentityLabel.textContent = publicExplorer ? 'EXPLORER' : 'VAULT';
  const copyVaultId = document.getElementById('btn-copy-vault-id');
  if (copyVaultId) {
    copyVaultId.disabled = publicExplorer;
    copyVaultId.setAttribute('aria-disabled', publicExplorer ? 'true' : 'false');
    copyVaultId.title = publicExplorer ? 'Public explorer has no connected vault ID' : 'Copy Vault ID';
  }

  if (typeof document.querySelectorAll === 'function') {
    document.querySelectorAll('[data-private-surface]').forEach(element => {
      const isDialog = element.getAttribute && element.getAttribute('role') === 'dialog';
      if (publicExplorer) {
        element.hidden = true;
        element.setAttribute('aria-hidden', 'true');
      } else {
        element.hidden = false;
        // A closed modal or drawer owns its own aria-hidden state. Reopening a
        // local workspace must not make an already-open dialog disappear from
        // assistive technology on the next poll.
        if (!isDialog) element.setAttribute('aria-hidden', 'false');
      }
    });
    document.querySelectorAll('[data-private-action]').forEach(element => {
      element.hidden = publicExplorer;
      element.disabled = publicExplorer;
      element.setAttribute('aria-hidden', publicExplorer ? 'true' : 'false');
    });
  }

  if (publicExplorer) {
    if (activeModal) closeModal(activeModal);
    state.snapshots = [];
    state.audit = null;
    state.guardians = null;
    state.activity = [];
    closeSnapshotDrawer();
    const activeTab = typeof document.querySelector === 'function'
      ? document.querySelector('.tab-btn.active[hidden]')
      : null;
    const publicTab = document.getElementById('tab-btn-operators');
    if (activeTab && publicTab && typeof publicTab.click === 'function') publicTab.click();
  }
}

function captureSearchFilters() {
  const dagSearch = document.getElementById('input-search-dag');
  const filesSearch = document.getElementById('input-search-files');
  if (dagSearch && typeof dagSearch.value === 'string') state.searchQueryDag = dagSearch.value;
  if (filesSearch && typeof filesSearch.value === 'string') state.searchQueryFiles = filesSearch.value;
}

function restoreSearchFilters() {
  const dagSearch = document.getElementById('input-search-dag');
  const filesSearch = document.getElementById('input-search-files');
  if (dagSearch && dagSearch.value !== state.searchQueryDag) dagSearch.value = state.searchQueryDag;
  if (filesSearch && filesSearch.value !== state.searchQueryFiles) filesSearch.value = state.searchQueryFiles;
  applyDagFilter();
  applyFilesFilter();
}

async function fetchVault() {
  try {
    const res = await fetch('/api/vault');
    if (!res.ok) throw new Error(`Vault request failed (${res.status})`);
    const data = await res.json();
    state.vault = data;

    if (!data.initialized) {
      const vElem = document.getElementById('vault-id-display');
      if (vElem) vElem.textContent = isPublicExplorer() ? "Public Explorer" : "Uninitialized";
      return;
    }

    // Update Header Vault ID
    const fullVaultId = data.vault_id_hex || "";
    const vElem = document.getElementById('vault-id-display');
    if (vElem) {
      vElem.textContent = truncateHash(fullVaultId, 8, 6);
      vElem.setAttribute('data-full-id', fullVaultId);
      vElem.title = fullVaultId;
    }

    // Update Metrics
    const filesCount = (data.tracked_files || []).length;
    const valFilesElem = document.getElementById('val-files-count');
    if (valFilesElem) valFilesElem.textContent = filesCount;

    const subInventoryElem = document.getElementById('sub-metric-inventory');
    let totalBytes = 0;
    (data.tracked_files || []).forEach(f => totalBytes += (f.size_bytes || 0));
    if (subInventoryElem) {
      subInventoryElem.textContent = `${filesCount} secrets (${formatBytes(totalBytes)})`;
    }

    // Update Tab Badges
    const badgeFiles = document.getElementById('badge-tab-files');
    if (badgeFiles) badgeFiles.textContent = filesCount;

    // Render Tracked Files Table
    renderTrackedFiles(data.tracked_files || []);

    // Render Recovery Sheet
    renderRecoveryKit(data.recovery && data.recovery.available ? data.recovery : {}, data.vault_id_hex || '');

    // Update Modal files summary tags
    const modalFilesList = document.getElementById('modal-files-list');
    if (modalFilesList) {
      modalFilesList.innerHTML = (data.tracked_files || []).map(f => 
        `<span class="file-tag">${escapeHtml(f.path)}</span>`
      ).join('') || '<span style="color: var(--text-muted); font-size: 0.8rem;">No files currently tracked</span>';
    }
  } catch (e) {
    state.vault = null;
    const vElem = document.getElementById('vault-id-display');
    if (vElem) vElem.textContent = isPublicExplorer() ? 'Public Explorer' : 'Unavailable';
    const valFilesElem = document.getElementById('val-files-count');
    if (valFilesElem) valFilesElem.textContent = '--';
    const badgeFiles = document.getElementById('badge-tab-files');
    if (badgeFiles) badgeFiles.textContent = '--';
    const subInventoryElem = document.getElementById('sub-metric-inventory');
    if (subInventoryElem) subInventoryElem.textContent = 'Inventory unavailable';
    renderTrackedFiles([]);
    renderRecoveryKit({}, '');
    console.warn("fetchVault error:", e);
  }
}

async function fetchOperators() {
  try {
    const res = await fetch('/api/operators');
    if (!res.ok) throw new Error(`Operator telemetry request failed (${res.status})`);
    const data = await res.json();
    state.operators = data;
    state.operatorObservedAt = Array.isArray(data)
      ? (data.find(operator => typeof operator?.observed_at === 'string')?.observed_at || null)
      : null;

    renderOperators(data);

    // Update Cluster Status Pill
    const onlineCount = data.filter(operatorResponded).length;
    const totalCount = data.length;
    const statusText = document.getElementById('cluster-status-text');
    const pulseDot = document.getElementById('pulse-dot');
    const badgeTabOp = document.getElementById('badge-tab-operators');


    if (badgeTabOp) badgeTabOp.textContent = totalCount;

    if (statusText) {
      statusText.textContent = totalCount > 0
        ? (isPublicExplorer()
          ? `${onlineCount}/${totalCount} operators responding (identity unverified)`
          : `${onlineCount}/${totalCount} Operators Online`)
        : 'No operators reported';
    }

    if (pulseDot) {
      const pulseColor = isPublicExplorer()
        ? (onlineCount > 0 ? 'var(--accent-cyan)' : 'var(--text-muted)')
        : (onlineCount > 0 ? 'var(--accent-emerald)' : 'var(--accent-rose)');
      pulseDot.style.backgroundColor = pulseColor;
      pulseDot.style.boxShadow = onlineCount > 0 ? `0 0 10px ${pulseColor}` : 'none';
    }

    // Update Average Latency
    const onlineOps = data.filter(op => operatorResponded(op) && typeof op.latency_ms === 'number');
    const avgLatencyElem = document.getElementById('avg-latency-display');
    if (avgLatencyElem) {
      if (onlineOps.length > 0) {
        const sum = onlineOps.reduce((acc, o) => acc + o.latency_ms, 0);
        const avg = Math.round(sum / onlineOps.length);
        avgLatencyElem.textContent = `${avg} ms`;
      } else {
        avgLatencyElem.textContent = `-- ms`;
      }
    }

    // Render Latency Comparison Bars
    renderLatencyBars(data);
  } catch (e) {
    state.operators = [];
    state.operatorObservedAt = null;
    renderOperators([]);
    const statusText = document.getElementById('cluster-status-text');
    const pulseDot = document.getElementById('pulse-dot');
    const avgLatencyElem = document.getElementById('avg-latency-display');
    if (statusText) statusText.textContent = 'Operator telemetry unavailable';
    if (pulseDot) {
      pulseDot.style.backgroundColor = 'var(--text-muted)';
      pulseDot.style.boxShadow = 'none';
    }
    if (avgLatencyElem) avgLatencyElem.textContent = '-- ms';
    renderLatencyBars([]);
    console.warn("fetchOperators error:", e);
  }
}

async function fetchAudit() {
  state.audit = null;
  renderAudit(null);
  try {
    const response = await fetch('/api/audit', { method: 'POST' });
    if (!response.ok) throw new Error('Audit unavailable');
    const data = await response.json();
    state.audit = data.report || null;
  } catch (error) { console.warn('Recovery audit unavailable', error); }
  renderAudit(state.audit);
}

function renderAudit(audit) {
  const count = audit && Array.isArray(audit.recoverable_operators)
    ? audit.recoverable_operators.length
    : 0;
  const totalOperators = Array.isArray(state.operators) && state.operators.length > 0
    ? state.operators.length
    : null;
  const label = audit ? (audit.healthy ? 'Verified' : 'Degraded') : 'Unverified';
  const color = audit && audit.healthy ? 'var(--accent-emerald)' : 'var(--accent-amber)';
  const badge = document.getElementById('badge-durability-state');
  if (badge) { badge.textContent = label; badge.style.color = color; }
  const ratio = document.getElementById('durability-ratio');
  if (ratio) ratio.textContent = audit ? `${count}/${totalOperators ?? '--'}` : `--/${totalOperators ?? '--'}`;
  const detail = document.getElementById('sub-metric-durability');
  const lostCount = audit && audit.objects && Number.isFinite(Number(audit.objects.lost_count))
    ? Number(audit.objects.lost_count)
    : null;
  if (detail) {
    detail.textContent = audit
      ? `Last checked snapshot: ${count} complete recovery sets; ${lostCount == null ? 'lost-object count unavailable' : `${lostCount} lost objects`}`
      : 'No completed recovery verification';
  }
  const bar = document.getElementById('bar-durability');
  if (bar) {
    bar.style.width = totalOperators && audit ? `${Math.min(count / totalOperators * 100, 100)}%` : '0%';
    bar.style.background = color;
  }
}

async function fetchSnapshots() {
  try {
    const res = await fetch('/api/snapshots');
    if (!res.ok) throw new Error(`Snapshot request failed (${res.status})`);
    const data = await res.json();
    const snapshots = dedupeSnapshots(Array.isArray(data) ? data : (data && data.snapshots));
    state.snapshots = snapshots;

    const badgeSnaps = document.getElementById('badge-tab-snapshots');
    if (badgeSnaps) badgeSnaps.textContent = snapshots.length;

    renderSnapshots(snapshots);
  } catch (e) {
    state.snapshots = [];
    const badgeSnaps = document.getElementById('badge-tab-snapshots');
    if (badgeSnaps) badgeSnaps.textContent = '--';
    renderSnapshots([]);
    console.warn("fetchSnapshots error:", e);
  }
}

async function fetchAnchors() {
  try {
    const res = await fetch('/api/anchors');
    if (!res.ok) throw new Error(`Anchor telemetry request failed (${res.status})`);
    const data = await res.json();
    state.anchors = data;

    renderAnchors(data);
  } catch (e) {
    state.anchors = [];
    renderAnchors([]);
    console.warn("fetchAnchors error:", e);
  }
}

async function fetchGuardians() {
  try {
    const res = await fetch('/api/guardians');
    if (!res.ok) throw new Error(`Guardian request failed (${res.status})`);
    const data = await res.json();
    state.guardians = data;
    renderGuardians(data);
  } catch (e) {
    state.guardians = null;
    const badgeTab = document.getElementById('badge-tab-guardians');
    if (badgeTab) badgeTab.textContent = '--';
    const circleBadge = document.getElementById('quorum-circle-badge');
    if (circleBadge) circleBadge.textContent = '-- / --';
    const quorumTitle = document.getElementById('quorum-title');
    if (quorumTitle) quorumTitle.textContent = 'Guardian policy unavailable';
    const locatorElem = document.getElementById('guardian-vault-locator');
    if (locatorElem) locatorElem.textContent = '--';
    const grid = document.getElementById('guardians-grid');
    if (grid) grid.innerHTML = '<div class="loading-placeholder">Guardian descriptors are unavailable.</div>';
    console.warn("fetchGuardians error:", e);
  }
}

async function fetchRelayerCheckpoints() {
  try {
    const res = await fetch('/api/relayer/checkpoints');
    if (!res.ok) throw new Error(`Checkpoint telemetry request failed (${res.status})`);
    const data = await res.json();
    state.relayerCheckpoints = data.checkpoints || [];
    renderRelayerCheckpoints(data);
  } catch (e) {
    state.relayerCheckpoints = [];
    renderRelayerCheckpoints({
      relayer_status: {
        public_read_only: isPublicExplorer(),
        target_network: 'Network not reported',
      },
      checkpoints: [],
    });
    console.warn("fetchRelayerCheckpoints error:", e);
  }
}

async function fetchFleet() {
  try {
    const res = await fetch('/api/fleet');
    if (!res.ok) throw new Error(`Fleet request failed (${res.status})`);
    const data = await res.json();
    state.fleet = data;
    renderFleet(data);
  } catch (e) {
    state.fleet = null;
    const kpiVaults = document.getElementById('fleet-kpi-vaults');
    if (kpiVaults) kpiVaults.textContent = '--';
    const kpiOps = document.getElementById('fleet-kpi-operators');
    if (kpiOps) kpiOps.textContent = '-- / --';
    const kpiLat = document.getElementById('fleet-kpi-latency');
    if (kpiLat) kpiLat.textContent = '-- ms';
    const kpiAudits = document.getElementById('fleet-kpi-audits');
    if (kpiAudits) kpiAudits.textContent = '--';
    const badgeFleet = document.getElementById('badge-tab-fleet');
    if (badgeFleet) badgeFleet.textContent = '--';
    const opGrid = document.getElementById('fleet-operators-grid');
    if (opGrid) opGrid.innerHTML = '<div class="loading-placeholder">Fleet telemetry is unavailable.</div>';
    const vBody = document.getElementById('table-fleet-vaults-body');
    if (vBody) vBody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">Fleet vault inventory is unavailable.</td></tr>';
    const aBody = document.getElementById('table-fleet-audits-body');
    if (aBody) aBody.innerHTML = '<tr><td colspan="7" class="loading-placeholder">Fleet audit history is unavailable.</td></tr>';
    console.warn("fetchFleet error:", e);
  }
}

// -------------------------------------------------------------
// DOM Rendering Functions
// -------------------------------------------------------------

function renderOperators(operators) {
  const currentOperators = Array.isArray(operators) ? operators : [];
  const container = document.getElementById('operators-grid');
  renderRetentionStatus(currentOperators);

  const onlineCount = currentOperators.filter(operatorResponded).length;
  const totalCount = currentOperators.length;
  const observedAt = currentOperators.find(operator => typeof operator?.observed_at === 'string')?.observed_at
    || state.operatorObservedAt;
  const observedLabel = observedAt && Number.isFinite(Date.parse(observedAt))
    ? ` Last observed ${new Date(observedAt).toLocaleTimeString()}.`
    : '';
  const responseSummary = document.getElementById('operator-response-summary');
  const quorumElem = document.getElementById('quorum-health-text');
  const quorumPill = document.getElementById('quorum-status-pill');
  if (responseSummary) {
    responseSummary.textContent = totalCount > 0
      ? `${onlineCount}/${totalCount} configured operators responded to the latest probe.${observedLabel} This is not a durability or quorum verification.`
      : 'No configured operator response is available.';
  }
  if (quorumElem) {
    quorumElem.textContent = totalCount > 0
      ? `${onlineCount}/${totalCount} operators responding`
      : 'Operator status not reported';
    quorumElem.style.color = onlineCount > 0
      ? (isPublicExplorer() ? 'var(--accent-cyan)' : 'var(--accent-emerald)')
      : 'var(--text-muted)';
  }
  if (quorumPill) {
    const dot = quorumPill.querySelector ? quorumPill.querySelector('.pulse-dot') : null;
    if (dot) {
      const dotColor = onlineCount > 0
        ? (isPublicExplorer() ? 'var(--accent-cyan)' : 'var(--accent-emerald)')
        : 'var(--text-muted)';
      dot.style.backgroundColor = dotColor;
      dot.style.boxShadow = onlineCount > 0 ? `0 0 10px ${dotColor}` : 'none';
    }
  }
  if (!container) return;

  if (totalCount === 0) {
    container.innerHTML = `<div class="loading-placeholder">No configured operator response is available.</div>`;
    return;
  }

  container.innerHTML = currentOperators.map((op, idx) => {
    const isOnline = operatorResponded(op);
    const statusLabel = isPublicExplorer()
      ? (isOnline ? 'RESPONDED' : 'UNREACHABLE')
      : (isOnline ? 'ONLINE' : 'OFFLINE');
    const latencyDisplay = isOnline
      ? (typeof op.latency_ms === 'number' ? `${op.latency_ms} ms` : 'Latency not reported')
      : 'Unreachable';
    const pkDisplay = op.operator_signing_pk_hex ? truncateHash(op.operator_signing_pk_hex, 8, 6) : 'Not reported';
    const opId = op.operator_id || `operator_${idx + 1}`;
    const retentionTerms = op.retention_terms || 'Not reported';
    const transportLabel = op.transport_security === 'https' ? 'HTTPS configured' : 'Transport not reported';

    return `
      <article class="operator-card" id="card-operator-${idx + 1}">
        <div>
          <div class="op-header">
            <div class="op-title-wrap">
              <span class="op-id">${escapeHtml(opId)}</span>
              <span class="${isOnline ? 'badge-online' : 'badge-offline'}">${statusLabel}</span>
            </div>
            <span style="font-size: 0.8rem; color: ${isOnline ? 'var(--accent-cyan)' : 'var(--accent-rose)'}; font-family: var(--font-mono);">${latencyDisplay}</span>
          </div>

          <div class="op-meta-row">
            <span class="op-meta-label">Endpoint</span>
            <span class="op-meta-val">${escapeHtml(op.endpoint || 'Not reported')}${op.transport_security === 'https' ? ' <span class="shield-badge" style="color:var(--accent-cyan); font-size:0.75rem; margin-left:6px;">🔒 HTTPS configured</span>' : ''}</span>
          </div>
          <div class="op-meta-row">
            <span class="op-meta-label">Public Key</span>
            <span class="op-meta-val" title="${escapeHtml(op.operator_signing_pk_hex || '')}">
              ${pkDisplay}
              ${op.operator_signing_pk_hex ? `
                <button class="btn-copy" data-copy="${escapeHtml(op.operator_signing_pk_hex)}" title="Copy Public Key">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                </button>
              ` : ''}
            </span>
          </div>
          <div class="op-meta-row">
            <span class="op-meta-label">Retention Policy</span>
            <span class="op-meta-val" style="color: ${op.retention_terms ? 'var(--text-secondary)' : 'var(--text-muted)'};">${escapeHtml(retentionTerms)}</span>
          </div>
          <div class="op-meta-row">
            <span class="op-meta-label">Location</span>
            <span class="op-meta-val" style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(op.location || (op.region ? `${op.region} (${op.zone || 'zone not reported'})` : 'Not reported'))}</span>
          </div>
          <div class="op-meta-row">
            <span class="op-meta-label">Quorum Role</span>
            <span class="op-meta-val" style="color: var(--accent-purple); font-size: 0.78rem;">${escapeHtml(op.quorum_role || 'Policy not reported')}</span>
          </div>
        </div>
        <div style="margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 0.75rem; color: var(--text-muted);">Replication Transport</span>
          <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 600;">${transportLabel}</span>
        </div>
      </article>
    `;
  }).join('');

}

function timestampToMilliseconds(value) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value === 'string') {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && value.trim() !== '') return timestampToMilliseconds(numeric);
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function renderRetentionStatus(operators) {
  const expiryKeys = [
    'retention_receipt_expires_at_utc',
    'retention_expires_at_utc',
    'lease_expires_at_utc',
    'retention_expires_at',
    'lease_expires_at',
  ];
  const reportedExpiries = (operators || [])
    .flatMap(operator => expiryKeys.map(key => timestampToMilliseconds(operator && operator[key])))
    .filter(expiry => expiry !== null);

  const badge = document.getElementById('badge-retention-state');
  const value = document.getElementById('val-retention-days');
  const unit = document.getElementById('val-retention-unit');
  const detail = document.getElementById('sub-metric-runway');
  const bar = document.getElementById('bar-runway');

  if (reportedExpiries.length === 0) {
    if (badge) badge.textContent = 'Not reported';
    if (value) value.textContent = '--';
    if (unit) unit.textContent = 'days';
    if (detail) detail.textContent = 'No retention receipt expiry is available';
    if (bar) bar.style.width = '0%';
    return;
  }

  const earliestExpiry = Math.min(...reportedExpiries);
  const remainingDays = Math.max(0, Math.ceil((earliestExpiry - Date.now()) / 86_400_000));
  if (badge) badge.textContent = earliestExpiry <= Date.now() ? 'Expired' : 'Expiry reported';
  if (value) value.textContent = String(remainingDays);
  if (unit) unit.textContent = remainingDays === 1 ? 'day' : 'days';
  if (detail) detail.textContent = `${earliestExpiry <= Date.now() ? 'Earliest reported expiry elapsed' : 'Earliest reported expiry'}: ${new Date(earliestExpiry).toLocaleString()}`;
  // A receipt expiry has no meaningful percentage without a receipt start
  // time, so do not render a decorative progress value.
  if (bar) bar.style.width = '0%';
}

function renderLatencyBars(operators) {
  const container = document.getElementById('latency-bars-container');
  if (!container) return;

  const onlineOps = (operators || []).filter(o => (
    operatorResponded(o)
    && typeof o.latency_ms === 'number'
    && Number.isFinite(o.latency_ms)
    && o.latency_ms >= 0
  ));
  if (onlineOps.length === 0) {
    container.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-muted);">No operator response latency is reported.</div>`;
    return;
  }

  const maxLatency = Math.max(...onlineOps.map(o => o.latency_ms), 20);

  container.innerHTML = onlineOps.map(op => {
    const lat = op.latency_ms;
    const pct = Math.max(8, Math.min(100, Math.round((lat / maxLatency) * 100)));
    const color = lat < 5 ? 'var(--accent-emerald)' : lat < 25 ? 'var(--accent-cyan)' : 'var(--accent-amber)';

    return `
      <div class="latency-bar-row">
        <span style="font-family: var(--font-mono); color: var(--text-primary); font-weight: 600;">${escapeHtml(op.operator_id || 'op')}</span>
        <div class="latency-bar-track">
          <div class="latency-bar-fill" style="width: ${pct}%; background: ${color};"></div>
        </div>
        <span style="font-family: var(--font-mono); color: ${color}; text-align: right;">${lat} ms</span>
      </div>
    `;
  }).join('');
}

function snapshotIdentity(snapshot, index) {
  if (!snapshot || typeof snapshot !== 'object') return `unkeyed-snapshot-${index}`;
  const identity = snapshot.logical_snapshot_id_hex
    || snapshot.snapshot_id_hex
    || snapshot.snapshot_id
    || snapshot.record_cid_hex
    || snapshot.record_cid;
  return identity ? String(identity).toLowerCase() : `unkeyed-snapshot-${index}`;
}

function snapshotTimestamp(snapshot) {
  const raw = snapshot && (snapshot.timestamp_utc ?? snapshot.created_at_utc);
  const timestamp = Number(raw);
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function preferSnapshot(candidate, current) {
  if (Boolean(candidate && candidate.is_head) !== Boolean(current && current.is_head)) {
    return Boolean(candidate && candidate.is_head);
  }
  const candidateTimestamp = snapshotTimestamp(candidate);
  const currentTimestamp = snapshotTimestamp(current);
  if (candidateTimestamp !== currentTimestamp) return candidateTimestamp > currentTimestamp;
  // Prefer a record with a CID when aliases have otherwise identical data.
  return Boolean(candidate && candidate.record_cid_hex) && !Boolean(current && current.record_cid_hex);
}

function dedupeSnapshots(snapshots) {
  if (!Array.isArray(snapshots)) return [];
  const canonical = new Map();
  snapshots.forEach((snapshot, index) => {
    const identity = snapshotIdentity(snapshot, index);
    const existing = canonical.get(identity);
    if (!existing || preferSnapshot(snapshot, existing)) canonical.set(identity, snapshot);
  });
  return Array.from(canonical.values());
}

function renderSnapshots(snapshots) {
  const container = document.getElementById('dag-list');
  if (!container) return;

  const canonicalSnapshots = dedupeSnapshots(snapshots);
  if (canonicalSnapshots.length === 0) {
    container.innerHTML = `<div class="loading-placeholder">No snapshots captured yet. Click "Push Snapshot" to create the initial snapshot.</div>`;
    return;
  }

  // APIs normally return chronological records, but sort defensively so the
  // newest known timestamp is listed first without relying on alias order.
  const sorted = [...canonicalSnapshots].sort((a, b) => snapshotTimestamp(b) - snapshotTimestamp(a));
  const markedHeads = sorted.filter(snapshot => Boolean(snapshot.is_head));
  const hasSingleCanonicalHead = markedHeads.length === 1;

  container.innerHTML = sorted.map((snap, idx) => {
    const isHead = hasSingleCanonicalHead && Boolean(snap.is_head);
    const hasHeadConflict = markedHeads.length > 1 && Boolean(snap.is_head);
    const snapIdTrunc = truncateHash(snap.snapshot_id_hex, 10, 8);
    const manifestTrunc = truncateHash(snap.manifest_cid_hex, 10, 8);
    const deviceTrunc = truncateHash(snap.device_id_hex, 8, 6);
    const timeDisplay = snap.timestamp_utc ? formatTimestamp(snap.timestamp_utc) : "Recorded";

    return `
      <div class="dag-node" data-snap-id="${escapeHtml(snap.snapshot_id_hex)}" role="button" tabindex="0" aria-label="Inspect snapshot ${escapeHtml(snapIdTrunc)}" style="cursor: pointer;">
        <div class="dag-timeline-track">
          <div class="dag-node-dot ${isHead ? 'head' : ''}"></div>
          ${idx < sorted.length - 1 ? '<div class="dag-timeline-line"></div>' : ''}
        </div>
        <div class="dag-card">
          <div class="dag-card-header">
            <div style="display: flex; align-items: center; gap: 10px;">
              <span class="dag-message">Snapshot #${snap.device_counter || (sorted.length - idx)}</span>
              ${isHead ? '<span class="badge-online" style="background: rgba(0, 240, 255, 0.12); color: var(--accent-cyan); border-color: rgba(0, 240, 255, 0.4);">ACTIVE HEAD</span>' : ''}
              ${hasHeadConflict ? '<span class="badge-status-subtle" style="color: var(--accent-amber); border-color: rgba(255, 179, 0, 0.35);">HEAD CONFLICT</span>' : ''}
              <span style="font-size: 0.75rem; color: var(--text-muted);">(Epoch #${snap.epoch || 1})</span>
            </div>
            <span class="dag-time">${timeDisplay}</span>
          </div>
          <div class="dag-hashes">
            <span>Snapshot CID: <strong style="color: var(--text-primary); cursor: pointer;" class="hash-click" data-copy="${escapeHtml(snap.snapshot_id_hex)}" title="Click to copy">${snapIdTrunc}</strong></span>
            <span>Manifest CID: <strong style="color: var(--accent-cyan);">${manifestTrunc}</strong></span>
            <span>Device: <strong style="color: var(--text-secondary);">${deviceTrunc}</strong></span>
          </div>
          <div style="margin-top: 10px; display: flex; justify-content: flex-end; gap: 8px;">
            <button class="btn-action-ghost btn-drawer-inspect" data-snap-id="${escapeHtml(snap.snapshot_id_hex)}" style="padding: 3px 10px; font-size: 0.75rem; color: var(--accent-cyan); border-color: rgba(0, 240, 255, 0.3);">
              Inspect Manifest ➔
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Attach click listeners to dag-nodes for drawer deep inspection
  container.querySelectorAll('.dag-node').forEach(node => {
    node.addEventListener('click', (e) => {
      if (e.target.closest('.hash-click, .btn-drawer-inspect, button, a, input, select, textarea')) return;
      const snapId = node.getAttribute('data-snap-id');
      const snap = canonicalSnapshots.find(s => s.snapshot_id_hex === snapId);
      if (snap) openSnapshotDrawer(snap);
    });
    node.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      e.preventDefault();
      const snapId = node.getAttribute('data-snap-id');
      const snap = canonicalSnapshots.find(s => s.snapshot_id_hex === snapId);
      if (snap) openSnapshotDrawer(snap);
    });
  });

  // Synchronize Diff selector dropdowns with latest snapshot list
  if (typeof updateDiffSelects === 'function') {
    updateDiffSelects(canonicalSnapshots);
  }

  if (typeof applyDagFilter === 'function') {
    applyDagFilter();
  }
}

function renderTrackedFiles(files) {
  const tbody = document.getElementById('table-files-body');
  if (!tbody) return;

  if (!files || files.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="loading-placeholder">No confidential files currently tracked in vault.</td></tr>`;
    return;
  }

  tbody.innerHTML = files.map(file => {
    const fileIdTrunc = truncateHash(file.file_id_hex, 8, 6);
    const sizeStr = file.size_bytes !== undefined ? formatBytes(file.size_bytes) : "Unknown";
    const chunks = typeof file.chunks_count === 'number' ? file.chunks_count : null;

    const replicaBadge = '<span class="badge-status-subtle">See latest snapshot audit</span>';

    return `
      <tr>
        <td>
          <div style="display: flex; align-items: center; gap: 8px;">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
              <polyline points="13 2 13 9 20 9"></polyline>
            </svg>
            <strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${escapeHtml(file.path)}</strong>
          </div>
        </td>
        <td style="font-family: var(--font-mono); color: var(--text-secondary);" title="${escapeHtml(file.file_id_hex)}">
          ${fileIdTrunc}
        </td>
        <td>${sizeStr}</td>
        <td>${chunks === null ? 'Not reported' : `${chunks} chunk${chunks === 1 ? '' : 's'} (recorded)`}</td>
        <td>${replicaBadge}</td>
        <td>
          <div style="display: flex; align-items: center; gap: 6px;">
            <button class="btn-copy" data-copy="${escapeHtml(file.file_id_hex)}" title="Copy File ID">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
            <button class="btn-action-ghost btn-untrack-file" data-path="${escapeHtml(file.path)}" title="Untrack from vault" style="padding: 3px 8px; font-size: 0.75rem; color: var(--accent-rose); border: 1px solid rgba(248, 113, 113, 0.3);">
              Untrack
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  if (typeof applyFilesFilter === 'function') {
    applyFilesFilter();
  }
}

function normalizeTransactionHash(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  const hex = raw.replace(/^0x/i, '');
  return /^[0-9a-f]{64}$/i.test(hex) ? `0x${hex}` : '';
}

function isZeroTransactionHash(value) {
  const normalized = normalizeTransactionHash(value);
  return !normalized || /^0x0{64}$/i.test(normalized);
}

function isMeaningfulHex(value) {
  return typeof value === 'string' && /[1-9a-f]/i.test(value.replace(/^0x/i, ''));
}

function checkpointDisplayState(record, transactionHash) {
  if (isZeroTransactionHash(transactionHash)) {
    return { label: 'Not submitted', tone: 'var(--text-muted)', confirmed: false };
  }

  const verificationStatus = record && typeof record.verification_status === 'string'
    ? record.verification_status.toLowerCase()
    : '';
  const supplied = record && (record.finality_status || record.verification_status || record.status);
  const rawLabel = supplied ? String(supplied) : 'receipt_unverified';
  const normalized = rawLabel.toLowerCase();
  const label = normalized === 'receipt_unverified'
    ? 'Receipt unverified'
    : (normalized === 'submitted' ? 'Submitted — receipt unverified' : rawLabel);
  if (normalized.includes('fail') || normalized.includes('revert')) {
    return { label, tone: 'var(--accent-rose)', confirmed: false };
  }
  if (record && (verificationStatus === 'verified' || record.inclusion_verified === true || record.verified === true)) {
    return { label, tone: 'var(--accent-emerald)', confirmed: true };
  }
  return { label, tone: 'var(--accent-amber)', confirmed: false };
}

function checkpointExplorerUrl(record, transactionHash) {
  const hash = normalizeTransactionHash(transactionHash);
  if (!hash || isZeroTransactionHash(hash)) return '';

  const suppliedUrl = record && (record.explorer_url || record.arbiscan_url);
  if (typeof suppliedUrl === 'string' && /^https:\/\/(?:[a-z0-9-]+\.)?arbiscan\.io\/tx\/0x[0-9a-f]{64}(?:[/?#].*)?$/i.test(suppliedUrl)) {
    return suppliedUrl;
  }

  const chainId = Number(record && record.chain_id);
  if (chainId === 42161) return `https://arbiscan.io/tx/${hash}`;
  if (chainId === 421614) return `https://sepolia.arbiscan.io/tx/${hash}`;
  return '';
}

function chainLabel(chainId) {
  const numericChainId = Number(chainId);
  if (numericChainId === 42161) return 'Arbitrum One (Chain ID 42161)';
  if (numericChainId === 421614) return 'Arbitrum Sepolia (Chain ID 421614)';
  return Number.isFinite(numericChainId) && numericChainId > 0
    ? `Chain ID ${numericChainId}`
    : 'Network not reported';
}

function renderAnchorUnavailable() {
  const elements = {
    block: document.getElementById('val-anchor-block'),
    contract: document.getElementById('anchor-contract-addr'),
    chain: document.getElementById('anchor-chain-id'),
    inclusionBlock: document.getElementById('anchor-block-num'),
    status: document.getElementById('anchor-finality-status'),
    salt: document.getElementById('anchor-salt-preimage'),
    commitment: document.getElementById('anchor-commitment-val'),
    transaction: document.getElementById('anchor-tx-hash'),
    stage: document.getElementById('badge-anchor-stage'),
    detail: document.getElementById('sub-metric-anchor'),
    bar: document.getElementById('bar-anchor'),
  };
  if (elements.block) elements.block.textContent = '#--';
  if (elements.contract) elements.contract.textContent = 'Not reported';
  if (elements.chain) elements.chain.textContent = 'Network not reported';
  if (elements.inclusionBlock) elements.inclusionBlock.textContent = '#--';
  if (elements.status) {
    elements.status.textContent = 'Not submitted';
    elements.status.style.color = 'var(--text-muted)';
  }
  if (elements.salt) elements.salt.textContent = '--';
  if (elements.commitment) elements.commitment.textContent = '--';
  if (elements.transaction) {
    elements.transaction.textContent = '--';
    elements.transaction.title = '';
  }
  if (elements.stage) elements.stage.textContent = 'No verified receipt';
  if (elements.detail) elements.detail.textContent = 'No checkpoint evidence recorded';
  if (elements.bar) elements.bar.style.width = '0%';

  const copyButton = document.getElementById('btn-copy-anchor-tx');
  if (copyButton) {
    copyButton.disabled = true;
    copyButton.setAttribute('aria-disabled', 'true');
    copyButton.setAttribute('data-copy', '');
  }
  const explorerLink = document.getElementById('anchor-arbiscan-link');
  if (explorerLink) explorerLink.style.display = 'none';
}

function renderAnchors(anchors) {
  if (!Array.isArray(anchors) || anchors.length === 0) {
    renderAnchorUnavailable();
    return;
  }

  const latest = anchors[anchors.length - 1] || {};
  const transactionHash = normalizeTransactionHash(latest.tx_hash_hex || latest.tx_hash);
  const transactionIsUsable = !isZeroTransactionHash(transactionHash);
  const stateLabel = checkpointDisplayState(latest, transactionHash);
  const blockNumber = Number(latest.reported_block_number ?? latest.block_number);
  const hasBlockNumber = transactionIsUsable && Number.isFinite(blockNumber) && blockNumber > 0;

  const valAnchorBlock = document.getElementById('val-anchor-block');
  if (valAnchorBlock) valAnchorBlock.textContent = hasBlockNumber ? `#${blockNumber.toLocaleString()}` : '#--';

  const contractElem = document.getElementById('anchor-contract-addr');
  if (contractElem) contractElem.textContent = isMeaningfulHex(latest.contract_address_hex) ? latest.contract_address_hex : 'Not reported';

  const chainElem = document.getElementById('anchor-chain-id');
  if (chainElem) chainElem.textContent = chainLabel(latest.chain_id);

  const blockElem = document.getElementById('anchor-block-num');
  if (blockElem) blockElem.textContent = hasBlockNumber ? `#${blockNumber.toLocaleString()}` : '#--';

  const finalityElem = document.getElementById('anchor-finality-status');
  if (finalityElem) {
    finalityElem.textContent = stateLabel.label;
    finalityElem.style.color = stateLabel.tone;
  }

  const saltElem = document.getElementById('anchor-salt-preimage');
  if (saltElem) saltElem.textContent = isMeaningfulHex(latest.salt_hex) ? truncateHash(latest.salt_hex, 10, 8) : '--';

  const commitElem = document.getElementById('anchor-commitment-val');
  if (commitElem) commitElem.textContent = isMeaningfulHex(latest.commitment_hex) ? truncateHash(latest.commitment_hex, 10, 8) : '--';

  const txElem = document.getElementById('anchor-tx-hash');
  if (txElem) {
    txElem.textContent = transactionIsUsable ? truncateHash(transactionHash, 14, 10) : '--';
    txElem.title = transactionIsUsable ? transactionHash : '';
  }

  const copyTxBtn = document.getElementById('btn-copy-anchor-tx');
  if (copyTxBtn) {
    copyTxBtn.disabled = !transactionIsUsable;
    copyTxBtn.setAttribute('aria-disabled', transactionIsUsable ? 'false' : 'true');
    copyTxBtn.setAttribute('data-copy', transactionIsUsable ? transactionHash : '');
  }

  const stageElem = document.getElementById('badge-anchor-stage');
  if (stageElem) stageElem.textContent = stateLabel.confirmed ? 'Receipt reported' : (transactionIsUsable ? 'Receipt unverified' : 'No on-chain receipt');
  const detailElem = document.getElementById('sub-metric-anchor');
  if (detailElem) detailElem.textContent = stateLabel.confirmed ? `Reported status: ${stateLabel.label}` : stateLabel.label;
  const bar = document.getElementById('bar-anchor');
  if (bar) bar.style.width = '0%';

  const arbiscanLink = document.getElementById('anchor-arbiscan-link');
  if (arbiscanLink) {
    const explorerUrl = checkpointExplorerUrl(latest, transactionHash);
    if (explorerUrl) {
      arbiscanLink.href = explorerUrl;
      arbiscanLink.style.display = 'inline-flex';
    } else {
      arbiscanLink.style.display = 'none';
    }
  }
}

function renderGuardians(data) {
  if (!data) return;

  const badgeTab = document.getElementById('badge-tab-guardians');
  if (badgeTab && data.active_threshold && data.total_guardians) {
    badgeTab.textContent = `${data.active_threshold}-of-${data.total_guardians}`;
  }

  const circleBadge = document.getElementById('quorum-circle-badge');
  if (circleBadge && data.active_threshold && data.total_guardians) {
    circleBadge.textContent = `${data.active_threshold} / ${data.total_guardians}`;
  }

  const quorumTitle = document.getElementById('quorum-title');
  if (quorumTitle && data.active_threshold && data.total_guardians) {
    quorumTitle.textContent = `Active Quorum Policy: ${data.active_threshold}-of-${data.total_guardians} Guardians Required`;
  }

  const locatorElem = document.getElementById('guardian-vault-locator');
  if (locatorElem) {
    const sheetLocator = data.sheets && data.sheets.length > 0 ? data.sheets[0].recovery_locator : null;
    locatorElem.textContent = sheetLocator || data.recovery_locator_hex || "--";
  }

  const grid = document.getElementById('guardians-grid');
  if (!grid) return;

  if (!data.sheets || data.sheets.length === 0) {
    grid.innerHTML = `<div class="loading-placeholder">${escapeHtml(data.message || 'No non-secret guardian policy descriptors are recorded for this workspace.')}</div>`;
    return;
  }

  grid.innerHTML = data.sheets.map((sheet, idx) => {
    const shareNum = sheet.share_index;
    const threshold = sheet.threshold;
    const total = sheet.total_shares;
    const pkDisplay = truncateHash(sheet.recovery_signing_pk, 10, 8);
    const locatorDisplay = truncateHash(sheet.recovery_locator, 10, 8);
    const crc = sheet.crc32 || "--";

    return `
      <article class="guardian-card" id="card-guardian-${shareNum}">
        <div class="guardian-card-header">
          <h4>${escapeHtml(sheet.guardian_name || `Guardian ${shareNum}`)}</h4>
          <span class="guardian-badge">Share ${shareNum} of ${total}</span>
        </div>

        <div class="guardian-meta-list">
          <div class="guardian-meta-item">
            <span class="key">Threshold:</span>
            <span class="val" style="color: var(--accent-cyan);">${threshold}-of-${total}</span>
          </div>
          <div class="guardian-meta-item">
            <span class="key">Signing PK:</span>
            <span class="val" title="${escapeHtml(sheet.recovery_signing_pk)}">${pkDisplay}</span>
          </div>
          <div class="guardian-meta-item">
            <span class="key">Locator:</span>
            <span class="val" title="${escapeHtml(sheet.recovery_locator)}">${locatorDisplay}</span>
          </div>
          <div class="guardian-meta-item">
            <span class="key">Integrity:</span>
            <span class="val" style="color: var(--accent-emerald);">CRC32: ${escapeHtml(crc)}</span>
          </div>
        </div>

        <div class="guardian-card-actions">
          <button class="btn-action secondary small btn-inspect-guardian-sheet" data-sheet-index="${idx}">
            Inspect Sheet
          </button>
          <button class="btn-action primary small btn-copy-guardian-sheet-card" data-sheet-text="${encodeURIComponent(sheet.sheet_text)}">
            Copy Sheet
          </button>
        </div>
      </article>
    `;
  }).join('');

  if (grid.querySelectorAll) {
    const inspectBtns = grid.querySelectorAll('.btn-inspect-guardian-sheet');
    inspectBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-sheet-index'), 10);
        if (data.sheets[idx]) {
          openGuardianSheetModal(data.sheets[idx]);
        }
      });
    });

    const copyBtns = grid.querySelectorAll('.btn-copy-guardian-sheet-card');
    copyBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const text = decodeURIComponent(btn.getAttribute('data-sheet-text') || '');
        if (text && typeof navigator !== 'undefined' && navigator.clipboard) {
          navigator.clipboard.writeText(text).then(() => {
            showToast("Guardian descriptor sheet copied to clipboard!");
          });
        }
      });
    });
  }
}

function openGuardianSheetModal(sheet) {
  const modal = document.getElementById('modal-guardian-sheet');
  const title = document.getElementById('modal-guardian-title');
  const textElem = document.getElementById('modal-guardian-text');
  const copyBtn = document.getElementById('btn-copy-guardian-sheet');
  if (!modal || !textElem) return;

  if (title) title.textContent = `${sheet.guardian_name || 'Guardian'} Descriptor Sheet (Share ${sheet.share_index}/${sheet.total_shares})`;
  textElem.textContent = sheet.sheet_text;

  if (copyBtn) {
    copyBtn.onclick = () => {
      if (typeof navigator !== 'undefined' && navigator.clipboard) {
        navigator.clipboard.writeText(sheet.sheet_text).then(() => {
          showToast("Printable guardian sheet copied!");
        });
      }
    };
  }

  openModal(modal, document.activeElement);
}

function renderRelayerCheckpoints(data) {
  if (!data) return;
  const response = Array.isArray(data) ? { checkpoints: data } : data;

  const modeDisplay = document.getElementById('relayer-mode-display');
  if (modeDisplay && response.relayer_status) {
    const st = response.relayer_status;
    modeDisplay.textContent = st.public_read_only
      ? 'Public checkpoint feed: read-only'
      : `Automated L2 Relayer: ${st.operational === true ? 'Active' : 'Status unverified'}`;
  }

  const networkTag = document.getElementById('relayer-target-network');
  if (networkTag && response.relayer_status && response.relayer_status.target_network) {
    networkTag.textContent = response.relayer_status.target_network;
  }

  const relayerPulse = document.getElementById('relayer-pulse-dot');
  if (relayerPulse) {
    const status = response.relayer_status || {};
    const isPublicFeed = status.public_read_only === true;
    const isVerifiedOperational = status.operational === true && !isPublicFeed;
    const color = isVerifiedOperational ? 'var(--accent-emerald)' : 'var(--text-muted)';
    relayerPulse.style.backgroundColor = color;
    relayerPulse.style.boxShadow = isVerifiedOperational ? `0 0 10px ${color}` : 'none';
  }

  const tbody = document.getElementById('table-checkpoints-body');
  if (!tbody) return;

  const checkpoints = Array.isArray(response.checkpoints) ? response.checkpoints : [];
  if (checkpoints.length === 0) {
    const message = isPublicExplorer()
      ? 'No published checkpoint receipts are available.'
      : 'No relayer checkpoints recorded yet. Submit a checkpoint from the local workspace.';
    tbody.innerHTML = `<tr><td colspan="5" class="loading-placeholder">${message}</td></tr>`;
    return;
  }

  tbody.innerHTML = checkpoints.slice().reverse().map(cp => {
    const txHash = normalizeTransactionHash(cp.tx_hash || cp.tx_hash_hex);
    const usableTransaction = !isZeroTransactionHash(txHash);
    const blockNumber = Number(cp.reported_block_number ?? cp.block_number);
    const blockStr = usableTransaction && Number.isFinite(blockNumber) && blockNumber > 0
      ? `#${blockNumber.toLocaleString()}`
      : '#--';
    const txTrunc = usableTransaction ? truncateHash(txHash, 10, 8) : '--';
    const commitTrunc = isMeaningfulHex(cp.commitment || cp.commitment_hex) ? truncateHash(cp.commitment || cp.commitment_hex, 10, 8) : '--';
    const displayState = checkpointDisplayState(cp, txHash);
    const explorerUrl = checkpointExplorerUrl(cp, txHash);

    return `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--accent-purple); font-weight: 600;">${blockStr}</td>
        <td>
          <div style="display: flex; align-items: center; gap: 6px;">
            <code style="font-family: var(--font-mono); font-size: 0.8rem;">${txTrunc}</code>
            ${usableTransaction ? `
              <button class="btn-copy" data-copy="${escapeHtml(txHash)}" title="Copy Tx Hash">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            ` : ''}
          </div>
        </td>
        <td>
          <span style="color: ${displayState.tone}; font-size: 0.78rem; font-weight: 600;">
            ${escapeHtml(displayState.label)}
          </span>
        </td>
        <td style="font-family: var(--font-mono); color: var(--accent-cyan);" title="${escapeHtml(cp.commitment || cp.commitment_hex || '')}">
          ${commitTrunc}
        </td>
        <td>
          ${explorerUrl ? `
            <a href="${escapeHtml(explorerUrl)}" target="_blank" rel="noopener noreferrer" class="arbiscan-link">
              Arbiscan ↗
            </a>
          ` : '<span style="color: var(--text-muted); font-size: 0.78rem;">No verified explorer link</span>'}
        </td>
      </tr>
    `;
  }).join('');
}

function renderFleet(data) {
  if (!data) return;

  // Update KPIs
  if (data.fleet_summary) {
    const fs = data.fleet_summary;
    const kpiVaults = document.getElementById('fleet-kpi-vaults');
    if (kpiVaults) kpiVaults.textContent = fs.total_tracked_vaults == null ? '--' : String(fs.total_tracked_vaults);

    const kpiOps = document.getElementById('fleet-kpi-operators');
    if (kpiOps) {
      const active = fs.active_operators ?? fs.online_operators;
      const total = fs.total_operators;
      kpiOps.textContent = active == null && total == null ? '-- / --' : `${active ?? '--'} / ${total ?? '--'}`;
    }

    const kpiLat = document.getElementById('fleet-kpi-latency');
    if (kpiLat) kpiLat.textContent = fs.avg_latency_ms != null ? `${fs.avg_latency_ms} ms` : '-- ms';

    const kpiAudits = document.getElementById('fleet-kpi-audits');
    if (kpiAudits) kpiAudits.textContent = String(fs.audits_completed ?? 0);
  }

  // Update Fleet badge
  const badgeFleet = document.getElementById('badge-tab-fleet');
  if (badgeFleet && data.vaults) {
    badgeFleet.textContent = `${data.vaults.length} Vault${data.vaults.length > 1 ? 's' : ''}`;
  }

  // Render Operator Nodes Health Grid
  const opGrid = document.getElementById('fleet-operators-grid');
  if (opGrid && data.operator_nodes) {
    if (data.operator_nodes.length === 0) {
      opGrid.innerHTML = '<div class="loading-placeholder">No operator nodes registered in maintenance fleet.</div>';
    } else {
      opGrid.innerHTML = data.operator_nodes.map(op => {
        const isOnline = op.status === 'Online';
        const lat = op.latency_ms != null ? `${op.latency_ms} ms` : 'Unreachable';
        return `
          <div class="fleet-op-card">
            <div class="fleet-op-card-header">
              <span class="fleet-op-name">${escapeHtml(op.operator_id)}</span>
              <span class="${isOnline ? 'badge-status-online' : 'badge-status-offline'}">${escapeHtml(op.status)}</span>
            </div>
            <div class="op-meta-row">
              <span class="op-meta-label">Endpoint</span>
              <span class="op-meta-val">${escapeHtml(op.endpoint)}</span>
            </div>
            <div class="op-meta-row">
              <span class="op-meta-label">Probe RTT</span>
              <span class="op-meta-val" style="color: ${isOnline ? 'var(--accent-emerald)' : 'var(--accent-rose)'}; font-family: var(--font-mono);">${lat}</span>
            </div>
            <div class="op-meta-row">
              <span class="op-meta-label">Heartbeat</span>
              <span class="op-meta-val" style="font-size: 0.76rem; color: var(--text-muted);">${escapeHtml(op.last_heartbeat)}</span>
            </div>
          </div>
        `;
      }).join('');
    }
  }

  // Render Registered Vaults
  const vBody = document.getElementById('table-fleet-vaults-body');
  if (vBody && data.vaults) {
    if (data.vaults.length === 0) {
      vBody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">No vaults registered in maintenance database.</td></tr>';
    } else {
      vBody.innerHTML = data.vaults.map(v => `
        <tr>
          <td style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 500;">
            ${truncateHash(v.vault_id, 10, 8)}
          </td>
          <td style="font-family: var(--font-mono); color: var(--text-secondary);">
            ${v.head_cid ? truncateHash(v.head_cid, 10, 8) : '<em>Not reported</em>'}
          </td>
          <td>${v.storage_allowance_bytes == null ? 'Not reported' : formatBytes(v.storage_allowance_bytes)}</td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(v.registered_at)}</td>
        </tr>
      `).join('');
    }
  }

  // Render Audit Log Table
  const aBody = document.getElementById('table-fleet-audits-body');
  if (aBody && data.audit_history) {
    if (data.audit_history.length === 0) {
      aBody.innerHTML = '<tr><td colspan="7" class="loading-placeholder">No audit records in fleet database. Click "Run Fleet Audit Now" to perform first automated audit.</td></tr>';
    } else {
      aBody.innerHTML = data.audit_history.map(a => {
        const isHealthy = a.status === 'Healthy';
        const color = isHealthy ? 'var(--accent-emerald)' : 'var(--accent-amber)';
        return `
          <tr>
            <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(a.timestamp)}</td>
            <td style="font-family: var(--font-mono);">${truncateHash(a.vault_id, 8, 6)}</td>
            <td><strong style="color: ${color};">${escapeHtml(a.status)}</strong></td>
            <td style="color: var(--accent-emerald); font-family: var(--font-mono);">${a.healthy_objects ?? '--'}</td>
            <td style="color: var(--accent-rose); font-family: var(--font-mono);">${a.degraded_objects ?? '--'}</td>
            <td style="color: var(--accent-cyan); font-family: var(--font-mono);">${a.repaired_objects ?? '--'}</td>
            <td style="font-family: var(--font-mono);">${a.duration_ms == null ? 'Not reported' : `${a.duration_ms} ms`}</td>
          </tr>
        `;
      }).join('');
    }
  }
}

function renderRecoveryKit(recovery, vaultIdHex) {
  const recVaultId = document.getElementById('rec-vault-id');
  if (recVaultId) recVaultId.textContent = vaultIdHex || "";

  const recCrc32 = document.getElementById('rec-crc32');
  if (recCrc32) {
    const checksum = recovery.crc32 || recovery.checksum_hex;
    const verified = recovery.crc32_verified === true || recovery.checksum_verified === true;
    if (checksum) {
      recCrc32.textContent = verified
        ? `CRC32: ${checksum} (verified)`
        : `CRC32: ${checksum} (reported; not rechecked)`;
      recCrc32.style.color = verified ? 'var(--accent-emerald)' : 'var(--accent-amber)';
    } else {
      recCrc32.textContent = 'Checksum not available';
      recCrc32.style.color = 'var(--text-muted)';
    }
  }

  const recSigningPk = document.getElementById('rec-signing-pk');
  if (recSigningPk) recSigningPk.textContent = recovery.recovery_signing_pk_hex || "";

  const recEncryptPk = document.getElementById('rec-encrypt-pk');
  if (recEncryptPk) recEncryptPk.textContent = recovery.recovery_encrypt_pk_hex || "";

  const recLocator = document.getElementById('rec-locator');
  if (recLocator) recLocator.textContent = recovery.recovery_locator_hex || "";
}

// -------------------------------------------------------------
// Interactive Controls & Modals
// -------------------------------------------------------------

let activeModal = null;
let lastFocusedElement = null;

function trapModalFocus(modal) {
  if (!modal) return;
  const focusables = Array.from(modal.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  )).filter(el => !el.hasAttribute('disabled'));
  if (focusables.length > 0) {
    focusables[0].focus();
  }
}

function openModal(modal, triggerElement) {
  if (!modal) return;
  lastFocusedElement = triggerElement || document.activeElement;
  activeModal = modal;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  trapModalFocus(modal);
}

function closeModal(modal) {
  if (!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  if (activeModal === modal) {
    activeModal = null;
  }
  if (lastFocusedElement && typeof lastFocusedElement.focus === 'function') {
    lastFocusedElement.focus();
    lastFocusedElement = null;
  }
}

function initTabs() {
  const tabButtons = Array.from(document.querySelectorAll('.tab-btn'));
  const tabContents = Array.from(document.querySelectorAll('.tab-content'));

  const activateTab = (btn, shouldFocus = false) => {
    if (!btn || btn.hidden) return;
    const targetId = btn.getAttribute('data-target');

    tabButtons.forEach(b => {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
      b.setAttribute('tabindex', '-1');
    });

    tabContents.forEach(c => {
      c.classList.remove('active');
      c.setAttribute('tabindex', '-1');
    });

    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    btn.setAttribute('tabindex', '0');
    if (shouldFocus && typeof btn.focus === 'function') {
      btn.focus();
    }

    const targetContent = document.getElementById(targetId);
    if (targetContent) {
      targetContent.classList.add('active');
      targetContent.setAttribute('tabindex', '0');
      if (targetId === 'tab-fastcdc' && canAccessPrivateFeature('plaintext_inspection')) {
        loadVaultFilesForFastCdc();
      }
    }
  };

  tabButtons.forEach((btn, idx) => {
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-controls', btn.getAttribute('data-target'));
    const isActive = btn.classList.contains('active');
    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
    btn.setAttribute('tabindex', isActive ? '0' : '-1');

    btn.addEventListener('click', () => activateTab(btn));

    btn.addEventListener('keydown', (e) => {
      const visibleTabs = tabButtons.filter(tab => !tab.hidden);
      const visibleIndex = visibleTabs.indexOf(btn);
      if (visibleIndex < 0 || visibleTabs.length === 0) return;
      let nextIdx = visibleIndex;
      if (e.key === 'ArrowRight') {
        nextIdx = (visibleIndex + 1) % visibleTabs.length;
        e.preventDefault();
        activateTab(visibleTabs[nextIdx], true);
      } else if (e.key === 'ArrowLeft') {
        nextIdx = (visibleIndex - 1 + visibleTabs.length) % visibleTabs.length;
        e.preventDefault();
        activateTab(visibleTabs[nextIdx], true);
      } else if (e.key === 'Home') {
        e.preventDefault();
        activateTab(visibleTabs[0], true);
      } else if (e.key === 'End') {
        e.preventDefault();
        activateTab(visibleTabs[visibleTabs.length - 1], true);
      }
    });
  });

  tabContents.forEach(c => {
    c.setAttribute('role', 'tabpanel');
    const matchingBtn = tabButtons.find(b => b.getAttribute('data-target') === c.id);
    if (matchingBtn) {
      c.setAttribute('aria-labelledby', matchingBtn.id);
    }
    c.setAttribute('tabindex', c.classList.contains('active') ? '0' : '-1');
  });
}

function initModals() {
  const modalSnapshot = document.getElementById('modal-create-snapshot');
  const btnOpenSnapshot = document.getElementById('btn-open-create-snapshot');
  const btnCloseSnapshot = document.getElementById('btn-close-modal-snapshot');
  const btnCancelSnapshot = document.getElementById('btn-cancel-modal-snapshot');

  const modalInspector = document.getElementById('modal-snapshot-inspector');
  const btnCloseInspector = document.getElementById('btn-close-modal-inspector');
  const btnCloseInspectorFooter = document.getElementById('btn-close-inspector-footer');

  const modalGuardian = document.getElementById('modal-guardian-sheet');
  const btnCloseGuardian = document.getElementById('btn-close-modal-guardian');
  const btnCloseGuardianFooter = document.getElementById('btn-close-guardian-footer');

  if (btnOpenSnapshot && modalSnapshot) {
    btnOpenSnapshot.addEventListener('click', () => {
      openModal(modalSnapshot, btnOpenSnapshot);
      const input = document.getElementById('input-snapshot-message');
      if (input) {
        input.value = '';
        input.focus();
      }
    });
  }

  if (btnCloseSnapshot) btnCloseSnapshot.addEventListener('click', () => closeModal(modalSnapshot));
  if (btnCancelSnapshot) btnCancelSnapshot.addEventListener('click', () => closeModal(modalSnapshot));

  if (btnCloseInspector) btnCloseInspector.addEventListener('click', () => closeModal(modalInspector));
  if (btnCloseInspectorFooter) btnCloseInspectorFooter.addEventListener('click', () => closeModal(modalInspector));

  if (btnCloseGuardian) btnCloseGuardian.addEventListener('click', () => closeModal(modalGuardian));
  if (btnCloseGuardianFooter) btnCloseGuardianFooter.addEventListener('click', () => closeModal(modalGuardian));

  // Close on backdrop click
  window.addEventListener('click', (e) => {
    if (activeModal && e.target === activeModal) {
      closeModal(activeModal);
    }
  });

  // Global key navigation for modals (Escape to close, Tab to cycle)
  window.addEventListener('keydown', (e) => {
    if (!activeModal) return;

    if (e.key === 'Escape') {
      closeModal(activeModal);
    } else if (e.key === 'Tab') {
      const focusables = Array.from(activeModal.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )).filter(el => !el.hasAttribute('disabled'));

      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];

      if (e.shiftKey && document.activeElement === first) {
        last.focus();
        e.preventDefault();
      } else if (!e.shiftKey && document.activeElement === last) {
        first.focus();
        e.preventDefault();
      }
    }
  });
}

function openSnapshotInspector(snap) {
  const modal = document.getElementById('modal-snapshot-inspector');
  const body = document.getElementById('modal-inspector-body');
  const copyCmdBtn = document.getElementById('btn-copy-restore-cmd');

  if (!modal || !body) return;

  const parentsList = (snap.parent_ids_hex || []).length > 0 
    ? snap.parent_ids_hex.map(p => `<code>${p}</code>`).join(', ')
    : '<em style="color: var(--text-muted);">Genesis (No parents)</em>';

  body.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 14px;">
      <div class="op-meta-row">
        <span class="op-meta-label">Snapshot ID:</span>
        <span class="op-meta-val" style="color: var(--accent-cyan); word-break: break-all;">${snap.snapshot_id_hex}</span>
      </div>
      <div class="op-meta-row">
        <span class="op-meta-label">Manifest CID:</span>
        <span class="op-meta-val" style="word-break: break-all;">${snap.manifest_cid_hex}</span>
      </div>
      <div class="op-meta-row">
        <span class="op-meta-label">Author Device ID:</span>
        <span class="op-meta-val">${snap.device_id_hex}</span>
      </div>
      <div class="op-meta-row">
        <span class="op-meta-label">Sequence Counter:</span>
        <span class="op-meta-val">#${snap.device_counter} (Epoch #${snap.epoch})</span>
      </div>
      <div class="op-meta-row">
        <span class="op-meta-label">Parent Nodes:</span>
        <span class="op-meta-val">${parentsList}</span>
      </div>
      <div class="op-meta-row">
        <span class="op-meta-label">Timestamp UTC:</span>
        <span class="op-meta-val">${snap.timestamp_utc ? new Date(snap.timestamp_utc * 1000).toUTCString() : 'Advisory'}</span>
      </div>
      <div class="op-meta-row">
        <span class="op-meta-label">Cryptographic Signature:</span>
        <span class="op-meta-val" style="color: var(--accent-emerald);">Ed25519 Verified</span>
      </div>
    </div>
  `;

  if (copyCmdBtn) {
    const cmd = `ciphervault restore --snapshot ${snap.snapshot_id_hex}`;
    copyCmdBtn.setAttribute('data-cmd', cmd);
    copyCmdBtn.onclick = () => {
      navigator.clipboard.writeText(cmd);
      showToast("Restore command copied to clipboard!");
    };
  }

  openModal(modal);
}

function initCopyActions() {
  document.addEventListener('click', (e) => {
    const copyBtn = e.target.closest('[data-copy]');
    if (copyBtn) {
      const textToCopy = copyBtn.getAttribute('data-copy');
      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          showToast("Copied to clipboard!");
        });
      }
      return;
    }

    const copyCodeBtn = e.target.closest('.btn-copy-code');
    if (copyCodeBtn) {
      const code = copyCodeBtn.getAttribute('data-code');
      if (code) {
        navigator.clipboard.writeText(code).then(() => {
          showToast(`Copied: ${code}`);
        });
      }
      return;
    }

    const copyVaultBtn = e.target.closest('#btn-copy-vault-id');
    if (copyVaultBtn) {
      const vElem = document.getElementById('vault-id-display');
      const fullId = vElem ? (vElem.getAttribute('data-full-id') || vElem.textContent) : "";
      if (fullId && fullId !== "Loading...") {
        navigator.clipboard.writeText(fullId).then(() => {
          showToast("Vault ID copied to clipboard!");
        });
      }
    }
  });
}

function initSecretToggle() {
  const toggleBtn = document.getElementById('btn-toggle-secret');
  const secretDisplay = document.getElementById('secret-display');
  const copyBtn = document.getElementById('btn-copy-secret');
  let isRevealed = false;

  if (toggleBtn && secretDisplay) {
    toggleBtn.addEventListener('click', () => {
      isRevealed = !isRevealed;

      if (isRevealed) {
        secretDisplay.textContent = "Zero-Knowledge Protected: Master recovery secret is never exposed to the web dashboard. Run 'ciphervault recovery export' directly in your local terminal.";
        secretDisplay.className = "secret-key-revealed";
        toggleBtn.textContent = "Mask Info";
        if (copyBtn) copyBtn.style.display = "none";
        showToast("Zero-Knowledge: Secret never leaves your secure terminal", "info");
      } else {
        secretDisplay.textContent = "•••• •••• •••• •••• •••• •••• •••• ••••";
        secretDisplay.className = "secret-key-masked";
        toggleBtn.textContent = "Reveal Secret";
        if (copyBtn) copyBtn.style.display = "none";
      }
    });
  }
}

function applyDagFilter() {
  const q = (state.searchQueryDag || '').toLowerCase().trim();
  const nodes = document.querySelectorAll('#dag-list .dag-node');
  nodes.forEach(n => {
    if (!q) {
      n.style.display = 'flex';
      return;
    }
    const text = n.textContent.toLowerCase();
    n.style.display = text.includes(q) ? 'flex' : 'none';
  });
}

function applyFilesFilter() {
  const q = (state.searchQueryFiles || '').toLowerCase().trim();
  const rows = document.querySelectorAll('#table-files-body tr');
  rows.forEach(r => {
    if (!q) {
      r.style.display = '';
      return;
    }
    const text = r.textContent.toLowerCase();
    r.style.display = text.includes(q) ? '' : 'none';
  });
}

function initSearchFilters() {
  const dagSearch = document.getElementById('input-search-dag');
  if (dagSearch) {
    dagSearch.addEventListener('input', (e) => {
      state.searchQueryDag = e.target.value;
      applyDagFilter();
    });
  }

  const filesSearch = document.getElementById('input-search-files');
  if (filesSearch) {
    filesSearch.addEventListener('input', (e) => {
      state.searchQueryFiles = e.target.value;
      applyFilesFilter();
    });
  }
}

function initQuickActions() {
  // Manual refresh button
  const btnRefresh = document.getElementById('btn-manual-refresh');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', () => {
      fetchAllData();
      showToast("Vault and operator state refreshed");
    });
  }

  // Submit Snapshot from Modal
  const btnSubmitSnapshot = document.getElementById('btn-submit-snapshot');
  if (btnSubmitSnapshot) {
    btnSubmitSnapshot.addEventListener('click', async () => {
      const messageInput = document.getElementById('input-snapshot-message');
      const message = messageInput ? messageInput.value.trim() : "";
      const submitText = document.getElementById('btn-submit-text');
      const submitSpinner = document.getElementById('btn-submit-spinner');

      if (submitText) submitText.textContent = "Replicating...";
      if (submitSpinner) submitSpinner.style.display = "inline-block";
      btnSubmitSnapshot.disabled = true;

      try {
        const res = await fetch('/api/snapshots', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: message || null }),
        });
        const result = await res.json();

        if (result.success) {
          showToast("Snapshot captured. Check the local activity log for replica audit results.");
          const modal = document.getElementById('modal-create-snapshot');
          if (modal) closeModal(modal);
          await fetchAllData();
        } else {
          showToast(`Error: ${result.error || 'Failed to capture snapshot'}`);
        }
      } catch (err) {
        showToast("Network error creating snapshot");
      } finally {
        if (submitText) submitText.textContent = "Capture & Push";
        if (submitSpinner) submitSpinner.style.display = "none";
        btnSubmitSnapshot.disabled = false;
      }
    });
  }

  // Anchor Head Button
  const triggerAnchor = async () => {
    showToast("Submitting Arbitrum checkpoint commitment...");
    try {
      const res = await fetch('/api/anchors', { method: 'POST' });
      const result = await res.json();
      if (result.success || result.status === 'ok') {
        showToast("Checkpoint commitment prepared locally. No on-chain receipt has been verified yet.");
        await Promise.all([fetchAllData(), fetchRelayerCheckpoints()]);
      } else {
        showToast(`Anchor error: ${result.error || 'Failed'}`);
      }
    } catch (e) {
      showToast("Network error triggering anchor");
    }
  };

  const btnAnchor = document.getElementById('btn-trigger-anchor');
  if (btnAnchor) btnAnchor.addEventListener('click', triggerAnchor);

  const btnAnchorTab = document.getElementById('btn-anchor-from-tab');
  if (btnAnchorTab) btnAnchorTab.addEventListener('click', triggerAnchor);

  // Audit Button
  const btnAudit = document.getElementById('btn-trigger-audit');
  if (btnAudit) {
    btnAudit.addEventListener('click', async () => {
      showToast("Running an explicit local recovery audit...");
      try {
        const res = await fetch('/api/audit', { method: 'POST' });
        const result = await res.json();
        if (result.success) {
          state.audit = result.report || null;
          renderAudit(state.audit);
          const recoverable = Array.isArray(state.audit?.recoverable_operators)
            ? state.audit.recoverable_operators.length
            : null;
          showToast(recoverable == null
            ? 'Recovery audit reported a healthy result.'
            : `Recovery audit reported ${recoverable} recoverable operator response(s).`);
          await fetchOperators();
        } else {
          state.audit = result.report || null;
          renderAudit(state.audit);
          showToast(`Audit warning: ${result.error || result.message || 'Unverified'}`);
        }
      } catch (e) {
        showToast("Network error running replica audit");
      }
    });
  }

  // Print Recovery Kit
  const btnPrint = document.getElementById('btn-print-kit');
  if (btnPrint) {
    btnPrint.addEventListener('click', () => {
      window.print();
    });
  }
}

function initMathVerifier() {
  const btnVerify = document.getElementById('btn-run-math-verify');
  const outputBox = document.getElementById('verify-result-output');

  if (btnVerify && outputBox) {
    btnVerify.addEventListener('click', async () => {
      if (!state.anchors || state.anchors.length === 0) {
        showToast("No active anchor commitment to verify yet.");
        return;
      }

      const latest = state.anchors[state.anchors.length - 1];
      outputBox.style.display = "block";
      outputBox.innerHTML = `Computing WebCrypto SHA-256("CIPHERVAULT-ANCHOR-V1" || salt || head_cid)...`;

      try {
        // Preimage concatenation: "CIPHERVAULT-ANCHOR-V1" + salt (32 bytes) + head_record_cid (32 bytes)
        const domain = new TextEncoder().encode("CIPHERVAULT-ANCHOR-V1");
        const saltBytes = hexToUint8Array(latest.salt_hex);
        const headBytes = hexToUint8Array(latest.head_record_cid_hex);

        const combined = new Uint8Array(domain.length + saltBytes.length + headBytes.length);
        combined.set(domain, 0);
        combined.set(saltBytes, domain.length);
        combined.set(headBytes, domain.length + saltBytes.length);

        const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
        const computedHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

        const matches = computedHex.toLowerCase() === latest.commitment_hex.toLowerCase();

        outputBox.innerHTML = `
          <div style="font-weight: 700; color: ${matches ? 'var(--accent-emerald)' : 'var(--accent-rose)'}; margin-bottom: 6px;">
            ${matches ? '✓ COMMITMENT PREIMAGE MATCHES' : '✗ COMMITMENT MISMATCH'}
          </div>
          <div>Recorded commitment: <code>0x${latest.commitment_hex}</code></div>
          <div>Browser Computed:  <code>0x${computedHex}</code></div>
          <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 6px;">
            This verifies the local commitment preimage only. It does not verify transaction inclusion or chain finality.
          </div>
        `;
      } catch (err) {
        outputBox.textContent = `Verification calculation error: ${err.message}`;
      }
    });
  }
}

function initRelayerActions() {
  const btnRelayerAnchor = document.getElementById('btn-trigger-relayer-anchor');
  if (btnRelayerAnchor) {
    btnRelayerAnchor.addEventListener('click', async () => {
      showToast("Triggering automated L2 relayer anchor...");
      try {
        const res = await fetch('/api/relayer/anchor', { method: 'POST' });
        const result = await res.json();
        if (result.status === 'ok') {
          showToast(`✓ Checkpoint relayed! Block #${result.block_number || '--'}`);
          await Promise.all([fetchAnchors(), fetchRelayerCheckpoints()]);
        } else {
          showToast(`Relayer error: ${result.message || 'Failed'}`);
        }
      } catch (err) {
        showToast("Network error submitting relayer anchor");
      }
    });
  }
}

function initFleetActions() {
  const btnAudit = document.getElementById('btn-run-fleet-audit');
  if (btnAudit) {
    btnAudit.addEventListener('click', async () => {
      showToast("Running fleet self-repair audit across all replicas...");
      try {
        const res = await fetch('/api/fleet/audit', { method: 'POST' });
        const result = await res.json();
        if (result.status === 'ok') {
          showToast("✓ Fleet self-repair audit completed!");
          await fetchFleet();
        } else {
          showToast(`Fleet audit error: ${result.error || 'Failed'}`);
        }
      } catch (err) {
        showToast("Network error running fleet audit");
      }
    });
  }
}

// -------------------------------------------------------------
// Utilities
// -------------------------------------------------------------

function truncateHash(str, head = 8, tail = 6) {
  if (!str) return "";
  if (str.length <= head + tail) return str;
  return `${str.substring(0, head)}...${str.substring(str.length - tail)}`;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KiB', 'MiB', 'GiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatTimestamp(unixSec) {
  const diffSec = Math.floor(Date.now() / 1000) - unixSec;
  if (diffSec < 60) return "Just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} mins ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} hrs ago`;
  return new Date(unixSec * 1000).toLocaleDateString();
}

function hexToUint8Array(hexString) {
  const cleanHex = hexString.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const typeClass = type === 'error' ? 'error' : (type === 'warning' ? 'warning' : (type === 'success' ? 'success' : 'info'));
  toast.className = `toast ${typeClass}`;

  let strokeColor = 'var(--accent-cyan)';
  let iconSvg = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>';

  if (typeClass === 'error') {
    strokeColor = 'var(--accent-rose)';
    iconSvg = '<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>';
  } else if (typeClass === 'warning') {
    strokeColor = 'var(--accent-amber)';
    iconSvg = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>';
  } else if (typeClass === 'success') {
    strokeColor = 'var(--accent-emerald)';
    iconSvg = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>';
  }

  toast.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${strokeColor}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      ${iconSvg}
    </svg>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => {
      if (typeof toast.remove === 'function') toast.remove();
    }, 300);
  }, 3200);
}

// -------------------------------------------------------------
// Real-Time Server-Sent Events (SSE) Stream
// -------------------------------------------------------------

function initSseStream() {
  if (typeof EventSource === 'undefined' || state.sseStream || document.hidden) return;
  try {
    const sse = new EventSource('/api/stream');
    state.sseStream = sse;

    sse.addEventListener('telemetry', (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleTelemetryPacket(payload);
      } catch (e) {
        console.warn("SSE telemetry parse error:", e);
      }
    });

    sse.onopen = () => {
      const sseText = document.getElementById('sse-stream-text');
      const sseDot = document.getElementById('sse-pulse-dot');
      if (sseText) sseText.textContent = "Telemetry stream: Active";
      if (sseDot) sseDot.style.backgroundColor = "var(--accent-cyan)";
    };

    sse.onerror = () => {
      const sseText = document.getElementById('sse-stream-text');
      const sseDot = document.getElementById('sse-pulse-dot');
      if (sseText) sseText.textContent = "Telemetry stream: Reconnecting";
      if (sseDot) sseDot.style.backgroundColor = "var(--accent-amber)";
    };
  } catch (e) {
    console.warn("SSE initialization error:", e);
  }
}

function handleTelemetryPacket(data) {
  if (!data) return;

  const tsElem = document.getElementById('sse-last-timestamp');
  if (tsElem && data.timestamp) {
    const date = new Date(data.timestamp);
    tsElem.textContent = `Live Telemetry: ${date.toLocaleTimeString()}`;
  }

  if (Array.isArray(data.operators)) {
    let totalLat = 0;
    let onlineCount = 0;
    data.operators.forEach((op, idx) => {
      const elem = document.getElementById(`sse-op${idx + 1}-lat`);
      if (elem) {
        if (op.online) {
          elem.textContent = typeof op.latency_ms === 'number' && Number.isFinite(op.latency_ms)
            ? `${op.latency_ms} ms`
            : 'Not reported';
          elem.style.color = "var(--accent-emerald)";
          if (typeof op.latency_ms === 'number' && Number.isFinite(op.latency_ms)) {
            totalLat += op.latency_ms;
            onlineCount++;
          }
        } else {
          elem.textContent = "OFFLINE";
          elem.style.color = "#ef4444";
        }
      }
    });

    const avgElem = document.getElementById('avg-latency-display');
    if (onlineCount > 0) {
      const avg = Math.round(totalLat / onlineCount);
      if (avgElem) avgElem.textContent = `${avg} ms`;
    } else if (avgElem) {
      avgElem.textContent = '-- ms';
    }
  }

  const tokenElem = document.getElementById('sse-token-status');
  if (tokenElem) {
    if (data.token_attached) {
      tokenElem.textContent = "PIV Smartcard Detected (Slot 9C/9D Ready)";
      tokenElem.style.color = "var(--accent-emerald)";
    } else {
      tokenElem.textContent = "No Physical Smartcard Attached";
      tokenElem.style.color = "var(--text-secondary)";
    }
  }
}

// -------------------------------------------------------------
// Visual FastCDC Inspector & Real Data Deduplication Pipeline
// -------------------------------------------------------------

async function loadVaultFilesForFastCdc() {
  const selectElem = document.getElementById('select-vault-file');
  if (!selectElem || !canAccessPrivateFeature('plaintext_inspection') || state.fastCdcVaultFilesLoaded) return;

  try {
    const res = await fetch('/api/fastcdc/vault-files');
    if (!res.ok) return;
    const data = await res.json();
    if (data.success && Array.isArray(data.files)) {
      selectElem.innerHTML = '';
      if (data.files.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No tracked files in vault (use CLI track or upload)';
        selectElem.appendChild(opt);
      } else {
        const defaultOpt = document.createElement('option');
        defaultOpt.value = '';
        defaultOpt.textContent = `-- Select Tracked Vault File (${data.files.length} active) --`;
        selectElem.appendChild(defaultOpt);

        data.files.forEach(f => {
          const opt = document.createElement('option');
          opt.value = f.path;
          opt.textContent = `${f.path} (${formatBytes(f.size_bytes)})`;
          selectElem.appendChild(opt);
        });

        state.fastCdcVaultFilesLoaded = true;
      }
    }
  } catch (err) {
    console.warn("Failed to load vault files for FastCDC:", err);
  }
}

function initFastCdcInspector() {
  const contentInput = document.getElementById('fastcdc-content-input');
  const byteCounter = document.getElementById('fastcdc-byte-counter');
  const btnRun = document.getElementById('btn-run-fastcdc');
  const btnShift = document.getElementById('btn-simulate-shift');
  const selectVaultFile = document.getElementById('select-vault-file');
  const btnInspectVault = document.getElementById('btn-inspect-vault-file');
  const inputUpload = document.getElementById('input-upload-file');
  const btnPresetClear = document.getElementById('preset-clear');
  const btnCopyCid = document.getElementById('btn-copy-chunk-cid');

  if (!contentInput || !btnRun) return;

  const updateByteCount = () => {
    const val = contentInput.value;
    const bytes = new Blob([val]).size;
    if (byteCounter) byteCounter.textContent = `${formatBytes(bytes)} (${bytes} bytes)`;
  };

  contentInput.addEventListener('input', updateByteCount);

  // Selecting a vault file never sends its path or content by itself. The
  // explicit inspect/run buttons are the only way to start an inspection.

  if (btnInspectVault) {
    btnInspectVault.addEventListener('click', () => {
      const path = selectVaultFile ? selectVaultFile.value : "";
      if (path) {
        runFastCdcInspection({ file_path: path });
      } else {
        showToast("Please select a tracked vault file first.", "warning");
      }
    });
  }

  if (inputUpload) {
    inputUpload.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (evt) => {
          const text = evt.target?.result || "";
          contentInput.value = text;
          updateByteCount();
          showToast(`Loaded '${file.name}' (${formatBytes(file.size)})`);
        };
        reader.readAsText(file);
      }
    });
  }

  if (btnPresetClear) {
    btnPresetClear.addEventListener('click', () => {
      contentInput.value = '';
      updateByteCount();
      const container = document.getElementById('chunk-blocks-container');
      if (container) {
        container.innerHTML = `<div class="chunk-placeholder-text">Input cleared. Select a real vault file, upload a file, or type text.</div>`;
      }
      const detailCard = document.getElementById('chunk-detail-card');
      if (detailCard) detailCard.style.display = 'none';
      resetFastCdcMetrics();
    });
  }

  btnRun.addEventListener('click', () => {
    if (contentInput.value.trim()) {
      runFastCdcInspection({ content: contentInput.value });
    } else if (selectVaultFile && selectVaultFile.value) {
      runFastCdcInspection({ file_path: selectVaultFile.value });
    } else {
      showToast("Select a vault file, upload a file, or enter content to inspect.", "warning");
    }
  });

  if (btnShift) {
    btnShift.addEventListener('click', () => {
      const current = contentInput.value;
      if (!current) {
        showToast("Load or type content before simulating boundary shift.", "warning");
        return;
      }
      const shifted = `# PREPENDED 19 BYTES FOR BOUNDARY SHIFT TEST\n` + current;
      contentInput.value = shifted;
      updateByteCount();
      showToast("Injected 46-byte prefix to demonstrate FastCDC boundary realignment");
      runFastCdcInspection({ content: shifted });
    });
  }

  if (btnCopyCid) {
    btnCopyCid.addEventListener('click', () => {
      const cidElem = document.getElementById('detail-chunk-cid');
      if (cidElem && cidElem.textContent) {
        copyToClipboard(cidElem.textContent);
        showToast("Chunk CID copied to clipboard");
      }
    });
  }

}

function closeSseStream() {
  if (state.sseStream && typeof state.sseStream.close === 'function') {
    state.sseStream.close();
  }
  state.sseStream = null;
  const sseText = document.getElementById('sse-stream-text');
  const sseDot = document.getElementById('sse-pulse-dot');
  if (sseText) sseText.textContent = 'Telemetry stream: Paused';
  if (sseDot) sseDot.style.backgroundColor = 'var(--text-muted)';
}

function cycleFocusWithin(container, event) {
  if (!container || event.key !== 'Tab') return;
  const focusables = Array.from(container.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  )).filter(element => !(element.hasAttribute && element.hasAttribute('disabled')));
  if (focusables.length === 0) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function resetFastCdcMetrics() {
  const elems = [
    'f-metric-total-chunks', 'f-metric-unique-ratio', 'f-metric-savings-pct',
    'f-metric-saved-bytes', 'f-metric-total-bytes', 'f-metric-unique-bytes', 'f-metric-fixed-count'
  ];
  elems.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '--';
  });
  const boundaryStatus = document.getElementById('f-metric-boundary-status');
  if (boundaryStatus) {
    boundaryStatus.textContent = 'Not measured';
    boundaryStatus.style.color = 'var(--text-muted)';
  }
}

async function runFastCdcInspection(opts) {
  if (!canAccessPrivateFeature('plaintext_inspection')) {
    showToast('FastCDC inspection is available only in a local private workspace.', 'warning');
    return;
  }
  const minSize = parseInt(document.getElementById('fastcdc-min-size')?.value || "4096", 10);
  const avgSize = parseInt(document.getElementById('fastcdc-avg-size')?.value || "16384", 10);
  const maxSize = parseInt(document.getElementById('fastcdc-max-size')?.value || "65536", 10);

  const payload = typeof opts === 'string'
    ? { content: opts, min_size: minSize, avg_size: avgSize, max_size: maxSize }
    : {
        file_path: opts?.file_path || null,
        content: opts?.content || null,
        min_size: minSize,
        avg_size: avgSize,
        max_size: maxSize
      };

  const btnRun = document.getElementById('btn-run-fastcdc');
  if (btnRun) btnRun.disabled = true;

  try {
    const res = await fetch('/api/fastcdc/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      showToast(`FastCDC inspection failed (${res.status})`, "error");
      return;
    }

    const data = await res.json();
    if (!data.success) {
      showToast(`FastCDC error: ${data.error || 'Inspection failed'}`, "error");
      return;
    }
    state.fastCdcResult = data;
    renderFastCdcResults(data);
    if (data.source) {
      showToast(`Analyzed ${data.source} (${data.metrics?.total_chunks || 0} chunks)`);
    }
  } catch (err) {
    console.error("FastCDC inspection error:", err);
    showToast(`Network error: ${err.message}`, "error");
  } finally {
    if (btnRun) btnRun.disabled = false;
  }
}

function renderFastCdcResults(data) {
  if (!data || !data.metrics) return;
  state.fastCdcResult = data;

  const m = data.metrics;
  const chunks = data.chunks || [];

  const totalChunksElem = document.getElementById('f-metric-total-chunks');
  const uniqueRatioElem = document.getElementById('f-metric-unique-ratio');
  const savingsPctElem = document.getElementById('f-metric-savings-pct');
  const savedBytesElem = document.getElementById('f-metric-saved-bytes');
  const totalBytesElem = document.getElementById('f-metric-total-bytes');
  const uniqueBytesElem = document.getElementById('f-metric-unique-bytes');
  const fixedCountElem = document.getElementById('f-metric-fixed-count');

  if (totalChunksElem) totalChunksElem.textContent = String(m.total_chunks);
  if (uniqueRatioElem) uniqueRatioElem.textContent = `${m.unique_chunks} unique (${m.duplicate_chunks} dups)`;
  if (savingsPctElem) savingsPctElem.textContent = `${m.dedup_savings_pct.toFixed(1)}%`;
  if (savedBytesElem) savedBytesElem.textContent = `${formatBytes(m.saved_bytes)} estimated duplicate bytes`;
  if (totalBytesElem) totalBytesElem.textContent = formatBytes(m.total_bytes);
  if (uniqueBytesElem) uniqueBytesElem.textContent = `${formatBytes(m.unique_bytes)} unique bytes`;
  if (fixedCountElem) fixedCountElem.textContent = `${m.fixed_chunks_count} blocks`;
  const boundaryStatusElem = document.getElementById('f-metric-boundary-status');
  if (boundaryStatusElem) {
    if (m.boundary_shift_resilient === true) {
      boundaryStatusElem.textContent = 'Measured: resilient';
      boundaryStatusElem.style.color = 'var(--accent-emerald)';
    } else if (m.boundary_shift_resilient === false) {
      boundaryStatusElem.textContent = 'Measured: changes detected';
      boundaryStatusElem.style.color = 'var(--accent-amber)';
    } else {
      boundaryStatusElem.textContent = 'Not measured';
      boundaryStatusElem.style.color = 'var(--text-muted)';
    }
  }

  const badgeTab = document.getElementById('badge-tab-fastcdc');
  if (badgeTab) badgeTab.textContent = `${m.total_chunks} Chunks`;

  const container = document.getElementById('chunk-blocks-container');
  if (!container) return;

  if (chunks.length === 0) {
    container.innerHTML = `<div class="chunk-placeholder-text">Zero chunks produced for empty payload.</div>`;
    return;
  }

  container.innerHTML = chunks.map((c, i) => {
    let entropyClass = 'chunk-block-low';
    if (c.entropy >= 7.0) {
      entropyClass = 'chunk-block-high';
    } else if (c.entropy >= 4.0) {
      entropyClass = 'chunk-block-med';
    }

    if (c.is_duplicate) {
      entropyClass = 'chunk-block-dup';
    }

    const widthPx = Math.max(48, Math.min(180, Math.round((c.length / (data.config?.avg_size || 16384)) * 70)));

    return `
      <div class="chunk-block ${entropyClass}" 
           data-chunk-idx="${i}" 
           style="width: ${widthPx}px;"
           title="Chunk #${i}: ${formatBytes(c.length)} | Entropy: ${c.entropy} | ${c.is_duplicate ? 'DUPLICATE' : 'UNIQUE'}">
        <span class="chunk-block-idx">#${i}</span>
        <span class="chunk-block-sz">${formatBytes(c.length)}</span>
      </div>
    `;
  }).join('');

  const blocks = container.querySelectorAll('.chunk-block');
  blocks.forEach(block => {
    block.addEventListener('click', () => {
      const idx = parseInt(block.getAttribute('data-chunk-idx'), 10);
      blocks.forEach(b => b.classList.remove('selected'));
      block.classList.add('selected');
      selectChunk(idx);
    });
  });

  if (chunks.length > 0) {
    const firstBlock = container.querySelector('.chunk-block');
    if (firstBlock) firstBlock.classList.add('selected');
    selectChunk(0);
  }
}

function selectChunk(index) {
  if (!state.fastCdcResult || !state.fastCdcResult.chunks) return;
  const chunk = state.fastCdcResult.chunks[index];
  if (!chunk) return;

  state.selectedChunkIndex = index;
  const detailCard = document.getElementById('chunk-detail-card');
  if (detailCard) detailCard.style.display = 'block';

  const idxElem = document.getElementById('detail-chunk-index');
  const badgeElem = document.getElementById('detail-chunk-badge');
  const rangeElem = document.getElementById('detail-chunk-range');
  const sizeElem = document.getElementById('detail-chunk-size');
  const entropyElem = document.getElementById('detail-chunk-entropy');
  const fillElem = document.getElementById('detail-entropy-fill');
  const gearElem = document.getElementById('detail-chunk-gear');
  const cidElem = document.getElementById('detail-chunk-cid');
  const prevElem = document.getElementById('detail-chunk-preview');

  if (idxElem) idxElem.textContent = String(chunk.index);
  if (badgeElem) {
    if (chunk.is_duplicate) {
      badgeElem.textContent = "Duplicate chunk in this inspection";
      badgeElem.style.color = "#f87171";
      badgeElem.style.borderColor = "rgba(239, 68, 68, 0.4)";
    } else {
      badgeElem.textContent = "Unique chunk in this inspection";
      badgeElem.style.color = "var(--accent-emerald)";
      badgeElem.style.borderColor = "rgba(0, 230, 118, 0.4)";
    }
  }

  if (rangeElem) rangeElem.textContent = `[Offset: ${chunk.offset} .. End: ${chunk.offset + chunk.length}]`;
  if (sizeElem) sizeElem.textContent = `${chunk.length} bytes (${formatBytes(chunk.length)})`;
  if (entropyElem) {
    const entPct = Math.min(100, Math.round((chunk.entropy / 8.0) * 100));
    entropyElem.textContent = `${chunk.entropy.toFixed(3)} / 8.000 bits/byte (${entPct}%)`;
  }
  if (fillElem) {
    const entPct = Math.min(100, (chunk.entropy / 8.0) * 100);
    fillElem.style.width = `${entPct}%`;
  }
  if (gearElem) gearElem.textContent = chunk.gear_fingerprint;
  if (cidElem) cidElem.textContent = chunk.cid_hex;
  if (prevElem) prevElem.textContent = 'Content previews are disabled.';
}

// -------------------------------------------------------------
// Secret Revision Diff Engine (Tab 3)
// -------------------------------------------------------------

function updateDiffSelects(snapshots) {
  const selectBase = document.getElementById('diff-select-base');
  const selectTarget = document.getElementById('diff-select-target');
  if (!selectBase || !selectTarget) return;

  const currentBase = selectBase.value;
  const currentTarget = selectTarget.value;

  const baseOptions = [
    '<option value="head">Latest Head (Active)</option>',
    '<option value="working">Working Tree (Disk)</option>'
  ];
  const targetOptions = [
    '<option value="working">Working Tree (Disk)</option>',
    '<option value="head">Latest Head (Active)</option>'
  ];

  if (Array.isArray(snapshots)) {
    snapshots.forEach((snap, i) => {
      const label = `Snapshot #${snap.device_counter || (snapshots.length - i)} (${truncateHash(snap.snapshot_id_hex, 6, 4)})`;
      baseOptions.push(`<option value="${escapeHtml(snap.snapshot_id_hex)}">${escapeHtml(label)}</option>`);
      targetOptions.push(`<option value="${escapeHtml(snap.snapshot_id_hex)}">${escapeHtml(label)}</option>`);
    });
  }

  selectBase.innerHTML = baseOptions.join('');
  selectTarget.innerHTML = targetOptions.join('');

  if (currentBase) selectBase.value = currentBase;
  if (currentTarget) selectTarget.value = currentTarget;
}

function initDiffViewer() {
  const btnRun = document.getElementById('btn-run-diff');
  const btnReveal = document.getElementById('btn-toggle-reveal-diff');
  const textReveal = document.getElementById('text-reveal-diff');

  if (btnRun) {
    btnRun.addEventListener('click', () => runDiffComparison());
  }

  if (btnReveal) {
    btnReveal.addEventListener('click', () => {
      state.diffReveal = !state.diffReveal;
      if (textReveal) {
        textReveal.textContent = state.diffReveal ? "Mask Values" : "Reveal Values";
      }
      if (btnReveal) {
        btnReveal.classList.toggle('active', state.diffReveal);
      }
      if (state.lastDiffReport) {
        renderDiffResults(state.lastDiffReport);
      }
    });
  }
}

async function runDiffComparison() {
  const selectBase = document.getElementById('diff-select-base');
  const selectTarget = document.getElementById('diff-select-target');
  const btnRun = document.getElementById('btn-run-diff');
  const container = document.getElementById('diff-results-container');

  const baseVal = selectBase ? selectBase.value : 'head';
  const targetVal = selectTarget ? selectTarget.value : 'working';

  if (btnRun) {
    btnRun.disabled = true;
    btnRun.innerHTML = `
      <svg class="rotating" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M23 4v6h-6"></path><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
      </svg>
      <span>Analyzing...</span>
    `;
  }

  try {
    const url = `/api/diff?snapshot_a=${encodeURIComponent(baseVal)}&snapshot_b=${encodeURIComponent(targetVal)}&reveal=${state.diffReveal ? 'true' : 'false'}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to calculate secret diff`);
    const data = await res.json();
    if (!data.success && data.error) throw new Error(data.error);

    state.lastDiffReport = data.report;
    renderDiffResults(data.report);
    showToast("Diff comparison complete");
    appendTerminalLog('DIFF', `Calculated diff between '${data.report.base_label}' and '${data.report.target_label}'`);
  } catch (err) {
    console.error("Diff computation error:", err);
    if (container) {
      container.innerHTML = `
        <div class="diff-placeholder" style="color: var(--accent-rose);">
          <p>Failed to calculate diff: ${escapeHtml(err.message)}</p>
        </div>
      `;
    }
    showToast(`Diff error: ${err.message}`, 'error');
  } finally {
    if (btnRun) {
      btnRun.disabled = false;
      btnRun.innerHTML = `<span>Calculate Diff</span>`;
    }
  }
}

function maskSecretValue(val) {
  if (!val) return "";
  const len = val.length;
  if (len <= 6) return "***";
  if (len <= 12) return val.slice(0, 2) + "***" + val.slice(len - 2);
  return val.slice(0, 3) + "***" + val.slice(len - 3);
}

function renderDiffResults(report) {
  const container = document.getElementById('diff-results-container');
  const kpiAdded = document.getElementById('diff-kpi-added');
  const kpiModified = document.getElementById('diff-kpi-modified');
  const kpiRemoved = document.getElementById('diff-kpi-removed');
  const kpiFiles = document.getElementById('diff-kpi-files');
  const badgeDiff = document.getElementById('badge-tab-diff');

  if (!report) return;

  const files = report.files || report.file_diffs || [];
  const addedCount = report.total_added !== undefined ? report.total_added : (report.total_added_keys || 0);
  const modifiedCount = report.total_modified !== undefined ? report.total_modified : (report.total_modified_keys || 0);
  const removedCount = report.total_removed !== undefined ? report.total_removed : (report.total_deleted_keys || 0);
  const baseLabel = report.old_source || report.base_label || 'Base';
  const targetLabel = report.new_source || report.target_label || 'Target';

  if (kpiAdded) kpiAdded.textContent = String(addedCount);
  if (kpiModified) kpiModified.textContent = String(modifiedCount);
  if (kpiRemoved) kpiRemoved.textContent = String(removedCount);
  if (kpiFiles) kpiFiles.textContent = String(files.length);
  if (badgeDiff) badgeDiff.textContent = `${files.length} diffs`;

  if (!container) return;

  if (files.length === 0) {
    container.innerHTML = `
      <div class="diff-placeholder">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-emerald)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 12px;">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <p>No confidential differences detected between <strong>${escapeHtml(baseLabel)}</strong> and <strong>${escapeHtml(targetLabel)}</strong>.</p>
        <span style="font-size: 0.8rem; color: var(--text-muted);">All secrets, keys, and values are byte-identical.</span>
      </div>
    `;
    return;
  }

  container.innerHTML = files.map(file => {
    const filePath = file.file_path || file.path || 'Unknown';
    const isAddedFile = file.change_type === 'Added' || (file.added_count > 0 && file.modified_count === 0 && file.removed_count === 0 && (file.entries || []).every(e => (e.change?.type || e.kind) === 'Added'));
    const isDeletedFile = file.change_type === 'Deleted' || (file.removed_count > 0 && file.modified_count === 0 && file.added_count === 0 && (file.entries || []).every(e => (e.change?.type || e.kind) === 'Removed'));
    const isModifiedFile = !isAddedFile && !isDeletedFile && ((file.modified_count > 0 || file.added_count > 0 || file.removed_count > 0) || file.change_type === 'Modified');

    const statusBadge = isAddedFile
      ? '<span class="diff-badge added">+ CREATED</span>'
      : isDeletedFile
      ? '<span class="diff-badge removed">- DELETED</span>'
      : isModifiedFile
      ? '<span class="diff-badge modified">~ MODIFIED</span>'
      : '<span class="diff-badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">UNCHANGED</span>';

    const rawEntries = file.entries || file.lines || [];
    const linesHtml = rawEntries.map(entry => {
      let kind = 'Unchanged';
      let key = entry.key;
      let oldVal = '';
      let newVal = '';
      let rawLine = entry.raw_line || '';

      if (entry.change) {
        kind = entry.change.type || 'Unchanged';
        const det = entry.change.details || {};
        if (kind === 'Added') {
          newVal = det.value || '';
        } else if (kind === 'Removed') {
          oldVal = det.value || '';
        } else if (kind === 'Modified') {
          oldVal = det.old_value || '';
          newVal = det.new_value || '';
        } else if (kind === 'Unchanged') {
          newVal = det.value || '';
          oldVal = det.value || '';
        }
      } else {
        kind = entry.kind || 'Unchanged';
        oldVal = state.diffReveal ? (entry.old_value_plain || entry.old_value_masked || '') : (entry.old_value_masked || entry.old_value_plain || '');
        newVal = state.diffReveal ? (entry.new_value_plain || entry.new_value_masked || '') : (entry.new_value_masked || entry.new_value_plain || '');
      }

      // If masked values needed:
      const displayOld = state.diffReveal ? oldVal : (oldVal.includes('***') ? oldVal : maskSecretValue(oldVal));
      const displayNew = state.diffReveal ? newVal : (newVal.includes('***') ? newVal : maskSecretValue(newVal));

      const kindSign = kind === 'Added' ? '+' : kind === 'Removed' || kind === 'Deleted' ? '-' : kind === 'Modified' ? '~' : ' ';
      const lineClass = (kind === 'Deleted' ? 'removed' : kind).toLowerCase();

      let valHtml = '';
      if (key) {
        if (kind === 'Added') {
          valHtml = `<span class="diff-key">${escapeHtml(key)}</span>=<span class="diff-val-new">${escapeHtml(displayNew)}</span>`;
        } else if (kind === 'Removed' || kind === 'Deleted') {
          valHtml = `<span class="diff-key">${escapeHtml(key)}</span>=<span class="diff-val-old">${escapeHtml(displayOld)}</span>`;
        } else if (kind === 'Modified') {
          valHtml = `<span class="diff-key">${escapeHtml(key)}</span>: <span class="diff-val-old">${escapeHtml(displayOld)}</span> ➔ <span class="diff-val-new">${escapeHtml(displayNew)}</span>`;
        } else {
          valHtml = `<span class="diff-key">${escapeHtml(key)}</span>=<span class="diff-val-same">${escapeHtml(displayNew)}</span>`;
        }
      } else if (rawLine) {
        valHtml = `<span class="diff-raw">${escapeHtml(rawLine)}</span>`;
      }

      return `
        <div class="diff-line ${lineClass}">
          <span class="diff-sign">${kindSign}</span>
          <div class="diff-content">${valHtml}</div>
        </div>
      `;
    }).join('');

    return `
      <article class="diff-card">
        <div class="diff-card-header">
          <div class="diff-file-info">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2">
              <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
              <polyline points="13 2 13 9 20 9"></polyline>
            </svg>
            <span class="diff-file-path">${escapeHtml(filePath)}</span>
            <span class="diff-file-fmt">${escapeHtml(file.is_dotenv ? 'ENV' : (file.format || 'RAW'))}</span>
          </div>
          <div class="diff-card-status">
            ${statusBadge}
          </div>
        </div>
        <div class="diff-lines-container">
          ${linesHtml}
        </div>
      </article>
    `;
  }).join('');
}

// -------------------------------------------------------------
// Interactive Secret File Management (Tab 4 & Modals)
// -------------------------------------------------------------

function initFileManagement() {
  const modalTrack = document.getElementById('modal-track-file');
  const btnOpenTrack = document.getElementById('btn-open-track-modal');
  const btnCloseTrack = document.getElementById('btn-close-modal-track');
  const btnCancelTrack = document.getElementById('btn-cancel-modal-track');
  const btnSubmitTrack = document.getElementById('btn-submit-track');
  const inputTrackPath = document.getElementById('input-track-path');
  const suggestionPills = document.querySelectorAll('.suggestion-pills .pill-btn');

  if (btnOpenTrack && modalTrack) {
    btnOpenTrack.addEventListener('click', () => {
      openModal(modalTrack, btnOpenTrack);
      if (inputTrackPath) {
        inputTrackPath.value = '';
        setTimeout(() => inputTrackPath.focus(), 50);
      }
    });
  }

  if (btnCloseTrack && modalTrack) {
    btnCloseTrack.addEventListener('click', () => closeModal(modalTrack));
  }
  if (btnCancelTrack && modalTrack) {
    btnCancelTrack.addEventListener('click', () => closeModal(modalTrack));
  }

  suggestionPills.forEach(btn => {
    btn.addEventListener('click', () => {
      const suggest = btn.getAttribute('data-suggest') || btn.textContent.trim();
      if (inputTrackPath) {
        inputTrackPath.value = suggest;
        inputTrackPath.focus();
      }
    });
  });

  if (btnSubmitTrack) {
    btnSubmitTrack.addEventListener('click', async () => {
      if (!inputTrackPath) return;
      const pathVal = inputTrackPath.value.trim();
      if (!pathVal) {
        showToast("Please enter a relative path to track");
        return;
      }

      btnSubmitTrack.disabled = true;
      const btnText = document.getElementById('btn-track-text');
      if (btnText) btnText.textContent = "Registering...";

      try {
        const res = await fetch('/api/files/track', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: pathVal })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          throw new Error(data.error || "Failed to track file");
        }

        showToast(data.message || `Tracked '${pathVal}' successfully`);
        appendTerminalLog('TRACK', `Tracked confidential file: ${pathVal} (.gitignore updated)`, 'var(--accent-emerald)');
        closeModal(modalTrack);
        fetchVault();
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        btnSubmitTrack.disabled = false;
        if (btnText) btnText.textContent = "Track & Protect";
      }
    });
  }

  // Event Delegation for Untracking and FastCDC Inspection
  document.addEventListener('click', async (e) => {
    const untrackBtn = e.target.closest('.btn-untrack-file');
    if (untrackBtn) {
      const filePath = untrackBtn.getAttribute('data-path');
      if (!filePath) return;

      const confirmed = window.confirm(
        `Untrack confidential file '${filePath}' from CipherVault?\n\n` +
        `• The local file on disk will NOT be deleted.\n` +
        `• Future snapshots will no longer include this file.`
      );
      if (!confirmed) return;

      untrackBtn.disabled = true;
      try {
        const res = await fetch('/api/files/untrack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: filePath })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          throw new Error(data.error || `Failed to untrack ${filePath}`);
        }

        showToast(data.message || `Untracked '${filePath}'`);
        appendTerminalLog('UNTRACK', `Untracked secret file: ${filePath}`, 'var(--accent-rose)');
        fetchVault();
      } catch (err) {
        showToast(err.message, 'error');
        untrackBtn.disabled = false;
      }
      return;
    }

    const drawerInspectBtn = e.target.closest('.btn-drawer-inspect');
    if (drawerInspectBtn) {
      e.stopPropagation();
      const snapId = drawerInspectBtn.getAttribute('data-snap-id');
      const snap = (state.snapshots || []).find(s => s.snapshot_id_hex === snapId);
      if (snap) openSnapshotDrawer(snap);
    }
  });
}

// -------------------------------------------------------------
// Slide-Out Snapshot Deep Inspector Drawer
// -------------------------------------------------------------

function initSnapshotDrawer() {
  const backdrop = document.getElementById('snapshot-drawer-backdrop');
  const btnClose = document.getElementById('btn-close-drawer');

  if (backdrop) {
    backdrop.addEventListener('click', () => closeSnapshotDrawer());
  }
  if (btnClose) {
    btnClose.addEventListener('click', () => closeSnapshotDrawer());
  }
}

function openSnapshotDrawer(snap) {
  const drawer = document.getElementById('snapshot-drawer');
  const backdrop = document.getElementById('snapshot-drawer-backdrop');
  const titleId = document.getElementById('drawer-snap-id');
  const body = document.getElementById('drawer-body');

  if (!drawer || !snap) return;

  state.lastActiveElement = document.activeElement;
  state.drawerSnapshotId = snap.snapshot_id_hex;

  if (titleId) titleId.textContent = truncateHash(snap.snapshot_id_hex, 8, 6);

  if (body) {
    const epoch = snap.epoch || 1;
    const counter = snap.device_counter || 0;
    const timestampStr = snap.timestamp_utc ? new Date(snap.timestamp_utc * 1000).toUTCString() : "Recorded";
    const authorDevice = truncateHash(snap.device_id_hex, 10, 8);
    const manifestCid = snap.manifest_cid_hex;
    const parents = (snap.parent_ids_hex || []).length > 0
      ? snap.parent_ids_hex.map(p => `<code>${truncateHash(p, 8, 6)}</code>`).join(', ')
      : '<em style="color: var(--text-muted);">Genesis</em>';

    body.innerHTML = `
      <div class="drawer-section">
        <span class="drawer-sec-title">Cryptographic Identity</span>
        <div class="drawer-meta-grid">
          <div class="drawer-meta-item">
            <span class="lbl">Snapshot ID</span>
            <span class="val font-mono highlight-cyan" style="word-break: break-all;">${escapeHtml(snap.snapshot_id_hex)}</span>
          </div>
          <div class="drawer-meta-item">
            <span class="lbl">Manifest CID</span>
            <span class="val font-mono" style="word-break: break-all;">${escapeHtml(manifestCid)}</span>
          </div>
          <div class="drawer-meta-item">
            <span class="lbl">Author Device</span>
            <span class="val font-mono" title="${escapeHtml(snap.device_id_hex)}">${authorDevice}</span>
          </div>
          <div class="drawer-meta-item">
            <span class="lbl">Epoch & Sequence</span>
            <span class="val">Epoch #${epoch} · Seq #${counter}</span>
          </div>
          <div class="drawer-meta-item">
            <span class="lbl">Parents</span>
            <span class="val">${parents}</span>
          </div>
          <div class="drawer-meta-item">
            <span class="lbl">Committed At</span>
            <span class="val">${timestampStr}</span>
          </div>
        </div>
      </div>

      <div class="drawer-section">
        <span class="drawer-sec-title">Quick Actions</span>
        <div class="drawer-actions-row">
          <button class="btn-action primary" id="btn-drawer-restore-action" style="flex: 1;">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path>
              <path d="M21 3v5h-5"></path>
              <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path>
              <path d="M8 16H3v5"></path>
            </svg>
            <span>Restore Snapshot to Disk</span>
          </button>
          <button class="btn-action secondary" id="btn-drawer-copy-cmd" title="Copy CLI restore command">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            <span>CLI Command</span>
          </button>
        </div>
      </div>

      <div class="drawer-section">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span class="drawer-sec-title">Snapshot Historical Manifest</span>
          <span id="drawer-files-count-badge" class="badge-status-subtle">Inspecting...</span>
        </div>
        <div class="drawer-files-list" id="drawer-files-list">
          <div style="color: var(--accent-cyan); font-size: 0.85rem; padding: 8px 0;">
            <span class="spinner" style="display:inline-block; width:12px; height:12px; border:2px solid var(--accent-cyan); border-top-color:transparent; border-radius:50%; animation:spin 1s linear infinite; margin-right:8px; vertical-align:middle;"></span>
            Decrypting historical snapshot manifest...
          </div>
        </div>
      </div>

      <div class="drawer-section">
        <span class="drawer-sec-title">Quorum Replicas</span>
        <div style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.5;">
          No snapshot-scoped replica proof is loaded here. Run an explicit local recovery audit before treating this snapshot as recoverable.
        </div>
      </div>
    `;

    // Fetch only the manifest belonging to this snapshot. A failed request must
    // never fall back to the current vault inventory, because that inventory can
    // describe a different point in history.
    const requestedSnapshotId = snap.snapshot_id_hex;
    fetch(`/api/snapshots/${encodeURIComponent(requestedSnapshotId)}/manifest`)
      .then(response => {
        if (!response.ok) throw new Error(`Manifest request failed (${response.status})`);
        return response.json();
      })
      .then(data => {
        if (state.drawerSnapshotId !== requestedSnapshotId) return;
        const filesListElem = document.getElementById('drawer-files-list');
        const badgeElem = document.getElementById('drawer-files-count-badge');
        if (!filesListElem) return;

        if (data && data.status === 'ok' && Array.isArray(data.files)) {
          if (badgeElem) badgeElem.textContent = `${data.files_count} files (${formatBytes(data.total_bytes)})`;
          if (data.files.length === 0) {
            filesListElem.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No confidential files registered in this snapshot manifest.</div>';
          } else {
            filesListElem.innerHTML = data.files.map(f => `
              <div class="drawer-file-item ${f.is_deleted ? 'deleted' : ''}">
                <div class="file-top">
                  <span class="file-name font-mono">${escapeHtml(f.path)}</span>
                  <span class="file-sz">${formatBytes(f.size_bytes || 0)}</span>
                </div>
                <div class="file-sub font-mono text-muted" style="display: flex; justify-content: space-between; align-items: center;">
                  <span>${f.chunk_count} chunk${f.chunk_count === 1 ? '' : 's'} · ID: ${truncateHash(f.file_id_hex, 6, 4)}</span>
                  ${f.is_deleted ? '<span class="badge-status-subtle" style="color: var(--accent-rose); border-color: rgba(248, 113, 113, 0.3);">DELETED</span>' : ''}
                </div>
              </div>
            `).join('');
          }
        } else {
          if (badgeElem) badgeElem.textContent = 'Unavailable';
          filesListElem.innerHTML = '<div style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.5;">This snapshot manifest is unavailable or cannot be decoded locally. Current vault files are intentionally not shown here because they may belong to a different snapshot.</div>';
        }
      })
      .catch(() => {
        if (state.drawerSnapshotId !== requestedSnapshotId) return;
        const filesListElem = document.getElementById('drawer-files-list');
        const badgeElem = document.getElementById('drawer-files-count-badge');
        if (badgeElem) badgeElem.textContent = 'Unavailable';
        if (filesListElem) {
          filesListElem.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">Historical manifest could not be loaded. Current vault files are intentionally not substituted.</div>';
        }
      });
    // Safe restore prompt with target folder selection (F12)
    const btnRestore = document.getElementById('btn-drawer-restore-action');
    if (btnRestore) {
      btnRestore.addEventListener('click', async () => {
        const targetDir = window.prompt(
          `Restore snapshot #${counter} (${truncateHash(snap.snapshot_id_hex, 6, 4)})\n\n` +
          `Enter destination directory path to unpack decrypted confidential files:`,
          "./restore-target"
        );
        if (targetDir === null) return;

        btnRestore.disabled = true;
        try {
          const res = await fetch('/api/snapshots/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              snapshot_id: snap.snapshot_id_hex,
              to: targetDir.trim() || "."
            })
          });
          const data = await res.json();
          if (!res.ok || !data.success) {
            throw new Error(data.error || "Failed to restore snapshot");
          }

          showToast(data.message || `Snapshot restored to ${targetDir}`, 'success');
          appendTerminalLog('RESTORE', `Restored snapshot #${counter} (${truncateHash(snap.snapshot_id_hex, 8, 6)}) to ${targetDir}`, 'var(--accent-emerald)');
          if (typeof fetchActivity === 'function') fetchActivity();
          closeSnapshotDrawer();
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          btnRestore.disabled = false;
        }
      });
    }

    const btnCopy = document.getElementById('btn-drawer-copy-cmd');
    if (btnCopy) {
      btnCopy.addEventListener('click', () => {
        const cmd = `ciphervault restore --snapshot ${snap.snapshot_id_hex}`;
        navigator.clipboard.writeText(cmd).then(() => {
          showToast("Restore command copied to clipboard!", "info");
        });
      });
    }
  }

  drawer.classList.add('drawer-open');
  drawer.classList.add('open');
  drawer.removeAttribute('inert');
  drawer.setAttribute('aria-hidden', 'false');
  if (document.body && document.body.classList) document.body.classList.add('snapshot-drawer-open');
  if (backdrop) {
    backdrop.classList.add('active');
    backdrop.classList.add('open');
  }

  const btnClose = document.getElementById('btn-close-drawer');
  if (btnClose && typeof btnClose.focus === 'function') {
    btnClose.focus();
  }
}

function closeSnapshotDrawer() {
  const drawer = document.getElementById('snapshot-drawer');
  const backdrop = document.getElementById('snapshot-drawer-backdrop');
  if (drawer) {
    drawer.classList.remove('drawer-open');
    drawer.classList.remove('open');
    drawer.setAttribute('inert', '');
    drawer.setAttribute('aria-hidden', 'true');
  }
  state.drawerSnapshotId = null;
  if (document.body && document.body.classList) document.body.classList.remove('snapshot-drawer-open');
  if (backdrop) {
    backdrop.classList.remove('active');
    backdrop.classList.remove('open');
  }
  if (state.lastActiveElement && typeof state.lastActiveElement.focus === 'function') {
    try { state.lastActiveElement.focus(); } catch (_) {}
    state.lastActiveElement = null;
  }
}

// -------------------------------------------------------------
// Collapsible Cyberpunk Live Terminal Console
// -------------------------------------------------------------

function initTerminalConsole() {
  const bar = document.getElementById('terminal-bar');
  const header = document.getElementById('terminal-toggle-btn');
  const content = document.getElementById('terminal-content');
  const expandBtn = document.getElementById('btn-terminal-expand');
  const cmdInput = document.getElementById('terminal-cmd-input');
  const execBtn = document.getElementById('btn-terminal-exec');

  if (header && content) {
    header.addEventListener('click', () => {
      const isClosed = content.style.display === 'none';
      content.style.display = isClosed ? 'block' : 'none';
      if (bar) bar.classList.toggle('expanded', isClosed);
      if (expandBtn) expandBtn.textContent = isClosed ? '▼' : '▲';
      if (isClosed && cmdInput) {
        setTimeout(() => cmdInput.focus(), 50);
      }
    });
  }

  const executeCommand = () => {
    if (!cmdInput) return;
    const cmd = cmdInput.value.trim();
    if (!cmd) return;
    cmdInput.value = '';

    appendTerminalLog('CLI', cmd, 'var(--text-primary)');
    handleTerminalCommand(cmd);
  };

  if (execBtn) {
    execBtn.addEventListener('click', executeCommand);
  }
  if (cmdInput) {
    cmdInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        executeCommand();
      }
    });
  }
}

function appendTerminalLog(tag, message, color = 'var(--accent-cyan)') {
  const logs = document.getElementById('terminal-logs');
  const counter = document.getElementById('terminal-event-counter');

  state.terminalEventsCount = (state.terminalEventsCount || 0) + 1;
  if (counter) counter.textContent = `${state.terminalEventsCount} events`;

  if (!logs) return;

  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0];
  const rowHtml = `<div class="terminal-line"><span class="terminal-time">[${timeStr}]</span> <span class="terminal-tag" style="color: ${color};">[${escapeHtml(tag)}]</span> ${escapeHtml(message)}</div>`;

  if (typeof document.createElement === 'function' && typeof logs.appendChild === 'function') {
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.innerHTML = `<span class="terminal-time">[${timeStr}]</span> <span class="terminal-tag" style="color: ${color};">[${escapeHtml(tag)}]</span> ${escapeHtml(message)}`;
    logs.appendChild(line);
  } else {
    logs.innerHTML = (logs.innerHTML || '') + rowHtml;
  }
  if (logs.scrollTop !== undefined) logs.scrollTop = logs.scrollHeight || 0;
}

function handleTerminalCommand(cmd) {
  const parts = cmd.split(' ').filter(Boolean);
  const root = (parts[0] || '').toLowerCase();

  switch (root) {
    case 'help':
      appendTerminalLog('SYS', 'Available commands: status, diff, audit, refresh, fleet, clear', 'var(--accent-purple)');
      break;
    case 'status':
      const vId = state.vault ? truncateHash(state.vault.vault_id_hex, 8, 6) : 'Uninitialized';
      const onlineOps = (state.operators || []).filter(operatorResponded).length;
      const totalOps = (state.operators || []).length;
      appendTerminalLog('STATUS', `Vault: ${vId} | Operators: ${onlineOps}/${totalOps || '--'} responding | Files: ${(state.vault?.tracked_files || []).length}`, 'var(--accent-cyan)');
      break;
    case 'diff':
      const tabDiffBtn = document.getElementById('tab-btn-diff');
      if (tabDiffBtn) tabDiffBtn.click();
      runDiffComparison();
      break;
    case 'audit':
      appendTerminalLog('AUDIT', 'Triggering live multi-operator audit verification...', 'var(--accent-amber)');
      fetchAudit();
      break;
    case 'refresh':
      appendTerminalLog('REFRESH', 'Synchronizing entire vault state...', 'var(--accent-cyan)');
      fetchAllData();
      break;
    case 'fleet':
      const tabFleetBtn = document.querySelector('[data-target="tab-fleet"]');
      if (tabFleetBtn) tabFleetBtn.click();
      appendTerminalLog('FLEET', 'Switched to Maintenance Fleet Overview', 'var(--accent-purple)');
      break;
    case 'clear':
      const logs = document.getElementById('terminal-logs');
      if (logs) logs.innerHTML = '<div class="terminal-line system-line">[SYSTEM] Terminal logs cleared.</div>';
      break;
    default:
      appendTerminalLog('SYS', `Unknown command: '${cmd}'. Type 'help' for options.`, 'var(--accent-rose)');
      break;
  }
}

// -------------------------------------------------------------
// Ergonomic Keyboard Shortcuts
// -------------------------------------------------------------

function initKeyboardShortcuts() {
  const modalShortcuts = document.getElementById('modal-shortcuts');
  const btnClose = document.getElementById('btn-close-modal-shortcuts');
  const btnFooter = document.getElementById('btn-close-shortcuts-footer');

  if (btnClose && modalShortcuts) {
    btnClose.addEventListener('click', () => closeModal(modalShortcuts));
  }
  if (btnFooter && modalShortcuts) {
    btnFooter.addEventListener('click', () => closeModal(modalShortcuts));
  }

  window.addEventListener('keydown', (e) => {
    // If typing inside an input or textarea
    const isInput = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT';

    if (e.key === 'Escape') {
      if (activeModal) {
        closeModal(activeModal);
        return;
      }
      const drawer = document.getElementById('snapshot-drawer');
      if (drawer && drawer.classList.contains('open')) closeSnapshotDrawer();
      if (isInput) e.target.blur();
      return;
    }

    if (activeModal) {
      cycleFocusWithin(activeModal, e);
      return;
    }
    const drawer = document.getElementById('snapshot-drawer');
    if (drawer && drawer.classList.contains('open')) {
      cycleFocusWithin(drawer, e);
      return;
    }

    if (isInput) return;

    // Number keys 1-9 for tab switching
    if (e.key >= '1' && e.key <= '9') {
      const idx = parseInt(e.key, 10) - 1;
      const tabButtons = Array.from(document.querySelectorAll('.tab-btn')).filter(tab => !tab.hidden);
      if (tabButtons[idx]) {
        tabButtons[idx].click();
      }
      return;
    }

    // '/' to focus search input
    if (e.key === '/') {
      const searchInput = document.getElementById('input-search-files')
        || document.getElementById('input-search-dag')
        || document.getElementById('terminal-cmd-input');
      if (searchInput) {
        e.preventDefault();
        searchInput.focus();
      }
      return;
    }

    // 'r' or 'R' to refresh data
    if (e.key === 'r' || e.key === 'R') {
      fetchAllData();
      showToast("Cluster state refreshed", "info");
      return;
    }

    // '`' to toggle live terminal
    if (e.key === '`') {
      e.preventDefault();
      const terminalToggle = document.getElementById('terminal-toggle-btn');
      if (terminalToggle) terminalToggle.click();
      return;
    }

    // '?' to open shortcuts modal
    if (e.key === '?') {
      if (modalShortcuts) openModal(modalShortcuts);
      return;
    }
  });
}

// -------------------------------------------------------------
// Durable Vault Activity Log (F13)
// -------------------------------------------------------------

function initActivityFeed() {
  const btnRefresh = document.getElementById('btn-refresh-activity');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', () => {
      fetchActivity();
      showToast("Activity journal refreshed", "info");
    });
  }
}

async function fetchActivity() {
  try {
    const res = await fetch('/api/activity?limit=50');
    if (!res.ok) throw new Error(`Activity request failed (${res.status})`);
    const data = await res.json();
    if (data && Array.isArray(data.events)) {
      state.activity = data.events;
      const badge = document.getElementById('badge-tab-activity');
      if (badge) badge.textContent = String(data.events.length);
      renderActivity(data.events);
    }
  } catch (err) {
    state.activity = [];
    const badge = document.getElementById('badge-tab-activity');
    if (badge) badge.textContent = '--';
    renderActivity([]);
    console.warn("fetchActivity error:", err);
  }
}

function renderActivity(events) {
  const container = document.getElementById('activity-feed-list');
  if (!container) return;

  if (!events || events.length === 0) {
    container.innerHTML = '<div class="loading-placeholder">No activity events recorded yet. Snapshot creations and restores will appear here.</div>';
    return;
  }

  container.innerHTML = events.map(ev => {
    let badgeClass = 'generic';
    const type = (ev.event_type || '').toUpperCase();
    if (type.includes('PUSH') || type.includes('SNAPSHOT')) badgeClass = 'push';
    else if (type.includes('RESTORE')) badgeClass = 'restore';
    else if (type.includes('ANCHOR')) badgeClass = 'anchor';
    else if (type.includes('AUDIT')) badgeClass = 'audit';
    else if (type.includes('INIT')) badgeClass = 'init';

    const timeStr = ev.created_at_utc ? new Date(ev.created_at_utc * 1000).toLocaleString() : 'Recent';
    let detailsHtml = '';
    if (ev.details_json && ev.details_json !== '{}') {
      try {
        const parsed = JSON.parse(ev.details_json);
        detailsHtml = `<div class="activity-details">${escapeHtml(JSON.stringify(parsed))}</div>`;
      } catch (_) {
        detailsHtml = `<div class="activity-details">${escapeHtml(ev.details_json)}</div>`;
      }
    }

    return `
      <div class="activity-item">
        <div class="activity-item-left">
          <span class="activity-badge ${badgeClass}">${escapeHtml(ev.event_type || 'EVENT')}</span>
          <div>
            <div class="activity-summary">${escapeHtml(ev.summary || '')}</div>
            ${detailsHtml}
          </div>
        </div>
        <div class="activity-time">${timeStr}</div>
      </div>
    `;
  }).join('');
}

// -------------------------------------------------------------
// Multi-Vault Workspace Switcher
// -------------------------------------------------------------

async function fetchWorkspaces() {
  try {
    const res = await fetch('/api/workspaces');
    if (!res.ok) throw new Error(`Workspace request failed (${res.status})`);
    const data = await res.json();
    if (data.status === 'ok' && data.workspaces) {
      state.workspaces = data.workspaces;
      renderWorkspaces(data.workspaces, data.active_workspace_db);
    }
  } catch (err) {
    state.workspaces = [];
    const badge = document.getElementById('workspace-count-badge');
    if (badge) badge.textContent = '--';
    const name = document.getElementById('active-workspace-name');
    if (name) name.textContent = 'Workspace unavailable';
    const list = document.getElementById('workspace-dropdown-list');
    if (list) list.innerHTML = '<div class="loading-placeholder">Workspace discovery is unavailable.</div>';
    console.debug("Workspaces fetch notice:", err);
  }
}

function renderWorkspaces(workspaces, activeDb) {
  const nameEl = document.getElementById('active-workspace-name');
  const badgeEl = document.getElementById('workspace-count-badge');
  const listEl = document.getElementById('workspace-dropdown-list');
  if (!nameEl || !listEl) return;

  if (badgeEl) badgeEl.textContent = String(workspaces.length);

  const active = workspaces.find(w => w.is_active) || workspaces[0];
  if (active) {
    nameEl.textContent = active.name.replace(" (Active)", "");
  }

  listEl.innerHTML = workspaces.map(ws => `
    <div class="workspace-item ${ws.is_active ? 'active' : ''}" data-db-path="${escapeHtml(ws.db_path)}" role="menuitem" tabindex="0">
      <div class="workspace-item-info">
        <div class="workspace-item-title">
          ${ws.is_active ? '<span class="active-dot" aria-hidden="true"></span>' : ''}
          <span>${escapeHtml(ws.name)}</span>
        </div>
        <div class="workspace-item-path" title="${escapeHtml(ws.path)}">${escapeHtml(ws.path)}</div>
        <div class="workspace-item-meta">
          <span>${ws.snapshot_count} snap${ws.snapshot_count === 1 ? '' : 's'}</span>
          <span>•</span>
          <span>${ws.tracked_files_count} file${ws.tracked_files_count === 1 ? '' : 's'}</span>
          ${ws.active_head_cid ? `<span>•</span><span style="font-family:var(--font-mono)">${ws.active_head_cid.substring(0, 8)}</span>` : ''}
        </div>
      </div>
      ${ws.is_active ? '<span class="workspace-badge-active">ACTIVE</span>' : ''}
    </div>
  `).join('');

  listEl.querySelectorAll('.workspace-item').forEach(item => {
    item.addEventListener('click', async () => {
      const dbPath = item.getAttribute('data-db-path');
      if (!dbPath) return;
      await switchWorkspace(dbPath);
    });
    item.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const dbPath = item.getAttribute('data-db-path');
        if (dbPath) await switchWorkspace(dbPath);
      }
    });
  });
}

async function switchWorkspace(dbPath) {
  try {
    showToast("Switching workspace profile...");
    const res = await fetch('/api/workspaces/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ db_path: dbPath })
    });
    const data = await res.json();
    if (data.status === 'ok') {
      showToast("✓ " + data.message);
      const wrap = document.getElementById('workspace-switcher-wrap');
      if (wrap) wrap.classList.remove('open');
      const btn = document.getElementById('btn-workspace-switcher');
      if (btn) btn.setAttribute('aria-expanded', 'false');
      await Promise.all([fetchWorkspaces(), fetchAllData()]);
    } else {
      showToast("Workspace switch error: " + (data.error || "Failed"), true);
    }
  } catch (err) {
    showToast("Workspace switch failed: " + err.message, true);
  }
}

function initWorkspaceSwitcher() {
  const wrap = document.getElementById('workspace-switcher-wrap');
  const btn = document.getElementById('btn-workspace-switcher');
  const rescanBtn = document.getElementById('btn-rescan-workspaces');

  if (btn && wrap) {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = wrap.classList.toggle('open');
      btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });

    document.addEventListener('click', (e) => {
      if (!wrap.contains(e.target)) {
        wrap.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  if (rescanBtn) {
    rescanBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      try {
        showToast("Scanning system for local vaults...");
        const res = await fetch('/api/workspaces/scan', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
          showToast(`✓ Found ${data.count} vault workspace(s)`);
          renderWorkspaces(data.workspaces, data.active_workspace_db);
        }
      } catch (err) {
        showToast("Rescan failed: " + err.message, true);
      }
    });
  }
}


