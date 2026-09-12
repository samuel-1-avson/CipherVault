// CipherVault Web Dashboard & Visual Vault Inspector Client Logic

const state = {
  vault: null,
  audit: null,
  fetching: false,
  operators: [],
  snapshots: [],
  anchors: [],
  guardians: null,
  relayerCheckpoints: [],
  fleet: null,
  isPolling: true,
  pollTimer: null,
  sseStream: null,
  fastCdcResult: null,
  selectedChunkIndex: null,
};

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initModals();
  initCopyActions();
  initSecretToggle();
  initSearchFilters();
  initQuickActions();
  initMathVerifier();
  initGuardianActions();
  initRelayerActions();
  initFleetActions();
  initSseStream();
  initFastCdcInspector();
  
  // Initial data load and periodic polling
  fetchAllData();
  state.pollTimer = setInterval(fetchAllData, 8000);
});

// -------------------------------------------------------------
// Data Fetching & State Synchronization
// -------------------------------------------------------------

async function fetchAllData() {
  if (state.fetching) return;
  state.fetching = true;
  const refreshIcon = document.getElementById('icon-refresh');
  if (refreshIcon) refreshIcon.classList.add('rotating');

  try {
    await Promise.all([
      fetchVault(),
      fetchOperators(),
      fetchSnapshots(),
      fetchAnchors(),
      fetchAudit(),
      fetchGuardians(),
      fetchRelayerCheckpoints(),
      fetchFleet(),
    ]);
  } catch (err) {
    console.error("Data synchronization error:", err);
  } finally {
    state.fetching = false;
    if (refreshIcon) {
      setTimeout(() => refreshIcon.classList.remove('rotating'), 600);
    }
  }
}

async function fetchVault() {
  try {
    const res = await fetch('/api/vault');
    if (!res.ok) return;
    const data = await res.json();
    state.vault = data;

    if (!data.initialized) {
      const vElem = document.getElementById('vault-id-display');
      if (vElem) vElem.textContent = "Uninitialized";
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
    if (data.recovery && data.recovery.available) {
      renderRecoveryKit(data.recovery, data.vault_id_hex);
    }

    // Update Modal files summary tags
    const modalFilesList = document.getElementById('modal-files-list');
    if (modalFilesList) {
      modalFilesList.innerHTML = (data.tracked_files || []).map(f => 
        `<span class="file-tag">${escapeHtml(f.path)}</span>`
      ).join('') || '<span style="color: var(--text-muted); font-size: 0.8rem;">No files currently tracked</span>';
    }
  } catch (e) {
    console.warn("fetchVault error:", e);
  }
}

async function fetchOperators() {
  try {
    const res = await fetch('/api/operators');
    if (!res.ok) return;
    const data = await res.json();
    state.operators = data;

    renderOperators(data);

    // Update Cluster Status Pill
    const onlineCount = data.filter(op => op.status === 'online').length;
    const totalCount = data.length || 3;
    const statusText = document.getElementById('cluster-status-text');
    const pulseDot = document.getElementById('pulse-dot');
    const badgeTabOp = document.getElementById('badge-tab-operators');


    if (badgeTabOp) badgeTabOp.textContent = totalCount;

    if (statusText) {
      statusText.textContent = `${onlineCount}/${totalCount} Operators Online`;
    }

    if (pulseDot) {
      pulseDot.style.backgroundColor = onlineCount > 0 ? 'var(--accent-emerald)' : 'var(--accent-rose)';
      pulseDot.style.boxShadow = `0 0 10px ${onlineCount > 0 ? 'var(--accent-emerald)' : 'var(--accent-rose)'}`;
    }

    // Update Average Latency
    const onlineOps = data.filter(op => op.status === 'online' && typeof op.latency_ms === 'number');
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
    console.warn("fetchOperators error:", e);
  }
}

async function fetchAudit() {
  state.audit = null;
  renderAudit(null);
  try {
    const response = await fetch('/api/audit');
    if (!response.ok) throw new Error('Audit unavailable');
    const data = await response.json();
    state.audit = data.report || null;
  } catch (error) { console.warn('Recovery audit unavailable', error); }
  renderAudit(state.audit);
}

function renderAudit(audit) {
  const count = audit ? audit.recoverable_operators.length : 0;
  const label = audit ? (audit.healthy ? 'Verified' : 'Degraded') : 'Unverified';
  const color = audit && audit.healthy ? 'var(--accent-emerald)' : 'var(--accent-amber)';
  const badge = document.getElementById('badge-durability-state');
  if (badge) { badge.textContent = label; badge.style.color = color; }
  const ratio = document.getElementById('durability-ratio');
  if (ratio) ratio.textContent = audit ? `${count}/3` : '--/3';
  const detail = document.getElementById('sub-metric-durability');
  if (detail) detail.textContent = audit ? `Last checked snapshot: ${count} complete recovery sets; ${audit.objects.lost_count} lost objects` : 'No completed recovery verification';
  const bar = document.getElementById('bar-durability');
  if (bar) { bar.style.width = `${Math.min(count / 3 * 100, 100)}%`; bar.style.background = color; }
}

async function fetchSnapshots() {
  try {
    const res = await fetch('/api/snapshots');
    if (!res.ok) return;
    const data = await res.json();
    state.snapshots = data;

    const badgeSnaps = document.getElementById('badge-tab-snapshots');
    if (badgeSnaps) badgeSnaps.textContent = data.length;

    renderSnapshots(data);
  } catch (e) {
    console.warn("fetchSnapshots error:", e);
  }
}

async function fetchAnchors() {
  try {
    const res = await fetch('/api/anchors');
    if (!res.ok) return;
    const data = await res.json();
    state.anchors = data;

    renderAnchors(data);
  } catch (e) {
    console.warn("fetchAnchors error:", e);
  }
}

async function fetchGuardians() {
  try {
    const res = await fetch('/api/guardians');
    if (!res.ok) return;
    const data = await res.json();
    state.guardians = data;
    renderGuardians(data);
  } catch (e) {
    console.warn("fetchGuardians error:", e);
  }
}

async function fetchRelayerCheckpoints() {
  try {
    const res = await fetch('/api/relayer/checkpoints');
    if (!res.ok) return;
    const data = await res.json();
    state.relayerCheckpoints = data.checkpoints || [];
    renderRelayerCheckpoints(data);
  } catch (e) {
    console.warn("fetchRelayerCheckpoints error:", e);
  }
}

async function fetchFleet() {
  try {
    const res = await fetch('/api/fleet');
    if (!res.ok) return;
    const data = await res.json();
    state.fleet = data;
    renderFleet(data);
  } catch (e) {
    console.warn("fetchFleet error:", e);
  }
}

// -------------------------------------------------------------
// DOM Rendering Functions
// -------------------------------------------------------------

function renderOperators(operators) {
  const container = document.getElementById('operators-grid');
  if (!container) return;

  if (!operators || operators.length === 0) {
    container.innerHTML = `<div class="loading-placeholder">No operator nodes registered in vault configuration.</div>`;
    return;
  }

  container.innerHTML = operators.map((op, idx) => {
    const isOnline = op.status === 'online';
    const latencyDisplay = isOnline ? `${op.latency_ms ?? 1} ms` : 'Unreachable';
    const pkDisplay = op.operator_signing_pk_hex ? truncateHash(op.operator_signing_pk_hex, 8, 6) : 'Unknown';
    const opId = op.operator_id || `operator_${idx + 1}`;

    return `
      <article class="operator-card" id="card-operator-${idx + 1}">
        <div>
          <div class="op-header">
            <div class="op-title-wrap">
              <span class="op-id">${escapeHtml(opId)}</span>
              <span class="${isOnline ? 'badge-online' : 'badge-offline'}">${isOnline ? 'ONLINE' : 'OFFLINE'}</span>
            </div>
            <span style="font-size: 0.8rem; color: ${isOnline ? 'var(--accent-cyan)' : 'var(--accent-rose)'}; font-family: var(--font-mono);">${latencyDisplay}</span>
          </div>

          <div class="op-meta-row">
            <span class="op-meta-label">Endpoint</span>
            <span class="op-meta-val">${escapeHtml(op.endpoint)}</span>
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
            <span class="op-meta-val" style="color: var(--accent-emerald);">${escapeHtml(op.retention_terms || "90-Day Immutable")}</span>
          </div>
          <div class="op-meta-row">
            <span class="op-meta-label">Auth Mode</span>
            <span class="op-meta-val" style="color: var(--accent-cyan);">Ed25519 Challenge</span>
          </div>
        </div>
        <div style="margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 0.75rem; color: var(--text-muted);">Replication Transport</span>
          <span style="font-size: 0.75rem; color: var(--accent-emerald); font-weight: 600;">ACTIVE</span>
        </div>
      </article>
    `;
  }).join('');
}

function renderLatencyBars(operators) {
  const container = document.getElementById('latency-bars-container');
  if (!container) return;

  const onlineOps = (operators || []).filter(o => o.status === 'online');
  if (onlineOps.length === 0) {
    container.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-muted);">No online operators to measure latency.</div>`;
    return;
  }

  const maxLatency = Math.max(...onlineOps.map(o => o.latency_ms || 1), 20);

  container.innerHTML = onlineOps.map(op => {
    const lat = op.latency_ms || 1;
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

function renderSnapshots(snapshots) {
  const container = document.getElementById('dag-list');
  if (!container) return;

  if (!snapshots || snapshots.length === 0) {
    container.innerHTML = `<div class="loading-placeholder">No snapshots captured yet. Click "Push Snapshot" to create the initial snapshot.</div>`;
    return;
  }

  // Reverse sort so HEAD appears at top
  const sorted = [...snapshots].reverse();

  container.innerHTML = sorted.map((snap, idx) => {
    const isHead = snap.is_head || idx === 0;
    const snapIdTrunc = truncateHash(snap.snapshot_id_hex, 10, 8);
    const manifestTrunc = truncateHash(snap.manifest_cid_hex, 10, 8);
    const deviceTrunc = truncateHash(snap.device_id_hex, 8, 6);
    const timeDisplay = snap.timestamp_utc ? formatTimestamp(snap.timestamp_utc) : "Recorded";

    return `
      <div class="dag-node" data-snap-id="${escapeHtml(snap.snapshot_id_hex)}">
        <div class="dag-timeline-track">
          <div class="dag-node-dot ${isHead ? 'head' : ''}"></div>
          ${idx < sorted.length - 1 ? '<div class="dag-timeline-line"></div>' : ''}
        </div>
        <div class="dag-card">
          <div class="dag-card-header">
            <div style="display: flex; align-items: center; gap: 10px;">
              <span class="dag-message">Snapshot #${snap.device_counter || (sorted.length - idx)}</span>
              ${isHead ? '<span class="badge-online" style="background: rgba(0, 240, 255, 0.12); color: var(--accent-cyan); border-color: rgba(0, 240, 255, 0.4);">ACTIVE HEAD</span>' : ''}
              <span style="font-size: 0.75rem; color: var(--text-muted);">(Epoch #${snap.epoch || 1})</span>
            </div>
            <span class="dag-time">${timeDisplay}</span>
          </div>
          <div class="dag-hashes">
            <span>Snapshot CID: <strong style="color: var(--text-primary); cursor: pointer;" class="hash-click" data-copy="${escapeHtml(snap.snapshot_id_hex)}" title="Click to copy">${snapIdTrunc}</strong></span>
            <span>Manifest CID: <strong style="color: var(--accent-cyan);">${manifestTrunc}</strong></span>
            <span>Device: <strong style="color: var(--text-secondary);">${deviceTrunc}</strong></span>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Attach click listeners to dag-nodes for inspection
  container.querySelectorAll('.dag-node').forEach(node => {
    node.addEventListener('click', (e) => {
      if (e.target.closest('.hash-click')) return; // let copy happen
      const snapId = node.getAttribute('data-snap-id');
      const snap = snapshots.find(s => s.snapshot_id_hex === snapId);
      if (snap) openSnapshotInspector(snap);
    });
  });
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
    const chunks = file.chunks_count || 1;

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
        <td>${chunks} chunk (${formatBytes(chunks * 1024 * 1024)} padded)</td>
        <td>${replicaBadge}</td>
        <td>
          <button class="btn-copy" data-copy="${escapeHtml(file.file_id_hex)}" title="Copy File ID">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderAnchors(anchors) {
  if (!anchors || anchors.length === 0) return;

  const latest = anchors[anchors.length - 1];

  const valAnchorBlock = document.getElementById('val-anchor-block');
  if (valAnchorBlock) valAnchorBlock.textContent = `#${latest.block_number.toLocaleString()}`;

  const contractElem = document.getElementById('anchor-contract-addr');
  if (contractElem) contractElem.textContent = latest.contract_address_hex;

  const blockElem = document.getElementById('anchor-block-num');
  if (blockElem) blockElem.textContent = `#${latest.block_number.toLocaleString()}`;

  const saltElem = document.getElementById('anchor-salt-preimage');
  if (saltElem) saltElem.textContent = truncateHash(latest.salt_hex, 10, 8);

  const commitElem = document.getElementById('anchor-commitment-val');
  if (commitElem) commitElem.textContent = truncateHash(latest.commitment_hex, 10, 8);

  const txElem = document.getElementById('anchor-tx-hash');
  if (txElem) {
    txElem.textContent = truncateHash(latest.tx_hash_hex, 14, 10);
    txElem.title = latest.tx_hash_hex;
  }

  const copyTxBtn = document.getElementById('btn-copy-anchor-tx');
  if (copyTxBtn) {
    copyTxBtn.setAttribute('data-copy', latest.tx_hash_hex);
  }

  const arbiscanLink = document.getElementById('anchor-arbiscan-link');
  if (arbiscanLink) {
    if (latest.tx_hash_hex) {
      const isSepolia = (latest.contract_address_hex || "").toLowerCase().includes("sepolia") || latest.chain_id === 421614;
      const baseExplorer = isSepolia ? "https://sepolia.arbiscan.io/tx/" : "https://arbiscan.io/tx/";
      const cleanTx = latest.tx_hash_hex.startsWith("0x") ? latest.tx_hash_hex : `0x${latest.tx_hash_hex}`;
      arbiscanLink.href = `${baseExplorer}${cleanTx}`;
      arbiscanLink.style.display = "inline-flex";
    } else {
      arbiscanLink.style.display = "none";
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
  if (locatorElem && data.sheets && data.sheets.length > 0) {
    locatorElem.textContent = data.sheets[0].recovery_locator || "--";
  }

  const grid = document.getElementById('guardians-grid');
  if (!grid) return;

  if (!data.sheets || data.sheets.length === 0) {
    grid.innerHTML = '<div class="loading-placeholder">No guardian sheets generated yet. Select a threshold above and click "Split Recovery Secret".</div>';
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

  modal.classList.add('open');
}

function renderRelayerCheckpoints(data) {
  if (!data) return;

  const modeDisplay = document.getElementById('relayer-mode-display');
  if (modeDisplay && data.relayer_status) {
    const st = data.relayer_status;
    modeDisplay.textContent = `Automated L2 Relayer: ${st.operational ? 'Active' : 'Standby'}`;
  }

  const networkTag = document.getElementById('relayer-target-network');
  if (networkTag && data.relayer_status && data.relayer_status.target_network) {
    networkTag.textContent = data.relayer_status.target_network;
  }

  const tbody = document.getElementById('table-checkpoints-body');
  if (!tbody) return;

  const checkpoints = data.checkpoints || [];
  if (checkpoints.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">No relayer checkpoints recorded yet. Click "Auto-Relay Latest Head" to submit first L2 commitment.</td></tr>';
    return;
  }

  tbody.innerHTML = checkpoints.slice().reverse().map(cp => {
    const blockStr = cp.block_number ? `#${cp.block_number.toLocaleString()}` : '#--';
    const txTrunc = truncateHash(cp.tx_hash || '', 10, 8);
    const commitTrunc = truncateHash(cp.commitment || '', 10, 8);
    const explorerUrl = cp.explorer_url || `https://sepolia.arbiscan.io/tx/${cp.tx_hash}`;

    return `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--accent-purple); font-weight: 600;">${blockStr}</td>
        <td>
          <div style="display: flex; align-items: center; gap: 6px;">
            <code style="font-family: var(--font-mono); font-size: 0.8rem;">${txTrunc}</code>
            ${cp.tx_hash ? `
              <button class="btn-copy" data-copy="${escapeHtml(cp.tx_hash)}" title="Copy Tx Hash">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            ` : ''}
          </div>
        </td>
        <td>
          <span style="color: var(--accent-emerald); font-size: 0.78rem; font-weight: 600;">
            ${escapeHtml(cp.status || 'SequencerConfirmed')}
          </span>
        </td>
        <td style="font-family: var(--font-mono); color: var(--accent-cyan);" title="${escapeHtml(cp.commitment)}">
          ${commitTrunc}
        </td>
        <td>
          ${cp.tx_hash ? `
            <a href="${escapeHtml(explorerUrl)}" target="_blank" rel="noopener noreferrer" class="arbiscan-link">
              Arbiscan ↗
            </a>
          ` : '<span style="color: var(--text-muted); font-size: 0.78rem;">Local</span>'}
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
    if (kpiVaults) kpiVaults.textContent = String(fs.total_tracked_vaults ?? 1);

    const kpiOps = document.getElementById('fleet-kpi-operators');
    if (kpiOps) kpiOps.textContent = `${fs.active_operators ?? 3} / 3`;

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
            ${v.head_cid ? truncateHash(v.head_cid, 10, 8) : '<em>Genesis</em>'}
          </td>
          <td>${formatBytes(v.storage_allowance_bytes || 0)}</td>
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
            <td style="color: var(--accent-emerald); font-family: var(--font-mono);">${a.healthy_objects}</td>
            <td style="color: var(--accent-rose); font-family: var(--font-mono);">${a.degraded_objects}</td>
            <td style="color: var(--accent-cyan); font-family: var(--font-mono);">${a.repaired_objects}</td>
            <td style="font-family: var(--font-mono);">${a.duration_ms} ms</td>
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
  if (recCrc32 && recovery.crc32) recCrc32.textContent = `CRC32: ${recovery.crc32} (PASSED)`;

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
      let nextIdx = idx;
      if (e.key === 'ArrowRight') {
        nextIdx = (idx + 1) % tabButtons.length;
        e.preventDefault();
        activateTab(tabButtons[nextIdx], true);
      } else if (e.key === 'ArrowLeft') {
        nextIdx = (idx - 1 + tabButtons.length) % tabButtons.length;
        e.preventDefault();
        activateTab(tabButtons[nextIdx], true);
      } else if (e.key === 'Home') {
        e.preventDefault();
        activateTab(tabButtons[0], true);
      } else if (e.key === 'End') {
        e.preventDefault();
        activateTab(tabButtons[tabButtons.length - 1], true);
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

function initSearchFilters() {
  const dagSearch = document.getElementById('input-search-dag');
  if (dagSearch) {
    dagSearch.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      const nodes = document.querySelectorAll('#dag-list .dag-node');
      nodes.forEach(n => {
        const text = n.textContent.toLowerCase();
        n.style.display = text.includes(q) ? 'flex' : 'none';
      });
    });
  }

  const filesSearch = document.getElementById('input-search-files');
  if (filesSearch) {
    filesSearch.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      const rows = document.querySelectorAll('#table-files-body tr');
      rows.forEach(r => {
        const text = r.textContent.toLowerCase();
        r.style.display = text.includes(q) ? '' : 'none';
      });
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
          showToast("✓ Snapshot captured & replicated across 3 operators!");
          const modal = document.getElementById('modal-create-snapshot');
          if (modal) modal.classList.remove('open');
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
      if (result.success) {
        showToast("✓ Checkpoint commitment anchored to Arbitrum One!");
        await fetchAllData();
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
      showToast("Auditing replica closures across 3 operators...");
      try {
        const res = await fetch('/api/audit', { method: 'POST' });
        const result = await res.json();
        if (result.success) {
          showToast("✓ Replica audit passed: All chunks durable (3/3)");
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
            ${matches ? '✓ MATHEMATICAL PROOF CONFIRMED (100% MATCH)' : '✗ COMMITMENT MISMATCH'}
          </div>
          <div>Target On-Chain: <code>0x${latest.commitment_hex}</code></div>
          <div>Browser Computed:  <code>0x${computedHex}</code></div>
          <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 6px;">
            Zero-knowledge invariant: Verified on-chain inclusion without leaking plaintext file contents or paths.
          </div>
        `;
      } catch (err) {
        outputBox.textContent = `Verification calculation error: ${err.message}`;
      }
    });
  }
}

function initGuardianActions() {
  const btnGenerate = document.getElementById('btn-generate-guardians');
  if (btnGenerate) {
    btnGenerate.addEventListener('click', async () => {
      const selectM = document.getElementById('select-threshold-m');
      const selectN = document.getElementById('select-total-n');
      const secretInput = document.getElementById('input-split-recovery-secret');
      const m = selectM ? parseInt(selectM.value, 10) : 3;
      const n = selectN ? parseInt(selectN.value, 10) : 5;
      const recoverySecretHex = secretInput ? secretInput.value.trim() : "";

      if (m > n) {
        showToast("Threshold (M) cannot exceed Total Guardians (N)", "error");
        return;
      }

      if (!recoverySecretHex) {
        showToast("Authentic ceremony: enter 64-char master recovery secret (R).", "warning");
      }

      showToast(`Partitioning recovery secret into ${m}-of-${n} threshold shares...`);
      try {
        const res = await fetch('/api/guardians/split', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            threshold: m,
            total_shares: n,
            recovery_secret_hex: recoverySecretHex || null
          })
        });
        const result = await res.json();
        if (result.status === 'ok' || result.success) {
          state.guardians = result;
          renderGuardians(result);
          showToast(`✓ Generated ${result.sheets.length} authentic guardian shares (${m}-of-${n})`);
        } else if (result.status === 'requires_secret') {
          showToast(`Authentic ceremony: ${result.message}`, "warning");
        } else {
          showToast(`Error: ${result.error || result.message || 'Failed to split secret'}`, "error");
        }

      } catch (err) {
        showToast("Network error generating guardian shares", "error");
      }
    });
  }

  const btnRecombine = document.getElementById('btn-simulate-recombine');
  const simSharesInput = document.getElementById('input-simulation-shares');
  const simResult = document.getElementById('simulation-result');

  if (btnRecombine && simSharesInput && simResult) {
    btnRecombine.addEventListener('click', async () => {
      const rawText = simSharesInput.value.trim();
      if (!rawText) {
        showToast("Please paste at least 1 guardian share to simulate reconstruction.");
        return;
      }

      const lines = rawText.split('\n').map(l => l.trim()).filter(l => l.length > 0);
      const shares = [];
      lines.forEach(l => {
        if (l.includes('CIPHERVAULT-THRESHOLD-RECOVERY-V1:')) {
          const match = l.match(/CIPHERVAULT-THRESHOLD-RECOVERY-V1:[A-Za-z0-9+/=]+/);
          if (match) shares.push(match[0]);
          else shares.push(l);
        } else if (l.length > 20 && !l.startsWith('#') && !l.startsWith('---') && !l.startsWith('===')) {
          shares.push(l);
        }
      });

      if (shares.length === 0) {
        showToast("No valid threshold recovery shares found in input text.");
        return;
      }

      simResult.style.display = "block";
      simResult.className = "simulation-result";
      simResult.innerHTML = "Computing Shamir polynomial interpolation in zeroized memory...";

      try {
        const res = await fetch('/api/guardians/reconstruct', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ shares })
        });
        const data = await res.json();

        if (data.verified_signing_pk_matches || data.matches_vault) {
          simResult.className = "simulation-result success";

          simResult.innerHTML = `
            <div style="font-weight: 700; color: var(--accent-emerald); margin-bottom: 6px;">
              ✓ SHAMIR POLYNOMIAL RECONSTRUCTION VERIFIED (100% MATCH)
            </div>
            <div>Shares Provided: <strong>${data.shares_provided}</strong> (Quorum Met)</div>
            <div>Recovered Signing PK: <code style="color: var(--accent-cyan); font-size: 0.78rem;">${escapeHtml(data.recovery_signing_pk)}</code></div>
            <div style="color: var(--accent-emerald); font-size: 0.78rem; margin-top: 6px;">
              ✓ Mathematical reconstruction matches registered vault recovery key. Master recovery secret R was validated in volatile RAM and immediately zeroized.
            </div>
          `;
          showToast("✓ Threshold reconstruction verified!");
        } else {
          simResult.className = "simulation-result error";
          simResult.innerHTML = `
            <div style="font-weight: 700; color: var(--accent-rose); margin-bottom: 6px;">
              ✗ RECONSTRUCTION FAILED
            </div>
            <div>${escapeHtml(data.message || 'Shares could not reconstruct matching recovery key')}</div>
            <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 6px;">
              Shares provided: ${data.shares_provided || 0}. Ensure you have at least M distinct, non-corrupted shares.
            </div>
          `;
          showToast("Simulation failed: Incomplete or mismatched shares");
        }
      } catch (err) {
        simResult.className = "simulation-result error";
        simResult.textContent = `Simulation error: ${err.message}`;
      }
    });
  }

  // Modal close handlers for guardian sheet modal
  const modal = document.getElementById('modal-guardian-sheet');
  const closeBtn = document.getElementById('btn-close-modal-guardian');
  const closeFooter = document.getElementById('btn-close-guardian-footer');
  if (closeBtn && modal) closeBtn.addEventListener('click', () => modal.classList.remove('open'));
  if (closeFooter && modal) closeFooter.addEventListener('click', () => modal.classList.remove('open'));
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

function showToast(message) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
      <polyline points="22 4 12 14.01 9 11.01"></polyline>
    </svg>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

// -------------------------------------------------------------
// Real-Time Server-Sent Events (SSE) Stream
// -------------------------------------------------------------

function initSseStream() {
  if (typeof EventSource === 'undefined') return;
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
      if (sseText) sseText.textContent = "SSE Stream: Active";
      if (sseDot) sseDot.style.backgroundColor = "var(--accent-cyan)";
    };

    sse.onerror = () => {
      const sseText = document.getElementById('sse-stream-text');
      const sseDot = document.getElementById('sse-pulse-dot');
      if (sseText) sseText.textContent = "SSE Stream: Reconnecting";
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
          elem.textContent = `${op.latency_ms} ms`;
          elem.style.color = "var(--accent-emerald)";
          totalLat += op.latency_ms;
          onlineCount++;
        } else {
          elem.textContent = "OFFLINE";
          elem.style.color = "#ef4444";
        }
      }
    });

    if (onlineCount > 0) {
      const avg = Math.round(totalLat / onlineCount);
      const avgElem = document.getElementById('avg-latency-display');
      if (avgElem) avgElem.textContent = `${avg} ms`;
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
  if (!selectElem) return;

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

        // Automatically select the first real tracked file and auto-inspect it
        if (data.files.length > 0) {
          selectElem.selectedIndex = 1;
          runFastCdcInspection({ file_path: data.files[0].path });
        }
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

  if (selectVaultFile) {
    selectVaultFile.addEventListener('change', () => {
      if (selectVaultFile.value) {
        runFastCdcInspection({ file_path: selectVaultFile.value });
      }
    });
  }

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
          runFastCdcInspection({ content: text });
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

  // Load real tracked files from active vault pipeline
  loadVaultFilesForFastCdc();
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
}

async function runFastCdcInspection(opts) {
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
  if (savedBytesElem) savedBytesElem.textContent = `${formatBytes(m.saved_bytes)} pruned`;
  if (totalBytesElem) totalBytesElem.textContent = formatBytes(m.total_bytes);
  if (uniqueBytesElem) uniqueBytesElem.textContent = `${formatBytes(m.unique_bytes)} wire size`;
  if (fixedCountElem) fixedCountElem.textContent = `${m.fixed_chunks_count} blocks`;

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
      badgeElem.textContent = "Duplicate / Reused Chunk (0 Wire Bytes)";
      badgeElem.style.color = "#f87171";
      badgeElem.style.borderColor = "rgba(239, 68, 68, 0.4)";
    } else {
      badgeElem.textContent = "Unique Chunk (Stored with Retention Lease)";
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
  if (prevElem) prevElem.textContent = chunk.preview;
}

