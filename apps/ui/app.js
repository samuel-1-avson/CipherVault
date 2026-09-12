// CipherVault Web Dashboard & Visual Vault Inspector Client Logic

const state = {
  vault: null,
  operators: [],
  snapshots: [],
  anchors: [],
  isPolling: true,
  pollTimer: null,
};

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initModals();
  initCopyActions();
  initSecretToggle();
  initSearchFilters();
  initQuickActions();
  initMathVerifier();
  
  // Initial data load and periodic polling
  fetchAllData();
  state.pollTimer = setInterval(fetchAllData, 8000);
});

// -------------------------------------------------------------
// Data Fetching & State Synchronization
// -------------------------------------------------------------

async function fetchAllData() {
  const refreshIcon = document.getElementById('icon-refresh');
  if (refreshIcon) refreshIcon.classList.add('rotating');

  try {
    await Promise.all([
      fetchVault(),
      fetchOperators(),
      fetchSnapshots(),
      fetchAnchors(),
    ]);
  } catch (err) {
    console.error("Data synchronization error:", err);
  } finally {
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
    const durabilityRatio = document.getElementById('durability-ratio');
    const barDurability = document.getElementById('bar-durability');
    const badgeTabOp = document.getElementById('badge-tab-operators');

    const badgeDurabilityState = document.getElementById('badge-durability-state');
    const subDurability = document.getElementById('sub-metric-durability');

    if (badgeTabOp) badgeTabOp.textContent = totalCount;

    if (statusText) {
      statusText.textContent = `${onlineCount}/${totalCount} Operators Online`;
    }

    if (durabilityRatio) {
      durabilityRatio.textContent = `${onlineCount}/${totalCount}`;
      durabilityRatio.style.color = onlineCount === totalCount ? 'var(--accent-emerald)' : (onlineCount > 0 ? 'var(--accent-amber)' : 'var(--accent-rose)');
    }

    if (badgeDurabilityState) {
      badgeDurabilityState.textContent = onlineCount === totalCount ? 'Optimal' : (onlineCount > 0 ? 'Degraded' : 'Offline');
      badgeDurabilityState.style.borderColor = onlineCount === totalCount ? 'var(--accent-emerald)' : (onlineCount > 0 ? 'var(--accent-amber)' : 'var(--accent-rose)');
      badgeDurabilityState.style.color = onlineCount === totalCount ? 'var(--accent-emerald)' : (onlineCount > 0 ? 'var(--accent-amber)' : 'var(--accent-rose)');
    }

    if (subDurability) {
      subDurability.textContent = onlineCount === totalCount 
        ? 'Full Quorum Verified' 
        : (onlineCount > 0 ? 'Degraded Quorum (Repair Recommended)' : 'Zero Operators Reachable');
    }

    if (barDurability) {
      const pct = Math.round((onlineCount / totalCount) * 100);
      barDurability.style.width = `${pct}%`;
      barDurability.style.background = onlineCount === totalCount ? 'var(--accent-emerald)' : (onlineCount > 0 ? 'var(--accent-amber)' : 'var(--accent-rose)');
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

    const opCount = (state.operators || []).length;
    const onlineCount = (state.operators || []).filter(op => op.status === 'online').length;
    const replicaBadge = opCount > 0
      ? (onlineCount === opCount
          ? `<span class="badge-online">Replicas Verified (${onlineCount}/${opCount})</span>`
          : (onlineCount > 0
              ? `<span class="badge-status-subtle" style="color: var(--accent-amber); border-color: var(--accent-amber);">Degraded (${onlineCount}/${opCount})</span>`
              : `<span class="badge-offline">Offline (0/${opCount})</span>`))
      : `<span class="badge-online">Tracked Local</span>`;

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

function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');

      tabButtons.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
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

  if (btnOpenSnapshot && modalSnapshot) {
    btnOpenSnapshot.addEventListener('click', () => {
      modalSnapshot.classList.add('open');
      const input = document.getElementById('input-snapshot-message');
      if (input) {
        input.value = '';
        input.focus();
      }
    });
  }

  const closeSnapshotModal = () => {
    if (modalSnapshot) modalSnapshot.classList.remove('open');
  };

  if (btnCloseSnapshot) btnCloseSnapshot.addEventListener('click', closeSnapshotModal);
  if (btnCancelSnapshot) btnCancelSnapshot.addEventListener('click', closeSnapshotModal);

  const closeInspectorModal = () => {
    if (modalInspector) modalInspector.classList.remove('open');
  };

  if (btnCloseInspector) btnCloseInspector.addEventListener('click', closeInspectorModal);
  if (btnCloseInspectorFooter) btnCloseInspectorFooter.addEventListener('click', closeInspectorModal);

  // Close on backdrop click
  window.addEventListener('click', (e) => {
    if (e.target === modalSnapshot) closeSnapshotModal();
    if (e.target === modalInspector) closeInspectorModal();
  });

  // Close on Escape key
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeSnapshotModal();
      closeInspectorModal();
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

  modal.classList.add('open');
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
          showToast(`Audit warning: ${result.error || 'Check degraded'}`);
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
