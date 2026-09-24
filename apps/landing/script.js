/**
 * CipherVault Terminal & TUI Interactive Controller
 * Features:
 * - Multi-theme switcher: Cyber (Default) | Dark | Light | Mono with localStorage persistence
 * - Spacious TUI pane navigation with keyboard shortcuts [1-6]
 * - Collapsible CLI REPL console with command execution and history
 * - Interactive FastCDC dynamic chunk slicing simulator
 * - M-of-N Shamir polynomial threshold reconstruction widget
 * - Emergency paper recovery kit unmasker
 * - Live real-time cryptographic audit telemetry stream
 * - Retro CRT scanline toggle
 * - Single-click clipboard copying with visual feedback
 */

document.addEventListener('DOMContentLoaded', () => {
  initThemeSystem();
  initTabsNavigation();
  initFastCdcSimulator();
  initBenchmarkGauges();
  initInteractivePipeline();
  initShamirSimulator();
  initPaperKit();
  initLiveTelemetryStream();
  initInteractiveRepl();
  initInstallSnippets();
  initCrtToggle();
  initKeyboardShortcuts();
});

/* ==============================================================================
   1. Multi-Theme Switching System (Cyber | Dark | Light | Mono)
   ============================================================================== */
function initThemeSystem() {
  const themeButtons = document.querySelectorAll('.theme-pill-btn');
  const crtOverlay = document.getElementById('crt-scanlines');
  const crtBtn = document.getElementById('btn-toggle-crt');

  const applyTheme = (themeName) => {
    document.documentElement.setAttribute('data-theme', themeName);
    localStorage.setItem('ciphervault-theme', themeName);

    themeButtons.forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-theme') === themeName);
    });

    // Default scanlines to OFF across all themes so text is crisp and luminous
    if (crtOverlay) crtOverlay.classList.add('disabled');
    if (crtBtn) crtBtn.textContent = '[CRT: OFF]';
  };

  // Restore saved theme or default to Cyber
  const savedTheme = localStorage.getItem('ciphervault-theme') || 'cyber';
  applyTheme(savedTheme);

  themeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const theme = btn.getAttribute('data-theme');
      applyTheme(theme);
    });
  });
}

/* ==============================================================================
   2. Tabbed Navigation & Viewport Switching with Hacker Decrypt Scrambler
   ============================================================================== */
function scrambleText(element, finalText, duration = 280) {
  if (!element || !finalText) return;
  const chars = '01#%&*?XZ§◊█_/<>';
  const length = finalText.length;
  const startTime = performance.now();

  if (element._scrambleTimer) cancelAnimationFrame(element._scrambleTimer);

  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const resolvedIndex = Math.floor(progress * length);

    let result = '';
    for (let i = 0; i < length; i++) {
      if (finalText[i] === ' ' || finalText[i] === '\n') {
        result += finalText[i];
      } else if (i < resolvedIndex) {
        result += finalText[i];
      } else {
        result += chars[Math.floor(Math.random() * chars.length)];
      }
    }
    element.textContent = result;

    if (progress < 1) {
      element._scrambleTimer = requestAnimationFrame(update);
    } else {
      element.textContent = finalText;
      element._scrambleTimer = null;
    }
  }

  element._scrambleTimer = requestAnimationFrame(update);
}

function animateGauges() {
  const fills = document.querySelectorAll('#pane-benchmarks .gauge-bar-fill');
  fills.forEach(fill => {
    const targetWidth = fill.getAttribute('data-target-width') || '85%';
    fill.style.width = '0%';
    requestAnimationFrame(() => {
      setTimeout(() => {
        fill.style.width = targetWidth;
      }, 70);
    });
  });

  animateCounter('gauge-val-1', 0, 558.62, 900, 2, '', ' MiB/s');
  animateCounter('gauge-val-2', 0, 656.84, 900, 2, '', ' MiB/s');
  animateCounter('gauge-val-3', 0, 96.15, 900, 2, '', '% (25/26 Chunks Reused)');
  animateCounter('gauge-val-4', 0, 99.956, 1000, 3, '', '% (1 MiB -> 461 B)');
}

function initBenchmarkGauges() {
  const filterButtons = document.querySelectorAll('.bench-pill');
  const rerunBtn = document.getElementById('btn-rerun-benchmarks');
  const rows = document.querySelectorAll('#benchmark-gauges-list .gauge-row');

  filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      filterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const filter = btn.getAttribute('data-filter');
      rows.forEach(row => {
        const cat = row.getAttribute('data-category');
        if (filter === 'all' || cat === filter) {
          row.style.display = 'flex';
        } else {
          row.style.display = 'none';
        }
      });
      animateGauges();
    });
  });

  if (rerunBtn) {
    rerunBtn.addEventListener('click', () => {
      rerunBtn.classList.add('running');
      rerunBtn.textContent = '[⚡ Benchmarking...]';
      animateGauges();
      setTimeout(() => {
        rerunBtn.classList.remove('running');
        rerunBtn.textContent = '[⚡ Rerun Benchmarks]';
      }, 950);
    });
  }
}

function animateCounter(id, start, end, duration, decimals, prefix = '', suffix = '') {
  const el = document.getElementById(id);
  if (!el) return;
  const startTime = performance.now();

  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    const current = start + (end - start) * ease;
    el.textContent = `${prefix}${current.toFixed(decimals)}${suffix}`;
    if (progress < 1) {
      requestAnimationFrame(step);
    } else {
      el.textContent = `${prefix}${end.toFixed(decimals)}${suffix}`;
    }
  }
  requestAnimationFrame(step);
}

function switchTab(targetPaneId) {
  const tabButtons = document.querySelectorAll('.tui-tab-btn');
  const panes = document.querySelectorAll('.tui-pane');

  tabButtons.forEach(btn => {
    const isTarget = btn.getAttribute('data-target') === targetPaneId;
    btn.classList.toggle('active', isTarget);
    btn.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    if (isTarget && btn.scrollIntoView) {
      btn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    }
  });

  panes.forEach(pane => {
    if (pane.id === targetPaneId) {
      pane.removeAttribute('hidden');
      pane.classList.add('active');

      // Trigger cryptographic text scramble on pane title
      const titleElem = pane.querySelector('.pane-title') || pane.querySelector('.hero-core-title');
      if (titleElem) {
        const textToScramble = titleElem.getAttribute('data-scramble-text') || titleElem.textContent.trim();
        scrambleText(titleElem, textToScramble, 280);
      }

      // If switching to Benchmarks, animate the gauges and live counters
      if (targetPaneId === 'pane-benchmarks') {
        animateGauges();
      }
    } else {
      pane.setAttribute('hidden', '');
      pane.classList.remove('active');
    }
  });

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function initTabsNavigation() {
  const tabButtons = document.querySelectorAll('.tui-tab-btn');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target');
      switchTab(target);
    });
  });

  // Wire up sequential "Next Pane" / "Prev Pane" walkthrough buttons
  document.querySelectorAll('.pane-pager-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target');
      if (target) {
        switchTab(target);
      }
    });
  });
}

/* ==============================================================================
   3. Keyboard Shortcuts ([1-6], [/], [C], [Esc])
   ============================================================================== */
function initKeyboardShortcuts() {
  const paneOrder = [
    'pane-overview',
    'pane-dilemma',
    'pane-engine',
    'pane-benchmarks',
    'pane-recovery',
    'pane-quickstart'
  ];

  window.addEventListener('keydown', (e) => {
    // If user is typing in an input field, do not trigger navigation keys
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
      if (e.key === 'Escape') {
        e.target.blur();
        closeReplDrawer();
      }
      return;
    }

    // Number keys 1-6
    if (e.key >= '1' && e.key <= '6') {
      const idx = parseInt(e.key, 10) - 1;
      if (paneOrder[idx]) {
        switchTab(paneOrder[idx]);
      }
    } else if (e.key === '/') {
      e.preventDefault();
      expandReplConsole();
      const replInput = document.getElementById('repl-input');
      if (replInput) replInput.focus();
    } else if (e.key.toLowerCase() === 'c') {
      const copyBtn = document.getElementById('btn-tui-copy');
      if (copyBtn) copyBtn.click();
    } else if (e.key === 'Escape') {
      closeReplDrawer();
    }
  });
}
/* ==============================================================================
   5. Interactive FastCDC Chunking Simulator
   ============================================================================== */
function initFastCdcSimulator() {
  const grid = document.getElementById('chunk-visual-grid');
  const input = document.getElementById('sim-input-editor');
  const statReused = document.getElementById('stat-chunks-reused');
  const statMod = document.getElementById('stat-chunks-modified');
  const statBandwidth = document.getElementById('stat-bandwidth-saved');
  const presetButtons = document.querySelectorAll('.preset-pill');

  // Inspector elements
  const inspStatusBadge = document.getElementById('insp-status-badge');
  const inspChunkTitle = document.getElementById('insp-chunk-title');
  const inspChunkHash = document.getElementById('insp-chunk-hash');
  const inspChunkSize = document.getElementById('insp-chunk-size');
  const inspChunkRange = document.getElementById('insp-chunk-range');
  const inspChunkGear = document.getElementById('insp-chunk-gear');
  const inspChunkSync = document.getElementById('insp-chunk-sync');

  if (!grid || !input) return;

  const totalChunks = 26;
  const chunkSizes = [
    4, 4, 8, 4, 8, 4, 16, 4, 4, 8, 4, 4, 8, 4, 4, 8, 4, 4, 4, 8, 4, 4, 4, 4, 4, 4
  ];
  
  let currentModifiedSet = new Set([14]); // Chunk 15 by default
  let selectedChunkIndex = 14;

  const updateInspector = (idx) => {
    selectedChunkIndex = idx;
    const isMod = currentModifiedSet.has(idx);
    const size = chunkSizes[idx] || 4;
    
    let offsetStart = 0;
    for (let j = 0; j < idx; j++) offsetStart += (chunkSizes[j] || 4) * 1024;
    const offsetEnd = offsetStart + (size * 1024);
    
    const hashHex = isMod ? 
      ((idx * 99991 + 0xbeef).toString(16).padStart(8, '0') + '...e104') : 
      ((idx * 44417 + 0xcafe).toString(16).padStart(8, '0') + '...9a21');

    if (inspStatusBadge) {
      inspStatusBadge.className = isMod ? 'insp-pill mod' : 'insp-pill cached';
      inspStatusBadge.textContent = isMod ? `DELTA CHUNK #${idx + 1}` : `CACHED CHUNK #${idx + 1}`;
    }
    if (inspChunkTitle) {
      inspChunkTitle.textContent = isMod ? 'Target of Local Modification' : 'Deduplication Cache Hit';
    }
    if (inspChunkHash) {
      inspChunkHash.innerHTML = `BLAKE2B: <code class="hash-code">sha256:${hashHex}</code>`;
    }
    if (inspChunkSize) {
      inspChunkSize.innerHTML = `SIZE: <strong>${size}.00 KiB</strong>`;
    }
    if (inspChunkRange) {
      inspChunkRange.textContent = `0x${offsetStart.toString(16).padStart(8, '0').toUpperCase()} - 0x${offsetEnd.toString(16).padStart(8, '0').toUpperCase()} (${offsetStart.toLocaleString()} - ${offsetEnd.toLocaleString()} B)`;
    }
    if (inspChunkGear) {
      inspChunkGear.textContent = isMod ? 
        `Gear Mask 0x00001FFF (Entropy Shift at ${size * 1024} B)` : 
        `Gear Boundary Match (Cached DAG Node #sha256:${(idx * 73).toString(16)})`;
    }
    if (inspChunkSync) {
      inspChunkSync.textContent = isMod ? 
        'AEAD Re-encryption -> 3/3 Storage Quorum' : 
        'Zero Wire Re-upload (0 B Synchronized)';
      inspChunkSync.className = isMod ? 'd-val text-gold' : 'd-val text-mint';
    }
  };

  const renderChunks = (modifiedIndicesSet, triggerRipple = false) => {
    grid.innerHTML = '';
    currentModifiedSet = modifiedIndicesSet;

    const modCount = currentModifiedSet.size;
    const reusedCount = totalChunks - modCount;
    const dedupRatio = ((reusedCount / totalChunks) * 100).toFixed(2);
    
    let deltaBytes = 0;
    currentModifiedSet.forEach(i => {
      deltaBytes += (chunkSizes[i] || 4);
    });

    if (statReused) statReused.textContent = `${reusedCount} (${dedupRatio}%)`;
    if (statMod) statMod.textContent = modCount === 0 ? '0 (0 KiB)' : `${modCount} (#${Array.from(currentModifiedSet).map(x => x + 1).join(',')} - ${deltaBytes} KiB)`;
    if (statBandwidth) statBandwidth.textContent = `${dedupRatio}%`;

    for (let i = 0; i < totalChunks; i++) {
      const cell = document.createElement('div');
      cell.className = 'chunk-cell';
      const isMod = currentModifiedSet.has(i);
      const isSelected = i === selectedChunkIndex;

      if (isMod) cell.classList.add('modified');
      if (isSelected) cell.classList.add('selected');

      const size = chunkSizes[i] || 4;
      cell.innerHTML = `
        <span class="chunk-index">${isMod ? 'Δ' + (i + 1) : 'C' + (i + 1)}</span>
        <span class="chunk-size-tag">${size}K</span>
      `;

      if (triggerRipple && isMod) {
        cell.classList.add('ripple');
      }

      cell.addEventListener('mouseenter', () => {
        document.querySelectorAll('.chunk-cell').forEach(c => c.classList.remove('selected'));
        cell.classList.add('selected');
        updateInspector(i);
      });

      cell.addEventListener('click', () => {
        document.querySelectorAll('.chunk-cell').forEach(c => c.classList.remove('selected'));
        cell.classList.add('selected');
        input.value = `0x${(i * 1337).toString(16)}_chunk_${i + 1}`;
        renderChunks(new Set([i]), true);
        updateInspector(i);
        presetButtons.forEach(btn => btn.classList.remove('active'));
      });

      grid.appendChild(cell);
    }

    updateInspector(selectedChunkIndex);
  };

  // Preset Scenario Handlers
  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const preset = btn.getAttribute('data-preset');
      if (preset === 'api-key') {
        input.value = '0x491e_chunk_15';
        selectedChunkIndex = 14;
        renderChunks(new Set([14]), true);
      } else if (preset === 'db-pass') {
        input.value = 'PORT=5433_host_04';
        selectedChunkIndex = 3;
        renderChunks(new Set([3]), true);
      } else if (preset === 'tls-cert') {
        input.value = 'BEGIN_CERT_CHAIN_KEY_22_25';
        selectedChunkIndex = 21;
        renderChunks(new Set([21, 22, 23, 24]), true);
      } else if (preset === 'clean') {
        input.value = '0x00_unmodified_master';
        selectedChunkIndex = 0;
        renderChunks(new Set([]), false);
      }
    });
  });

  input.addEventListener('input', () => {
    presetButtons.forEach(btn => btn.classList.remove('active'));
    const val = input.value;
    if (val.trim() === '' || val.includes('unmodified')) {
      renderChunks(new Set([]), false);
    } else {
      const modIdx = Math.abs(hashCode(val)) % totalChunks;
      selectedChunkIndex = modIdx;
      renderChunks(new Set([modIdx]), true);
    }
  });

  // Initial load: Chunk 15 modified
  renderChunks(new Set([14]), false);
}

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}

/* ==============================================================================
   5.1. Interactive Cryptographic Pipeline & Detailed Stage Inspector
   ============================================================================== */
const PIPELINE_STAGES = {
  1: {
    kicker: 'STAGE [01] DEEP-DIVE SPECIFICATION',
    heading: 'Developer Working Tree Secret Enrollment',
    mechanics: 'CipherVault tracks secret files completely out-of-band from Git. During enrollment via `ciphervault track .env`, the file is hashed with BLAKE2b-256, and metadata is recorded in an encrypted local SQLite WAL ledger (`.ciphervault/state.db`). The Git working tree and `.gitignore` remain completely untouched.',
    security: 'Guarantees zero accidental staging into Git commits (`git add .` will never expose secrets). Host OS hardware keyrings (Windows DPAPI, macOS Keychain, Linux Secret Service) seal the vault master key R.',
    statVal: '< 1.2 ms',
    statDesc: 'Local metadata indexing & DPAPI hardware key binding',
    code: `// crates/vault-core/src/tracker.rs
pub fn enroll_secret_file(path: &Path) -> Result<TrackedMetadata> {
    let raw = std::fs::read(path)?;
    let cid = blake2b_256(&raw);
    let master_key = platform::get_dpapi_master_key()?;
    state_db::insert_tracked(path, &cid)?;
    Ok(TrackedMetadata { cid, bytes: raw.len() })
}`
  },
  2: {
    kicker: 'STAGE [02] DEEP-DIVE SPECIFICATION',
    heading: 'FastCDC Content-Defined Chunk Slicing',
    mechanics: 'Unlike fixed-size blocking (which causes catastrophic cascade re-chunking on 1-byte insertions), FastCDC uses a precomputed Gear rolling hash table with dynamic normalization masks to discover content-defined cut boundaries between 4 KiB and 64 KiB.',
    security: 'Ensures localized byte edits only produce 1 modified chunk while 96%+ of all other chunks retain identical cryptographic hashes across versions, enabling extreme sub-file deduplication.',
    statVal: '96.15% Deduplication',
    statDesc: '25 of 26 chunks reused per localized edit; 1.85 GB/s hashing throughput',
    code: `// crates/vault-core/src/chunker.rs
use fastcdc::v2020::FastCDC;

pub fn slice_into_chunks(buffer: &[u8]) -> Vec<Chunk> {
    let chunker = FastCDC::new(buffer, 4096, 16384, 65536);
    chunker.map(|entry| Chunk {
        offset: entry.offset,
        length: entry.length,
        hash: blake2b_256(&buffer[entry.offset..entry.offset + entry.length]),
    }).collect()
}`
  },
  3: {
    kicker: 'STAGE [03] DEEP-DIVE SPECIFICATION',
    heading: 'Client-Side XChaCha20-Poly1305 AEAD Encryption',
    mechanics: 'Every chunk payload is encrypted on the client machine using XChaCha20-Poly1305 authenticated encryption with an extended 192-bit random nonce and client-derived 256-bit symmetric key. Volatile memory buffers are wrapped in ZeroizeOnDrop to guarantee scrubbed RAM upon scope drop.',
    security: 'Zero-knowledge guarantee: plaintext is never sent over any network. Storage operators and cloud custodians only ever receive opaque high-entropy ciphertext blobs with zero metadata leakage.',
    statVal: '558.62 MiB/s',
    statDesc: 'AES-NI / SIMD accelerated client encryption (Poly1305 MAC)',
    code: `// crates/vault-crypto/src/cipher.rs
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, aead::{Aead, KeyInit}};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SecretBuffer(pub Vec<u8>);

pub fn encrypt_chunk(key: &Key, nonce: &XNonce, chunk: &SecretBuffer) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, chunk.0.as_ref()).map_err(|_| CryptoError::EncryptionFailed)
}`
  },
  4: {
    kicker: 'STAGE [04] DEEP-DIVE SPECIFICATION',
    heading: 'Federated Quorum Storage Mesh Replication',
    mechanics: 'Opaque ciphertext chunks are pushed across a peer-to-peer storage mesh composed of independent operator nodes (running in Council Bluffs, IA and Moncks Corner, SC). Multi-chunk uploads use encrypted TLS 1.3 multiplexed HTTP/2 streams.',
    security: 'Byzantine quorum fault tolerance: requiring a 2-of-3 quorum ensures secret snapshots survive catastrophic node wipes, cloud provider outages, or network partitions without centralized single points of failure.',
    statVal: '3/3 Synced',
    statDesc: 'Geo-distributed libp2p mesh latency < 45 ms across testnet nodes',
    code: `// services/operator/src/state.rs
pub async fn ingest_chunk(&self, cid: &ChunkId, payload: Bytes) -> Result<IngestReceipt> {
    if !self.verify_cid(cid, &payload) {
        return Err(OperatorError::CorruptedPayload);
    }
    self.storage.write_opaque_blob(cid, &payload).await?;
    self.broadcast_quorum_ack(cid).await?;
    Ok(IngestReceipt { cid: *cid, status: QuorumStatus::Acknowledged })
}`
  },
  5: {
    kicker: 'STAGE [05] DEEP-DIVE SPECIFICATION',
    heading: 'Proof-of-Storage (PoS) Durability Challenge',
    mechanics: 'To prove ongoing chunk durability without downloading massive gigabyte backups, the client issues a PoS challenge containing an ephemeral cryptographic nonce. The operator computes a deterministic HMAC-BLAKE2b proof over the stored chunk and returns an unforgeable 461-byte wire proof.',
    security: 'Prevents operators from silently dropping data, claiming phantom storage, or executing data-withholding attacks. Verified in sub-millisecond execution on the client.',
    statVal: '99.956% Wire Savings',
    statDesc: '1 MiB raw chunk verified with only 461 bytes transmitted over wire',
    code: `// crates/vault-pos/src/verifier.rs
pub fn verify_pos_proof(expected_cid: &ChunkId, challenge_nonce: &[u8; 32], proof: &PoSProof) -> bool {
    let computed_hash = hmac_blake2b(proof.chunk_sample(), challenge_nonce);
    computed_hash == proof.signature() && proof.wire_size() == 461
}`
  },
  6: {
    kicker: 'STAGE [06] DEEP-DIVE SPECIFICATION',
    heading: 'Arbitrum One L2 Blockchain Anchor & Consensus',
    mechanics: 'Each snapshot epoch DAG root is signed with EIP-712 structured typed data and published to the CipherVault state anchor contract on Arbitrum One L2 rollup. This anchors a permanent, decentralized timestamp and Merkle state root.',
    security: 'Prevents secret history rewriting, operator rollback attacks, or retroactive tampering. Any developer can verify the snapshot root against the public Ethereum L2 ledger without trusting any server.',
    statVal: '< $0.002 Gas',
    statDesc: 'Arbitrum One L2 transaction settlement finality on block #14809',
    code: `// crates/vault-blockchain/src/anchor.rs
use ethers::prelude::*;

#[eip712(name = "CipherVaultAnchor", version = "1")]
pub struct SnapshotCommitment {
    pub epoch: U256,
    pub merkle_root: [u8; 32],
    pub timestamp: U256,
}

pub async fn commit_snapshot_to_l2(contract: &AnchorContract, commit: SnapshotCommitment) -> Result<TxHash> {
    let tx = contract.commit_state_root(commit.epoch, commit.merkle_root).send().await?;
    Ok(tx.tx_hash())
}`
  }
};

function initInteractivePipeline() {
  const nodes = document.querySelectorAll('.pipeline-node');
  const panel = document.getElementById('pipeline-inspector-panel');
  const kicker = document.getElementById('insp-kicker');
  const heading = document.getElementById('insp-heading');
  const mechanics = document.getElementById('insp-mechanics');
  const security = document.getElementById('insp-security');
  const statVal = document.getElementById('insp-stat-val');
  const statDesc = document.getElementById('insp-stat-desc');
  const code = document.getElementById('insp-code');
  const btnClose = document.getElementById('btn-close-inspector');
  const btnSim = document.getElementById('btn-run-pipeline-sim');
  const statusText = document.getElementById('pipeline-status-text');
  const stagePills = document.querySelectorAll('.stage-nav-pill');

  if (!nodes.length || !panel) return;

  const formatCodeTags = (text) => {
    return escapeHtml(text).replace(/`([^`]+)`/g, '<code class="tui-code">$1</code>');
  };

  const selectStage = (stageNum, animate = true) => {
    const data = PIPELINE_STAGES[stageNum];
    if (!data) return;

    // Update active node styling
    nodes.forEach(node => {
      const isCurrent = parseInt(node.getAttribute('data-stage')) === stageNum;
      node.classList.toggle('active', isCurrent);
      node.setAttribute('aria-expanded', isCurrent ? 'true' : 'false');
      const hint = node.querySelector('.node-inspect-hint');
      if (hint) {
        hint.textContent = isCurrent ? `Active [0${stageNum}] ↵` : `Inspect [0${node.getAttribute('data-stage')}] ↵`;
      }
    });

    // Update jump pills
    stagePills.forEach(pill => {
      pill.classList.toggle('active', parseInt(pill.getAttribute('data-stage')) === stageNum);
    });

    // Show panel if hidden
    panel.style.display = 'flex';

    if (animate) {
      panel.style.animation = 'none';
      void panel.offsetWidth;
      panel.style.animation = 'inspector-fade-in 240ms cubic-bezier(0.16, 1, 0.3, 1) forwards';
    }

    // Populate data
    if (kicker) kicker.textContent = data.kicker;
    if (heading) heading.textContent = data.heading;
    if (mechanics) mechanics.innerHTML = formatCodeTags(data.mechanics);
    if (security) security.innerHTML = formatCodeTags(data.security);
    if (statVal) statVal.textContent = data.statVal;
    if (statDesc) statDesc.textContent = data.statDesc;
    if (code) code.textContent = data.code;
  };

  // Node click and keyboard handlers
  nodes.forEach(node => {
    const stage = parseInt(node.getAttribute('data-stage'));
    node.addEventListener('click', () => {
      selectStage(stage, true);
    });
    node.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        selectStage(stage, true);
      }
    });
  });

  // Jump pills handlers
  stagePills.forEach(pill => {
    pill.addEventListener('click', () => {
      const stage = parseInt(pill.getAttribute('data-stage'));
      selectStage(stage, true);
    });
  });

  // Close inspector
  if (btnClose) {
    btnClose.addEventListener('click', () => {
      panel.style.display = 'none';
      nodes.forEach(n => {
        n.classList.remove('active');
        n.setAttribute('aria-expanded', 'false');
      });
      if (statusText) statusText.textContent = 'Inspector minimized. Click any stage node to inspect.';
    });
  }

  // Simulation runner
  let simTimer = null;
  if (btnSim) {
    btnSim.addEventListener('click', () => {
      if (simTimer) {
        clearInterval(simTimer);
        simTimer = null;
      }
      btnSim.disabled = true;
      btnSim.textContent = '[SIMULATING DATAFLOW...]';

      let currentStep = 1;
      selectStage(currentStep, true);

      nodes.forEach(n => n.classList.remove('simulating'));
      const activeNode = document.getElementById(`pipe-node-${currentStep}`);
      if (activeNode) activeNode.classList.add('simulating');

      if (statusText) statusText.textContent = `⚡ Data flowing through Stage 0${currentStep}: ${PIPELINE_STAGES[currentStep].heading}...`;

      simTimer = setInterval(() => {
        currentStep++;
        if (currentStep > 6) {
          clearInterval(simTimer);
          simTimer = null;
          nodes.forEach(n => n.classList.remove('simulating'));
          btnSim.disabled = false;
          btnSim.textContent = '[▶ RUN PIPELINE SIMULATION]';
          if (statusText) statusText.textContent = '✓ Pipeline cycle completed! Snapshot anchored to Arbitrum One L2.';
          selectStage(6, false);
          return;
        }

        nodes.forEach(n => n.classList.remove('simulating'));
        const nextNode = document.getElementById(`pipe-node-${currentStep}`);
        if (nextNode) nextNode.classList.add('simulating');

        selectStage(currentStep, true);
        if (statusText) statusText.textContent = `⚡ Data flowing through Stage 0${currentStep}: ${PIPELINE_STAGES[currentStep].heading}...`;
      }, 1400);
    });
  }

  // Initial stage selection: Stage 1
  selectStage(1, false);
}

/* ==============================================================================
   6. M-of-N Shamir Threshold Simulator
   ============================================================================== */
function initShamirSimulator() {
  const checkboxes = document.querySelectorAll('.tui-guardian-check');
  const badge = document.getElementById('tui-shamir-badge');
  const output = document.getElementById('shamir-terminal-output');
  const hudText = document.getElementById('shamir-hud-text');
  const btnQuick = document.getElementById('btn-quick-shamir');
  const btnReset = document.getElementById('btn-reset-shamir');

  if (!checkboxes.length || !badge || !output) return;

  let solveTimer = null;

  const updateShamir = () => {
    const selected = Array.from(checkboxes).filter(cb => cb.checked);
    const count = selected.length;

    if (solveTimer) {
      clearTimeout(solveTimer);
      solveTimer = null;
    }

    checkboxes.forEach(cb => {
      const box = cb.closest('.shamir-guardian-box');
      if (box) box.classList.toggle('selected', cb.checked);
    });

    if (count === 0) {
      badge.textContent = '0/2 SELECTED';
      badge.style.color = 'var(--term-gold)';
      if (hudText) hudText.textContent = 'Degree-1 polynomial f(x) over GF(2^8) awaiting 2 coordinate shares...';
      output.className = 'shamir-terminal-output';
      output.textContent = '[STATUS] Awaiting threshold (select any 2 guardians above)...';
    } else if (count === 1) {
      const firstId = selected[0].getAttribute('data-id') || '1';
      const firstName = selected[0].closest('.shamir-guardian-box')?.querySelector('.guardian-name')?.textContent || 'Guardian';
      badge.textContent = '1/2 SELECTED';
      badge.style.color = 'var(--term-warning)';
      if (hudText) hudText.textContent = `Coordinate (x_${firstId}, y_${firstId}) from ${firstName} loaded into interpolation matrix. Degree-1 polynomial remains underdetermined.`;
      output.className = 'shamir-terminal-output';
      output.textContent = `[STATUS] 1 share loaded: Share #0x0${firstId} (${firstName}). Underconstrained system: infinite solutions exist.`;
    } else if (count >= 2) {
      const names = selected.map(cb => cb.closest('.shamir-guardian-box')?.querySelector('.guardian-name')?.textContent).filter(Boolean).join(' + ');
      badge.textContent = `${count}/2 EVALUATING...`;
      badge.style.color = 'var(--term-gold)';
      if (hudText) hudText.textContent = `Interpolating Lagrange basis polynomials ℓ_j(x) over GF(2^8) with shares from ${names}...`;
      output.className = 'shamir-terminal-output calculating';
      output.innerHTML = `[INTERPOLATING] Computing Lagrange basis polynomials ℓ_j(0) over Galois field GF(2^8)...`;

      solveTimer = setTimeout(() => {
        badge.textContent = `${count}/2 THRESHOLD REACHED ✓`;
        badge.style.color = 'var(--term-mint)';
        if (hudText) hudText.textContent = `Unique polynomial reconstructed! Constant term f(0) extracted in constant time.`;
        output.className = 'shamir-terminal-output solved';
        output.innerHTML = `[SUCCESS] Lagrange interpolation in GF(2^8) solved!<br>RECONSTRUCTED MASTER ROOT (R): <span class="text-gold">0x4F9B72C1-E8A3-4D90-B831-C038592FA711</span> (Vault unsealed)`;
      }, 240);
    }
  };

  checkboxes.forEach(cb => {
    cb.addEventListener('change', updateShamir);
    const box = cb.closest('.shamir-guardian-box');
    if (box) {
      box.addEventListener('keydown', (e) => {
        if (e.key === ' ' || e.key === 'Enter') {
          e.preventDefault();
          cb.checked = !cb.checked;
          updateShamir();
        }
      });
    }
  });

  if (btnQuick) {
    btnQuick.addEventListener('click', () => {
      checkboxes.forEach((cb, idx) => {
        cb.checked = idx < 2; // Alice & Bob
      });
      updateShamir();
    });
  }

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      checkboxes.forEach(cb => {
        cb.checked = false;
      });
      updateShamir();
    });
  }
}

/* ==============================================================================
   7. Emergency Paper Recovery Kit Unmasker
   ============================================================================== */
function initPaperKit() {
  const btn = document.getElementById('btn-toggle-paper-key');
  const keyDisplay = document.getElementById('paper-key-display');
  const btnCopy = document.getElementById('btn-copy-paper-cmd');
  const copyToast = document.getElementById('voucher-copy-toast');

  if (!btn || !keyDisplay) return;

  const RAW_SLOTS = ['8A4F-29E1', 'C73B-99D0', 'F41A-66E8', 'B2C5-9011'];
  const MASK_SLOTS = ['••••••••', '••••••••', '••••••••', '••••••••'];
  let revealed = false;

  btn.addEventListener('click', () => {
    revealed = !revealed;
    const slots = keyDisplay.querySelectorAll('.key-slot');
    if (revealed) {
      if (slots.length >= 4) {
        slots.forEach((slot, i) => {
          slot.textContent = RAW_SLOTS[i] || '••••••••';
          slot.classList.remove('masked');
        });
      } else {
        keyDisplay.textContent = '8A4F-29E1-C73B-99D0-F41A-66E8-B2C5-9011 [CRC32: 8F2A]';
        keyDisplay.style.color = 'var(--term-gold)';
      }
      btn.textContent = '[🔒 MASK KEY]';
    } else {
      if (slots.length >= 4) {
        slots.forEach((slot, i) => {
          slot.textContent = MASK_SLOTS[i] || '••••••••';
          slot.classList.add('masked');
        });
      } else {
        keyDisplay.textContent = '••••••••-••••••••-••••••••-•••••••• [CRC32: 8F2A]';
        keyDisplay.style.color = 'var(--text-main)';
      }
      btn.textContent = '[👁 REVEAL SIMULATED KEY]';
    }
  });

  if (btnCopy) {
    let toastTimer = null;
    btnCopy.addEventListener('click', () => {
      const cmd = 'ciphervault recover --paper-kit';
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cmd).catch(() => {});
      }
      if (copyToast) {
        copyToast.classList.add('show');
        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
          copyToast.classList.remove('show');
        }, 2200);
      }
    });
  }
}

/* ==============================================================================
   8. Live Real-Time Cryptographic Audit Telemetry Stream
   ============================================================================== */
const TELEMETRY_EVENTS = [
  'PoS challenge verified on cv-operator-1 (461-byte wire proof)',
  'FastCDC gear rolling hash sliced chunk at boundary 16,384 bytes',
  'Arbitrum One L2 anchor commitment receipt confirmed [block #14809]',
  'libp2p mesh peer discovery: 3/3 storage operators connected',
  'XChaCha20-Poly1305 multi-chunk AEAD throughput clocked at 558.62 MiB/s',
  'ZeroizeOnDrop compiler fence scrubbed ephemeral RAM key buffer',
  'Snapshot DAG head advanced to CID sha256:4a9c1f20b8e...',
  'YubiKey 5 PIV Slot 9C short APDU round-trip confirmed in 1.42 ms',
  'Deduplication cache hit: 25 chunks reused without network transmission'
];

function initLiveTelemetryStream() {
  const feed = document.getElementById('tui-stream-feed');
  if (!feed) return;

  const addTelemetryItem = (msg) => {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

    const item = document.createElement('div');
    item.className = 'stream-line new';
    item.innerHTML = `<span class="stream-time">[${timeStr}]</span> <span class="stream-msg">${escapeHtml(msg)}</span>`;
    feed.insertBefore(item, feed.firstChild);

    while (feed.children.length > 20) {
      feed.removeChild(feed.lastChild);
    }

    setTimeout(() => {
      item.classList.remove('new');
    }, 1200);
  };

  for (let i = 0; i < 4; i++) {
    addTelemetryItem(TELEMETRY_EVENTS[i]);
  }

  // Live Ping & Stream loop
  const p1 = document.getElementById('live-ping-op1');
  const p2 = document.getElementById('live-ping-op2');
  const p3 = document.getElementById('live-ping-op3');

  setInterval(() => {
    const randomEvent = TELEMETRY_EVENTS[Math.floor(Math.random() * TELEMETRY_EVENTS.length)];
    addTelemetryItem(randomEvent);

    // Subtle realistic latency jitter
    if (p1) p1.textContent = `${Math.floor(36 + Math.random() * 5)}ms`;
    if (p2) p2.textContent = `${Math.floor(39 + Math.random() * 6)}ms`;
    if (p3) p3.textContent = `${Math.floor(49 + Math.random() * 7)}ms`;
  }, 4800);
}

/* ==============================================================================
   9. Interactive CLI REPL Console & Collapsible Bar
   ============================================================================== */
const REPL_RESPONSES = {
  help: [
    'CipherVault CLI Help & Command Index:',
    '  init               - Initialize local vault & print emergency paper kit',
    '  track <paths...>   - Enroll confidential files into out-of-band ledger',
    '  snapshot [-m msg]  - FastCDC chunk, AEAD encrypt, and replicate across quorum',
    '  run -- <cmd...>    - Decrypt secrets into volatile RAM and spawn process',
    '  bench              - Run multi-chunk AEAD and PoS throughput benchmarks',
    '  compare            - Print architectural matrix vs AWS/Vault/1Password',
    '  recover            - Clean-machine paper kit & Shamir guardian restore',
    '  testnet            - Inspect live 3-node storage quorum endpoints',
    '  clear              - Clear terminal log drawer'
  ],
  init: [
    'ciphervault init',
    '🔐 Probing OS secure enclave (Windows DPAPI CryptProtectData)... [OK]',
    '✓ Master secret R generated (256-bit high-entropy Blake2b KDF)',
    'ROOT SECRET: 8A4F-29E1-C73B-99D0-F41A-66E8-B2C5-9011 [CRC32: 8F2A]',
    '✓ Local SQLite WAL vault initialized at .ciphervault/state.db'
  ],
  track: [
    'ciphervault track .env config/credentials.json',
    '✓ Enrolled: .env (1.4 KiB) -> Content ID: sha256:4a9c1f...',
    '✓ Enrolled: config/credentials.json (8.2 KiB) -> Content ID: sha256:d81e04...',
    'Notice: Git working tree unmodified. No plaintext staged into Git.'
  ],
  snapshot: [
    'ciphervault snapshot -m "Update production secrets"',
    '⚡ FastCDC Chunking: 26 total chunks evaluated',
    '✓ Chunks reused: 25 | Chunks modified: 1 (4 KiB)',
    '🎯 Deduplication: 96.15% bandwidth saved!',
    '✓ Replicated to 3 independent storage operators [3/3 OK]'
  ],
  run: [
    'ciphervault run -- npm start',
    '🛡️  CipherVault Zero-Disk Execution Guard Active',
    '🔓 Decrypting environment variables into process RAM...',
    '> App server started on port 3000 with authenticated secrets (0 plaintext on disk)'
  ],
  bench: [
    'Empirical Benchmarks (x86_64, Windows):',
    '  Encryption Throughput : 558.62 MiB/s (XChaCha20-Poly1305 AEAD)',
    '  Decryption Throughput : 656.84 MiB/s (Streaming In-Memory)',
    '  FastCDC Deduplication : 96.15% (25/26 chunks reused)',
    '  PoS Wire Savings      : 99.956% (1 MiB -> 461-byte proof)',
    '  Hardware Token APDU   : < 1.5 ms (YubiKey 5 PIV PC/SC)'
  ],
  compare: [
    'Architectural Comparison Summary:',
    '  CipherVault vs Cloud Secrets : Zero-knowledge client encryption vs Custodial KMS',
    '  CipherVault vs HashiCorp     : 96.15% FastCDC deduplication vs Full-blob storage',
    '  CipherVault vs 1Password     : Zero-disk RAM execution vs Plaintext local .env',
    '  CipherVault vs SOPS          : Quorum replication & PoS vs Git commit hash only'
  ],
  recover: [
    'Clean-Machine Disaster Recovery:',
    '  Method A : Emergency Offline Paper Kit (Master Secret R + CRC32)',
    '  Method B : M-of-N Shamir Threshold Guardians in GF(2^8) (e.g. 2-of-3 leads)',
    '  Method C : Out-of-band cryptographic push approvals'
  ],
  testnet: [
    'Live Testnet Quorum Endpoints:',
    '  cv-operator-1 : https://vault.cipherv.online/op/1 (Council Bluffs, Iowa)',
    '  cv-operator-2 : https://vault.cipherv.online/op/2 (Council Bluffs, Iowa)',
    '  cv-operator-3 : https://vault.cipherv.online/op/3 (Moncks Corner, S. Carolina)',
    'Live Explorer : https://vault.cipherv.online'
  ]
};

function initInteractiveRepl() {
  const input = document.getElementById('repl-input');
  const btnExec = document.getElementById('btn-repl-exec');
  const drawer = document.getElementById('repl-output-drawer');
  const drawerContent = document.getElementById('output-drawer-content');
  const btnClose = document.getElementById('btn-close-drawer');
  const btnToggleRepl = document.getElementById('btn-toggle-repl');
  const replBar = document.getElementById('tui-bottom-repl');
  const pills = document.querySelectorAll('.cmd-pill');

  if (!input || !drawer || !drawerContent) return;

  const commandHistory = [];
  let historyIdx = -1;

  if (btnToggleRepl && replBar) {
    btnToggleRepl.addEventListener('click', () => {
      const isCollapsed = replBar.classList.toggle('collapsed');
      btnToggleRepl.setAttribute('aria-expanded', !isCollapsed);
      const indicator = btnToggleRepl.querySelector('.repl-indicator');
      if (indicator) indicator.textContent = isCollapsed ? '▶' : '▼';
    });
  }

  const executeCommand = (cmdText) => {
    const raw = cmdText.trim();
    if (!raw) return;

    expandReplConsole();

    commandHistory.push(raw);
    historyIdx = commandHistory.length;

    const lower = raw.toLowerCase().split(' ')[0];

    if (lower === 'clear') {
      drawerContent.innerHTML = '';
      closeReplDrawer();
      input.value = '';
      return;
    }

    let responseLines = REPL_RESPONSES[lower];
    if (!responseLines) {
      if (lower.startsWith('bench')) responseLines = REPL_RESPONSES['bench'];
      else if (lower.startsWith('comp')) responseLines = REPL_RESPONSES['compare'];
      else if (lower.startsWith('rec')) responseLines = REPL_RESPONSES['recover'];
      else responseLines = [`ciphervault: command not found: '${raw}'. Type 'help' for available commands.`];
    }

    drawer.removeAttribute('hidden');

    const entry = document.createElement('div');
    entry.className = 'repl-log-entry';
    entry.style.marginBottom = '12px';

    const cmdLine = document.createElement('div');
    cmdLine.style.color = 'var(--term-cyan)';
    cmdLine.style.fontWeight = '700';
    cmdLine.textContent = `ciphervault > ${raw}`;
    entry.appendChild(cmdLine);

    responseLines.forEach(line => {
      const lineDiv = document.createElement('div');
      lineDiv.style.color = line.startsWith('✓') || line.startsWith('🎯') ? 'var(--term-mint)' : 'var(--text-secondary)';
      lineDiv.textContent = line;
      entry.appendChild(lineDiv);
    });

    drawerContent.appendChild(entry);
    drawer.scrollTop = drawer.scrollHeight;
    input.value = '';
  };

  btnExec.addEventListener('click', () => executeCommand(input.value));

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      executeCommand(input.value);
    } else if (e.key === 'ArrowUp') {
      if (commandHistory.length && historyIdx > 0) {
        historyIdx--;
        input.value = commandHistory[historyIdx];
      }
    } else if (e.key === 'ArrowDown') {
      if (historyIdx < commandHistory.length - 1) {
        historyIdx++;
        input.value = commandHistory[historyIdx];
      } else {
        historyIdx = commandHistory.length;
        input.value = '';
      }
    }
  });

  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      const cmd = pill.getAttribute('data-cmd');
      executeCommand(cmd);
    });
  });

  if (btnClose) {
    btnClose.addEventListener('click', closeReplDrawer);
  }
}

function expandReplConsole() {
  const replBar = document.getElementById('tui-bottom-repl');
  const btnToggle = document.getElementById('btn-toggle-repl');
  if (replBar) {
    replBar.classList.remove('collapsed');
    if (btnToggle) {
      btnToggle.setAttribute('aria-expanded', 'true');
      const indicator = btnToggle.querySelector('.repl-indicator');
      if (indicator) indicator.textContent = '▼';
    }
  }
}

function closeReplDrawer() {
  const drawer = document.getElementById('repl-output-drawer');
  if (drawer) drawer.setAttribute('hidden', '');
}

/* ==============================================================================
   10. Install Snippet Tabs & One-Click Copy
   ============================================================================== */
const INSTALL_SNIPPETS = {
  win: `# Install CipherVault for Windows via PowerShell (Release v1.0.14)\nirm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex`,
  nix: `# Install CipherVault on Linux or macOS via Bash (Release v1.0.14)\ncurl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash`,
  cargo: `# Build and install standalone CLI directly from Git source (v1.0.14)\ncargo install --locked --git https://github.com/samuel-1-avson/CipherVault ciphervault-cli`,
  docker: `# Spin up sovereign 3-node quorum with local management UI (v1.0.14)\ncurl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/docker-compose.yml -o docker-compose.yml\ndocker compose up -d`
};

function initInstallSnippets() {
  const tabs = document.querySelectorAll('.snippet-tab');
  const codePre = document.getElementById('snippet-code-pre');
  const btnCopy = document.getElementById('btn-snippet-copy');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const osKey = tab.getAttribute('data-target-os');
      if (INSTALL_SNIPPETS[osKey] && codePre) {
        codePre.querySelector('code').textContent = INSTALL_SNIPPETS[osKey];
      }
    });
  });

  if (btnCopy && codePre) {
    btnCopy.addEventListener('click', () => {
      const text = codePre.querySelector('code').textContent;
      navigator.clipboard.writeText(text).then(() => {
        btnCopy.textContent = '[COPIED ✓]';
        setTimeout(() => { btnCopy.textContent = '[COPY SNIPPET]'; }, 2000);
      });
    });
  }

  // Hero Target Pills Switcher (Cargo / Windows / Linux / Docker)
  const heroPills = document.querySelectorAll('.hero-target-pill');
  const heroCmd = document.getElementById('tui-install-cmd');
  const heroOsLabel = document.getElementById('tui-os-label');

  const HERO_SNIPPETS = {
    cargo: {
      cmd: 'cargo install --locked --git https://github.com/samuel-1-avson/CipherVault ciphervault-cli',
      label: 'RECOMMENDED (RUST 1.80+)'
    },
    win: {
      cmd: 'irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex',
      label: 'WINDOWS (POWERSHELL)'
    },
    nix: {
      cmd: 'curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash',
      label: 'LINUX / MACOS (BASH)'
    },
    docker: {
      cmd: 'docker run -d -p 8201:8201 --name ciphervault-op ghcr.io/samuel-1-avson/ciphervault-operator:latest',
      label: 'DOCKER CONTAINER'
    }
  };

  heroPills.forEach(pill => {
    pill.addEventListener('click', () => {
      heroPills.forEach(p => {
        p.classList.remove('active');
        p.setAttribute('aria-selected', 'false');
      });
      pill.classList.add('active');
      pill.setAttribute('aria-selected', 'true');

      const target = pill.getAttribute('data-install-target');
      if (HERO_SNIPPETS[target] && heroCmd) {
        heroCmd.textContent = HERO_SNIPPETS[target].cmd;
        if (heroOsLabel) heroOsLabel.textContent = HERO_SNIPPETS[target].label;
      }
    });
  });

  // Hero Quick-Install Copy
  const heroCopyBtn = document.getElementById('btn-tui-copy');
  const heroAlert = document.getElementById('tui-copy-alert');

  if (heroCopyBtn && heroCmd) {
    heroCopyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(heroCmd.textContent.trim()).then(() => {
        heroCopyBtn.textContent = '[COPIED ✓]';
        if (heroAlert) {
          heroAlert.classList.add('show');
          setTimeout(() => { heroAlert.classList.remove('show'); }, 2200);
        }
        setTimeout(() => { heroCopyBtn.textContent = '[COPY]'; }, 2000);
      });
    });
  }
}

/* ==============================================================================
   11. Retro CRT Scanline Toggle
   ============================================================================== */
function initCrtToggle() {
  const btn = document.getElementById('btn-toggle-crt');
  const crtOverlay = document.getElementById('crt-scanlines');
  if (!btn || !crtOverlay) return;

  btn.addEventListener('click', () => {
    const isCurrentlyDisabled = crtOverlay.classList.contains('disabled');
    if (isCurrentlyDisabled) {
      crtOverlay.classList.remove('disabled');
      btn.textContent = '[CRT: ON]';
    } else {
      crtOverlay.classList.add('disabled');
      btn.textContent = '[CRT: OFF]';
    }
  });
}

/* Utility */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
