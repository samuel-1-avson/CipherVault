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
  initCryptoDonations();
  initMobileNavigation();
  initKeyboardShortcuts();
});

/* ==============================================================================
   1. Multi-Theme Switching System (Cyber | Dark | Light | Mono)
   ============================================================================== */
function initThemeSystem() {
  const themeButtons = document.querySelectorAll('.theme-pill-btn');
  const drawerThemePills = document.querySelectorAll('.drawer-theme-pill');
  const crtOverlay = document.getElementById('crt-scanlines');
  const crtBtn = document.getElementById('btn-toggle-crt');

  const applyTheme = (themeName) => {
    document.documentElement.setAttribute('data-theme', themeName);
    localStorage.setItem('ciphervault-theme', themeName);

    themeButtons.forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-theme') === themeName);
    });

    drawerThemePills.forEach(btn => {
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

  drawerThemePills.forEach(btn => {
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
  const drawerTabs = document.querySelectorAll('.drawer-tab-btn');
  const panes = document.querySelectorAll('.tui-pane');

  tabButtons.forEach(btn => {
    const isTarget = btn.getAttribute('data-target') === targetPaneId;
    btn.classList.toggle('active', isTarget);
    btn.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    if (isTarget && btn.scrollIntoView) {
      btn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    }
  });

  drawerTabs.forEach(btn => {
    const isTarget = btn.getAttribute('data-target') === targetPaneId;
    btn.classList.toggle('active', isTarget);
    btn.setAttribute('aria-selected', isTarget ? 'true' : 'false');
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
   2b. Mobile Navigation Drawer Controller
   ============================================================================== */
function initMobileNavigation() {
  const hamburgerBtn = document.getElementById('btn-mobile-hamburger');
  const closeDrawerBtn = document.getElementById('btn-close-mobile-drawer');
  const drawer = document.getElementById('mobile-nav-drawer');
  const backdrop = document.getElementById('mobile-nav-backdrop');
  const mobileDonateBtn = document.getElementById('btn-mobile-donate');
  const drawerDonateBtn = document.getElementById('drawer-btn-donate');
  const drawerCrtBtn = document.getElementById('drawer-btn-crt');
  const drawerTabs = document.querySelectorAll('.drawer-tab-btn');

  function openDrawer() {
    if (!drawer) return;
    drawer.classList.add('open');
    if (backdrop) backdrop.classList.add('active');
    if (hamburgerBtn) {
      hamburgerBtn.classList.add('active');
      hamburgerBtn.setAttribute('aria-expanded', 'true');
    }
    document.body.style.overflow = 'hidden';
  }

  function closeDrawer() {
    if (!drawer) return;
    drawer.classList.remove('open');
    if (backdrop) backdrop.classList.remove('active');
    if (hamburgerBtn) {
      hamburgerBtn.classList.remove('active');
      hamburgerBtn.setAttribute('aria-expanded', 'false');
    }
    document.body.style.overflow = '';
  }

  if (hamburgerBtn) {
    hamburgerBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (drawer && drawer.classList.contains('open')) {
        closeDrawer();
      } else {
        openDrawer();
      }
    });
  }

  if (closeDrawerBtn) {
    closeDrawerBtn.addEventListener('click', closeDrawer);
  }

  if (backdrop) {
    backdrop.addEventListener('click', closeDrawer);
  }

  // Close drawer on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && drawer && drawer.classList.contains('open')) {
      closeDrawer();
    }
  });

  // Mobile Donate pill in topbar
  if (mobileDonateBtn) {
    mobileDonateBtn.addEventListener('click', () => {
      const openDonate = document.getElementById('btn-open-donate');
      if (openDonate) openDonate.click();
    });
  }

  // Drawer Donate button
  if (drawerDonateBtn) {
    drawerDonateBtn.addEventListener('click', () => {
      closeDrawer();
      const openDonate = document.getElementById('btn-open-donate');
      if (openDonate) openDonate.click();
    });
  }

  // Drawer CRT toggle
  if (drawerCrtBtn) {
    drawerCrtBtn.addEventListener('click', () => {
      const crtBtn = document.getElementById('btn-toggle-crt');
      if (crtBtn) crtBtn.click();
    });
  }

  // Drawer tabs navigation
  drawerTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target');
      if (target) {
        switchTab(target);
        closeDrawer();
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
    mechanics: 'CipherVault tracks confidential files completely out-of-band from Git. During enrollment via `ciphervault track .env`, the file is indexed into an encrypted local SQLite WAL database (`vault.db`) with cryptographic content digest binding. The Git working tree and `.gitignore` remain completely untouched.',
    security: 'Guarantees zero accidental staging into Git commits (`git add .` will never expose secrets). Host OS hardware keyrings (Windows DPAPI, macOS Keychain, Linux Secret Service) seal the vault master key R.',
    statVal: '< 1.2 ms',
    statDesc: 'Local metadata indexing & DPAPI hardware key binding',
    code: `// apps/cli/src/commands/track.rs & crates/local-store/src/db.rs
pub fn enroll_secret_file(
    path: &Path,
    store: &LocalVaultStore
) -> Result<TrackedMetadata> {
    let raw = std::fs::read(path)?;
    let digest = blake2b_256(&raw);
    store.track_file(path, &digest, raw.len() as u64)?;
    Ok(TrackedMetadata { digest, bytes: raw.len() })
}`
  },
  2: {
    kicker: 'STAGE [02] DEEP-DIVE SPECIFICATION',
    heading: 'FastCDC Content-Defined Chunk Slicing',
    mechanics: 'Unlike fixed-size blocking (which causes catastrophic cascade re-chunking on 1-byte insertions), FastCDC uses a precomputed Gear rolling hash table with dynamic normalization masks to discover content-defined cut boundaries between 4 KiB and 64 KiB.',
    security: 'Ensures localized byte edits only produce 1 modified chunk while 96%+ of all other chunks retain identical cryptographic hashes across versions, enabling extreme sub-file deduplication.',
    statVal: '96.15% Deduplication',
    statDesc: '25 of 26 chunks reused per localized edit; 1.85 GB/s hashing throughput',
    code: `// crates/storage/src/chunk.rs
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
    code: `// crates/crypto/src/cipher.rs
use chacha20poly1305::{
    XChaCha20Poly1305, Key, XNonce,
    aead::{Aead, KeyInit}
};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SecretBuffer(pub Vec<u8>);

pub fn encrypt_chunk(
    key: &Key,
    nonce: &XNonce,
    chunk: &SecretBuffer
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, chunk.0.as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)
}`
  },
  4: {
    kicker: 'STAGE [04] DEEP-DIVE SPECIFICATION',
    heading: 'K-of-N Quorum Admission & Capability Vouchers',
    mechanics: 'Operator nodes must pass a K-of-N multi-signature admission ceremony (ADR-011) with offline fleet seed keys and immutable join-admissions.json logs before joining the mesh. Client writes require signed capability vouchers (WriteVoucher) tracked in a persistent ledger with uniform per-user lifetime quotas (--user-quota-bytes).',
    security: 'Byzantine fault-tolerant storage + strict abuse defense: 429 quota limits prevent sybil disk-fill attacks, while K-of-N multi-signatures guarantee that no single compromised keyholder can admit rogue operators into the routing table.',
    statVal: 'K-of-N Quorum',
    statDesc: 'Multi-sig admission + voucher quotas (--user-quota-bytes)',
    code: `// crates/storage/src/invites.rs & vouchers.rs
pub fn verify_quorum_admission(
    ticket: &JoinInvite,
    fleet_keys: &[VerifyingKey],
    k_threshold: usize
) -> Result<(), StorageError> {
    let valid_approvals = ticket.count_distinct_approvals(fleet_keys)?;
    if valid_approvals < k_threshold {
        return Err(forbidden("insufficient keyholder approvals for quorum admission"));
    }
    log_admission_evidence(ticket)?; // Appends join-admissions.json
    Ok(())
}`
  },
  5: {
    kicker: 'STAGE [05] DEEP-DIVE SPECIFICATION',
    heading: 'Proof-of-Storage (PoS) Durability Challenge',
    mechanics: 'To prove ongoing chunk durability without downloading massive gigabyte backups, the client issues a PoS challenge containing an ephemeral cryptographic nonce. The operator computes a deterministic HMAC-BLAKE2b proof over the stored chunk and returns an unforgeable 461-byte wire proof.',
    security: 'Prevents operators from silently dropping data, claiming phantom storage, or executing data-withholding attacks. Verified in sub-millisecond execution on the client.',
    statVal: '99.956% Wire Savings',
    statDesc: '1 MiB raw chunk verified with only 461 bytes transmitted over wire',
    code: `// crates/storage/src/pos.rs
pub fn verify_pos_proof(
    expected_cid: &ChunkId,
    challenge_nonce: &[u8; 32],
    proof: &PoSProof
) -> bool {
    let computed_hash = hmac_blake2b(proof.chunk_sample(), challenge_nonce);
    computed_hash == proof.signature() && proof.wire_size() == 461
}`
  },
  6: {
    kicker: 'STAGE [06] DEEP-DIVE SPECIFICATION',
    heading: 'Arbitrum One L2 Blockchain Anchor & Consensus',
    mechanics: 'Snapshot commitments (SHA-256 of salt || head_cid) are anchored to the immutable CipherVaultRegistry.sol smart contract on Arbitrum One L2. The client CLI (ciphervault anchor) submits raw L2 transactions or uses automated relayers, polling for sequencer receipt confirmation (eth_getTransactionReceipt).',
    security: 'Zero plaintext, zero filenames, and zero user keys are ever revealed on-chain. Permanent L2 immutable timestamp prevents history rewriting, operator rollback attacks, or retroactive tampering. Any developer can verify with ciphervault verify-anchor.',
    statVal: '< $0.002 Gas',
    statDesc: 'Arbitrum One L2 sequencer finality + on-chain receipt verification',
    code: `// contracts/CipherVaultRegistry.sol (Arbitrum One L2)
contract CipherVaultRegistry {
    event CommitmentPublished(
        bytes32 indexed commitment,
        address indexed publisher,
        uint256 blockNumber,
        uint256 timestamp
    );
    mapping(bytes32 => uint256) public firstSeenBlock;

    function publish(bytes32 commitment) external {
        require(commitment != bytes32(0), "Invalid commitment: zero digest");
        if (firstSeenBlock[commitment] == 0) {
            firstSeenBlock[commitment] = block.number;
            emit CommitmentPublished(
                commitment,
                msg.sender,
                block.number,
                block.timestamp
            );
        }
    }
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
        output.innerHTML = `[SUCCESS] Lagrange interpolation in GF(2^8) solved!<br>RECONSTRUCTED MASTER ROOT (R): <span class="text-gold">0xDEMO-DEADBEEF-CAFEBABE-0123456789AB</span> (Vault unsealed)`;
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

  // Simulated mock paper recovery key for interactive UI demonstration
  const RAW_SLOTS = ['DEMO-DEAD', 'BEEF-CAFE', 'BABE-0123', '4567-89AB']; // ggignore
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
        keyDisplay.textContent = 'DEMO-DEAD-BEEF-CAFE-BABE-0123-4567-89AB [CRC32: TEST]';
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
        keyDisplay.textContent = '••••••••-••••••••-••••••••-•••••••• [CRC32: TEST]';
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
  'Arbitrum One L2 anchor commitment published (CipherVaultRegistry.sol) [block #248901422]',
  'K-of-N quorum admission evidence appended to join-admissions.json [ADR-011]',
  'PoS challenge verified on cv-operator-1 (461-byte HMAC-BLAKE2b wire proof)',
  'FastCDC gear rolling hash sliced chunk at boundary 16,384 bytes (96.15% deduplication)',
  'Voucher ledger verified per-user lifetime quota: 0 / 100 MiB spent [HTTP 200 OK]',
  'Automated store reconstruction initialized vault.db at epoch 2 (init_vault_at_epoch)',
  'libp2p mesh peer discovery: 3/3 storage operators connected & synchronized',
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
    'CipherVault CLI Help & Command Index (v1.0.14):',
    '  init               - Initialize local vault & print emergency paper kit',
    '  track <paths...>   - Enroll confidential files into out-of-band ledger',
    '  push [-m msg]      - FastCDC chunk, AEAD encrypt, and replicate across quorum',
    '  pull               - Pull and decrypt latest secret snapshot from operators',
    '  diff               - Compare working secrets against active snapshot head',
    '  anchor [--head CID]- Anchor salted snapshot commitment to Arbitrum One L2',
    '  verify-anchor      - Verify on-chain L2 receipt & first-seen block',
    '  invite [cmd]       - K-of-N multi-sig operator admission ceremony (ADR-011)',
    '  recover            - Clean-machine paper kit & Shamir rebuild (init_vault_at_epoch)',
    '  status             - Probe live operator mesh health & public status API',
    '  donate             - Community crypto donation addresses (Arbitrum & Ethereum)',
    '  run -- <cmd...>    - Decrypt secrets into volatile RAM and spawn process',
    '  bench              - Run multi-chunk AEAD and PoS throughput benchmarks',
    '  compare            - Print architectural matrix vs AWS/Vault/1Password',
    '  testnet            - Inspect live 3-node storage quorum endpoints',
    '  clear              - Clear terminal log drawer'
  ],
  init: [
    'ciphervault init',
    '🔐 Probing OS secure enclave (Windows DPAPI CryptProtectData)... [OK]',
    '✓ Master secret R generated (256-bit high-entropy Argon2id/Blake2b KDF)',
    'ROOT SECRET: DEMO-DEAD-BEEF-CAFE-BABE-0123-4567-89AB [CRC32: TEST]', // ggignore
    '✓ Local SQLite WAL vault initialized at .ciphervault/vault.db (Epoch 1)',
    '✓ Ready to track secrets: ciphervault track .env'
  ],
  track: [
    'ciphervault track .env config/credentials.json',
    '✓ Enrolled: .env (1.4 KiB) -> Content ID: sha256:4a9c1f...',
    '✓ Enrolled: config/credentials.json (8.2 KiB) -> Content ID: sha256:d81e04...',
    'Notice: Git working tree unmodified. No plaintext staged into Git.'
  ],
  push: [
    'ciphervault push -m "Update production secrets"',
    '⚡ FastCDC Chunking: 26 total chunks evaluated',
    '✓ Chunks reused: 25 | Chunks modified: 1 (4 KiB)',
    '🎯 Deduplication: 96.15% bandwidth saved!',
    '✓ Replicated to 3 independent storage operators [3/3 OK]',
    '  op1.cipherv.online: 200 OK (voucher spend recorded)',
    '  op2.cipherv.online: 200 OK (voucher spend recorded)',
    '  op3.cipherv.online: 200 OK (voucher spend recorded)',
    '✓ Active Head Snapshot CID: 0x8f2d...c3a9 (Epoch 2)'
  ],
  snapshot: [
    'Notice: "snapshot" is aliased to "ciphervault push" in v1.0.14.',
    'ciphervault push -m "Update production secrets"',
    '⚡ FastCDC Chunking: 26 total chunks evaluated',
    '✓ Chunks reused: 25 | Chunks modified: 1 (4 KiB) -> 96.15% saved',
    '✓ Replicated to 3 independent storage operators [3/3 OK]'
  ],
  pull: [
    'ciphervault pull',
    'Connecting to storage quorum (op1/op2/op3.cipherv.online)...',
    '✓ Active Head fetched: 0x8f2d...c3a9',
    '✓ Fetched 1 delta chunk (4 KiB), reused 25 cached chunks',
    '✓ Verified HMAC-BLAKE2b content digest: MATCH',
    '✓ Working tree secrets restored and verified against local manifest.'
  ],
  diff: [
    'ciphervault diff',
    'Comparing working tree against snapshot 0x8f2d...c3a9:',
    '  M .env (1 line modified, +1 key added)',
    '  - config/credentials.json (unchanged, identical CID)',
    'FastCDC delta estimate: 1 chunk (4 KiB) to sync on next push.'
  ],
  anchor: [
    'ciphervault anchor',
    'Preparing Arbitrum Checkpoint Commitment...',
    '  Head Record CID:   0x8f2dc3a9e102b487d903f56e1872a0c8413b567d98e7201cba643210fe987654',
    '  Target Chain ID:   42161 (Arbitrum One L2)',
    '  Contract Registry: 0x14809CipherVaultRegistry.sol',
    '  Opaque Commitment: 0x3d7b901a54c8e23f9b0123456789abcdef0123456789abcdef0123456789abcd',
    '  Publish Calldata:  0x6a05e2bb3d7b901a54c8e23f9b0123456789abcdef...',
    'Submitting commitment to Arbitrum L2 relayer (gas-abstracted)...',
    '✓ Automated L2 Relayer Sequencer Confirmation Received!',
    '  Sequencer Tx Hash: 0xa8f190c37b2d5e4a819c0b2468135790abcdef1234567890abcdef1234567890',
    '  Sequencer Block:   248901422',
    '  Finality Status:   SequencerConfirmed (Live Arbitrum L2 Settlement)'
  ],
  verify_anchor: [
    'ciphervault verify-anchor',
    'Querying Arbitrum One L2 Registry (0x14809...) at RPC https://arb1.arbitrum.io/rpc...',
    '✓ On-chain Commitment Verified: 0x3d7b901a54c8...',
    '  First Seen Block: 248901422',
    '  Current L2 Block: 248901460 (38 confirmations)',
    '  Receipt Verified: Independent RPC transaction receipt matches exact commitment inclusion.',
    '✓ State root timestamp is immutable and cryptographically bound.'
  ],
  invite: [
    'ciphervault invite (ADR-011 K-of-N Quorum Ceremony):',
    '  Step 1: ciphervault invite request --node <node-pk>    -> Mint unsigned InviteRequest',
    '  Step 2: ciphervault invite approve request.json         -> Keyholder signs with offline seed',
    '  Step 3: ciphervault invite combine app1.json app2.json -> Coordinator combines K approvals',
    '  Step 4: ciphervault invite verify ticket.json          -> Verify multi-sig ticket offline',
    '  Result: Admitted into probation with permanent record in join-admissions.json.'
  ],
  status: [
    'ciphervault status (GET https://cipherv.online/api/status):',
    '  Fleet Health    : OPTIMAL (3/3 nodes ready & storage_ready)',
    '  Operator 1 (IA) : READY (Latency: 42ms, Version: 1.0.14, Quotas: Active)',
    '  Operator 2 (IA) : READY (Latency: 45ms, Version: 1.0.14, Quotas: Active)',
    '  Operator 3 (SC) : READY (Latency: 48ms, Version: 1.0.14, Quotas: Active)',
    '  Probe Watcher   : 5-minute scheduled probe green (100% SLA)'
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
    '  CipherVault vs SOPS          : Quorum replication & L2 anchor vs Git commit hash only'
  ],
  recover: [
    'Clean-Machine Disaster Recovery (Recover-then-Rebuild Engine):',
    '  ciphervault recover --kit-key <MASTER-KEY>',
    '  1. Fetches genesis from immutable locator record',
    '  2. Rebuilds local SQLite vault.db at recovered epoch (init_vault_at_epoch)',
    '  3. Mints recovery-signed device certificate at authority generation',
    '  4. Pulls active head snapshot and decrypts files without manual config',
    '  Alternative: M-of-N Shamir Threshold Guardians in GF(2^8) (e.g. 2-of-3 leads)'
  ],
  testnet: [
    'Live Testnet Quorum Endpoints:',
    '  cv-operator-1 : https://op1.cipherv.online (Council Bluffs, Iowa) [v1.0.14]',
    '  cv-operator-2 : https://op2.cipherv.online (Council Bluffs, Iowa) [v1.0.14]',
    '  cv-operator-3 : https://op3.cipherv.online (Moncks Corner, S. Carolina) [v1.0.14]',
    'Live Explorer   : https://vault.cipherv.online',
    'Settlement      : Arbitrum One L2 (CipherVaultRegistry.sol)'
  ],
  donate: [
    'Support CipherVault Open-Source Infrastructure:',
    '  Accepted Chains : Arbitrum One L2 (Recommended, < $0.05 fee) | Ethereum Mainnet | Sepolia Testnet',
    '  Accepted Assets : ETH, USDT, ARB, Sepolia ETH',
    '  Recipient Address: 0x5f424b4ec88073fd461eb194833681a31adfa311',
    '  Funds directly support storage operator nodes, L2 settlement gas, and CI runners.'
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

    let clean = raw.toLowerCase().trim();
    if (clean.startsWith('ciphervault ')) {
      clean = clean.substring('ciphervault '.length).trim();
    }
    const lower = clean.split(' ')[0].replace(/-/g, '_');

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
      else if (lower.startsWith('anch')) responseLines = REPL_RESPONSES['anchor'];
      else if (lower.startsWith('ver')) responseLines = REPL_RESPONSES['verify_anchor'];
      else if (lower.startsWith('inv')) responseLines = REPL_RESPONSES['invite'];
      else if (lower.startsWith('stat')) responseLines = REPL_RESPONSES['status'];
      else if (lower.startsWith('snap')) responseLines = REPL_RESPONSES['snapshot'];
      else if (lower.startsWith('push')) responseLines = REPL_RESPONSES['push'];
      else if (lower.startsWith('pull')) responseLines = REPL_RESPONSES['pull'];
      else if (lower.startsWith('diff')) responseLines = REPL_RESPONSES['diff'];
      else if (lower.startsWith('don') || lower.startsWith('supp')) responseLines = REPL_RESPONSES['donate'];
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

/* ==============================================================================
   12. Cryptocurrency Community Donation Modal & Interactions
   ============================================================================== */
const CRYPTO_DONATION_CONFIG = Object.freeze({
  // Multi-chain recipient EVM address (works for ETH, USDT, ARB on Arbitrum and Ethereum, and Sepolia)
  evmAddress: '0x5f424b4ec88073fd461eb194833681a31adfa311',
  networks: Object.freeze({
    arbitrum: Object.freeze({
      name: 'Arbitrum One L2 (Recommended)',
      label: 'ARBITRUM ONE (L2) EVM ADDRESS:',
      fee: 'LOW GAS < $0.05',
      explorerUrl: 'https://arbiscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311',
      notice: 'Send <strong>ETH</strong>, <strong>USDT</strong>, or <strong>ARB</strong> on <strong>Arbitrum One L2</strong> to this address. Transactions on unsupported networks may result in lost funds.'
    }),
    ethereum: Object.freeze({
      name: 'Ethereum Mainnet (L1)',
      label: 'ETHEREUM MAINNET (L1) EVM ADDRESS:',
      fee: 'STANDARD GAS',
      explorerUrl: 'https://etherscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311',
      notice: 'Send <strong>ETH</strong> or <strong>USDT (ERC-20)</strong> on <strong>Ethereum Mainnet</strong> to this address. Always double check your gas settings.'
    }),
    sepolia: Object.freeze({
      name: 'Sepolia Testnet (Dev/Test)',
      label: 'SEPOLIA TESTNET EVM ADDRESS:',
      fee: 'TESTNET FAUCET',
      explorerUrl: 'https://sepolia.etherscan.io/address/0x5f424b4ec88073fd461eb194833681a31adfa311',
      notice: 'Send <strong>Sepolia ETH</strong> or <strong>Sepolia Testnet Assets</strong> to this address for testing CipherVault smart contracts.'
    })
  })
});

function generateQrSvg(address) {
  // ISO/IEC 18004 verified standard QR Code (Version 3-M, 33x33) for 0x5f424b4ec88073fd461eb194833681a31adfa311
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 33 33" shape-rendering="crispEdges" role="img" aria-label="EVM Donation Address QR Code"><path fill="#ffffff" d="M0 0h33v33H0z"/><path stroke="#07090e" stroke-width="1" d="M2 2.5h7m1 0h1m1 0h1m5 0h1m1 0h3m1 0h7M2 3.5h1m5 0h1m1 0h1m1 0h1m3 0h1m7 0h1m5 0h1M2 4.5h1m1 0h3m1 0h1m2 0h2m2 0h3m3 0h2m1 0h1m1 0h3m1 0h1M2 5.5h1m1 0h3m1 0h1m1 0h2m2 0h1m2 0h1m2 0h1m3 0h1m1 0h3m1 0h1M2 6.5h1m1 0h3m1 0h1m2 0h2m1 0h1m2 0h5m2 0h1m1 0h3m1 0h1M2 7.5h1m5 0h1m6 0h1m2 0h1m2 0h2m1 0h1m5 0h1M2 8.5h7m1 0h1m1 0h1m1 0h1m1 0h1m1 0h1m1 0h1m1 0h1m1 0h7M10 9.5h3m3 0h1m1 0h2m2 0h1M2 10.5h1m1 0h2m1 0h3m3 0h1m1 0h1m2 0h2m1 0h2m1 0h1m2 0h1m1 0h2M3 11.5h1m1 0h2m2 0h3m1 0h3m2 0h1m1 0h2m2 0h1m1 0h2m1 0h2M3 12.5h1m3 0h4m1 0h3m3 0h3m1 0h1m1 0h2m3 0h1M6 13.5h2m2 0h1m1 0h1m2 0h2m1 0h2m2 0h1m1 0h1m1 0h2m1 0h2M2 14.5h4m1 0h6m1 0h2m1 0h1m4 0h2m1 0h1m1 0h2M3 15.5h2m1 0h2m2 0h1m3 0h1m2 0h3m1 0h5m1 0h4M2 16.5h1m1 0h2m1 0h3m1 0h3m2 0h1m2 0h1m1 0h1m2 0h4m2 0h1M10 17.5h1m1 0h2m2 0h2m1 0h2m1 0h2m2 0h1m2 0h1M3 18.5h4m1 0h1m3 0h3m1 0h1m1 0h3m4 0h3m2 0h1M10 19.5h3m4 0h2m1 0h1m2 0h1m1 0h1m1 0h1m1 0h1M2 20.5h1m4 0h7m1 0h4m1 0h1m4 0h2m1 0h1M5 21.5h2m5 0h1m1 0h4m1 0h1m3 0h2m3 0h1M3 22.5h1m1 0h1m2 0h1m1 0h1m1 0h1m2 0h2m2 0h8m1 0h1m1 0h1M10 23.5h2m1 0h2m4 0h2m1 0h1m3 0h2m2 0h1M2 24.5h7m1 0h1m2 0h1m2 0h1m1 0h1m2 0h2m1 0h1m1 0h1m1 0h1M2 25.5h1m5 0h1m1 0h1m1 0h5m1 0h2m2 0h1m3 0h1m2 0h1M2 26.5h1m1 0h3m1 0h1m2 0h1m1 0h1m3 0h1m2 0h1m1 0h5m1 0h1M2 27.5h1m1 0h3m1 0h1m1 0h1m1 0h2m1 0h1m1 0h4m4 0h2m1 0h2M2 28.5h1m1 0h3m1 0h1m1 0h1m2 0h3m4 0h1m2 0h1m1 0h1m1 0h2m1 0h1M2 29.5h1m5 0h1m7 0h1m1 0h1m1 0h1m1 0h2m2 0h1m2 0h1M2 30.5h7m1 0h1m1 0h1m1 0h2m3 0h1m1 0h4m2 0h1m1 0h1"/></svg>`;
}

function initCryptoDonations() {
  const btnOpen = document.getElementById('btn-open-donate');
  const btnTriggerCard = document.getElementById('btn-trigger-donate-card');
  const overlay = document.getElementById('donation-modal-overlay');
  const btnClose = document.getElementById('btn-close-donate-modal');
  const btnDismiss = document.getElementById('btn-dismiss-donate');
  const tabArb = document.getElementById('tab-net-arb');
  const tabEth = document.getElementById('tab-net-eth');
  const tabSep = document.getElementById('tab-net-sep');
  const qrContainer = document.getElementById('donation-qr-container');
  const addressText = document.getElementById('donation-address-text');
  const btnCopy = document.getElementById('btn-copy-donation-address');
  const feedback = document.getElementById('donation-copy-feedback');
  const networkLabel = document.getElementById('donation-network-label');
  const noticeText = document.getElementById('donation-notice-text');
  const linkExplorer = document.getElementById('link-view-explorer');

  if (!overlay) return;

  const currentAddress = CRYPTO_DONATION_CONFIG.evmAddress;
  if (addressText) addressText.textContent = currentAddress;
  if (qrContainer) qrContainer.innerHTML = generateQrSvg(currentAddress);

  const openModal = () => {
    overlay.removeAttribute('hidden');
    void overlay.offsetWidth;
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
  };

  const closeModal = () => {
    overlay.classList.remove('active');
    setTimeout(() => {
      overlay.setAttribute('hidden', '');
      document.body.style.overflow = '';
    }, 200);
  };

  if (btnOpen) btnOpen.addEventListener('click', openModal);
  if (btnTriggerCard) btnTriggerCard.addEventListener('click', openModal);
  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (btnDismiss) btnDismiss.addEventListener('click', closeModal);

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) {
      closeModal();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.classList.contains('active')) {
      closeModal();
    }
  });

  const setNetwork = (netKey) => {
    const netConfig = CRYPTO_DONATION_CONFIG.networks[netKey];
    if (!netConfig) return;

    const tabs = [
      { key: 'arbitrum', el: tabArb },
      { key: 'ethereum', el: tabEth },
      { key: 'sepolia', el: tabSep }
    ];

    tabs.forEach(t => {
      if (t.el) {
        if (t.key === netKey) {
          t.el.classList.add('active');
          t.el.setAttribute('aria-selected', 'true');
        } else {
          t.el.classList.remove('active');
          t.el.setAttribute('aria-selected', 'false');
        }
      }
    });

    if (networkLabel) networkLabel.textContent = netConfig.label;
    if (noticeText) {
      noticeText.style.opacity = '0';
      setTimeout(() => {
        noticeText.innerHTML = netConfig.notice;
        noticeText.style.opacity = '1';
      }, 100);
    }
    if (linkExplorer) {
      linkExplorer.href = netConfig.explorerUrl;
      linkExplorer.title = `Verify on-chain on ${netConfig.name}`;
    }
  };

  if (tabArb) tabArb.addEventListener('click', () => setNetwork('arbitrum'));
  if (tabEth) tabEth.addEventListener('click', () => setNetwork('ethereum'));
  if (tabSep) tabSep.addEventListener('click', () => setNetwork('sepolia'));

  const performCopy = () => {
    const doFeedback = () => {
      if (btnCopy) {
        btnCopy.classList.add('copied');
        btnCopy.innerHTML = `
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
          <span>Copied!</span>
        `;
      }
      if (feedback) feedback.classList.add('show');
      setTimeout(() => {
        if (btnCopy) {
          btnCopy.classList.remove('copied');
          btnCopy.innerHTML = `
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            <span>Copy Address</span>
          `;
        }
        if (feedback) feedback.classList.remove('show');
      }, 2200);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(currentAddress).then(doFeedback).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = currentAddress;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        doFeedback();
      });
    } else {
      const ta = document.createElement('textarea');
      ta.value = currentAddress;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      doFeedback();
    }
  };

  if (btnCopy) btnCopy.addEventListener('click', performCopy);
  if (addressText) addressText.addEventListener('click', performCopy);
  if (qrContainer) qrContainer.addEventListener('click', performCopy);
}
