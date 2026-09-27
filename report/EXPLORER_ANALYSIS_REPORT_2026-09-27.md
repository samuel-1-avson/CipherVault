# CipherVault Explorer — System & Architecture Deep Analysis

**Date:** 2026-09-27  
**Version:** v1.0.18  
**Scope:** Public Cluster Explorer, Private Vault Inspector, Axum Serving Backend, Frontend Web Architecture, TUI Mirror, Security Boundaries, and Deployment Topology.  
**Baseline:** Post-v1.0.18 release (`1e86265`), comparing against prior analysis `report/EXPLORER_DEEP_ANALYSIS_2026-09-21.md`.  
**Verification Results:**  
- Rust Dashboard Unit & Integration Tests: **43 / 43 Passed**  
- UI Audit & WCAG 2.1 AA Accessibility Harness (`audit.test.cjs`): **Passed**  
- Dashboard Container Deployment Contract (`dashboard_container_contract.cjs`): **Passed**  

---

## 1. Executive Summary

The **CipherVault Explorer** is the central visual inspection, disaster recovery, and cluster intelligence interface of the CipherVault platform. Rather than a separate standalone web service, the Explorer is an **embedded zero-dependency single-page application (SPA)** compiled directly into the sovereign CLI binary (`apps/cli/src/main.rs`) via compile-time `include_str!` macros.

Since the previous deep analysis on 2026-09-21 (v1.0.7), the Explorer has undergone substantial architectural maturation and visual elevation:
1. **Complete Remediation of Prior Audit Findings (F1–F8):** Per-IP sliding-window rate limiting (in-app + edge-aware), strict Content-Security-Policy (`default-src 'none'`), RequestBodyLimitLayer (2 MiB cap), HTML quote-escaping hardening, and `nosniff` headers are fully implemented and verified in CI.
2. **Blockchain Explorer + GitHub (Primer) Aesthetics:** Overhauled layout featuring dark/light theme switching, fast native system typography, modern border hierarchy, and high-contrast accessibility compliance.
3. **Category Filtering & Unified Navigation:** 12 dedicated views categorized into *Network & Cluster*, *Secrets & Storage*, and *Security & Governance*, with interactive breadcrumbs, keyboard shortcuts (`1`–`9`, `[`, `]`), and responsive multi-tier layouts.
4. **Spotlight Command Palette & Omni-Search (`Ctrl+K` / `/`):** Instant modal search across snapshots, transaction hashes, operator nodes, and workspace actions.
5. **Live Production Telemetry & Zero Mock Data:** Purged all synthetic placeholders. Displays truthful reachability, cryptographic Proof-of-Storage (PoS) presence proofs, and Arbitrum L2 signed checkpoint feeds.
6. **Unified Hosted & Local Account Gateway:** Integrated device key sign-in, WebAuthn passkeys, TOTP enrollment, role matrix inspection, and multi-vault workspace switching.

**Overall Rating:** **Production-Grade (A+)**. Cryptographically sound, fail-closed security boundary, resilient rate-limiting, and zero runtime dependencies.

---

## 2. Serving Modes & Binary Architecture

CipherVault serves all three operational modes from a single Rust binary:

| Mode | Command | Network Bind | Capabilities & Surfaces |
|---|---|---|---|
| **Cloud Pointer** (Default) | `ciphervault ui` | None (opens browser) | Opens configured cloud portal (`https://vault.cipherv.online`). |
| **Private Workspace** | `ciphervault ui --local` | Loopback only (`127.0.0.1` / `[::1]`) | Full secret management: tracked files, FastCDC chunk inspector, encrypted snapshots, masked diffs, threshold guardians, restore engine, local account sessions. |
| **Public Cluster Explorer** | `ciphervault ui --serve` | Any host / `0.0.0.0:8080` | Read-only cluster telemetry, operator reachability, PoS object presence, signed Arbitrum checkpoint feeds, live SSE stream, proxied account authentication. |

### Zero-Asset Compilation Pipeline
The entire frontend shell (`apps/ui/index.html`, `apps/ui/styles.css`, `apps/ui/app.js` — ~350 KB uncompressed) is statically baked into `ciphervault`:
```rust
// apps/cli/src/main.rs:1710-1712
const UI_INDEX_HTML: &str = include_str!("../../ui/index.html");
const UI_STYLES_CSS: &str = include_str!("../../ui/styles.css");
const UI_APP_JS: &str = include_str!("../../ui/app.js");
```
This guarantees **zero static asset drift**: the web interface running on any operator, client machine, or container is strictly identical to the binary build version.

---

## 3. Security Boundary & Defense-in-Depth

The Explorer implements an industry-leading **6-layer defense-in-depth model**:

```
                       Inbound HTTP Request
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
   [Private Router]                       [Public Router]
  (ciphervault ui --local)              (ciphervault ui --serve)
            │                                     │
   [Layer 1: Loopback Host]               [Layer 1: Allowlist Only]
   Host must be 127.0.0.1/[::1]           Unknown routes -> 403 Forbidden
            │                                     │
   [Layer 2: Origin Guard]                [Layer 2: In-App Rate Limiter]
   Mutations require loopback Origin      30/min PoS Object, 600/min General
            │                                     │
   [Layer 3: Session Authentication]      [Layer 3: Hardening Headers]
   HttpOnly SameSite=Strict cookie        nosniff, max-age=30 on telemetry
            │                                     │
   [Layer 4: Body Limit Layer]            [Layer 4: Body Limit Layer]
   2 MiB max buffer (RequestBodyLimit)    2 MiB max buffer (RequestBodyLimit)
            │                                     │
   [Layer 5: UI Content-Security-Policy]  [Layer 5: UI Content-Security-Policy]
   default-src 'none', script 'self'      default-src 'none', script 'self'
            │                                     │
   [Layer 6: Fail-Closed Frontend]        [Layer 6: Fail-Closed Frontend]
   Gated by /api/context capabilities     Private surfaces hidden/wiped
```

### Layer Details:
1. **Structural Router Isolation:** Private handlers (guardians, diff, files, snapshots, workspaces) do not exist in `public_ui_router`. Any probe to a private route returns `403 PRIVATE_API_DISABLED` (`router.rs:574`).
2. **Private Request Guard (`private_ui_request_guard`):** 
   - Validates loopback `Host`.
   - Requires matching loopback `Origin` for state-mutating requests (`POST`/`PUT`/`DELETE`).
   - Validates encrypted, 30-minute vault-bound session cookies.
3. **In-App Per-IP Sliding-Window Rate Limiter:**
   - Object lookup budget: **30 requests / min** (protects operator fan-out).
   - General explorer budget: **600 requests / min** (supports 30s UI polling).
   - Bounded memory tracker capped at 10,000 clients with automatic prune.
   - Evaluates `CIPHERVAULT_TRUST_XFF` to trust the rightmost proxy header when deployed behind Caddy/Nginx, or peer TCP socket when direct.
   - Returns HTTP 429 with explicit `Retry-After`.
4. **Content-Security-Policy (CSP):**
   ```text
   default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
   connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self';
   form-action 'self'; frame-ancestors 'none'
   ```
   Completely prevents inline script injection, external font leaks, and framing/clickjacking.
5. **Request Body Cap:** Enforces `tower_http::limit::RequestBodyLimitLayer` at 2 MiB across all routes before reaching extractors.
6. **Fail-Closed Frontend:** Starts in `restricted` mode until `/api/context` responds with authenticated local capabilities. Switching modes immediately wipes all in-memory private state.

---

## 4. Frontend Architecture & Feature Overview

The web client (`apps/ui/app.js` — 5,446 lines; `styles.css` — 5,693 lines) is written in vanilla JavaScript and CSS without external frameworks, bundlers, or third-party CDNs.

### 4.1 The 12 Explorer Views & Category Filtering
The UI organizes functionality into 3 primary categories via `tabs-category-filter`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  [All Views (12)]   [Network & Cluster]   [Secrets & Storage]   [Security]  │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Storage Operators (`tab-operators`):** Live latency ribbon, reachable node grid, identity status (pinned, verified, unverified), storage capacity, and reachability timeline.
2. **My Data (`tab-overview`):** Private storage allocation across the decentralized operator fleet, aggregated lease receipts, and retention status.
3. **Explorer (`tab-explorer`):** Global CID lookup, cryptographic PoS replica verification, recent block commitments, and operator distribution.
4. **Snapshot DAG (`tab-dag`):** Interactive commit tree representing encrypted backup snapshots, parent-child lineages, manifest inspection, and rollback restore triggers.
5. **Secret Diff (`tab-diff`):** Side-by-side or unified diff comparing snapshot states. Values are masked by default with an explicit "Reveal Plaintext" toggle.
6. **Tracked Secrets (`tab-files`):** File inventory tracked for encrypted sync, FastCDC chunk stats, and automatic `.gitignore` protection.
7. **Threshold Guardians (`tab-guardians`):** K-of-N Shamir secret sharing visualizer, guardian sheet locators, verification checksums (CRC32), and recovery key certificates.
8. **Arbitrum Relayer (`tab-anchor`):** On-chain L2 anchor ledger, block confirmations, transaction receipts, Merkle head roots, and reorg canary alarms.
9. **Maintenance Fleet (`tab-fleet`):** Automated background repair workers, scrub audit logs, replication drift repair, and storage rebalancing.
10. **Recovery Readiness (`tab-recovery`):** Air-gapped disaster recovery readiness test, cryptographic validation of guardian shares, and recovery bundle exports.
11. **FastCDC Inspector (`tab-fastcdc`):** Visual chunk boundary inspector, variable-size deduplication analyzer, Shannon entropy meter, and chunk fingerprint table.
12. **Activity Log (`tab-activity`):** Real-time chronological audit trail of all vault operations, cryptographic signatures, and operator interactions.

### 4.2 Modern Enhancements in v1.0.18
- **Spotlight Command Palette (`Ctrl+K` / `Cmd+K` / `/`):** Modal interface offering instant search for commands, files, snapshot IDs, and navigation targets with arrow-key traversal.
- **Dynamic Breadcrumbs & Page Context:** Header reflects real-time location (`CipherVault / <Category> / <View>`) with quick-action shortcut buttons.
- **Multi-Vault Workspace Switcher:** Dropdown in the top header supporting multiple `.ciphervault` workspaces with a one-click local filesystem rescan.
- **Dual-Theme Engine (Phosphor / Primer):** Instant toggle between Dark Slate (`#0d1117`) and Clean Paper (`#f6f8fa`) using CSS custom properties with zero layout shift.
- **Real-Time SSE Stream:** Live connection badge with heartbeat detection and automatic pause when the browser tab is hidden to conserve resources.
- **Collapsible Terminal Console (`` ` `` key):** Embedded developer console showing raw JSON RPC payloads and internal state events.

---

## 5. Backend Implementation Analysis

Key modules under `apps/cli/src/dashboard/`:

| Module | Responsibility | Key Security & Architectural Features |
|---|---|---|
| `router.rs` | Route definitions & dispatch | Houses `private_ui_router`, `public_ui_router`, `RateLimiter`, CSP header injection, and body limits. |
| `handlers.rs` | HTTP endpoint controllers | Implements `private_ui_request_guard`, loopback checking, cookie verification, and public stubs. |
| `collectors.rs` | Background telemetry engine | Polls operators on a 30s cadence (3s probe timeout, 3 attempts with exponential backoff); caches in memory under a shared mutex; persists up to 288 history and 1,000 job records. |
| `finality.rs` | Checkpoint verification & PoS | Verifies Ed25519 signatures over canonical CBOR; pins publisher public keys; normalizes `0x` transaction hashes; checks Arbitrum RPC receipts; runs reorg alarms; enforces 60s probe cache and 16-permit semaphore. |
| `session.rs` | Session lifecycle | Mints 30-minute vault-bound HttpOnly cookies; enforces `SameSite=Strict`; manages mode capabilities. |
| `account_proxy.rs` | Hosted account proxy | Proxies registration, WebAuthn, TOTP, and memberships to hosted account microservice; enforces strict `cvacct_*` regex to block SSRF or path traversal. |
| `files_api.rs` | Local file operations | Manages tracking/untracking of secret files; prevents path traversal outside the workspace. |
| `fastcdc_api.rs` | Chunk inspection engine | Computes FastCDC chunking parameters and chunk hashes for user-selected local files. |
| `server.rs` | Axum server runtime | Initializes TCP listener, attaches logging middleware, launches browser in local mode, binds signals for graceful shutdown. |

---

## 6. Test Suite & Verification Matrix

The Explorer is verified across 3 distinct test harnesses:

### 6.1 Rust Integration & Router Suite (`cargo test --bin ciphervault dashboard`)
- **Status:** **43 / 43 Passed (100%)**
- **Highlights:**
  - `public_router_allows_only_explicit_public_api_routes`: Asserts all private endpoints return 403.
  - `public_rate_limit_trips_429_with_retry_after`: Verifies client IP rate throttling and header correctness.
  - `explorer_probe_cache_serves_fresh_and_drops_expired`: Proves CID lookups do not fan out to the network when cached.
  - `public_responses_carry_hardening_headers_and_shell_has_csp`: Validates CSP, `nosniff`, and cache headers.
  - `account_proxy_rejects_oversized_bodies_before_upstream`: Verifies 2 MiB request body protection.
  - `reorg_alarm_fires_on_deeply_confirmed_receipt_regression`: Asserts blockchain reorg detection.

### 6.2 Frontend DOM & Accessibility Suite (`node apps/ui/audit.test.cjs`)
- **Status:** **Passed**
- **Highlights:**
  - Validates zero leakage of private identifiers in public mode.
  - Tests secret value masking in the diff viewer.
  - Asserts WCAG 2.1 AA accessibility (aria roles, live regions, tab indexing, focus traps).
  - Verifies category filter toggling and command palette navigation.

### 6.3 Deployment Contract Suite (`node tests/dashboard_container_contract.cjs`)
- **Status:** **Passed**
- **Highlights:**
  - Enforces `ciphervault ui --serve --no-browser` in container entrypoint.
  - Asserts non-root user execution (`ciphervault`, UID 10001).
  - Verifies publisher signing key isolation.

---

## 7. Deployment & Infrastructure Posture

The Explorer is deployed in production behind a high-performance Caddy reverse proxy:

```
 Internet (HTTPS)
       │
       ▼
 [Caddy Edge Gateway] (vault.cipherv.online)
   ├── HSTS Preload (max-age=31536000)
   ├── TLS Termination & SNI routing
   ├── SSE Unbuffered Pipe (flush_interval -1)
   ├── Rate Limit Defense & X-Forwarded-For injection
   └── Reverse Proxy to localhost:8080
            │
            ▼
 [Docker Container: ciphervault-ui]
   ├── Base: debian:bookworm-slim (sha256 pinned)
   ├── User: ciphervault (non-root UID 10001)
   ├── Port: 8080 (ciphervault ui --serve)
   └── Healthcheck: GET /api/vault (15s interval)
```

- **Publisher Key Isolation:** Checkpoint publisher runs as a distinct sidecar profile with read/write access to the feed volume; the explorer container never has access to the private signing key (`CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX`).
- **Edge Logging Hygiene:** Access logs are configured with rotation to avoid perpetual retention of queried CID capability hashes.

---

## 8. Summary of Findings & Recommended Roadmap

| ID | Category | Description | Status |
|---|---|---|---|
| **F1** | Security | Fan-out amplification on public `/api/explorer/object/:cid` | **RESOLVED** (60s probe cache + 16 concurrency semaphore + in-app 30/min rate limiter) |
| **F2** | Security | Missing Content-Security-Policy on UI shell | **RESOLVED** (Strict same-origin CSP applied to `/`) |
| **F3** | Security | `escapeHtml` omitted single quote escaping | **RESOLVED** (Escapes `&`, `<`, `>`, `"`, `'`) |
| **F4** | Security | Missing security response headers on public API | **RESOLVED** (`nosniff` + `max-age=30` on telemetry) |
| **F5** | Architecture | Unbounded body potential on account proxy | **RESOLVED** (Pinned 2 MiB `RequestBodyLimitLayer`) |
| **F6** | Robustness | `formatBytes` NaN edge cases | **RESOLVED** (Clamped to non-negative, supports EiB, fallback `'--'`) |
| **F7** | Hygiene | CID paths in reverse proxy access logs | **RESOLVED** (Documented in deployment runbook) |
| **F8** | UI | Command palette dismissal and accessibility | **RESOLVED** (Hidden by default, dismissible via Esc/backdrop, keyboard operable) |

### Future Opportunities:
1. **Prometheus Metrics Exporter:** Expose a standard `/metrics` endpoint on the public router to integrate directly with Grafana and Prometheus monitoring.
2. **WebAuthn Conditional UI:** Add autofill support for passkeys in modern browsers during the sign-in ceremony.
3. **P2P Swarm Visualizer:** Connect the Explorer to the libp2p DON Phase 2 gossipsub mesh to render real-time peer topology maps.
