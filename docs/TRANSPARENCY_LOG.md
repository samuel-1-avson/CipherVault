# Transparency log operator guide (ADR-014 Phase 2)

Each operator runs one append-only transparency log beside its storage
service. Vault devices submit anchor commitments to it; anyone can
verify inclusion against the checkpoints it signs. This replaces
CipherChain multi-validator voting (review CC-04): there are no
proposals, votes or quorums to run, and devices are never validators.
CipherChain solo anchors stay verifiable read-only.

## Layout (under the operator data dir)

| File | What it is |
|---|---|
| `log/entries.bin` | Concatenated 65-byte v1 entries (`0x01 ‖ commitment ‖ monitor_tag`). An entry's index is its offset / 65. |
| `log/log.key` | 32-byte Ed25519 seed signing checkpoints. Created owner-only (0600 on Unix), never overwritten. |
| `log/origin` | The log origin, pinned on first open. |
| `log/checkpoint` | Latest signed checkpoint (static-serving cache; the entries file is the truth and it is re-signed from live state on open and on demand). |

Tiles and entry bundles are derived from the entries on demand, so
there are no tile files to keep in sync. Appends are one `write_all` +
`sync_all` before the submitter is acked. A crash mid-append leaves a
torn tail that the next open truncates (the entry was never acked); a
crash between the entry write and the checkpoint publish loses nothing
because checkpoints are recomputed from the entries.

## Configuration

| Setting | Flag / env | Default |
|---|---|---|
| Origin | `--log-origin` / `CIPHERVAULT_LOG_ORIGIN` | `cipherchain.<operator-id>.cipherv.online/log` |
| Submissions per device per minute | `--log-add-limit-per-min` / `CIPHERVAULT_LOG_ADD_LIMIT_PER_MIN` | 120 (0 disables) |
| Print origin + verifier key and exit | `--print-log-key` | — |

The origin is pinned in `log/origin` on first open. Starting later with
a different origin for the same data dir fails the log open (endpoints
answer 503) instead of quietly becoming a different log. Rotating the
log key likewise means starting a new log with a new origin; clients
learn about it by policy update, never in-band (ADR-014, Phase 6 may
add PIV/TPM keys).

## Endpoints

| Route | Auth | What it does |
|---|---|---|
| `POST /v1/log/add` | vault session (write) | Sequences one commitment. Body `{"commitment": "<32-byte hex>", "monitor_tag": "<32-byte hex, optional>"}`. Monitor tags are all-zero until Phase 5; a non-zero tag is a 400. Receipt: `index`, `leaf_hash`, `tree_size`, `root`, `origin`. Rate-limited per device session key (429). |
| `GET /v1/log/info` | public | `origin`, `verifier_key` (pin this out of band in client policy), `tree_size`, `root`. |
| `GET /v1/log/checkpoint` | public | Current signed checkpoint (C2SP signed note, text). Signed from live state on every call. |
| `GET /v1/log/tile/{*path}` | public | tlog-tiles bytes: `tile/0/000`, `tile/0/000.p/<w>`, `tile/1/...`, `tile/entries/000.p/<w>`. Wrong widths and tiles beyond the tree are 404. |
| `GET /v1/log/inclusion/{index}?size=` | public | Inclusion proof (hex hashes) for a leaf, default against the current tree. |
| `GET /v1/log/consistency?from=&to=` | public | Consistency proof between two tree sizes. |
| `GET /v1/log/lookup/{commitment}` | public | Indices a commitment was submitted at, so a client that lost its receipt recovers instead of duplicating. |

Sequencing is immediate in Phase 2: the sequencer appends, fsyncs,
extends the tree and signs a checkpoint under one lock, so when a
submission returns, a checkpoint covering its index already exists.
There is no batch timer yet.

## Failure behaviour

- Bad or wrong-length `log.key`, a corrupt entry, or an origin
  mismatch: the operator still boots and serves storage, but every
  `/v1/log/*` endpoint answers 503 and the boot log prints
  `ERROR: transparency log unavailable ...`. Fix the file; the log
  never rewrites a key file or an origin on its own.
- Over-limit device: 429 with no index consumed. A rejected submission
  (unauthenticated, malformed, non-zero tag) also consumes nothing.
- Witness cosignatures are Phase 3: checkpoints currently carry only
  the log's own signature, so they prove inclusion and append-only
  history to anyone who pinned the key, but "independent parties saw
  it" arrives with witnessing. CLI policy/anchoring is Phase 4.

## Quick check

```sh
ciphervault-operator --data-dir ./operator-data --print-log-key
curl -s https://op1.example/v1/log/info
curl -s https://op1.example/v1/log/checkpoint
curl -s https://op1.example/v1/log/inclusion/0
```

The checkpoint must open against the `verifier_key` from `--print-log-key`
(or an independently obtained copy of `/v1/log/info`), and the inclusion
proof must verify against that checkpoint's size and root. The operator
test suite (`services/operator/tests/translog_log.rs`) does exactly this
against a three-operator fleet, plus restart and rate-limit cases.
