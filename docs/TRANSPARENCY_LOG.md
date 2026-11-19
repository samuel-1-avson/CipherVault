# Transparency log operator guide (ADR-014 Phases 2 and 3)

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
| `log/checkpoint.witnessed` | Latest checkpoint published with a witness quorum (Phase 3). A cache: re-checked against the log key and tree on open and dropped with a warning if it no longer matches. |

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
| Witnesses to push to | `--log-witness <vkey>@<URL>` (repeatable) / `CIPHERVAULT_LOG_WITNESSES` | none |
| Cosignatures to publish as witnessed | `--log-witness-quorum` / `CIPHERVAULT_LOG_WITNESS_QUORUM` | 2, or every witness when fewer |
| Seconds between witnessing rounds | `--log-witness-interval-secs` / `CIPHERVAULT_LOG_WITNESS_INTERVAL_SECS` | 10 |

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
| `GET /v1/log/checkpoint/witnessed` | public | Newest checkpoint carrying a quorum of witness cosignatures; 404 before the first. It lags the live checkpoint by up to one witnessing round, so ask for inclusion proofs at its size (`?size=`). `/v1/log/info` reports its size as `witnessed_tree_size`. |
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
- A witness that is down or refuses only delays the witnessed
  checkpoint; the log keeps accepting entries. Each witnessing failure
  is logged when it changes. A witness reporting a size above the log's
  is reported as a serious fault and never "fixed" automatically.
- CLI policy and anchoring are Phase 4: until then the CLI does not use
  the witnessed checkpoint.

## Witnessing (Phase 3)

Every operator can also run a C2SP
[`tlog-witness`](https://c2sp.org/tlog-witness) witness. It cosigns other
logs' checkpoints with **ML-DSA-44** (signature type `0x06`, see the
ADR-014 amendment) after checking a consistency proof from the last
checkpoint it cosigned for that log. The default topology has every
operator witnessing every other operator's log.

### Witness state (under the data dir)

| File | What it is |
|---|---|
| `witness/witness.key` | 32-byte ML-DSA-44 seed. Created owner-only on first open (0600 on Unix, a user-only ACL on Windows), never overwritten. |
| `witness/name` | The witness name, pinned on first open. The cosignature commits to it, so a different configured name fails closed. |
| `witness/logs/<sha256(origin)>` | Per log: the latest checkpoint this witness cosigned, with the log's signature and its own cosignature. Written atomically **before** the cosignature is returned, and re-verified on open. A damaged file makes the witness fail closed (503), because a witness that forgot what it signed could be made to cosign a fork. |
| `witness/evidence/<sha256(origin)>/<size>-<root>.txt` | Log-signed checkpoints the witness refused as inconsistent, each beside the checkpoint it had witnessed: the self-verifying evidence pair. One file per distinct signed checkpoint, at most 1,024 per log. |

### Witness configuration

| Setting | Flag / env | Default |
|---|---|---|
| Run the witness | `--witness` / `CIPHERVAULT_WITNESS_ENABLED=1` (also on when a trusted log is set) | off |
| Witness name | `--witness-name` / `CIPHERVAULT_WITNESS_NAME` | `cipherchain.<operator-id>.cipherv.online/witness` |
| Logs to cosign | `--witness-trusted-log <Ed25519 vkey>` (repeatable) / `CIPHERVAULT_WITNESS_TRUSTED_LOGS` | none |
| Print name + ML-DSA-44 verifier key and exit | `--print-witness-key` | — |

A trusted log's key name must be its origin, which is how operator logs
name their keys. A log is identified only by that key: anyone holding
it can get checkpoints cosigned.

### Witness endpoints

The prefix `/v1/witness` is both the spec's submission prefix and its
monitoring prefix. The endpoints are public and unauthenticated, as the
spec intends.

| Route | What it does |
|---|---|
| `POST /v1/witness/add-checkpoint` | `old <size>`, up to 63 base64 proof lines, a blank line, then the signed checkpoint. `200`: the cosignature line. `400` malformed, or old size above the checkpoint size. `403` no valid signature from the trusted log key. `404` unknown origin (and every origin when the witness is off). `409` stale old size, body `<size>\n` with `Content-Type: text/x.tlog.size`. `422` inconsistent (bad proof, fork, wrong empty root); evidence is kept when the refused checkpoint is a different signed tree. |
| `GET /v1/witness/<sha256(origin) hex>/checkpoint` | The latest checkpoint cosigned for that log, with the log signature and the cosignature; 404 if never cosigned. |
| `GET /v1/witness/info` | `name`, `verifier_key`, `trusted_logs` (origins). |

### Wiring a three-operator fleet

1. On each operator, print its keys: `--print-log-key` and
   `--print-witness-key`. They are created on first run.
2. Give each operator the other two logs' keys
   (`--witness-trusted-log`), and the other two witnesses as
   `--log-witness <witness vkey>@https://<operator>/v1/witness`.
3. With two witnesses each, the default quorum is 2. Set
   `--log-witness-quorum 1` to tolerate one witness being down. Client
   policy (Phase 4) decides what it finally accepts.

### Standalone witness

`ciphervault-witness --data-dir <dir> --name <witness name>
--trusted-log <vkey> [--listen 127.0.0.1:8190]` runs only the witness,
with the same state layout and the same `/v1/witness` routes. It has no
rate limiting of its own, so put it behind a reverse proxy.
`--print-key` prints its verifier key.

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
`services/operator/tests/translog_witness.rs` covers witnessing over real
HTTP: three operators cross-witness to a quorum, every witness status
code, a refused fork with its evidence pair, and the standalone binary.
