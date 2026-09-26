# CipherVault Chaos Drill Log

Running record of 10-node storm-gate evidence (`scripts/drill/chaos-10node.sh`
→ `services/operator/tests/chaos.rs`: Gate A kill-3/10 mid-write, Gate B 45s
partition-heal, Gate C repair-bandwidth bounds). Newest entry first. A
"verdict" entry without gate output is an honest gap marker, never a pass.

## 2026-09-19 — CHAOS PASS (all three gates green)

- Run ID: 2026-09-19 16:05 UTC, git SHA `6841f3f` (main, post-C6),
  Windows host, Docker 29.7.2.
- Image: `ciphervault-operator:chaos`
  `sha256:4c71b03ba94ef077c9fe07d77be4833f9802894b3fdc46b50287efaeb0117bd2`
  (release build of the same tree).
- Command: `bash scripts/drill/chaos-10node.sh` (Git Bash), exit 0.
  Test time 129.73 s; 10 nodes up, routing tables meshed (90 announces).

Gate output (verbatim):

```text
chaos: Gate A killed n1 n2 n5 mid-write
chaos: Gate A PASS (3 replicas x 4 objects on 7 survivors)
chaos: Gate B froze n3 n4 for 45s (past the 15s heartbeat timeout)
chaos: Gate B PASS (partition healed, liveness + replicas converged)
chaos: Gate C PASS (548864 repair bytes <= 2097152, 0 exhausted)
CHAOS PASS: kill-3/10, partition-heal, and bandwidth gates all green
```

What this proves: the mesh survives 30% sudden node loss mid-write with
no object dropping below 3 replicas, reconverges liveness and replicas
after a 45 s partition (3x the heartbeat timeout), and repair stays
bounded (537 KiB against a 2 MiB cap, zero budget rejections at the
default 8 MiB/s).

## 2026-09-19 — verdict: drill NOT run (no usable Docker daemon)

> Superseded the same day: the daemon recovered and the full drill
> passed — see the 16:05 UTC entry above. Kept for the fallback-suite
> record.

- Git SHA: `dd9008d` (main, post-C3).
- Attempted: `bash scripts/drill/chaos-10node.sh` prerequisites.
- Blocker: the Docker CLI hangs against the local daemon. `Docker Desktop`
  process is running and `\\.\pipe\docker_engine` exists, but `docker info`,
  `docker info --format`, and `docker version --format` all hung without
  output (two attempts terminated after minutes, one killed by a 90s
  timeout). No `docker build` or container gate could run from this
  workstation. Ports 18301/9101/9102 are free, so no stale mesh is the
  cause; the engine itself is unresponsive to the CLI.
- Storm-gate status: **no current evidence**. Gates A/B/C remain unproven
  on this tree. Do not cite this entry as storm verification.

### Fallback evidence (same tree, non-docker suites)

Single-process suites that exercise the same repair/liveness/transport
logic the container gates run multi-node. They prove logic, not storm
behavior under kill/partition — recorded here so the gap is bounded, not
hidden.

Command:

```powershell
cargo test --locked -p ciphervault-operator --test swarm --test swarm_liveness --test swarm_repair --test swarm_dos --test transport_conformance --test nat --test rendezvous --test dht_records --test bootstrap --test drill_flags
```

Run ID: 2026-09-19 14:51 UTC on `dd9008d`, Windows host. Result: **59
passed, 0 failed** across 10 suites:

| Suite | Tests | Result |
|---|---|---|
| bootstrap | 4 | ok |
| dht_records | 2 | ok |
| drill_flags | 2 | ok |
| nat | 3 | ok |
| rendezvous | 1 | ok |
| swarm | 1 | ok |
| swarm_dos | 5 | ok |
| swarm_liveness | 2 | ok |
| swarm_repair | 3 | ok |
| transport_conformance | 36 | ok |

Relevant gate mapping:

- Gate A (kill 3/10, backfill to 3 replicas): partly covered by
  `swarm_repair` (repair assessment/backfill logic) and
  `transport_conformance` (object roundtrips) — but replica loss under
  real kills is untested here.
- Gate B (partition-heal, liveness reconverge): partly covered by
  `swarm_liveness` and `nat` — but heartbeat-timeout eviction and
  reconvergence across a real split are untested here.
- Gate C (bandwidth cap, zero 429s): **not covered** — no fallback suite
  asserts repair-byte bounds.

### To produce real evidence

On a host with a working Docker daemon (or CI with docker):

```bash
bash scripts/drill/chaos-10node.sh
```

Expect ~10 minutes plus a release image build. Append the new entry above
with the PASS/FAIL lines, the git SHA, and the image digest (`docker
images --digests ciphervault-operator:chaos`).
