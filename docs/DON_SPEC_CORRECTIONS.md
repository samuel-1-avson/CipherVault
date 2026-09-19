# DON Spec Corrections Appendix

Parent: `docs/DECENTRALIZED_ARCHITECTURE_SPEC.md`. This appendix records verified
corrections; the parent document is left untouched.

## C1 — Content IDs are SHA-256, not BLAKE2b-512

Parent claims (§2, §2.1): CIDs are BLAKE2b-512 and chunks are "addressed strictly
by BLAKE2b hash".

Verified (`crates/format/src/canonical.rs`, `compute_digest`): content digests are
32-byte SHA-256. DHT keyspace design MUST use the 256-bit SHA-256 digest as the
key; any reference to BLAKE2b-512 in the parent spec is incorrect. No code change
is implied — SHA-256 CIDs are kept as-is.

## C2 — k=3 is crash tolerance, not Byzantine fault tolerance

Parent claims (§8 Q3): k=3 "provides Byzantine fault tolerance against 1 node
failure".

Correct statement: 3 self-verifying replicas tolerate up to 2 crash faults for
reads (any single surviving replica serves a digest-verified chunk) and require
quorum agreement for writes per `required_replicas`. Ordered Byzantine agreement
would require 3f+1 participants and is explicitly NOT claimed by this plan.

## C3 — Abstraction seam is transport-level, not pool-level

Parent proposes (§4.1): a 4-method `StoragePool` trait
(put/get/verify_pos/list_peers) implemented by both `MultiOperatorPool` and a new
P2P pool.

Verified (`crates/storage/src/pool.rs`, `replicate_and_verify`): real replication
is authenticate → PoS-dedup upload → lease commit → receipt-signature verify →
readback verify → recovery-log append → discovery readback, with quorum
early-exit. The 4-method trait cannot express leases, recovery logs, or readback
and would fork the protocol. This plan instead abstracts the byte transport
beneath `OperatorClient` (HTTP today, libp2p streams later) so the entire
pipeline runs identically on both paths. See `docs/DON_IMPLEMENTATION_PLAN.md`,
decision D1.

## C4 — Prior art: signed HTTP peer gossip already exists

Parent spec designs DHT identity/bootstrap from scratch. Verified existing
substrate to evolve instead of replace:

- `crates/storage/src/client.rs`: `announce_peer`, `get_peers`
  (`/v1/peers/announce`, `/v1/peers`)
- `crates/storage/src/types.rs`: `PeerDescriptor`
- `crates/storage/src/pool.rs`: `discover_and_expand_peers`

DHT peer identity, signed announcements, and the local routing table build on
these types and endpoints.
