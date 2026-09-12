# 02 — Technology decisions

All selections are provisional as of 11 September 2026. Comparisons below are engineering judgments based on the linked primary documentation, not independent reliability benchmarks or investment advice. Exact versions and current network parameters must be captured in the implementation lockfile and deployment review.

## Blockchain: select Arbitrum One

The chain's narrow job is to timestamp opaque snapshot commitments and expose a public checkpoint sequence independent of the coordinator. Encryption, storage, retrieval and repair operate off-chain. A chain outage delays checkpoints without preventing ciphertext recovery.

| Candidate | Relevant characteristics | Decision |
|---|---|---|
| Ethereum L1 | Direct base-layer checkpoint publication with fewer rollup dependencies; fee market varies with demand | Strong fallback for infrequent high-value roots, but unnecessary expense for frequent per-vault checkpoints |
| Arbitrum One | EVM rollup, Ethereum data publication, existing Solidity tooling; sequencer and upgrade dependencies; documented delayed-inbox escape route | **Selected** for batched/asynchronous opaque checkpoints, not synchronous file-save durability |
| Base | EVM rollup with distinct preconfirmation, L2 inclusion and L1 batch finality stages | Credible alternative; faster advertised early confirmation is not material when file saves do not wait for the chain |
| Sia chain | Storage-contract settlement native to Sia | Appropriate if Sia becomes the storage backend; does not justify an additional app chain for the selected Kubo MVP |
| Filecoin chain/FVM | Storage-related proofs and deals in the Filecoin ecosystem | Reconsider for archive automation; not needed for the simple checkpoint application |
| Custom appchain | Team would own consensus operations, security budget, upgrades and recovery | Rejected; no requirement demands it |

Ethereum describes its stake-based checkpoint finality and dynamic fee model in its [PoS documentation](https://ethereum.org/developers/docs/consensus-mechanisms/pos/). Base documents its [multiple finality stages](https://docs.base.org/specifications/transactions/transaction-finality). These are network properties, not end-to-end backup timings.

Arbitrum's [finality documentation](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/finality) distinguishes sequencer confirmation, parent-chain data finality and assertion settlement. Its [glossary](https://docs.arbitrum.io/intro/glossary) distinguishes One's rollup model from AnyTrust's additional data-availability committee assumption. Select **One, not Nova or a new Orbit chain**. Mainnet/testnet identifiers and contract addresses must be verified at implementation time, included in the signed recovery descriptor and checked by the client.

Arbitrum is not trust-free: monitor sequencer liveness, batch publication, Ethereum, RPC diversity, protocol upgrades and Security Council/DAO powers. The official [governance overview](https://github.com/ArbitrumFoundation/governance/blob/main/docs/overview.md) identifies upgrade executors and governance routes. Product contract immutability does not remove underlying chain upgrade risk. Two RPC endpoints improve outage tolerance but are not equivalent to locally verifying the chain.

## Why build on an existing Layer 2 instead of operating our own?

Both are technically possible. Building this application on Arbitrum One means deploying a small contract and running the backup services. Operating an application-specific rollup means also running a blockchain network and accepting its security, availability and governance obligations. A rollup built from an established stack is different from inventing a new consensus protocol, but it is still a substantial additional product.

| Dimension | Application on an existing L2 | Dedicated application rollup |
|---|---|---|
| Control | Existing execution, fee and sequencing rules | Can tune capacity, sequencing, fee policy and supported execution features within the selected stack |
| Capacity | Shares blockspace and congestion with other applications | Dedicated capacity and workload isolation; parent publication still constrains operation |
| Economics | Pay per checkpoint plus RPC/relayer overhead | Potential amortization at high sustained demand, but fixed infrastructure, parent-chain fees, monitoring and staffing |
| Security work | Review application contract and chain dependencies | Also review deployment configuration, bridge/system contracts, proofs, upgrade keys and emergency procedures |
| Availability | Depend on existing chain operators | Operate redundant sequencers/nodes and publication services or depend on a rollup service vendor |
| Governance | Accept existing chain governance | Define and secure upgrades, administrators, delays, emergency powers and migration policy |
| User ecosystem | Existing wallets, tooling and chain access | Add network onboarding, RPC endpoints, explorers, gas funding and potentially bridges |
| Decentralization | Inherits existing concentration risks | Does not improve automatically; one team controlling every chain role can add concentration |
| Secret recovery | Keys and independent off-chain replicas still required | Exactly the same requirement; owning the chain does not restore missing keys or bytes |

The real benefits of a dedicated rollup are control, dedicated capacity and potentially better economics at sufficient scale. Those benefits currently have little effect on this workload: encrypted files are off-chain and small checkpoint commitments are asynchronous. Faster blocks do not speed up a slow operator upload or recover a missing envelope. For the first product, use engineering effort to prove recovery after company/device failure before taking on chain operation.

Typical rollup roles include sequencing, parent-chain data publication, state proposals and dispute/challenge operation. The [OP Stack component documentation](https://docs.optimism.io/op-stack/protocol/components) and [chain configuration guide](https://docs.optimism.io/chain-operators/guides/configuration/getting-started) illustrate these responsibilities; its [challenger setup guide](https://docs.optimism.io/chain-operators/tutorials/create-l2-rollup/op-challenger-setup) adds production dispute-monitoring requirements. Buying rollup-as-a-service transfers tasks to a vendor; it does not remove their costs or trust dependencies.

A dedicated chain settling directly to Ethereum can be an L2; one settling to another L2 is often described as an L3. Choose settlement and data availability explicitly. An independent chain with a bridge is not automatically an Ethereum-secured rollup, and an off-chain data-availability committee introduces a different assumption from Ethereum-published data.

Reconsider the existing-chain recommendation only when measurements show sustained checkpoint demand or cost pressure that batching cannot solve, a concrete requirement needs custom execution/sequencing, and a funded team can operate and independently review the chain. Require a 12-month total-cost comparison including staffing, parent publication, RPC/archive infrastructure, disputes, upgrades, incident coverage and migration. Demonstrate recovery through sequencer/vendor failure and document data-availability and censorship paths. A token or the desire to call the product a blockchain is not sufficient evidence.

If those conditions are met, evaluate an established OP Stack or Arbitrum stack rollup in a separate architecture decision. Do not silently convert this MVP into a custom chain. Preserve the portable ciphertext format so changing checkpoint networks does not require decrypting and re-uploading all data.

## Storage: select three independently operated Kubo replicas

| Candidate | Strength for this product | Important limitation | MVP decision |
|---|---|---|---|
| IPFS/Kubo plus independently contracted operators | Content addressing, simple full-object transfer, direct recovery and provider substitution | Pinning alone has no payment enforcement, guaranteed retention or native proof that three independent copies exist | **Selected** with a small operator API, paid retention, readback checks and explicit trust disclosure |
| Filecoin | Storage deals and protocol-level storage proofs; useful independent archive layer | Deal lifecycle, packing and retrieval path must be engineered; proof does not guarantee rapid delivery | Research second backend after clean-machine restore works |
| Sia/renterd | Marketplace with storage contracts and automated renter operations | Renter metadata, maintenance, native payment and clean-machine recovery must be independently backed up and tested | Strong alternative spike, not an extra dependency in MVP |
| Storj | Distributed storage nodes and managed audit/repair | Satellite controls important metadata, authorization and coordination | Viable convenience adapter, insufficient alone for coordinator-independent product claim |
| Arweave | Upfront-funded permanent-storage design | Irreversible retention is a poor default for confidential files and long-term key exposure | Do not use for secrets in MVP |
| One conventional object-storage account | Operational simplicity | Single administrative account can suspend or delete all copies | Useful benchmark/control, not sufficient for independence requirement |

IPFS requires explicit retention arrangements; [pinning and persistence](https://docs.ipfs.tech/concepts/persistence/) are not equivalent to permanence. Its [privacy documentation](https://docs.ipfs.tech/concepts/privacy-and-encryption/) also describes public routing metadata and lack of built-in content encryption. Our direct HTTPS path avoids requiring a developer to announce CIDs to the public DHT, but does not make network activity anonymous.

Filecoin separates storage and retrieval providers and negotiates deals covering duration and price; see its [storage model](https://docs.filecoin.io/basics/what-is-filecoin/storage-model). The [proof glossary](https://docs.filecoin.io/reference/general/glossary) defines PoRep/PoSt; these do not establish that an application's missing manifest is available or that a user can retrieve it within seconds. Evaluate hot retrieval and [replication, renewal and repair](https://docs.filecoin.io/smart-contracts/programmatic-storage/raas) separately.

Sia describes host/renter contracts, fees and maintenance through renter software in [About Storing Data](https://docs.sia.tech/store-your-data/about-renting). Its advertised network-average storage price is not a quote for this workload; small vaults can be dominated by operations and minimum charges. The selected MVP avoids making a continuously available renter database the only recovery route.

Storj's [Satellite documentation](https://storj.dev/learn/concepts/satellite) explicitly assigns discovery, object metadata, authorization, billing, audits and repair to that service. Dispersed nodes do not eliminate that coordination dependency. Arweave's [protocol description](https://docs.arweave.org/developers/development/protocol) explains its endowment model; permanent retention is the reason to reject it here, not a claim that its economic assumptions guarantee eternity.

The operator wrapper proposed here is **new product engineering**, not an existing capability automatically supplied by Kubo or commercial pinning services. Validate that an operator can support independent recovery authorization, immutable retention, receipts and readback before counting it. If no three independent operators accept those requirements, the pilot may demonstrate multi-site backup but cannot claim the proposed decentralization level.

## Concrete provisional stack

| Component | Selection | Reason / constraint |
|---|---|---|
| Client, daemon, format verifier | Rust stable, Cargo workspace | One memory-safe core shared across platforms; unsafe FFI still needs review |
| Crypto | libsodium C library through a narrowly isolated Rust binding | Established AEAD, KDF, signatures and randomness; binding/library version selection is a security gate |
| Encryption | XChaCha20-Poly1305 AEAD, random keys/nonces | Chunk authentication and random access; format composition still needs independent review |
| Signing | Ed25519 through libsodium for product records | Separate recovery and device signers; do not reuse wallet signatures for encryption |
| Encoding | Deterministic CBOR profile, explicit versioned schemas | Compact portable signed bytes; reject duplicate/ambiguous encodings |
| Digests | SHA-256 over encrypted wire objects; CIDv1 raw objects | Compatible content identifiers; plaintext hashes remain encrypted |
| Local queue/index | SQLite with confidential payload columns encrypted | Crash-consistent queue and resumable state; index rebuildable from immutable records |
| Networking | Tokio, reqwest/rustls client; axum HTTPS operator/coordinator services | Provisional mature ecosystem candidates; exact releases require vulnerability review |
| Operator object store | Kubo behind private administration interface | Immutable ciphertext objects; raw administration API never exposed publicly |
| Coordinator data | PostgreSQL; durable jobs/outbox in database | Avoid adding Kafka/Redis until measurements show a need |
| Smart contract | Minimal Solidity contract; Foundry tests | Opaque checkpoint sequencing only; no custom crypto verification of file contents |
| Telemetry | OpenTelemetry metrics and structured redacted events | No paths, file contents, CIDs, key material or recovery locators in default telemetry |
| Distribution | Signed platform packages, SBOM, reproducible-build effort | Clean-machine users must authenticate the restore tool |
| GUI | Defer; later Tauri using the same core | Prevent duplicate crypto/protocol implementations |

The crypto choices follow libsodium's [AEAD guidance](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305) and [key derivation API](https://doc.libsodium.org/key_derivation). CBOR serialization follows a constrained deterministic profile of [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949). Tool names above are selections, not claims of audit coverage for our integration.

## Architectural decisions with revisit triggers

| ADR | Decision | Revisit when |
|---|---|---|
| A01 | Three full replicas instead of erasure coding | Stored history becomes large enough that measured cost outweighs recovery complexity |
| A02 | No global deduplication or plaintext addressing | Never silently relax; any change requires privacy and cryptographic review |
| A03 | Explicit immutable snapshots, no secret text merge | Teams become a concrete requirement |
| A04 | Immutable versioned checkpoint contract | Migration protocol is proven; never introduce an upgrade proxy casually |
| A05 | Offline recovery mandatory; guardians deferred | Recovery UX evidence supports a separate audited guardian design |
| A06 | Coordinator replaceable, operator admission initially curated | Independent operators and portable records are proven in real drills |
| A07 | Public DHT announcement optional and off by default | Users accept linkability and implementation confirms operator configuration |
