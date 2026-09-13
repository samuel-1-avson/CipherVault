# 08 — Sources and evidence

Research accessed 11–12 September 2026. Official documentation can change and some pages are indexed with older crawl dates. This pack does not establish exact live fees, deployed contract versions, provider independence, commercial guarantees or benchmark results. Recheck those at implementation and procurement time. The links below support factual background; the proposed architecture and numerical targets are our engineering judgments.

## Primary-source register

| Source | Used for | Evidence limit |
|---|---|---|
| [IPFS persistence](https://docs.ipfs.tech/concepts/persistence/) | Pinning, garbage collection, persistence versus permanence | Does not warrant a provider's future retention |
| [IPFS privacy and encryption](https://docs.ipfs.tech/concepts/privacy-and-encryption/) | Content encryption requirement and public routing metadata | Does not establish anonymity for the proposed design |
| [IPFS pinning services](https://docs.ipfs.tech/how-to/work-with-pinning-services/) | Kubo remote pinning and existing API ecosystem | Custom retention/recovery protocol is additional engineering |
| [Filecoin storage model](https://docs.filecoin.io/basics/what-is-filecoin/storage-model) | Providers, deals, sectors and retrieval separation | No tiny-vault price or latency guarantee |
| [Filecoin glossary](https://docs.filecoin.io/reference/general/glossary) | PoRep and PoSt claim definitions | No application-level recovery guarantee |
| [Filecoin RaaS](https://docs.filecoin.io/smart-contracts/programmatic-storage/raas) | Replication, renewal and repair concept | Integration and service maturity require a separate spike |
| [Sia storage overview](https://docs.sia.tech/store-your-data/about-renting) | Contracts, allowance and fee categories | Advertised averages are not procurement quotes |
| [Storj Satellite](https://storj.dev/learn/concepts/satellite) | Coordination, metadata, audit, billing and authorization responsibilities | Vendor description; independent recovery not tested here |
| [Arweave protocol](https://docs.arweave.org/developers/development/protocol) | Endowment and permanent-storage intent | Economic model is not unconditional permanence |
| [Arbitrum finality](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/finality) | Sequencer, parent data and assertion stages; delayed inclusion | Network guidance is not our backup SLO |
| [Arbitrum glossary](https://docs.arbitrum.io/intro/glossary) | Rollup versus AnyTrust, chain concepts | Recheck network-specific configuration at deployment |
| [Arbitrum fees](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/gas-and-fees) | Execution/data fee categories | Fees are variable; no live quote obtained |
| [Arbitrum governance overview](https://github.com/ArbitrumFoundation/governance/blob/main/docs/overview.md) | Upgrade executors and governance paths | Mutable source; capture deployed-state evidence before launch |
| [Base finality](https://docs.base.org/specifications/transactions/transaction-finality) | Alternative rollup's confirmation stages | Published latency/reorg claims are not independently verified here |
| [Ethereum PoS](https://ethereum.org/developers/docs/consensus-mechanisms/pos/) | Base-layer consensus/finality background | Does not secure off-chain file availability |
| [OP Stack components](https://docs.optimism.io/op-stack/protocol/components) | Dedicated-rollup architecture responsibilities | Framework availability does not make a deployment secure |
| [OP Stack chain configuration](https://docs.optimism.io/chain-operators/guides/configuration/getting-started) | Chain operator setup obligations | Configuration must be reviewed for the actual chosen stack |
| [OP Stack challenger setup](https://docs.optimism.io/chain-operators/tutorials/create-l2-rollup/op-challenger-setup) | Dispute monitoring and production challenger responsibilities | A challenger is only one part of rollup operations |
| [Libsodium AEAD](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305) | Authenticated encryption choice | Primitive documentation does not audit our format |
| [Libsodium KDF](https://doc.libsodium.org/key_derivation) | Purpose-separated key derivation | Constants and vectors remain to be frozen |
| [Libsodium sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) | Recovery key envelopes and lack of sender authentication | Outer sender authorization must be implemented separately |
| [Libsodium password hashing](https://doc.libsodium.org/password_hashing/default_phf) | Password-protected digital-kit option | Human password strength and hardware constraints remain |
| [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949) | CBOR and deterministic encoding foundations | Product's constrained profile requires its own specification |

No secondary-source investment commentary, anecdotal performance numbers or novel research cryptosystems are relied on for the recommendation. No provider was contacted, no commercial account was created, and no funds were spent.

## Local CREG context and boundaries

The originating task supplied prior inspection findings: CREG is a package-verification research alpha using off-chain package data, evidence/quorum and chain records. It reported a plaintext-before-optional-encryption private publication path and unwired threshold decryption. These were context for avoiding unsafe reuse, not an instruction to change CREG.

This task directly read the existing `docs/architecture/TARGET_ARCHITECTURE.md` under `C:\Users\samue\OneDrive\Desktop\projects\chain-registry-blockchain-CREG-`. It describes an evidence-first witnessed log, off-chain objects and minimal anchoring. File discovery also located the nested source paths `chain-registry/crates/cli/src/publish.rs` and `chain-registry/crates/node/src/validator_pipeline.rs`; the initially supplied shorter source paths did not resolve. The precise code findings from the originating task are not represented as a fresh line-by-line audit in this pack.

This product has a different trust boundary: validators and workers must never see secret plaintext. No CREG code was modified or reused. An architectural similarity such as off-chain objects plus a checkpoint does not authorize reuse of a plaintext package-processing path.

## Review status

The deliverable is a Markdown design pack with linked documents and Mermaid source diagrams. Documentation consistency and local link checks are recorded in the final handoff; no product tests, security audit, provider qualification or performance benchmark were run. Mermaid source is provided for compatible Markdown viewers; a rendered-diagram visual QA pass is not claimed.

Remaining evidence needed for build approval is explicit in document 07: operator capabilities, exact cryptographic format review, clean-machine discovery tests, measured workload costs, platform behavior and named operational/security owners.
