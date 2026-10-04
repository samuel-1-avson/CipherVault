# Publisher rotation evidence (2026-10-03)

Old publisher signing seed lost (owner-confirmed; never in repo or
Secret Manager). Full rotation per runbook §9 + `KEY_CEREMONIES`: new
offline seed, fresh anchor evidence, re-pin + fresh feed staged.

## Ceremony (Alice-only, owner-held seed)

- New 32-byte Ed25519 seed generated offline via OS CSPRNG, straight
  to `AppData\Local\ciphervault\publisher\publisher-seed.txt`
  (non-synced), ACL owner-only (`HALLDEAN\samue:(F)`, no inheritance).
- Offline paper/USB copy + KeePass entry: owner action (same custody
  as the fleet seed).
- Seed never printed, pasted, or committed; agent saw only the public
  verifying key.

## Key pins (public)

- Old: `5631c3669259b6345cc3572b310bef8403cb5249717faaa31f371607b5623052`
- New: `ea1284cd55a836f7c8730cb58d9f3e9737925221484b9b6ed132e4f5e176bc11`
- Old pin rejected everywhere after re-pin; lost seed is now harmless.

## Fresh evidence + feed

- `anchor` prepare step (Sepolia 421614, registry
  `0xa26E70293eb0007c8059FAe9c03649Cf24F63Db5`): commitment recorded
  at L2 block 315472456, tx pending (broadcast = follow-up, payer key).
- `publish-public-feed`: 1 record, v1, signature 64 bytes, issued
  minutes before staging. Old Sept 26 feed could not be re-signed:
  evidence salts are vault-local by design, feed omits them.

## Promotion (same images, metadata + feed only)

- Dashboard `164a9f89d313…`, account `dded4e0616b2…` (unchanged, live).
- Rollback staged: `ebf9b076…` / `738352bb…`; last-good feed kept.
- Dry run exit 0 (cosign edge identity ×4, VM pull, Caddy valid).
- Apply exit 0 on explicit owner go-ahead: pin flipped in metadata,
  fresh feed staged, controlled VM restart, build 1.0.28 verified live.

## Post-apply verification (independent)

- Metadata `checkpoint-publisher-key` == new pin.
- `/api/relayer/checkpoints` 200: canary `ok`, 1 checkpoint,
  `publisher_signed`, finality `unverified` (no on-chain tx yet —
  honest, broadcast pending).
- `/api/context` 1.0.28, `/api/operators` + `/api/explorer/overview` 200.
- Fleet watcher: red run during the restart window (37157424522),
  then green on manual trigger 37159914271 (`success`).

## Broadcast follow-up (same day, done)

- `cast send publish(bytes32)` 0x9a31d8… from payer 0xaCc4… (funded
  0.1 Sepolia ETH via faucet): tx
  `0x8daf8526397dc372ee0c2edf8c828f8c0617ac8b2d6636442353e013486659b3`,
  block 315494446, status success, `CommitmentPublished` log verified.
- Receipt bound (`anchor --tx-hash`): `SequencerConfirmed (Verified
  On-Chain Contract Inclusion)`; `verify-anchor`: L2 Confirmed,
  receipt independently verified.
- Feed re-published (1 record, same pin) and swapped live with no
  restart (directory mount + per-request reads; previous feed kept in
  `last-good`): `/api/relayer/checkpoints` now shows canary `ok`,
  `publisher_signed`, finality `deeply_confirmed` (L2, ≥64 confs).
- Foundry nightly 1.6.0 installed at
  `AppData\Local\foundry\bin` for the broadcast.

## Follow-ups

- ~~Broadcast the anchor~~ done (see above).
- Republish the feed before it ages past 7 days (weekly rhythm or
  automate with the seed in Secret Manager).
- Driver used: `C:\tmp\rollout-publisher-rotation*.ps1` (scratch).
