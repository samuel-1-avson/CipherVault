# Key Ceremonies & Backups (Track 4)

Every signing key in the system, where it lives, how it is backed up,
and the ceremony for issuing and rotating it. Anything marked MISSING
is a real gap: practice it before federating or promoting to mainnet.

## Inventory

| Key | Purpose | Holder / location | Backup |
|---|---|---|---|
| Fleet seed (`fleet.seed`) | Signs join tickets; root of fleet membership | Project holder, `fleet.seed` file, pubkey in KeePass | KeePass + offline copy; loss = re-bootstrap membership |
| Operator `operator.key` (x3) | Node identity, lease/PoS signatures | Each node's data dir, mode `0600` | `ciphervault node setup` backup bundle (`operator.key` + config + token); rotation keeps `operator.key.previous-*` |
| Publisher signing key | Signs the public checkpoint feed | Publisher worker env `CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX` | Offline copy with the fleet seed; verifying key pinned on dashboard (`..._PUBLISHER_KEY`) |
| Account TOTP key | Dashboard account second factor | GCP Secret Manager (`ciphervault-account-totp-key`) | Secret Manager versions; see runbook R3 |
| User master secret R | Vault root recovery | Paper recovery kit, holder only | Paper kit + M-of-N Shamir guardian shares (`recovery_kit`, `recover --shares`) |
| Device keys | Per-device vault auth | OS keyring-sealed `vault.db` | Included in vault backup; rotation via rekey flow |
| Anchor payer key | Pays L2 `publish(bytes32)` gas (manual) | Payer-held, never in chat/repo/CI | Payer's own custody; fund with small L2 balance only |
| Service tokens | Operator control-plane auth | `/opt/ciphervault/.env` per node | Same backup as node `.env` |

## Ceremonies

### New operator identity (exists, runbook section 8)

1. Boot once to mint `operator.key` (`0600`).
2. `--print-identity` offline, append `op_<id>=<key>` to
   `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES`, restart dashboard.
3. Confirm explorer card flips `Unverified` -> `Verified`.

### Operator rotation = revocation (exists, runbook section 8)

`--rotate-key --print-identity`, pin new key alongside old, confirm,
then remove the old fingerprint. A retired key that reappears shows
`Unverified`.

Rehearsal record (2026-09-26, local): mint identity A, `--rotate-key`
to identity B (A != B), timestamped `operator.key.previous-*` backup
kept, reprint stable at B. Tooling path PASS; live-fleet repinning
remains a human step per the runbook.

### Fleet-key rotation (MISSING procedure + drill)

No rotation drill has ever been run (playbook T5). First exercise, on
a rehearsal node before touching the fleet:

1. Generate a new offline seed; print both pubkeys.
2. Re-pin every node (`CIPHERVAULT_FLEET_KEY`); join fails closed while
   any node still pins the old key, so roll node by node and confirm
   `/healthz` + join-accept between each.
3. Old tickets die with the old key; re-issue any outstanding invites.
4. Record the drill (date, nodes, result) here.

### Publisher rotation (procedure exists, drill not recorded)

1. Generate a dedicated Ed25519 key offline.
2. Set it on the publisher worker; re-pin the dashboard
   (`CIPHERVAULT_PUBLIC_CHECKPOINT_PUBLISHER_KEY`).
3. Confirm `/api/anchors` still reports `publisher_signed`, then
   destroy the old signing key.

### User recovery (exists, drilled)

Paper kit or guardian shares rebuild files AND a working store
(`recover`), proven by the wipe-to-pull chaos drill. Guardians hold
printed share sheets; rotation = re-split + re-distribute.

## Backup rules

- Node data dirs (`/opt/ciphervault/data`) and web volumes back up on
  the operators' schedule; playbook section 6 covers restore.
- Never commit keys, seeds, `.env` files, or share sheets: the
  pre-commit secret check is the last line, not the first.
- Verify restores, not just backups: a backup counts only after a
  restore drill reads it back (operator key reprint, feed verify,
  recover-to-pull).

## Open gaps

- Fleet-key rotation drill never run (see above).
- Fleet is open-write (public live test); re-close procedure exists in
  the runbook but is a policy decision, not yet taken.
