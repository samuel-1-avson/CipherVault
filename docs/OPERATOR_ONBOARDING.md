# Joining CipherVault as an Operator

This guide is for a new community operator: what you need, what to run,
and what happens after you join. To join the network you need an invite
ticket from a fleet keyholder — there is no self-service signup yet.

## What you are signing up for

You run `ciphervault-operator` on your own server. It stores opaque,
client-side-encrypted chunks for the network: you cannot read user
data (ciphertext only), and anything corrupted fails digest checks and
is ignored. In exchange the network expects reasonable uptime so
replication and repair can rely on you.

A small VPS is enough to start (the founding fleet runs e2-micro
class machines). You need:

- Docker (or a Rust toolchain to build from source).
- A server that can receive inbound connections on your HTTP port plus
  P2P ports 9101/TCP and 9102/UDP (adjust if you remap them).
- A domain with TLS is recommended for the HTTP endpoint (the fleet
  terminates TLS at Caddy); plain HTTP behind your own reverse proxy
  also works for testing.

## The join flow

**1. Install and generate your node identity.**

```sh
ciphervault node setup --name <your-operator-name> --data-dir <path>
```

The wizard prints your node identity — a 64-character public key —
and asks whether you have a ticket yet. You do not: leave it running
standalone for now.

**2. Send your node public key to a fleet keyholder.**

Any ordinary channel (email, chat). This is also the vetting step: a
short conversation about who you are and what you will run. Expect to
share your planned endpoint and how you will keep the node online.

**3. Receive your ticket plus connection details.**

The keyholders will send you back:

- `ticket.json` — your invite ticket (single-use, expires; default
  TTL 7 days for grace rejoin).
- The fleet `--via` endpoints (HTTP URLs of admitting nodes).
- P2P bootstrap multiaddrs so your node can mesh after joining.

**4. Join.**

```sh
ciphervault invite join ticket.json --node <your-own-endpoint> --via <fleet-url-1> --via <fleet-url-2>
```

A successful join admits you into **probation**. If it fails: `403`
means the ticket is bad, expired, or for a different node key (ask for
a fresh one); `409` means it was already spent (same remedy).

**5. Probation (~24 hours), then graduation.**

Probation restricts exactly one thing: the fleet will not send you
repair replicas yet. Everything else works — you hold data, serve
reads, and heartbeat on the mesh. Stay online and keep heartbeating
(or run `ciphervault invite refresh` periodically); once you have
served the minimum time with recent liveness, you graduate to full
member automatically. A silent node does not graduate until it proves
life again.

After graduation the fleet admin adds your key to the trusted-peers
set and your endpoint to the mesh keepalive — from then on you are
maintained like every other member.

## Standing and expectations

- Check your standing any time: `ciphervault invite refresh` reports
  `probation` or `full`.
- Keep your node key safe: it is your identity. If it is lost or
  compromised, tell a keyholder — you will need a fresh ticket for a
  new key.
- Resource abuse (filling the network with junk, attacking peers)
  gets you removed; the abuse vocabulary the fleet uses is recorded
  in `docs/adr/010-incentives-sla-abuse.md`.
- Quorum note: tickets are approved K-of-N by fleet keyholders, and
  every admission is logged as evidence. No single person can add or
  remove operators unilaterally once the quorum is distributed.

## Quick command reference

| Step     | Command                                                        |
| -------- | -------------------------------------------------------------- |
| Setup    | `ciphervault node setup --name NAME --data-dir PATH`           |
| Join     | `ciphervault invite join TICKET --node SELF --via FLEET...`    |
| Refresh  | `ciphervault invite refresh --node SELF --via FLEET...`        |
| Diagnose | `ciphervault invite verify TICKET --fleet-keys K1,K2...`       |
