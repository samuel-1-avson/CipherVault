# CipherVault account and device identity

CipherVault has two identities with different jobs:

| Identity | Purpose | Secret material | Where it is valid |
| --- | --- | --- | --- |
| `account_id` (`cvacct_…`) | Optional control-plane account for hosted web/app access, device management, and vault membership | An Ed25519 account key protected by the host key facility | Account and device registry |
| `vault_id` | Cryptographic namespace for one vault | Vault/device keys and the offline recovery authority | Local vault and authorized operators |

The account key never replaces the vault key and the account record never contains vault plaintext or the offline recovery secret. Anonymous public explorer access and accountless local CLI use therefore remain possible.

## Local account record

The local registry is stored at the path selected by `CIPHERVAULT_ACCOUNT_PATH`, `CIPHERVAULT_ACCOUNT_DIR`, or the platform configuration directory. It contains:

- account ID, display name, public key, and creation time;
- enrolled devices with device ID, public key, label, last-seen time, and revocation time;
- linked vault IDs with a local alias and role; and
- a short-lived session record containing only a hash of a random session token.

The private account signing key is stored separately in an OS-protected `account.key` file. A session expires after 30 minutes, is bound to an enrolled device when a vault is linked, and is removed on logout or device revocation.

The local store exposes a domain-separated challenge-signing operation for the
future hosted login/device ceremony. Unlocking the key is explicit and still
requires the host key facility; no account private key is sent over the network.

## CLI flow

```text
ciphervault auth init --name "Alice"  -> create account and protected account key
ciphervault vault link --alias Work   -> enroll this device and link the current vault
ciphervault auth login                 -> unlock account key and create device session
ciphervault auth status                -> inspect account, links, and session expiry
ciphervault device list                -> inspect active/revoked devices
ciphervault device revoke <DEVICE_ID>  -> revoke a device and its local session
ciphervault vault unlink                -> remove the current vault link and sign out
```

`auth login` is a local session today. A hosted identity provider can exchange a
WebAuthn/device challenge for a cloud session; the local vault store never
receives a passkey private key.

## Self-hosted control-plane API

The repository now includes `services/account` (`ciphervault-account`). It is a
durable SQLite-backed control plane intended to run on a private network. Its
API creates account metadata, issues short-lived login/enrollment challenges,
verifies account-key proofs, persists device and vault links, and revokes
sessions. Set `CIPHERVAULT_ACCOUNT_DATA_DIR` and bind it to a private address;
the Compose files use port `8300` and a persistent volume.

The current ceremony is deliberately explicit:

1. `POST /v1/accounts` registers the account public key and returns the derived
   `cvacct_…` ID.
2. `POST /v1/accounts/:account_id/devices/challenge` creates a five-minute
   enrollment challenge.
3. The account key signs the canonical challenge tuple with the
   `account_device_enrollment` domain; `POST /v1/accounts/:account_id/devices`
   verifies and stores the device.
4. `POST /v1/sessions/challenge` and `POST /v1/sessions` perform the same
   account-key proof for a 30-minute bearer session.
5. `POST /v1/accounts/:account_id/devices/:device_id_hex/revoke` revokes the
   device, its sessions, and configured operator bindings.

For passkeys, an authenticated bootstrap session calls
`POST /v1/accounts/:account_id/webauthn/registration/options`, then submits the
browser's `clientDataJSON` and `attestationObject` to
`POST /v1/accounts/:account_id/webauthn/registration/verify`. Later sign-in
uses `POST /v1/webauthn/authentication/options` and
`POST /v1/webauthn/authentication/verify`; the returned bearer session is still
account-scoped and expires after 30 minutes. The server advertises these
capabilities at `GET /v1/capabilities`.

An authenticated account session can revoke a credential with
`POST /v1/accounts/:account_id/webauthn/credentials/:credential_id_hex/revoke`.
The revocation is durable, audited, and blocks future assertions.
Login responses also set an HttpOnly `ciphervault_account_session` cookie for
same-origin browser clients; the service accepts that cookie or an
`Authorization: Bearer` header on protected routes.

The dashboard proxies the account service at `/api/account/*` so browser
origins never need direct access to the control-plane container. The hosted
explorer exposes passkey and authenticator sign-in controls; account management
exposes passkey registration, TOTP enrollment, and revocation. It sends only
the ceremony payloads and retains resulting sessions in the HttpOnly cookie.
Account IDs are kept in browser storage only as a convenience for selecting the
account during sign-in.

The account service accepts browser WebAuthn registration and assertions for
`fmt=none` credentials using Ed25519 (`-8`) or ES256 (`-7`). It verifies the
configured origin and RP ID, challenge binding, user presence, credential
signature, and monotonic signature counter before issuing a 30-minute session.
Registration binds the credential to the enrolled device session; revoking that
device invalidates its WebAuthn sessions and configured operator bindings.
Challenges are single-use and consumed atomically so an assertion cannot be
replayed to mint a second session.

Authenticator-app MFA is available as a separate RFC 6238 ceremony. The
service exposes enrollment (`POST /v1/accounts/:account_id/totp/enrollment`,
then `/enrollment/verify`), revocation (`/totp/revoke`), and account-session
login (`POST /v1/totp/authentication/options` followed by `/verify`). Seeds are
wrapped with AES-256-GCM using the 32-byte `CIPHERVAULT_ACCOUNT_TOTP_KEY`
environment secret before they enter SQLite. Codes are six digits with a
30-second period, a one-step clock-skew window, and a durable replay barrier.
TOTP login produces an account session; a linked vault still requires an
enrolled device-bound session for private vault operations.
The account-key ceremony remains available for bootstrap and recovery. Packed
attestation and enterprise attestation policy are still outside the supported
`fmt=none` profile; the hosted UI intentionally asks the browser for
`attestation: none` and requires an already enrolled device session for adding
a new credential.

## Web and operator binding

The private dashboard reports account state at `/api/context` and exposes local status/login/logout endpoints. If the current vault is linked, private API calls require the same active account session and current device identity. If no account is configured, the accountless private dashboard remains available on the local host.

Operator enrollment records accept optional account and device identifiers. Strict challenge issuance compares those identifiers when an enrollment is bound, and the storage client/CLI pool sends them in the challenge payload and headers. Existing unbound records remain readable for migration; production still needs an owner-controlled enrollment ceremony and a decision to require the binding for all operators.

## Hosted work still required

1. Production WebAuthn policy and browser ceremony: packed-attestation support
   where required, discoverable-credential UX, and managed browser enrollment
   for a brand-new account.
2. Explicit vault-link authorization and audit events; linking must prove
   control of the vault device key without uploading vault secrets.
3. TLS, origin, rate, replay, expiry, and session-cookie policy for the hosted
   web/app clients.
4. Independent production provisioning of operator fingerprints and the
   account/device enrollment records.
5. Provisioning `CIPHERVAULT_ACCOUNT_TOTP_KEY`, enabling the dashboard's
   authenticator controls, and completing browser/CLI step-up authorization
   tests before exposing hosted private vault routes.

The hosted account API now includes invitation and membership routes
(`POST/GET /v1/accounts/:account_id/invitations`,
`POST /v1/invitations/accept`, membership listing/revocation) and one-time
recovery codes (`POST /v1/accounts/:account_id/recovery/codes`,
`POST /v1/recovery/redeem`). These are durable and audited; email delivery,
role-aware vault authorization, recovery policy approval, and polished account
management screens remain deployment work.

Until those services are deployed, an account is useful for local device/vault organization and for defining the protocol boundary, but it is not a cloud login by itself.
