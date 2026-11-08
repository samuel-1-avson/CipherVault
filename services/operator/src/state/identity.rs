//! Identity, enrollment, permissions, and membership views.

use super::*;

pub(crate) fn valid_account_id(value: &str) -> bool {
    let value = value.trim();
    value.len() == 39
        && value
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("cvacct_"))
        && hex::decode(&value[7..]).map(|bytes| bytes.len()) == Ok(16)
}

pub(crate) fn valid_device_id(value: &str) -> bool {
    hex::decode(value.trim()).map(|bytes| bytes.len()) == Ok(32)
}

pub(crate) fn normalize_identity_binding(
    account_id: Option<&str>,
    device_id_hex: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    let account_id = account_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let device_id_hex = device_id_hex
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    if let Some(account_id) = account_id.as_deref() {
        if !valid_account_id(account_id) {
            return Err("account_id must use the cvacct_<32 hex characters> format".into());
        }
    }
    if let Some(device_id_hex) = device_id_hex.as_deref() {
        if !valid_device_id(device_id_hex) {
            return Err("device_id_hex must be 32-byte hex".into());
        }
    }
    if account_id.is_none() != device_id_hex.is_none() {
        return Err("account_id and device_id_hex must be supplied together".into());
    }
    Ok((account_id, device_id_hex))
}

pub const PERMISSION_READ: u32 = 1;
pub const PERMISSION_WRITE: u32 = 2;
pub const PERMISSION_FLEET_ADMIN: u32 = 1 << 16;
pub const PERMISSION_VAULT_DEFAULT: u32 = PERMISSION_READ | PERMISSION_WRITE;

/// One immutable policy shared by startup, HTTP, P2P, and persisted sessions.
#[derive(Clone, Debug)]
pub struct OperatorSecurityConfig {
    pub strict_auth: bool,
    pub require_enrollment: bool,
}

impl OperatorSecurityConfig {
    pub fn from_env() -> Self {
        Self::from_flags(
            std::env::var("CIPHERVAULT_OPERATOR_STRICT_AUTH")
                .ok()
                .as_deref(),
            std::env::var("CIPHERVAULT_OPERATOR_REQUIRE_ENROLLMENT")
                .ok()
                .as_deref(),
        )
    }

    pub fn from_flags(strict: Option<&str>, enrollment: Option<&str>) -> Self {
        let enabled = |value: Option<&str>, default: bool| {
            value
                .map(|value| {
                    // Invalid values fail closed. Only an explicit false disables a guard.
                    !matches!(
                        value.trim().to_ascii_lowercase().as_str(),
                        "0" | "false" | "no"
                    )
                })
                .unwrap_or(default)
        };
        let strict_auth = enabled(strict, true);
        Self {
            strict_auth,
            require_enrollment: strict_auth || enabled(enrollment, false),
        }
    }

    /// Explicit compatibility policy for isolated tests or migration deployments.
    pub fn legacy() -> Self {
        Self {
            strict_auth: false,
            require_enrollment: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]

pub struct EnrolledIdentity {
    pub vault_id_hex: String,
    pub public_key_hex: String,
    pub permissions: u32,
    pub enrolled_at_utc: u64,
    #[serde(default)]
    pub revoked_at_utc: Option<u64>,
    /// Optional control-plane account that owns this device identity.
    /// Older identity records remain valid with this field omitted.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Optional account device ID. When present, strict challenge issuance
    /// requires the caller to present the same device binding.
    #[serde(default)]
    pub device_id_hex: Option<String>,
}

/// Fleet membership standing of a routing-table peer. Ticket joins enter
/// [`MembershipStatus::Probation`]; control-plane announces (service
/// token) and graduations confer [`MembershipStatus::Full`]. Peers with
/// no record at all (meshed before verified join existed) read as Full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MembershipStatus {
    Probation,
    Full,
}

/// Durable per-peer membership record (`peer-membership.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMembership {
    pub status: MembershipStatus,
    pub joined_utc: u64,
    pub last_seen_utc: u64,
    pub graduated_utc: Option<u64>,
}

/// Control-plane membership listing: routing entry plus standing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipView {
    pub operator_id: String,
    pub endpoint: String,
    pub signing_pk_hex: String,
    pub status: MembershipStatus,
    pub joined_utc: Option<u64>,
    pub last_seen_utc: Option<u64>,
    pub graduated_utc: Option<u64>,
}

/// Tamper-evident admission record (`join-admissions.json`): who admitted
/// whom, under what rule, and when. One entry per successful ticket
/// admission (legacy single-sig and quorum alike); `signer_pks` holds
/// the distinct approving fleet keys and `ticket_sha256` pins the exact
/// ticket bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRecord {
    pub admitted_utc: u64,
    pub node_pk_hex: String,
    pub operator_id: String,
    pub nonce_hex: String,
    pub expires_utc: u64,
    pub ticket_version: u32,
    pub signer_pks: Vec<String>,
    pub ticket_sha256: String,
}

/// Inbound fleet-join request (`join-requests.json`): a prospective operator
/// announcing itself. No trust is granted by submitting — the descriptor
/// must self-verify, and admission still requires the ticket/graduation
/// flow. One record per operator id (resubmits update in place).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestRecord {
    pub request_id: String,
    pub operator_id: String,
    pub endpoint: String,
    pub node_pk_hex: String,
    pub contact: String,
    pub requested_at_utc: u64,
    pub status: String,
}

/// Verified-join authorization mode: legacy single fleet key, or a
/// quorum key set with threshold.
pub(crate) enum JoinAuth {
    Legacy { key: String },
    Quorum { set: Vec<String>, threshold: usize },
}

/// Sovereign chain sync state (Phase 2 item 3). The hub is absent until the
/// fleet validator set is installed; its ledger opens from local blocks
/// when present and adopts certified tips otherwise.
#[derive(Debug, Default)]
pub struct ChainSyncSlot {
    pub validators: Option<ValidatorSet>,
    pub hub: Option<ChainSyncHub>,
}
