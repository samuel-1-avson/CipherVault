//! Scoped resource identifiers and validated domain records.
//!
//! Phase 1 (T-101) of the scoped-secret implementation plan
//! (`report/SCOPED_SECRETS_IMPLEMENTATION_TASKS.md`): every secret belongs to
//! an explicit scope `tenant → workspace → project → environment`, with
//! optional repository/service confinement. Identifiers are 128-bit
//! UUIDv7-layout values; human handles (slugs, secret names) are validated
//! display keys with zero authorization authority.

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::FormatError;

/// Maximum slug length (projects, environments, services).
pub const MAX_SLUG_LEN: usize = 64;
/// Maximum secret-name length.
pub const MAX_SECRET_NAME_LEN: usize = 128;
/// Maximum description length (characters).
pub const MAX_DESCRIPTION_LEN: usize = 1024;
/// Maximum single-tag length.
pub const MAX_TAG_LEN: usize = 64;
/// Maximum tags per secret.
pub const MAX_TAGS: usize = 32;
/// Maximum provider-issued repository identifier length.
pub const MAX_EXTERNAL_ID_LEN: usize = 256;
/// XChaCha20-Poly1305 nonce length (see `ciphervault_crypto::aead`).
pub const NONCE_LEN: usize = 24;
/// SHA-256 digest length.
pub const DIGEST_LEN: usize = 32;

/// Generates 16 random bytes laid out per RFC 9562 §5.2 (UUIDv7):
/// 48-bit big-endian unix milliseconds, 4-bit version (7), 12 random bits,
/// 2-bit variant (10), 62 random bits. Timestamp-ordered and CSPRNG-backed.
/// No `uuid` dependency needed: the layout is byte-compatible with UUIDv7.
fn new_v7_id() -> [u8; 16] {
    let unix_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| {
            elapsed
                .as_secs()
                .saturating_mul(1000)
                .saturating_add(u64::from(elapsed.subsec_millis()))
        })
        .unwrap_or(0);
    let mut out = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut out);
    out[0..6].copy_from_slice(&unix_ms.to_be_bytes()[2..8]);
    out[6] = (out[6] & 0x0f) | 0x70;
    out[8] = (out[8] & 0x3f) | 0x80;
    out
}

macro_rules! scoped_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Generates a fresh random v7-layout identifier (OS CSPRNG).
            pub fn generate() -> Self {
                Self(new_v7_id())
            }

            /// Constructs from raw 16 bytes (no validation; parsing validates).
            pub fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Exposes the raw identifier bytes.
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Lowercase hex encoding (32 chars), the canonical text form.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parses the canonical 32-char hex form (surrounding whitespace ignored).
            pub fn parse_hex(text: &str) -> Result<Self, FormatError> {
                let bytes = hex::decode(text.trim()).map_err(|err| {
                    FormatError::MalformedRecord(format!(
                        "invalid {} hex: {err}",
                        stringify!($name)
                    ))
                })?;
                if bytes.len() != 16 {
                    return Err(FormatError::MalformedRecord(format!(
                        "invalid {} length: expected 16 bytes, got {}",
                        stringify!($name),
                        bytes.len()
                    )));
                }
                let mut out = [0u8; 16];
                out.copy_from_slice(&bytes);
                Ok(Self(out))
            }

            /// UUID version nibble (7 for generated identifiers).
            pub fn version(&self) -> u8 {
                (self.0[6] >> 4) & 0x0f
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = FormatError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse_hex(text)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::parse_hex(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

scoped_id!(
    TenantId,
    "Tenant/organization identifier (top tenancy boundary)."
);
scoped_id!(WorkspaceId, "Workspace identifier within a tenant.");
scoped_id!(ProjectId, "Project identifier (primary security boundary).");
scoped_id!(EnvironmentId, "Environment identifier within a project.");
scoped_id!(
    RepositoryBindingId,
    "Repository-binding identifier (durable VCS link)."
);
scoped_id!(ServiceId, "Service/workload identifier within a project.");
scoped_id!(SecretId, "Secret logical-identity identifier.");
scoped_id!(SecretVersionId, "Secret-version identifier.");
scoped_id!(
    MigrationId,
    "Migration-run identifier (ledgered vault import)."
);
scoped_id!(
    MigrationEntryId,
    "Migration-ledger entry identifier (one secret's journey)."
);
scoped_id!(PolicyId, "Access-policy identifier.");
scoped_id!(KeyId, "Encryption-key identifier (KEK/DEK reference).");

fn is_slug_char(value: char) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit() || value == '-' || value == '_'
}

/// Validates project/environment/service slugs: `^[a-z0-9][a-z0-9\-_]{0,63}$`.
pub fn validate_slug(kind: &str, slug: &str) -> Result<(), FormatError> {
    if slug.len() > MAX_SLUG_LEN {
        return Err(FormatError::MalformedRecord(format!(
            "{kind} slug exceeds {MAX_SLUG_LEN} bytes"
        )));
    }
    let mut chars = slug.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() => {}
        _ => {
            return Err(FormatError::MalformedRecord(format!(
                "{kind} slug must start with a lowercase letter or digit"
            )))
        }
    }
    if !slug.chars().all(is_slug_char) {
        return Err(FormatError::MalformedRecord(format!(
            "{kind} slug must contain only lowercase letters, digits, '-' or '_'"
        )));
    }
    Ok(())
}

/// Validates secret names: `^[A-Z][A-Z0-9_]{0,127}$` (back-compatible with `.env` keys).
pub fn validate_secret_name(name: &str) -> Result<(), FormatError> {
    if name.len() > MAX_SECRET_NAME_LEN {
        return Err(FormatError::MalformedRecord(format!(
            "secret name exceeds {MAX_SECRET_NAME_LEN} bytes"
        )));
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {}
        _ => {
            return Err(FormatError::MalformedRecord(
                "secret name must start with an uppercase letter".to_string(),
            ))
        }
    }
    if !name
        .chars()
        .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == '_')
    {
        return Err(FormatError::MalformedRecord(
            "secret name must contain only uppercase letters, digits or '_'".to_string(),
        ));
    }
    Ok(())
}

fn is_tag_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '-' | ':' | '/')
}

/// Validates a single tag: 1–64 chars of `[A-Za-z0-9._\-:/]`.
pub fn validate_tag(tag: &str) -> Result<(), FormatError> {
    if tag.is_empty() || tag.len() > MAX_TAG_LEN {
        return Err(FormatError::MalformedRecord(format!(
            "tag must be 1–{MAX_TAG_LEN} bytes"
        )));
    }
    if !tag.chars().all(is_tag_char) {
        return Err(FormatError::MalformedRecord(
            "tag must contain only letters, digits or '._-:/'".to_string(),
        ));
    }
    Ok(())
}

/// Validates descriptions: at most 1024 characters of arbitrary text.
pub fn validate_description(description: &str) -> Result<(), FormatError> {
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(FormatError::MalformedRecord(format!(
            "description exceeds {MAX_DESCRIPTION_LEN} characters"
        )));
    }
    Ok(())
}

/// Validates provider-issued repository identifiers: non-empty printable
/// ASCII without surrounding whitespace, at most 256 bytes. The provider ID
/// (not the slug) is the durable identity — see Deliverable C §5.
pub fn validate_external_repo_id(id: &str) -> Result<(), FormatError> {
    if id.len() > MAX_EXTERNAL_ID_LEN || id.trim().is_empty() || id != id.trim() {
        return Err(FormatError::MalformedRecord(
            "repository external id must be 1–256 bytes with no surrounding whitespace".to_string(),
        ));
    }
    if !id.chars().all(|value| value.is_ascii_graphic()) {
        return Err(FormatError::MalformedRecord(
            "repository external id must be printable ASCII".to_string(),
        ));
    }
    Ok(())
}

/// Explicit authorization scope threaded through every scoped API.
/// Constructed from validated inputs only — never inferred from ambient state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub environment_id: EnvironmentId,
}

impl Scope {
    /// Builds a scope from its three mandatory boundaries.
    pub fn new(tenant_id: TenantId, project_id: ProjectId, environment_id: EnvironmentId) -> Self {
        Self {
            tenant_id,
            project_id,
            environment_id,
        }
    }
}

/// Supported version-control providers for repository bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryProvider {
    Github,
    Gitlab,
    Bitbucket,
    SelfHosted,
}

/// Lifecycle of a repository binding (`active → suspended → revoked`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Active,
    Suspended,
    Revoked,
}

/// Lifecycle of a project.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectStatus {
    Active,
    ScheduledDeletion,
    Purged,
}

/// Lifecycle of a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStatus {
    Active,
    Deprecated,
    ScheduledDeletion,
}

/// Project metadata (ownership boundary). Secrets live under a project;
/// repositories are bound to it (see [`RepositoryBindingRecord`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub project_id: ProjectId,
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub slug: String,
    pub name: String,
    pub status: ProjectStatus,
    pub created_at_utc: u64,
}

impl ProjectRecord {
    /// Validating constructor: slugs are checked, names must be non-empty.
    pub fn new(
        project_id: ProjectId,
        tenant_id: TenantId,
        workspace_id: WorkspaceId,
        slug: &str,
        name: &str,
        created_at_utc: u64,
    ) -> Result<Self, FormatError> {
        validate_slug("project", slug)?;
        if name.trim().is_empty() || name.chars().count() > MAX_DESCRIPTION_LEN {
            return Err(FormatError::MalformedRecord(
                "project name must be 1–1024 characters".to_string(),
            ));
        }
        Ok(Self {
            project_id,
            tenant_id,
            workspace_id,
            slug: slug.to_string(),
            name: name.to_string(),
            status: ProjectStatus::Active,
            created_at_utc,
        })
    }
}

/// Environment metadata (strict isolation gate within a project).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    pub environment_id: EnvironmentId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub slug: String,
    /// Ordering hint (0 = dev … 2 = prod). Ordering only — never authority.
    pub tier: u8,
    pub created_at_utc: u64,
}

impl EnvironmentRecord {
    /// Validating constructor.
    pub fn new(
        environment_id: EnvironmentId,
        scope: Scope,
        slug: &str,
        tier: u8,
        created_at_utc: u64,
    ) -> Result<Self, FormatError> {
        validate_slug("environment", slug)?;
        Ok(Self {
            environment_id,
            tenant_id: scope.tenant_id,
            project_id: scope.project_id,
            slug: slug.to_string(),
            tier,
            created_at_utc,
        })
    }
}

/// Durable VCS link binding a repository to a project. Identity is
/// `(provider, external_repo_id)`; names and URLs are display-only and may
/// change on rename/transfer without affecting secret references.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryBindingRecord {
    pub binding_id: RepositoryBindingId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub provider: RepositoryProvider,
    pub external_repo_id: String,
    pub repo_full_name: String,
    pub repo_url: String,
    pub installation_id: Option<String>,
    pub status: BindingStatus,
    pub created_at_utc: u64,
}

impl RepositoryBindingRecord {
    /// Validating constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding_id: RepositoryBindingId,
        tenant_id: TenantId,
        project_id: ProjectId,
        provider: RepositoryProvider,
        external_repo_id: &str,
        repo_full_name: &str,
        repo_url: &str,
        installation_id: Option<String>,
        created_at_utc: u64,
    ) -> Result<Self, FormatError> {
        validate_external_repo_id(external_repo_id)?;
        if repo_full_name.trim().is_empty() || repo_url.trim().is_empty() {
            return Err(FormatError::MalformedRecord(
                "repository display name and url must not be empty".to_string(),
            ));
        }
        Ok(Self {
            binding_id,
            tenant_id,
            project_id,
            provider,
            external_repo_id: external_repo_id.to_string(),
            repo_full_name: repo_full_name.to_string(),
            repo_url: repo_url.to_string(),
            installation_id,
            status: BindingStatus::Active,
            created_at_utc,
        })
    }
}

/// Service/workload metadata for least-privilege confinement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub service_id: ServiceId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub slug: String,
    pub created_at_utc: u64,
}

impl ServiceRecord {
    /// Validating constructor.
    pub fn new(
        service_id: ServiceId,
        tenant_id: TenantId,
        project_id: ProjectId,
        slug: &str,
        created_at_utc: u64,
    ) -> Result<Self, FormatError> {
        validate_slug("service", slug)?;
        Ok(Self {
            service_id,
            tenant_id,
            project_id,
            slug: slug.to_string(),
            created_at_utc,
        })
    }
}

/// Searchable secret metadata. Never carries the value — values live only in
/// [`SecretVersionRecord`] ciphertext (and transiently in `SecretValue` RAM).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub secret_id: SecretId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub environment_id: EnvironmentId,
    pub repository_binding_id: Option<RepositoryBindingId>,
    pub service_id: Option<ServiceId>,
    pub name: String,
    pub secret_type: String,
    pub description: String,
    pub tags: Vec<String>,
    pub status: SecretStatus,
    pub policy_id: Option<PolicyId>,
    pub current_version: u32,
    pub created_by: String,
    pub created_at_utc: u64,
    pub updated_at_utc: u64,
    pub last_rotated_at_utc: Option<u64>,
    pub expires_at_utc: Option<u64>,
    pub last_accessed_at_utc: Option<u64>,
}

impl SecretMetadata {
    /// Validating constructor for the mandatory fields; optional fields use
    /// the `with_*` builders. Starts at version 1, status active.
    pub fn new(
        scope: Scope,
        name: &str,
        secret_type: &str,
        created_by: &str,
        created_at_utc: u64,
    ) -> Result<Self, FormatError> {
        validate_secret_name(name)?;
        if secret_type.trim().is_empty() || created_by.trim().is_empty() {
            return Err(FormatError::MalformedRecord(
                "secret_type and created_by must not be empty".to_string(),
            ));
        }
        Ok(Self {
            secret_id: SecretId::generate(),
            tenant_id: scope.tenant_id,
            project_id: scope.project_id,
            environment_id: scope.environment_id,
            repository_binding_id: None,
            service_id: None,
            name: name.to_string(),
            secret_type: secret_type.to_string(),
            description: String::new(),
            tags: Vec::new(),
            status: SecretStatus::Active,
            policy_id: None,
            current_version: 1,
            created_by: created_by.to_string(),
            created_at_utc,
            updated_at_utc: created_at_utc,
            last_rotated_at_utc: None,
            expires_at_utc: None,
            last_accessed_at_utc: None,
        })
    }

    /// Sets the description (validated).
    pub fn with_description(mut self, description: &str) -> Result<Self, FormatError> {
        validate_description(description)?;
        description.clone_into(&mut self.description);
        Ok(self)
    }

    /// Sets tags (each validated, at most [`MAX_TAGS`]).
    pub fn with_tags(mut self, tags: &[String]) -> Result<Self, FormatError> {
        if tags.len() > MAX_TAGS {
            return Err(FormatError::MalformedRecord(format!(
                "too many tags: at most {MAX_TAGS}"
            )));
        }
        for tag in tags {
            validate_tag(tag)?;
        }
        self.tags = tags.to_vec();
        Ok(self)
    }

    /// Confines the secret to one repository binding (opt-in).
    pub fn with_repository_binding(mut self, binding: RepositoryBindingId) -> Self {
        self.repository_binding_id = Some(binding);
        self
    }

    /// Confines the secret to one service (opt-in).
    pub fn with_service(mut self, service: ServiceId) -> Self {
        self.service_id = Some(service);
        self
    }

    /// Attaches an explicit access policy (default: inherit project policy).
    pub fn with_policy(mut self, policy: PolicyId) -> Self {
        self.policy_id = Some(policy);
        self
    }

    /// Sets an expiry timestamp.
    pub fn with_expiry(mut self, expires_at_utc: u64) -> Self {
        self.expires_at_utc = Some(expires_at_utc);
        self
    }

    /// Re-validates a wire-received value (deserialization bypasses `new`).
    pub fn validate(&self) -> Result<(), FormatError> {
        validate_secret_name(&self.name)?;
        validate_description(&self.description)?;
        if self.tags.len() > MAX_TAGS {
            return Err(FormatError::MalformedRecord(format!(
                "too many tags: at most {MAX_TAGS}"
            )));
        }
        for tag in &self.tags {
            validate_tag(tag)?;
        }
        if self.current_version == 0 {
            return Err(FormatError::MalformedRecord(
                "current_version must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// One immutable encrypted version of a secret value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretVersionRecord {
    pub version_id: SecretVersionId,
    pub secret_id: SecretId,
    pub version: u32,
    pub encryption_key_id: KeyId,
    /// 24-byte XChaCha20-Poly1305 nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Ciphertext including the 16-byte Poly1305 tag.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// SHA-256 of the plaintext (audit/dedup only — never the value).
    #[serde(with = "serde_bytes")]
    pub value_sha256: Vec<u8>,
    pub created_by: String,
    pub created_at_utc: u64,
}

impl SecretVersionRecord {
    /// Validating constructor: 24-byte nonce, non-empty ciphertext, 32-byte digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_id: SecretId,
        version: u32,
        encryption_key_id: KeyId,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        value_sha256: Vec<u8>,
        created_by: &str,
        created_at_utc: u64,
    ) -> Result<Self, FormatError> {
        if version == 0 {
            return Err(FormatError::MalformedRecord(
                "version must be at least 1".to_string(),
            ));
        }
        if nonce.len() != NONCE_LEN {
            return Err(FormatError::MalformedRecord(format!(
                "nonce must be {NONCE_LEN} bytes, got {}",
                nonce.len()
            )));
        }
        if ciphertext.is_empty() {
            return Err(FormatError::MalformedRecord(
                "ciphertext must not be empty".to_string(),
            ));
        }
        if value_sha256.len() != DIGEST_LEN {
            return Err(FormatError::MalformedRecord(format!(
                "value digest must be {DIGEST_LEN} bytes, got {}",
                value_sha256.len()
            )));
        }
        if created_by.trim().is_empty() {
            return Err(FormatError::MalformedRecord(
                "created_by must not be empty".to_string(),
            ));
        }
        Ok(Self {
            version_id: SecretVersionId::generate(),
            secret_id,
            version,
            encryption_key_id,
            nonce,
            ciphertext,
            value_sha256,
            created_by: created_by.to_string(),
            created_at_utc,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{from_canonical_cbor, to_canonical_cbor};

    fn test_scope() -> Scope {
        Scope::new(
            TenantId::generate(),
            ProjectId::generate(),
            EnvironmentId::generate(),
        )
    }

    #[test]
    fn test_id_generation_version_and_uniqueness() {
        let first = SecretId::generate();
        assert_eq!(first.version(), 7);
        assert_eq!(first.to_hex().len(), 32);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(SecretId::generate()));
        }
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn test_id_hex_roundtrip_and_errors() {
        let id = ProjectId::generate();
        assert_eq!(ProjectId::parse_hex(&id.to_hex()).unwrap(), id);
        assert_eq!(id.to_string().parse::<ProjectId>().unwrap(), id);
        assert!(ProjectId::parse_hex("not-hex!!").is_err());
        assert!(ProjectId::parse_hex("abcd").is_err());
        assert!(ProjectId::parse_hex(&"00".repeat(17)).is_err());
    }

    #[test]
    fn test_id_serde_and_cbor_roundtrip() {
        let id = TenantId::generate();
        let json = serde_json::to_string(&id).expect("test requires serde_json");
        let back: TenantId = serde_json::from_str(&json).expect("test requires serde_json");
        assert_eq!(id, back);
        let cbor = to_canonical_cbor(&id).unwrap();
        let from_cbor: TenantId = from_canonical_cbor(&cbor).unwrap();
        assert_eq!(id, from_cbor);
        // Canonical stability: identical bytes for identical values.
        assert_eq!(cbor, to_canonical_cbor(&id).unwrap());
    }

    #[test]
    fn test_slug_validator() {
        for valid in ["payments", "a", "shop-v2", "back_end", "0init"] {
            validate_slug("project", valid).unwrap();
        }
        for invalid in [
            "",
            "Upper",
            "-lead",
            "_lead",
            "has space",
            "dot.name",
            "ünicode",
        ] {
            assert!(validate_slug("project", invalid).is_err(), "{invalid}");
        }
        assert!(validate_slug("project", &"a".repeat(65)).is_err());
    }

    #[test]
    fn test_secret_name_validator() {
        for valid in ["DATABASE_URL", "A", "X_9", &"A".repeat(128)] {
            validate_secret_name(valid).unwrap();
        }
        for invalid in [
            "",
            "lower",
            "9START",
            "_START",
            "HAS-DASH",
            "HAS SPACE",
            "ÜNICODE",
        ] {
            assert!(validate_secret_name(invalid).is_err(), "{invalid}");
        }
        assert!(validate_secret_name(&"A".repeat(129)).is_err());
    }

    #[test]
    fn test_tag_description_and_external_id_validators() {
        validate_tag("database").unwrap();
        validate_tag("pci-dss/v2:primary").unwrap();
        assert!(validate_tag("").is_err());
        assert!(validate_tag("has space").is_err());
        validate_description(&"x".repeat(1024)).unwrap();
        assert!(validate_description(&"x".repeat(1025)).is_err());
        validate_external_repo_id("84920194").unwrap();
        validate_external_repo_id("{a3b1c2d3-uuid}").unwrap();
        assert!(validate_external_repo_id("").is_err());
        assert!(validate_external_repo_id(" padded ").is_err());
    }

    #[test]
    fn test_scope_and_records_roundtrip() {
        let scope = test_scope();
        let cbor = to_canonical_cbor(&scope).unwrap();
        assert_eq!(from_canonical_cbor::<Scope>(&cbor).unwrap(), scope);

        let project = ProjectRecord::new(
            scope.project_id,
            scope.tenant_id,
            WorkspaceId::generate(),
            "payments",
            "Payments",
            1_790_520_400,
        )
        .unwrap();
        assert_eq!(project.status, ProjectStatus::Active);
        assert!(ProjectRecord::new(
            scope.project_id,
            scope.tenant_id,
            WorkspaceId::generate(),
            "Bad Slug",
            "Payments",
            0
        )
        .is_err());

        let env =
            EnvironmentRecord::new(EnvironmentId::generate(), scope, "production", 2, 0).unwrap();
        assert_eq!(env.tier, 2);

        let binding = RepositoryBindingRecord::new(
            RepositoryBindingId::generate(),
            scope.tenant_id,
            scope.project_id,
            RepositoryProvider::Github,
            "84920194",
            "acme/payments",
            "https://example.invalid/acme/payments",
            None,
            0,
        )
        .unwrap();
        assert_eq!(binding.status, BindingStatus::Active);
        let binding_cbor = to_canonical_cbor(&binding).unwrap();
        assert_eq!(
            from_canonical_cbor::<RepositoryBindingRecord>(&binding_cbor).unwrap(),
            binding
        );
    }

    #[test]
    fn test_secret_metadata_builders_and_validate() {
        let scope = test_scope();
        let meta = SecretMetadata::new(scope, "DATABASE_URL", "connection_string", "alice", 100)
            .unwrap()
            .with_description("Primary Postgres (synthetic)")
            .unwrap()
            .with_tags(&["database".to_string(), "pci".to_string()])
            .unwrap()
            .with_expiry(200);
        assert_eq!(meta.current_version, 1);
        meta.validate().unwrap();
        let cbor = to_canonical_cbor(&meta).unwrap();
        let back: SecretMetadata = from_canonical_cbor(&cbor).unwrap();
        assert_eq!(meta, back);
        back.validate().unwrap();

        assert!(SecretMetadata::new(scope, "bad-name", "t", "alice", 0).is_err());
        assert!(SecretMetadata::new(scope, "OK", "", "alice", 0).is_err());
        let too_many = vec!["t".to_string(); MAX_TAGS + 1];
        assert!(SecretMetadata::new(scope, "OK", "t", "alice", 0)
            .unwrap()
            .with_tags(&too_many)
            .is_err());
        let mut tampered = meta;
        tampered.current_version = 0;
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn test_secret_version_record_validation() {
        let rec = SecretVersionRecord::new(
            SecretId::generate(),
            1,
            KeyId::generate(),
            vec![0u8; NONCE_LEN],
            vec![1u8; 48],
            vec![2u8; DIGEST_LEN],
            "alice",
            0,
        )
        .unwrap();
        let cbor = to_canonical_cbor(&rec).unwrap();
        assert_eq!(
            from_canonical_cbor::<SecretVersionRecord>(&cbor).unwrap(),
            rec
        );
        let bad_nonce = SecretVersionRecord::new(
            rec.secret_id,
            1,
            KeyId::generate(),
            vec![0u8; 12],
            vec![1u8; 48],
            vec![2u8; DIGEST_LEN],
            "alice",
            0,
        );
        assert!(bad_nonce.is_err());
        let empty_ct = SecretVersionRecord::new(
            rec.secret_id,
            1,
            KeyId::generate(),
            vec![0u8; NONCE_LEN],
            Vec::new(),
            vec![2u8; DIGEST_LEN],
            "alice",
            0,
        );
        assert!(empty_ct.is_err());
    }
}
