//! Canonical audit taxonomy, hash-chain verification, and off-host export (T-901, §20).
//!
//! Every scoped-secret interaction funnels through
//! [`audit_secret_event`](crate::secrets::audit_secret_event) into
//! `secret_access_events`. This module owns the three T-901 gaps around
//! that sink:
//!
//! 1. **Taxonomy.** The 12 canonical event types (§20/G-spec) as
//!    [`AuditEventType`], with [`Other`](AuditEventType::Other) passthrough
//!    for extended literals so older rows keep their meaning. Canonical
//!    membership is closed: `secret.created/read/updated/deleted/moved/`
//!    `rebound/rotated`, `membership.granted/revoked`, `repository.bound/`
//!    `revoked`, `token.minted`. Extended (still chained + exported):
//!    repository lifecycle (`ownership_proved`, `ownership_proof_denied`,
//!    `suspended`, `rebound`, `drift`), `migration.*`, webhook outcomes.
//! 2. **Tamper evidence.** [`verify_chain`] recomputes the per-tenant hash
//!    chain over the FULL row (v2 preimage, [`chain_digest`]). The v1
//!    preimage covered only type/tenant/principal/request/result, so a
//!    reason/target rewrite was undetectable; v2 covers every stored
//!    column. The scoped tables have never shipped (created during this
//!    implementation), so no v1 rows exist in the wild to migrate.
//! 3. **Off-host shipping.** [`export_audit_log`] renders a tenant's chain
//!    as JSONL in the §20 shape (plus chain hashes) for append-only
//!    cold storage; the export test proves an independent verifier can
//!    recompute the chain from the JSONL alone.
//!
//! Append-only is enforced at the storage layer by
//! `secret_access_events_no_update` / `..._no_delete` triggers (§S6:
//! "audit store append-only"). Triggers stop accidents, not attackers
//! with raw database handles — the hash chain is the tamper evidence.
//!
//! ## Deliberate gaps
//!
//! * `token.revoked` is NOT in the taxonomy. Revocation takes a bare `jti`,
//!   which cannot resolve a tenant (the denylist is global and sessions
//!   are device-plane, not tenant-plane), and the audit table requires a
//!   tenant. Revocation evidence is the denylist row itself plus the
//!   `token.minted` event — inventing a tenant would be dishonest.
//! * Free-text `reason` fields are scrubbed at append time
//!   ([`ciphervault_redact`]) as a last-chance filter; values stay out of
//!   audit rows by construction (`SecretValue` has no `Display`/
//!   `Serialize` and a redacted `Debug`).

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// The 12 canonical scoped-audit event types (§20/G-spec).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuditEventType {
    SecretCreated,
    SecretRead,
    SecretUpdated,
    SecretDeleted,
    SecretMoved,
    SecretRebound,
    SecretRotated,
    MembershipGranted,
    MembershipRevoked,
    RepositoryBound,
    RepositoryRevoked,
    TokenMinted,
    /// Extended literal (repository lifecycle, `migration.*`, webhook
    /// outcomes). Chained and exported exactly like canonical types.
    Other(String),
}

impl AuditEventType {
    /// Wire literals of the 12 canonical types, in taxonomy order.
    pub(crate) const ALL_TWELVE: [&'static str; 12] = [
        "secret.created",
        "secret.read",
        "secret.updated",
        "secret.deleted",
        "secret.moved",
        "secret.rebound",
        "secret.rotated",
        "membership.granted",
        "membership.revoked",
        "repository.bound",
        "repository.revoked",
        "token.minted",
    ];

    /// Classifies a stored literal. Unknown literals become [`Other`](Self::Other),
    /// never an error — old rows must keep verifying. Consults
    /// [`ALL_TWELVE`](Self::ALL_TWELVE) so the closed set has one source of
    /// truth (the roundtrip test guards the index mapping).
    pub(crate) fn parse(value: &str) -> Self {
        match Self::ALL_TWELVE
            .iter()
            .position(|literal| *literal == value)
        {
            Some(0) => Self::SecretCreated,
            Some(1) => Self::SecretRead,
            Some(2) => Self::SecretUpdated,
            Some(3) => Self::SecretDeleted,
            Some(4) => Self::SecretMoved,
            Some(5) => Self::SecretRebound,
            Some(6) => Self::SecretRotated,
            Some(7) => Self::MembershipGranted,
            Some(8) => Self::MembershipRevoked,
            Some(9) => Self::RepositoryBound,
            Some(10) => Self::RepositoryRevoked,
            Some(11) => Self::TokenMinted,
            _ => Self::Other(value.to_string()),
        }
    }

    /// Wire literal for this type.
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::SecretCreated => "secret.created",
            Self::SecretRead => "secret.read",
            Self::SecretUpdated => "secret.updated",
            Self::SecretDeleted => "secret.deleted",
            Self::SecretMoved => "secret.moved",
            Self::SecretRebound => "secret.rebound",
            Self::SecretRotated => "secret.rotated",
            Self::MembershipGranted => "membership.granted",
            Self::MembershipRevoked => "membership.revoked",
            Self::RepositoryBound => "repository.bound",
            Self::RepositoryRevoked => "repository.revoked",
            Self::TokenMinted => "token.minted",
            Self::Other(literal) => literal,
        }
    }

    /// Whether this is one of the canonical twelve (vs extended).
    pub(crate) fn is_canonical(&self) -> bool {
        !matches!(self, Self::Other(_))
    }
}

/// Domain separator for the v2 chain preimage.
const CHAIN_DOMAIN: &[u8] = b"ciphervault-audit-chain-v2";

/// Genesis `prev_hash` for a tenant's first event (32 zero bytes).
pub(crate) const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Every field the v2 digest covers — the full stored row. `reason` is the
/// scrubbed form as stored (scrub-then-hash, so verifiers reproduce it).
pub(crate) struct ChainFields<'a> {
    pub prev: &'a [u8],
    pub event_type: &'a str,
    pub tenant_id: &'a str,
    pub project_id: Option<&'a str>,
    pub environment_id: Option<&'a str>,
    pub secret_id: Option<&'a str>,
    pub secret_version: Option<i64>,
    pub principal_id: &'a str,
    pub request_id: &'a str,
    pub source: &'a str,
    pub result: &'a str,
    pub reason: &'a str,
    pub now: u64,
}

fn push_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn push_opt(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            hasher.update([1u8]);
            push_field(hasher, bytes);
        }
        None => hasher.update([0u8]),
    }
}

/// v2 chain digest: `SHA-256(domain ‖ len-prefixed full row)`.
/// Length-prefixing removes concatenation ambiguity; the domain separator
/// versions the preimage so v1 digests can never validate as v2.
pub(crate) fn chain_digest(fields: &ChainFields<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_DOMAIN);
    push_field(&mut hasher, fields.prev);
    push_field(&mut hasher, fields.event_type.as_bytes());
    push_field(&mut hasher, fields.tenant_id.as_bytes());
    push_opt(&mut hasher, fields.project_id.map(str::as_bytes));
    push_opt(&mut hasher, fields.environment_id.map(str::as_bytes));
    push_opt(&mut hasher, fields.secret_id.map(str::as_bytes));
    match fields.secret_version {
        Some(version) => {
            hasher.update([1u8]);
            hasher.update(version.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }
    push_field(&mut hasher, fields.principal_id.as_bytes());
    push_field(&mut hasher, fields.request_id.as_bytes());
    push_field(&mut hasher, fields.source.as_bytes());
    push_field(&mut hasher, fields.result.as_bytes());
    push_field(&mut hasher, fields.reason.as_bytes());
    hasher.update(fields.now.to_be_bytes());
    hasher.finalize().into()
}

/// Extracts the principal from a stored `actor_json` envelope
/// (`{"principal_id": "…"}`). `None` means the row is malformed and fails
/// verification at that event.
pub(crate) fn principal_from_actor(actor_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(actor_json)
        .ok()?
        .get("principal_id")?
        .as_str()
        .map(str::to_string)
}

/// Result of [`verify_chain`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChainReport {
    /// Total events for the tenant (including any past the break).
    pub event_count: usize,
    /// Whether every link and digest recomputed cleanly.
    pub valid: bool,
    /// First event whose link or digest failed (`None` when valid).
    pub first_bad_event_id: Option<String>,
    /// Running head: last verified hash, or genesis when empty/broken-first.
    pub head_hash: Vec<u8>,
}

struct AuditRow {
    event_id: String,
    event_type: String,
    tenant_id: String,
    project_id: Option<String>,
    environment_id: Option<String>,
    secret_id: Option<String>,
    secret_version: Option<i64>,
    actor_json: String,
    request_id: String,
    source: String,
    result: String,
    reason: String,
    prev_hash: Vec<u8>,
    event_hash: Vec<u8>,
    created_at_utc: i64,
}

/// Checks one row's link and v2 digest against the running head. Shared by
/// full-chain verification and paged export so both fail on the same rows.
fn row_linkage_ok(row: &AuditRow, running: &[u8]) -> bool {
    let recomputed = principal_from_actor(&row.actor_json).map(|principal| {
        chain_digest(&ChainFields {
            prev: running,
            event_type: &row.event_type,
            tenant_id: &row.tenant_id,
            project_id: row.project_id.as_deref(),
            environment_id: row.environment_id.as_deref(),
            secret_id: row.secret_id.as_deref(),
            secret_version: row.secret_version,
            principal_id: &principal,
            request_id: &row.request_id,
            source: &row.source,
            result: &row.result,
            reason: &row.reason,
            now: row.created_at_utc as u64,
        })
    });
    row.prev_hash == running
        && recomputed.as_ref().map(|d| d.as_slice()) == Some(row.event_hash.as_slice())
}

/// Recomputes a tenant's hash chain in append order
/// (`created_at_utc, rowid` — the same order the writer uses to find the
/// head). Stops at the first break; the report names it. Rows stream one at
/// a time: verification never holds the full chain in memory.
pub(crate) fn verify_chain(
    db: &Connection,
    tenant_id: &str,
) -> Result<ChainReport, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT event_id, event_type, tenant_id, project_id, environment_id, secret_id,
                secret_version, actor_json, request_id, source, result, reason,
                prev_hash, event_hash, created_at_utc
         FROM secret_access_events WHERE tenant_id = ?1 ORDER BY created_at_utc, rowid",
    )?;
    // Total first: `event_count` covers the whole tenant chain even past a
    // break. Rows then stream one at a time instead of collecting.
    let total: i64 = db.query_row(
        "SELECT COUNT(*) FROM secret_access_events WHERE tenant_id = ?1",
        params![tenant_id],
        |row| row.get(0),
    )?;
    let mut mapped = stmt.query_map(params![tenant_id], |row| {
        Ok(AuditRow {
            event_id: row.get(0)?,
            event_type: row.get(1)?,
            tenant_id: row.get(2)?,
            project_id: row.get(3)?,
            environment_id: row.get(4)?,
            secret_id: row.get(5)?,
            secret_version: row.get(6)?,
            actor_json: row.get(7)?,
            request_id: row.get(8)?,
            source: row.get(9)?,
            result: row.get(10)?,
            reason: row.get(11)?,
            prev_hash: row.get(12)?,
            event_hash: row.get(13)?,
            created_at_utc: row.get(14)?,
        })
    })?;
    let mut report = ChainReport {
        event_count: total.max(0) as usize,
        valid: true,
        first_bad_event_id: None,
        head_hash: GENESIS_HASH.to_vec(),
    };
    let mut running: Vec<u8> = GENESIS_HASH.to_vec();
    for row in &mut mapped {
        let row = row?;
        if !row_linkage_ok(&row, &running) {
            report.valid = false;
            report.first_bad_event_id = Some(row.event_id.clone());
            break;
        }
        running = row.event_hash.clone();
    }
    report.head_hash = running;
    Ok(report)
}

/// Column list shared by the full and paged export SELECTs (positional
/// indices feed [`audit_row_from_export_row`]; keep the two in sync).
const AUDIT_EXPORT_COLUMNS: &str = "event_id, event_type, created_at_utc, tenant_id, project_id, environment_id, secret_id, secret_version, actor_json, result, reason, request_id, source, prev_hash, event_hash";

/// Default and maximum page sizes for the HTTP export. At ~1 KiB per JSONL
/// line, the largest page holds ~50 MiB — safe on an e2-micro, unlike the
/// unbounded full-chain materialization that OOM-killed the 2026-10-03 soak
/// canary at 703 MiB RSS.
pub(crate) const AUDIT_EXPORT_DEFAULT_LIMIT: usize = 10_000;
pub(crate) const AUDIT_EXPORT_MAX_LIMIT: usize = 50_000;

fn audit_row_from_export_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    Ok(AuditRow {
        event_id: row.get(0)?,
        event_type: row.get(1)?,
        created_at_utc: row.get(2)?,
        tenant_id: row.get(3)?,
        project_id: row.get(4)?,
        environment_id: row.get(5)?,
        secret_id: row.get(6)?,
        secret_version: row.get(7)?,
        actor_json: row.get(8)?,
        result: row.get(9)?,
        reason: row.get(10)?,
        request_id: row.get(11)?,
        source: row.get(12)?,
        prev_hash: row.get(13)?,
        event_hash: row.get(14)?,
    })
}

/// Renders one chain row as JSONL in the §20 shape (plus chain hashes and a
/// `canonical` taxonomy flag). Single definition shared by the full and
/// paged exporters so their lines are byte-identical.
fn audit_row_json(row: &AuditRow) -> String {
    let actor: serde_json::Value = serde_json::from_str(&row.actor_json)
        .unwrap_or_else(|_| serde_json::Value::String(row.actor_json.clone()));
    let canonical = AuditEventType::parse(&row.event_type).is_canonical();
    serde_json::json!({
        "event_id": row.event_id,
        "event_type": row.event_type,
        "canonical": canonical,
        "timestamp_utc": row.created_at_utc,
        "tenant_id": row.tenant_id,
        "project_id": row.project_id,
        "environment": row.environment_id,
        "secret_id": row.secret_id,
        "secret_version": row.secret_version,
        "actor": actor,
        "action_result": row.result,
        "reason": row.reason,
        "request_id": row.request_id,
        "source": row.source,
        "prev_hash_hex": hex::encode(&row.prev_hash),
        "event_hash_hex": hex::encode(&row.event_hash),
    })
    .to_string()
}

/// Exports a tenant's chain as JSONL in the §20 shape (plus chain hashes
/// and a `canonical` taxonomy flag) for off-host append-only cold storage.
/// Every line carries the full preimage, so an off-host verifier can
/// recompute the chain without database access (proven by
/// `export_verifies_off_host`).
///
/// Test-only oracle: the HTTP route serves bounded pages via
/// [`verify_and_export_audit_page`] (the unbounded full-chain
/// materialization OOM-killed the 2026-10-03 soak canary).
#[cfg(test)]
pub(crate) fn export_audit_log(
    db: &Connection,
    tenant_id: &str,
) -> Result<String, rusqlite::Error> {
    let sql = format!(
        "SELECT {AUDIT_EXPORT_COLUMNS} FROM secret_access_events \
         WHERE tenant_id = ?1 ORDER BY created_at_utc, rowid"
    );
    let mut stmt = db.prepare(&sql)?;
    let lines: Vec<String> = stmt
        .query_map(params![tenant_id], |row| {
            audit_row_from_export_row(row).map(|audit| audit_row_json(&audit))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = String::new();
    for line in &lines {
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

/// Failure modes of [`verify_and_export_audit_page`].
#[derive(Debug)]
pub(crate) enum AuditExportError {
    Db(rusqlite::Error),
    UnknownCursor,
}

impl From<rusqlite::Error> for AuditExportError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
}

/// One verified page of a tenant's chain.
#[derive(Debug)]
pub(crate) struct AuditExportPage {
    /// Events in this page (0 when invalid or exhausted).
    pub event_count: usize,
    /// Hash of the last event in this page (the exported prefix head), or
    /// the seed hash when the page is empty.
    pub head_hash: Vec<u8>,
    /// Cursor for the next page (last event id); `None` when the export is
    /// complete. Clients walk pages until it disappears.
    pub next_cursor: Option<String>,
    pub jsonl: String,
    /// Whether every link and digest in this page recomputed cleanly. A
    /// broken page ships no body (`jsonl` is empty).
    pub valid: bool,
    pub first_bad_event_id: Option<String>,
}

/// Verifies and exports one bounded page of a tenant's chain from a pinned
/// snapshot. `after` is an exclusive event-id cursor (`None` starts at
/// genesis); at most `limit` events are verified and rendered, so memory and
/// mutex hold time stay bounded no matter how large the chain grows.
///
/// Each page verifies its own linkage (seeded from the cursor event's stored
/// hash, or genesis): a break inside the page fails closed exactly like the
/// full export. A break *before* the cursor is not re-detected on later
/// pages — full-chain assurance means walking from genesis.
pub(crate) fn verify_and_export_audit_page(
    snapshot: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    after: Option<&str>,
    limit: usize,
) -> Result<AuditExportPage, AuditExportError> {
    // Clamp defensively; the route enforces 1..=MAX first.
    let limit = limit.clamp(1, AUDIT_EXPORT_MAX_LIMIT);
    let (seed, position): (Vec<u8>, Option<(i64, i64)>) = match after {
        None => (GENESIS_HASH.to_vec(), None),
        Some(event_id) => {
            let found: Option<(Vec<u8>, i64, i64)> = snapshot
                .query_row(
                    "SELECT event_hash, created_at_utc, rowid FROM secret_access_events \
                     WHERE tenant_id = ?1 AND event_id = ?2",
                    params![tenant_id, event_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            match found {
                Some((hash, created_at_utc, rowid)) => (hash, Some((created_at_utc, rowid))),
                None => return Err(AuditExportError::UnknownCursor),
            }
        }
    };
    // Over-fetch one row to detect truncation without a second query.
    let overfetch = limit.saturating_add(1) as i64;
    let sql = match position {
        None => format!(
            "SELECT {AUDIT_EXPORT_COLUMNS} FROM secret_access_events \
             WHERE tenant_id = ?1 ORDER BY created_at_utc, rowid LIMIT ?2"
        ),
        Some(_) => format!(
            "SELECT {AUDIT_EXPORT_COLUMNS} FROM secret_access_events \
             WHERE tenant_id = ?1 \
             AND (created_at_utc > ?2 OR (created_at_utc = ?2 AND rowid > ?3)) \
             ORDER BY created_at_utc, rowid LIMIT ?4"
        ),
    };
    let mut stmt = snapshot.prepare(&sql)?;
    let rows: Vec<AuditRow> = match position {
        None => stmt
            .query_map(params![tenant_id, overfetch], audit_row_from_export_row)?
            .collect::<Result<Vec<_>, _>>()?,
        Some((created_at_utc, rowid)) => stmt
            .query_map(
                params![tenant_id, created_at_utc, rowid, overfetch],
                audit_row_from_export_row,
            )?
            .collect::<Result<Vec<_>, _>>()?,
    };
    let has_more = rows.len() > limit;
    let mut running = seed;
    let mut out = String::new();
    let mut last_id: Option<String> = None;
    let mut emitted = 0usize;
    for row in rows.iter().take(limit) {
        if !row_linkage_ok(row, &running) {
            return Ok(AuditExportPage {
                event_count: 0,
                head_hash: running,
                next_cursor: None,
                jsonl: String::new(),
                valid: false,
                first_bad_event_id: Some(row.event_id.clone()),
            });
        }
        out.push_str(&audit_row_json(row));
        out.push('\n');
        running = row.event_hash.clone();
        last_id = Some(row.event_id.clone());
        emitted += 1;
    }
    Ok(AuditExportPage {
        event_count: emitted,
        head_hash: running,
        next_cursor: if has_more { last_id } else { None },
        jsonl: out,
        valid: true,
        first_bad_event_id: None,
    })
}

/// Verify and materialize one pinned SQLite snapshot. Requiring a transaction
/// keeps independent connections from appending between the report and JSONL.
/// A broken chain never produces an export body.
///
/// Test-only oracle alongside [`export_audit_log`]; the route pages through
/// [`verify_and_export_audit_page`].
#[cfg(test)]
pub(crate) fn verify_and_export_audit_log(
    snapshot: &rusqlite::Transaction<'_>,
    tenant_id: &str,
) -> Result<(ChainReport, String), rusqlite::Error> {
    let report = verify_chain(snapshot, tenant_id)?;
    let jsonl = if report.valid {
        export_audit_log(snapshot, tenant_id)?
    } else {
        String::new()
    };
    Ok((report, jsonl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::LocalKekService;
    use ciphervault_format::{EnvironmentId, ProjectId, SecretValue, TenantId};
    use rusqlite::params;

    use crate::policy::{grant_project_role, ProjectRole, RequestAttributes};
    use crate::scope_tokens::ScopeClaims;
    use crate::secrets::{
        audit_secret_event, create_secret, get_secret_value, CreateSecret, SecretAuditEvent,
    };
    use crate::test_support::{cleanup, test_app};
    use crate::util::random_hex;

    const KEK_ID: &str = "local:audit-test";
    const KEK: [u8; 32] = [0xA1; 32];

    #[allow(clippy::too_many_arguments)]
    fn emit(
        db: &Connection,
        event_type: &str,
        tenant: &str,
        principal: &str,
        request: &str,
        result: &str,
        reason: &str,
        now: u64,
    ) {
        audit_secret_event(
            db,
            &SecretAuditEvent {
                event_type,
                tenant_id: tenant,
                project_id: Some("p1"),
                environment_id: Some("e1"),
                secret_id: Some("s1"),
                secret_version: Some(3),
                principal_id: principal,
                request_id: request,
                source: "test",
                result,
                reason,
            },
            now,
        )
        .unwrap();
    }

    fn seed_project(db: &Connection) -> (String, String, ScopeClaims) {
        let tenant = TenantId::generate().to_hex();
        let project = ProjectId::generate().to_hex();
        let env = EnvironmentId::generate().to_hex();
        db.execute(
            "INSERT INTO organizations(tenant_id, name, created_at_utc) VALUES(?1, 'Acme', 1)",
            params![tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO workspaces(workspace_id, tenant_id, name, created_at_utc)
             VALUES('w1', ?1, 'Platform', 1)",
            params![tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
             VALUES(?1, ?2, 'w1', 'payments', 'Payments', 1)",
            params![project, tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier,
                                       created_at_utc)
             VALUES(?1, ?2, ?3, 'staging', 1, 1)",
            params![env, tenant, project],
        )
        .unwrap();
        grant_project_role(
            db,
            &project,
            "account:alice",
            ProjectRole::Developer,
            "root",
            1,
        )
        .unwrap();
        let claims = ScopeClaims::new(&tenant, &project, "account:alice", 1000, 9_999_999_999)
            .with_environment(&env);
        (project, env, claims)
    }

    #[test]
    fn canonical_twelve_roundtrip_and_other_passthrough() {
        assert_eq!(AuditEventType::ALL_TWELVE.len(), 12);
        for literal in AuditEventType::ALL_TWELVE {
            let parsed = AuditEventType::parse(literal);
            assert!(parsed.is_canonical(), "{literal}");
            assert_eq!(parsed.as_str(), literal);
        }
        // Extended literals keep their meaning and stay non-canonical.
        // ("secret.rebound" itself IS canonical; lookalikes are not.)
        for literal in [
            "secret.rebound-duplicate",
            "repository.suspended",
            "repository.ownership_proved",
            "repository.drift",
            "migration.started",
            "migration.completed",
            "webhook.applied",
        ] {
            let parsed = AuditEventType::parse(literal);
            assert!(!parsed.is_canonical(), "{literal}");
            assert_eq!(parsed.as_str(), literal);
        }
        assert_eq!(
            AuditEventType::parse("secret.rebound"),
            AuditEventType::SecretRebound
        );
    }

    #[test]
    fn verified_export_uses_snapshot_before_an_independent_writer_commit() {
        let (root, state, app) = test_app("audit-export-snapshot");
        let mut db = state.connection().unwrap();
        emit(
            &db,
            "secret.read",
            "t1",
            "alice",
            "before",
            "success",
            "",
            100,
        );
        let mut writer = Connection::open(root.join("accounts.sqlite3")).unwrap();
        writer
            .busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            writer
                .query_row("PRAGMA synchronous", [], |row| row.get::<_, u64>(0))
                .unwrap(),
            2,
            "independent writes retain FULL durability",
        );
        let snapshot = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .unwrap();
        let before = verify_chain(&snapshot, "t1").unwrap();
        assert_eq!(before.event_count, 1);
        let write = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        emit(
            &write,
            "secret.read",
            "t1",
            "alice",
            "committed-after-snapshot",
            "success",
            "",
            101,
        );
        write.commit().unwrap();
        assert_eq!(verify_chain(&writer, "t1").unwrap().event_count, 2);

        // Exercise the production export helper after a real independent
        // commit. It must preserve the pinned report and exclude that row.
        let (report, jsonl) = verify_and_export_audit_log(&snapshot, "t1").unwrap();
        assert_eq!(report, before);
        assert_eq!(jsonl.lines().count(), report.event_count);
        assert!(!jsonl.contains("committed-after-snapshot"));
        let row: serde_json::Value = serde_json::from_str(jsonl.lines().last().unwrap()).unwrap();
        assert_eq!(row["event_hash_hex"], hex::encode(&report.head_hash));
        snapshot.commit().unwrap();

        let next = db.transaction().unwrap();
        let (after, jsonl) = verify_and_export_audit_log(&next, "t1").unwrap();
        assert_eq!(after.event_count, 2);
        assert!(after.valid);
        assert_ne!(after.head_hash, before.head_hash);
        assert_eq!(jsonl.lines().count(), 2);
        assert!(jsonl.contains("committed-after-snapshot"));
        next.commit().unwrap();
        drop(writer);
        drop(db);
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn appended_events_verify_with_head() {
        let (root, state, _app) = test_app("audit-verify");
        let db = state.connection().unwrap();
        emit(
            &db,
            "secret.created",
            "t1",
            "alice",
            "r1",
            "success",
            "ok",
            100,
        );
        emit(
            &db,
            "secret.read",
            "t1",
            "alice",
            "r2",
            "success",
            "ok",
            101,
        );
        emit(&db, "secret.read", "t2", "bob", "r3", "success", "ok", 102);
        let report = verify_chain(&db, "t1").unwrap();
        assert!(report.valid);
        assert_eq!(report.event_count, 2);
        assert_eq!(report.first_bad_event_id, None);
        let head: Vec<u8> = db
            .query_row(
                "SELECT event_hash FROM secret_access_events WHERE tenant_id = 't1'
                 ORDER BY created_at_utc DESC, rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(report.head_hash, head);
        // Other tenants are independent chains.
        assert!(verify_chain(&db, "t2").unwrap().valid);
        // Empty tenants verify vacuously with a genesis head.
        let empty = verify_chain(&db, "nobody").unwrap();
        assert!(empty.valid);
        assert_eq!(empty.event_count, 0);
        assert_eq!(empty.head_hash, GENESIS_HASH.to_vec());
        cleanup(root);
    }

    #[test]
    fn tampered_reason_breaks_chain_at_that_event() {
        let (root, state, _app) = test_app("audit-tamper");
        let db = state.connection().unwrap();
        emit(
            &db,
            "secret.created",
            "t1",
            "alice",
            "r1",
            "success",
            "first",
            100,
        );
        emit(
            &db,
            "secret.read",
            "t1",
            "alice",
            "r2",
            "success",
            "second",
            101,
        );
        assert!(verify_chain(&db, "t1").unwrap().valid);
        let victim: String = db
            .query_row(
                "SELECT event_id FROM secret_access_events WHERE tenant_id = 't1'
                 ORDER BY created_at_utc, rowid LIMIT 1 OFFSET 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // Raw-handle attacker: triggers stop accidents, not this — the hash
        // chain is the evidence, so drop the guard and rewrite history.
        db.execute("DROP TRIGGER secret_access_events_no_update", [])
            .unwrap();
        db.execute(
            "UPDATE secret_access_events SET reason = 'forged' WHERE event_id = ?1",
            params![victim],
        )
        .unwrap();
        let report = verify_chain(&db, "t1").unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_bad_event_id, Some(victim));
        cleanup(root);
    }

    #[test]
    fn tampered_link_breaks_chain_at_that_event() {
        let (root, state, _app) = test_app("audit-link");
        let db = state.connection().unwrap();
        emit(
            &db,
            "secret.created",
            "t1",
            "alice",
            "r1",
            "success",
            "first",
            100,
        );
        emit(
            &db,
            "secret.read",
            "t1",
            "alice",
            "r2",
            "success",
            "second",
            101,
        );
        let victim: String = db
            .query_row(
                "SELECT event_id FROM secret_access_events WHERE tenant_id = 't1'
                 ORDER BY created_at_utc, rowid LIMIT 1 OFFSET 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        db.execute("DROP TRIGGER secret_access_events_no_update", [])
            .unwrap();
        db.execute(
            "UPDATE secret_access_events SET prev_hash = x'00' WHERE event_id = ?1",
            params![victim],
        )
        .unwrap();
        let report = verify_chain(&db, "t1").unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_bad_event_id, Some(victim));
        cleanup(root);
    }

    #[test]
    fn append_only_triggers_reject_mutation() {
        let (root, state, _app) = test_app("audit-append-only");
        let db = state.connection().unwrap();
        emit(
            &db,
            "secret.created",
            "t1",
            "alice",
            "r1",
            "success",
            "first",
            100,
        );
        let update = db
            .execute("UPDATE secret_access_events SET reason = 'x'", [])
            .unwrap_err()
            .to_string();
        assert!(update.contains("append-only"), "{update}");
        let delete = db
            .execute("DELETE FROM secret_access_events", [])
            .unwrap_err()
            .to_string();
        assert!(delete.contains("append-only"), "{delete}");
        cleanup(root);
    }

    #[test]
    fn reason_scrubbed_at_append() {
        let (root, state, _app) = test_app("audit-scrub");
        let db = state.connection().unwrap();
        emit(
            &db,
            "secret.read",
            "t1",
            "alice",
            "r1",
            "success",
            "login password=hunter2 token cvst1.eyJ9.e30",
            100,
        );
        let stored: String = db
            .query_row(
                "SELECT reason FROM secret_access_events WHERE tenant_id = 't1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored.contains("hunter2"), "{stored}");
        assert!(!stored.contains("cvst1.eyJ9"), "{stored}");
        assert!(stored.contains("[REDACTED]"), "{stored}");
        // Scrub-then-hash: the stored (scrubbed) row still verifies.
        assert!(verify_chain(&db, "t1").unwrap().valid);
        cleanup(root);
    }

    /// Independent v2 preimage recompute from exported JSON fields — the
    /// off-host verifier's view. Hand-rolled here (not via [`chain_digest`])
    /// so the export format is proven sufficient, not just self-consistent.
    fn ref_field(hasher: &mut sha2::Sha256, bytes: &[u8]) {
        use sha2::Digest;
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    fn ref_opt(hasher: &mut sha2::Sha256, value: Option<&str>) {
        use sha2::Digest;
        match value {
            Some(text) => {
                hasher.update([1u8]);
                ref_field(hasher, text.as_bytes());
            }
            None => hasher.update([0u8]),
        }
    }

    fn ref_str<'a>(line: &'a serde_json::Value, key: &str) -> &'a str {
        line[key].as_str().unwrap()
    }

    fn reference_digest(prev: &[u8], line: &serde_json::Value) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"ciphervault-audit-chain-v2");
        ref_field(&mut hasher, prev);
        ref_field(&mut hasher, ref_str(line, "event_type").as_bytes());
        ref_field(&mut hasher, ref_str(line, "tenant_id").as_bytes());
        ref_opt(&mut hasher, line["project_id"].as_str());
        ref_opt(&mut hasher, line["environment"].as_str());
        ref_opt(&mut hasher, line["secret_id"].as_str());
        match line["secret_version"].as_i64() {
            Some(version) => {
                hasher.update([1u8]);
                hasher.update(version.to_be_bytes());
            }
            None => hasher.update([0u8]),
        }
        ref_field(
            &mut hasher,
            line["actor"]["principal_id"].as_str().unwrap().as_bytes(),
        );
        ref_field(&mut hasher, ref_str(line, "request_id").as_bytes());
        ref_field(&mut hasher, ref_str(line, "source").as_bytes());
        ref_field(&mut hasher, ref_str(line, "action_result").as_bytes());
        ref_field(&mut hasher, ref_str(line, "reason").as_bytes());
        hasher.update((line["timestamp_utc"].as_i64().unwrap() as u64).to_be_bytes());
        hasher.finalize().into()
    }

    #[test]
    fn export_verifies_off_host() {
        let (root, state, _app) = test_app("audit-export");
        let db = state.connection().unwrap();
        emit(
            &db,
            "secret.created",
            "t1",
            "alice",
            "r1",
            "success",
            "first",
            100,
        );
        emit(
            &db,
            "migration.started",
            "t1",
            "alice",
            "r2",
            "success",
            "vault v1",
            101,
        );
        let jsonl = export_audit_log(&db, "t1").unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        // §20 shape on every line.
        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            for key in [
                "event_id",
                "event_type",
                "canonical",
                "timestamp_utc",
                "tenant_id",
                "actor",
                "action_result",
                "prev_hash_hex",
                "event_hash_hex",
            ] {
                assert!(value.get(key).is_some(), "missing {key} in {line}");
            }
        }
        // Taxonomy flag: canonical vs extended.
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["canonical"], true);
        assert_eq!(second["canonical"], false);
        // Independent chain recompute from the JSONL alone.
        let mut running = vec![0u8; 32];
        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            let prev = hex::decode(value["prev_hash_hex"].as_str().unwrap()).unwrap();
            let hash = hex::decode(value["event_hash_hex"].as_str().unwrap()).unwrap();
            assert_eq!(prev, running);
            assert_eq!(reference_digest(&running, &value).to_vec(), hash);
            running = hash;
        }
        assert_eq!(verify_chain(&db, "t1").unwrap().head_hash, running);
        cleanup(root);
    }

    #[test]
    fn backup_restore_roundtrip_preserves_chain() {
        // DR drill (T-903): `VACUUM INTO` snapshots a live WAL database to
        // one portable file; reopening it must verify with a byte-identical
        // export (rowids survive VACUUM, so order is stable).
        let (root, state, _app) = test_app("audit-backup");
        let db = state.connection().unwrap();
        emit(
            &db,
            "secret.created",
            "t1",
            "alice",
            "r1",
            "success",
            "first",
            100,
        );
        emit(
            &db,
            "secret.read",
            "t1",
            "alice",
            "r2",
            "success",
            "second",
            101,
        );
        let before = export_audit_log(&db, "t1").unwrap();
        let backup_dir = root.join("restore-drill");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // SQLite inherits NOFOLLOW into VACUUM targets. Resolve the existing
        // temporary parent so immutable macOS system aliases remain supported.
        let backup_path = backup_dir.canonicalize().unwrap().join("accounts.sqlite3");
        let literal = backup_path.to_str().unwrap().replace('\'', "''");
        db.execute(&format!("VACUUM INTO '{literal}'"), []).unwrap();
        drop(db);
        drop(state);
        let restored = crate::state::AccountState::open(&backup_dir).unwrap();
        let rdb = restored.connection().unwrap();
        let report = verify_chain(&rdb, "t1").unwrap();
        assert!(report.valid);
        assert_eq!(report.event_count, 2);
        assert_eq!(export_audit_log(&rdb, "t1").unwrap(), before);
        cleanup(root);
    }

    #[test]
    fn canary_value_never_lands_in_audit_or_export() {
        let (root, state, _app) = test_app("audit-canary");
        let mut db = state.connection().unwrap();
        let wrap = LocalKekService::new(KEK_ID, KEK);
        let (project, env, claims) = seed_project(&db);
        // High-entropy canary shaped like a real credential.
        let canary = format!("CANARY-{}-{}-canary", random_hex(8), random_hex(8));
        let tags = vec!["database".to_string()];
        let view = create_secret(
            &mut db,
            &wrap,
            KEK_ID,
            &claims,
            &RequestAttributes::default(),
            &CreateSecret {
                project_id: &project,
                environment_id: &env,
                name: "DATABASE_URL",
                secret_type: "key_value",
                description: "synthetic fixture",
                tags: &tags,
                repository_binding_id: None,
                service_id: None,
                value: &SecretValue::from(canary.as_str()),
                request_id: "req-canary",
            },
        )
        .unwrap();
        let fetched = get_secret_value(
            &mut db,
            &wrap,
            &claims,
            &RequestAttributes::default(),
            &view.secret_id,
            "req-canary-read",
        )
        .unwrap();
        assert_eq!(fetched.value.expose(), canary.as_bytes());
        // Every audit text column, the off-host export, and the Debug
        // render (the stack-trace surface) must be canary-free.
        let mut text = String::new();
        let mut stmt = db
            .prepare(
                "SELECT event_type, project_id, environment_id, secret_id, actor_json,
                        request_id, source, result, reason
                 FROM secret_access_events",
            )
            .unwrap();
        let rows: Vec<Vec<String>> = stmt
            .query_map([], |row| {
                Ok(vec![
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ])
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for row in &rows {
            text.push_str(&row.join("|"));
        }
        text.push_str(&export_audit_log(&db, &claims.tenant_id).unwrap());
        let debug = format!("{fetched:?}");
        assert!(!text.contains(&canary), "canary leaked into audit rows");
        assert!(!debug.contains(&canary), "canary leaked into Debug");
        assert!(
            !ciphervault_redact::contains_secret_shaped(&text),
            "audit surface is not scrubber-clean"
        );
        cleanup(root);
    }
}
