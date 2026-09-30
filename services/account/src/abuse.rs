//! Per-principal abuse quotas (T-902, OWASP API-4: unrestricted resource
//! consumption).
//!
//! The pre-existing [`auth_rate_limits`](crate::http) table throttles failed
//! *authentication* ceremonies only. This module throttles *authorized*
//! traffic: every scoped route consumes the [`API_BUCKET`] (enforced inside
//! [`authenticate`](crate::secret_routes::authenticate) after auth), and
//! sensitive operations consume a second, tighter bucket in their handler
//! (value reads, token mints, audit exports).
//!
//! Fixed windows in SQLite (no new dependencies; Redis arrives with T-903
//! scale-out). Quota keys are post-auth `(bucket, tenant, principal)`
//! tuples, so unauthenticated callers cannot plant rows and one tenant's
//! burst cannot starve another. Failures fail closed: a database error
//! surfaces 503 (fail-closed like the auth limiter), exhaustion surfaces
//! 429 with `Retry-After` plus `X-RateLimit-*` headers.
//!
//! Limits are compile-time defaults; tests pre-fill quota rows to prove
//! route wiring deterministically (no env-var races under parallel tests).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, Connection, OptionalExtension};

/// One quota bucket: at most `max_requests` per `window_seconds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuotaBucket {
    pub name: &'static str,
    pub max_requests: u64,
    pub window_seconds: u64,
}

/// Every authenticated scoped call. High enough for dashboard polling and
/// CI fans; low enough to blunt credential-stuffing replay at scale.
pub(crate) const API_BUCKET: QuotaBucket = QuotaBucket {
    name: "api",
    max_requests: 1000,
    window_seconds: 60,
};

/// Plaintext value reads — the highest-blast-radius operation.
pub(crate) const READ_VALUE_BUCKET: QuotaBucket = QuotaBucket {
    name: "read-value",
    max_requests: 300,
    window_seconds: 60,
};

/// Scope-token mints (credential issuance).
pub(crate) const MINT_BUCKET: QuotaBucket = QuotaBucket {
    name: "mint",
    max_requests: 30,
    window_seconds: 60,
};

/// Audit-chain exports (bulk read + hash recompute per call).
pub(crate) const EXPORT_BUCKET: QuotaBucket = QuotaBucket {
    name: "export",
    max_requests: 10,
    window_seconds: 300,
};

const CHALLENGE_ACCOUNT_BUCKET: QuotaBucket = QuotaBucket {
    name: "challenge-account",
    max_requests: 30,
    window_seconds: 300,
};
const CHALLENGE_SOURCE_BUCKET: QuotaBucket = QuotaBucket {
    name: "challenge-source",
    max_requests: 120,
    window_seconds: 60,
};
const CHALLENGE_GLOBAL_BUCKET: QuotaBucket = QuotaBucket {
    name: "challenge-global",
    max_requests: 2000,
    window_seconds: 60,
};

/// Reserve before persisting any login/enrollment challenge. All ceremonies
/// share the account budget, so switching methods cannot evade it.
pub(crate) fn check_challenge_quota(
    db: &Connection,
    headers: &axum::http::HeaderMap,
    account_id: &str,
    now: u64,
) -> Result<(), QuotaFailure> {
    check_quota(db, &CHALLENGE_GLOBAL_BUCKET, "auth", "all", now)?;
    check_quota(
        db,
        &CHALLENGE_SOURCE_BUCKET,
        "auth",
        &crate::http::request_source(headers),
        now,
    )?;
    check_quota(db, &CHALLENGE_ACCOUNT_BUCKET, "auth", account_id, now)?;
    Ok(())
}

/// Outcome of an allowed check, for limit headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuotaState {
    pub limit: u64,
    pub remaining: u64,
    pub reset_after_secs: u64,
}

/// Check failure: fail-closed store error vs explicit exhaustion.
#[derive(Debug, thiserror::Error)]
pub(crate) enum QuotaFailure {
    #[error("quota store unavailable")]
    Db(#[from] rusqlite::Error),
    #[error("quota exceeded")]
    Denied { retry_after_secs: u64, limit: u64 },
}

/// Consumes one unit of `bucket` for `(tenant_id, principal_id)` at `now`.
/// Window rollover is lazy (no background sweeper); long-expired rows are
/// pruned opportunistically on each check.
pub(crate) fn check_quota(
    db: &Connection,
    bucket: &QuotaBucket,
    tenant_id: &str,
    principal_id: &str,
    now: u64,
) -> Result<QuotaState, QuotaFailure> {
    // Opportunistic prune (fixed horizon covers the longest bucket window).
    db.execute(
        "DELETE FROM abuse_quotas WHERE window_started_at_utc < ?1",
        params![now.saturating_sub(3600)],
    )?;
    let key = format!("{}:{tenant_id}:{principal_id}", bucket.name);
    // One SQLite statement reserves the unit. Read-then-increment permits
    // independent account processes to overrun a shared quota.
    let reserved: Option<(u64, u64)> = db
        .query_row(
            "INSERT INTO abuse_quotas(quota_key, window_started_at_utc, count, updated_at_utc)
         VALUES(?1, ?2, 1, ?2)
         ON CONFLICT(quota_key) DO UPDATE SET
           window_started_at_utc = CASE WHEN ?2 >= window_started_at_utc + ?3
                                        THEN ?2 ELSE window_started_at_utc END,
           count = CASE WHEN ?2 >= window_started_at_utc + ?3 THEN 1 ELSE count + 1 END,
           updated_at_utc = ?2
         WHERE ?2 >= window_started_at_utc + ?3 OR count < ?4
         RETURNING window_started_at_utc, count",
            params![key, now, bucket.window_seconds, bucket.max_requests],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((started, count)) = reserved {
        return Ok(QuotaState {
            limit: bucket.max_requests,
            remaining: bucket.max_requests.saturating_sub(count),
            reset_after_secs: bucket
                .window_seconds
                .saturating_sub(now.saturating_sub(started)),
        });
    }
    let started: u64 = db.query_row(
        "SELECT window_started_at_utc FROM abuse_quotas WHERE quota_key = ?1",
        [&key],
        |row| row.get(0),
    )?;
    Err(QuotaFailure::Denied {
        retry_after_secs: bucket
            .window_seconds
            .saturating_sub(now.saturating_sub(started))
            .max(1),
        limit: bucket.max_requests,
    })
}

/// Maps a [`QuotaFailure`] to its HTTP response: 503 fail-closed on store
/// errors (mirrors the auth limiter), 429 + `Retry-After` on exhaustion.
pub(crate) fn quota_failure_response(failure: QuotaFailure) -> Response {
    match failure {
        QuotaFailure::Db(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "error",
                "code": "QUOTA_UNAVAILABLE",
                "error": "Request quota store unavailable",
            })),
        )
            .into_response(),
        QuotaFailure::Denied {
            retry_after_secs,
            limit,
        } => {
            let mut headers = axum::http::HeaderMap::new();
            if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                headers.insert(axum::http::header::RETRY_AFTER, value);
            }
            if let Ok(value) = axum::http::HeaderValue::from_str(&limit.to_string()) {
                headers.insert("x-ratelimit-limit", value);
            }
            headers.insert(
                "x-ratelimit-remaining",
                axum::http::HeaderValue::from_static("0"),
            );
            if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                headers.insert("x-ratelimit-reset", value);
            }
            (
                StatusCode::TOO_MANY_REQUESTS,
                headers,
                Json(serde_json::json!({
                    "status": "error",
                    "code": "QUOTA_EXCEEDED",
                    "error": "Request quota exceeded; try again later",
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{cleanup, test_app};

    const TINY: QuotaBucket = QuotaBucket {
        name: "tiny",
        max_requests: 3,
        window_seconds: 60,
    };

    #[test]
    fn allows_up_to_limit_then_denies_with_retry_after() {
        let (root, state, _app) = test_app("abuse-limit");
        let db = state.connection().unwrap();
        let first = check_quota(&db, &TINY, "t1", "alice", 1000).unwrap();
        assert_eq!(
            first,
            QuotaState {
                limit: 3,
                remaining: 2,
                reset_after_secs: 60,
            }
        );
        assert_eq!(
            check_quota(&db, &TINY, "t1", "alice", 1001)
                .unwrap()
                .remaining,
            1
        );
        assert_eq!(
            check_quota(&db, &TINY, "t1", "alice", 1002)
                .unwrap()
                .remaining,
            0
        );
        match check_quota(&db, &TINY, "t1", "alice", 1003).unwrap_err() {
            QuotaFailure::Denied {
                retry_after_secs,
                limit,
            } => {
                assert_eq!(limit, 3);
                assert_eq!(retry_after_secs, 57);
            }
            QuotaFailure::Db(err) => panic!("unexpected store error: {err}"),
        }
        cleanup(root);
    }

    #[test]
    fn window_rollover_resets_count() {
        let (root, state, _app) = test_app("abuse-rollover");
        let db = state.connection().unwrap();
        for now in [1000, 1001, 1002] {
            check_quota(&db, &TINY, "t1", "alice", now).unwrap();
        }
        assert!(matches!(
            check_quota(&db, &TINY, "t1", "alice", 1003).unwrap_err(),
            QuotaFailure::Denied { .. }
        ));
        // Window started at 1000 with a 60s span: 1060 rolls over.
        let reset = check_quota(&db, &TINY, "t1", "alice", 1060).unwrap();
        assert_eq!(reset.remaining, 2);
        cleanup(root);
    }

    #[test]
    fn quotas_isolate_principals_and_tenants() {
        let (root, state, _app) = test_app("abuse-isolation");
        let db = state.connection().unwrap();
        let one = QuotaBucket {
            name: "one",
            max_requests: 1,
            window_seconds: 60,
        };
        check_quota(&db, &one, "t1", "alice", 1000).unwrap();
        assert!(matches!(
            check_quota(&db, &one, "t1", "alice", 1001).unwrap_err(),
            QuotaFailure::Denied { .. }
        ));
        // Same principal, other tenant: fresh budget.
        check_quota(&db, &one, "t2", "alice", 1001).unwrap();
        // Same tenant, other principal: fresh budget.
        check_quota(&db, &one, "t1", "bob", 1001).unwrap();
        cleanup(root);
    }

    #[test]
    fn buckets_are_independent() {
        let (root, state, _app) = test_app("abuse-buckets");
        let db = state.connection().unwrap();
        let one = QuotaBucket {
            name: "one",
            max_requests: 1,
            window_seconds: 60,
        };
        let other = QuotaBucket {
            name: "other",
            max_requests: 1,
            window_seconds: 60,
        };
        check_quota(&db, &one, "t1", "alice", 1000).unwrap();
        assert!(matches!(
            check_quota(&db, &one, "t1", "alice", 1001).unwrap_err(),
            QuotaFailure::Denied { .. }
        ));
        check_quota(&db, &other, "t1", "alice", 1001).unwrap();
        cleanup(root);
    }
    #[test]
    fn quota_reservation_is_atomic_across_independent_connections() {
        use std::sync::{Arc, Barrier};
        let (root, _state, _app) = test_app("quota-concurrent");
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = root.join("accounts.sqlite3");
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let db = Connection::open(path).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                    barrier.wait();
                    let mut allowed = 0;
                    for _ in 0..10 {
                        match check_quota(&db, &TINY, "tenant", "principal", 1000) {
                            Ok(_) => allowed += 1,
                            Err(QuotaFailure::Denied { .. }) => {}
                            Err(error) => panic!("quota reservation failed: {error}"),
                        }
                    }
                    allowed
                })
            })
            .collect();
        let count: usize = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .sum();
        assert_eq!(count, TINY.max_requests as usize);
        cleanup(root);
    }
}
