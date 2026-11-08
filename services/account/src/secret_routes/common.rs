////! Shared auth context, error mapping, and crate-visible prelude.
pub(crate) use crate::key_lifecycle::VersionedKekService;
pub(crate) use axum::body::Bytes;
pub(crate) use axum::extract::{Path, Query, State};
pub(crate) use axum::http::{HeaderMap, StatusCode};
pub(crate) use axum::response::{IntoResponse, Response};
pub(crate) use axum::Json;
pub(crate) use ciphervault_format::SecretValue;
pub(crate) use rusqlite::OptionalExtension;
pub(crate) use serde::{Deserialize, Serialize};

pub(crate) use crate::abuse::{
    check_quota, quota_failure_response, API_BUCKET, EXPORT_BUCKET, MINT_BUCKET, READ_VALUE_BUCKET,
};
pub(crate) use crate::audit_chain::{
    verify_and_export_audit_page, AuditEventType, AuditExportError, AUDIT_EXPORT_DEFAULT_LIMIT,
    AUDIT_EXPORT_MAX_LIMIT,
};
pub(crate) use crate::guards::{require_recent_strong_session, STEP_UP_MAX_AGE_SECONDS};
pub(crate) use crate::http::{
    authenticated_session, bearer_token, error_response, service_error, session_token,
};
pub(crate) use crate::policy::{
    grant_project_role, project_role_of, revoke_project_role, scoped_denial_response, ProjectRole,
    RequestAttributes,
};
pub(crate) use crate::projects::{list_projects, show_project, ProjectError};
pub(crate) use crate::reconcile::NoProviderClient;
pub(crate) use crate::rotation::{rotate_secret, ManualReplacementVerifier, RotateSecret};
pub(crate) use crate::scope_tokens::{
    deny_scope_token, mint_scope_token, prune_scope_denylist, scope_token_denied,
    scope_token_signing_key, verify_scope_token, ScopeClaims, SCOPE_TOKEN_PREFIX,
};
pub(crate) use crate::secrets::{
    audit_secret_event, create_secret, delete_secret, get_secret_metadata, get_secret_value,
    list_secrets, move_secret, rebind_secret, update_secret_metadata, CreateSecret, MoveSecret,
    RebindSecret, SecretAuditEvent, SecretError, SecretListFilter, UpdateSecretMetadata,
};
pub(crate) use crate::state::{now_utc, AccountState};
pub(crate) use crate::util::random_hex;
pub(crate) use crate::vcs::{
    apply_webhook_event, bind_repository, list_bindings, prove_ownership, reactivate_binding,
    revoke_binding, suspend_binding, verify_webhook_signature, webhook_key_for,
    webhook_signing_key, BindRepository, VcsError, VcsProvider, WebhookEvent, WebhookOutcome,
};

pub(crate) struct RouteAuth {
    pub(crate) claims: ScopeClaims,
    pub(crate) attrs: RequestAttributes,
}
