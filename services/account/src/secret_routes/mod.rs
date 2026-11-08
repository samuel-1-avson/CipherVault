//! Scoped secret REST routes (Phase 4, T-403).
//!
//! Dual authentication: short-lived HMAC scope tokens (`cvst1.*`, CI and
//! workloads) or account sessions (humans). Token scope must cover the path
//! scope exactly for environment targets; session callers take scope from
//! the explicit path plus the project row, with identity from the session.
//! Denials and missing resources both return a uniform 404 (no oracle).
//!
//! Abuse protection (T-902): per-principal quotas (API bucket on every
//! authenticated call plus tighter read/mint/export buckets), dual-control
//! audit export, and opt-in DPoP-lite key binding for scope tokens. mTLS
//! stays deferred (needs a TLS-termination dependency).

//! Module layout: `common` (shared auth context + prelude), `auth`
//! (token/session authentication), and one file per route domain.

mod audit;
mod auth;
mod common;
mod projects;
mod scope_tokens;
mod secrets;
mod vcs;

#[cfg(test)]
mod tests;

pub(crate) use audit::*;
pub(crate) use auth::*;
pub(crate) use common::*;
pub(crate) use projects::*;
pub(crate) use scope_tokens::*;
pub(crate) use secrets::*;
pub(crate) use vcs::*;
