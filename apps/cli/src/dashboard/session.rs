//! Dashboard UI server mode, sessions, capabilities and context.

use rand::RngCore;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use ciphervault_local_store::AccountStore;

use crate::hosted_account_endpoint;
use crate::util::current_device_identity;

/// The embedded UI has two deliberately separate serving contexts. The local
/// workspace has access to a vault's private data and actions, while the
/// hosted server is a public explorer and must never acquire those routes by
/// accident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UiServerMode {
    LocalPrivate,
    PublicExplorer,
}

impl UiServerMode {
    pub(crate) fn access_mode(self) -> &'static str {
        match self {
            Self::LocalPrivate => "private",
            Self::PublicExplorer => "public",
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::LocalPrivate => "local_private",
            Self::PublicExplorer => "public_explorer",
        }
    }
}

#[derive(Clone)]
pub(crate) struct PrivateUiSessionState {
    pub(crate) token: String,
    pub(crate) vault_binding: Option<String>,
    pub(crate) issued_at: Instant,
}

static PRIVATE_UI_SESSION: OnceLock<RwLock<PrivateUiSessionState>> = OnceLock::new();
pub(crate) const PRIVATE_UI_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

pub(crate) fn new_private_ui_session(_vault_binding: Option<String>) -> PrivateUiSessionState {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    PrivateUiSessionState {
        token: hex::encode(token_bytes),
        // This token protects the loopback browser session. Selected workspace
        // authorization remains a separate account/device check per request.
        vault_binding: None,
        issued_at: Instant::now(),
    }
}

pub(crate) fn private_ui_session_should_rotate(
    state: &PrivateUiSessionState,
    _current_binding: &Option<String>,
) -> bool {
    state.issued_at.elapsed() >= PRIVATE_UI_SESSION_TTL
}

pub(crate) fn private_ui_session_snapshot() -> PrivateUiSessionState {
    let session = PRIVATE_UI_SESSION.get_or_init(|| RwLock::new(new_private_ui_session(None)));
    let mut state = session
        .write()
        .expect("private UI session lock must not be poisoned");
    if private_ui_session_should_rotate(&state, &None) {
        *state = new_private_ui_session(None);
    }
    state.clone()
}

pub(crate) fn revoke_private_ui_session() {
    let session = PRIVATE_UI_SESSION.get_or_init(|| RwLock::new(new_private_ui_session(None)));
    let mut state = session
        .write()
        .expect("private UI session lock must not be poisoned");
    *state = new_private_ui_session(None);
}

pub(crate) fn current_account_context() -> serde_json::Value {
    let Ok(account) = AccountStore::open(None) else {
        return serde_json::json!({
            "configured": false,
            "required": false,
            "authenticated": false,
        });
    };
    let mut context = serde_json::json!({
        "configured": true,
        "account_id": account.account_id(),
        "display_name": account.record().display_name,
        "session": account.session_status(),
        // If any vault has been linked, inability to resolve the current
        // device is surfaced as an authentication requirement rather than a
        // silent accountless fallback.
        "required": !account.record().vaults.is_empty(),
    });
    if let Ok((vault_id, device_id, device_pk)) = current_device_identity() {
        let linked = account.is_vault_linked(&vault_id);
        let authenticated = account.is_authenticated_for_device(&vault_id, &device_id, &device_pk);
        if let Some(object) = context.as_object_mut() {
            object.insert("vault_id_hex".into(), serde_json::Value::String(vault_id));
            object.insert("device_id_hex".into(), serde_json::Value::String(device_id));
            object.insert(
                "device_public_key_hex".into(),
                serde_json::Value::String(device_pk),
            );
            object.insert("linked".into(), serde_json::Value::Bool(linked));
            object.insert(
                "authenticated".into(),
                serde_json::Value::Bool(authenticated),
            );
            object.insert("required".into(), serde_json::Value::Bool(linked));
        }
    }
    context
}

/// Outcome of the best-effort startup sign-in for `ui --local`. The local
/// dashboard is loopback-only and runs as the machine owner, so it unlocks
/// the OS-protected account key itself instead of asking the browser to do
/// a device-key ceremony on every fresh boot.
pub(crate) enum LocalStartupSession {
    /// No sign-in was needed: either a live session already exists or this
    /// machine needs none (no account, no vault, or vault not linked).
    AlreadyValid { summary: String },
    /// A fresh device-bound session was established at startup.
    Established { display_name: String },
    /// Auto sign-in did not apply; the account panel's manual sign-in
    /// remains available as a fallback.
    NotApplicable { reason: String },
}

/// Best-effort account sign-in for `ui --local` startup so the dashboard
/// opens already authenticated. This only ever *creates* a session when one
/// is required-but-missing (a linked vault with no live device session);
/// accountless machines, unlinked vaults, and explicit logouts are left
/// untouched — logout must keep working, so this runs once at startup and
/// never on a polled route.
pub(crate) fn ensure_local_account_session() -> LocalStartupSession {
    if private_account_session_valid() {
        let summary = match AccountStore::open(None) {
            Ok(account) if account.session_status().authenticated => {
                format!("signed in as {}", account.record().display_name)
            }
            Ok(_) => "no active session required".to_string(),
            Err(_) => "no local account configured".to_string(),
        };
        return LocalStartupSession::AlreadyValid { summary };
    }
    let account = match AccountStore::open(None) {
        Ok(account) => account,
        Err(_) => {
            return LocalStartupSession::NotApplicable {
                reason:
                    "no local account is configured (run `ciphervault auth init` to create one)"
                        .to_string(),
            };
        }
    };
    let (vault_id, device_id, _) = match current_device_identity() {
        Ok(identity) => identity,
        Err(_) => {
            return LocalStartupSession::NotApplicable {
                reason: "no local vault found (run `ciphervault init` first)".to_string(),
            };
        }
    };
    if !account.is_vault_linked(&vault_id) {
        return LocalStartupSession::NotApplicable {
            reason: "this vault is not linked to the account (run `ciphervault vault link`)"
                .to_string(),
        };
    }
    match account.login(Some(&device_id)) {
        Ok(_) => LocalStartupSession::Established {
            display_name: account.record().display_name.clone(),
        },
        Err(error) => LocalStartupSession::NotApplicable {
            reason: format!("automatic sign-in failed: {error} (use the account panel to sign in)"),
        },
    }
}

/// Account authentication is optional. Once a vault is linked, private API
/// calls require a live session bound to that vault's enrolled device.
pub(crate) fn private_account_session_valid() -> bool {
    let Ok(account) = AccountStore::open(None) else {
        return true;
    };
    let Ok((vault_id, device_id, device_pk)) = current_device_identity() else {
        // An account with linked vaults must fail closed if the local vault
        // identity cannot be read. An account with no links still preserves
        // accountless local mode.
        return account.record().vaults.is_empty();
    };
    if !account.is_vault_linked(&vault_id) {
        return true;
    }
    account.is_authenticated_for_device(&vault_id, &device_id, &device_pk)
}

pub(crate) fn ui_capabilities(mode: UiServerMode) -> serde_json::Value {
    let private = mode == UiServerMode::LocalPrivate;
    let hosted_account = hosted_account_endpoint().is_some();
    let public_feed_configured = std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_FEED")
        .ok()
        .is_some_and(|path| !path.trim().is_empty());
    serde_json::json!({
        "public_operator_telemetry": true,
        // A public checkpoint publisher is opt-in. Never use a local vault
        // database as an implicit public feed.
        "public_checkpoint_metadata": !private && public_feed_configured,
        "vault_workspace": private,
        "snapshot_history": private,
        "file_inventory": private,
        "snapshot_mutation": private,
        "restore": private,
        "file_management": private,
        "recovery_ceremony": private,
        "plaintext_inspection": private,
        "workspace_switching": private,
        "fleet_audit": private,
        "hosted_account_proxy": hosted_account,
        "hosted_webauthn": hosted_account,
    })
}

pub(crate) fn ui_context(mode: UiServerMode) -> serde_json::Value {
    serde_json::json!({
        "mode": mode.name(),
        "access_mode": mode.access_mode(),
        "capabilities": ui_capabilities(mode),
        // Baked-in crate version so promotion automation can assert the
        // deployed build without trusting route freshness alone.
        "build_version": env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod local_startup_session_tests {
    use super::*;

    #[tokio::test]
    async fn accountless_machine_is_already_valid_without_login_attempt() {
        let _guard = crate::util::TEST_PROCESS_STATE.lock().await;
        // Startup sign-in must be a silent no-op where no account exists: it
        // must neither fail nor mint any session material.
        let empty_dir = std::env::temp_dir().join(format!(
            "cv_no_account_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&empty_dir).unwrap();
        let saved_dir = std::env::var_os("CIPHERVAULT_ACCOUNT_DIR");
        let saved_path = std::env::var_os("CIPHERVAULT_ACCOUNT_PATH");
        std::env::set_var("CIPHERVAULT_ACCOUNT_DIR", &empty_dir);
        std::env::remove_var("CIPHERVAULT_ACCOUNT_PATH");
        let outcome = ensure_local_account_session();
        match saved_dir {
            Some(value) => std::env::set_var("CIPHERVAULT_ACCOUNT_DIR", value),
            None => std::env::remove_var("CIPHERVAULT_ACCOUNT_DIR"),
        }
        match saved_path {
            Some(value) => std::env::set_var("CIPHERVAULT_ACCOUNT_PATH", value),
            None => std::env::remove_var("CIPHERVAULT_ACCOUNT_PATH"),
        }
        match outcome {
            LocalStartupSession::AlreadyValid { summary } => {
                assert!(summary.contains("no local account"), "{summary}");
            }
            LocalStartupSession::Established { .. } | LocalStartupSession::NotApplicable { .. } => {
                panic!("accountless startup must not attempt a sign-in")
            }
        }
        assert!(
            std::fs::read_dir(&empty_dir).unwrap().next().is_none(),
            "startup sign-in must not write into an empty account dir"
        );
        let _ = std::fs::remove_dir_all(&empty_dir);
    }
}
