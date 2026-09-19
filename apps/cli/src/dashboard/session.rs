//! Dashboard UI server mode, sessions, capabilities and context.

use rand::RngCore;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use ciphervault_local_store::AccountStore;

use crate::hosted_account_endpoint;
use crate::util::{current_device_identity, get_vault_store};

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

pub(crate) fn current_private_vault_binding() -> Option<String> {
    get_vault_store()
        .ok()
        .and_then(|store| store.get_vault_id().ok())
        .map(hex::encode)
}

pub(crate) fn new_private_ui_session(vault_binding: Option<String>) -> PrivateUiSessionState {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    PrivateUiSessionState {
        token: hex::encode(token_bytes),
        vault_binding,
        issued_at: Instant::now(),
    }
}

pub(crate) fn private_ui_session_should_rotate(
    state: &PrivateUiSessionState,
    current_binding: &Option<String>,
) -> bool {
    state.vault_binding != *current_binding || state.issued_at.elapsed() >= PRIVATE_UI_SESSION_TTL
}

pub(crate) fn private_ui_session_snapshot() -> PrivateUiSessionState {
    let current_binding = current_private_vault_binding();
    let session = PRIVATE_UI_SESSION
        .get_or_init(|| RwLock::new(new_private_ui_session(current_binding.clone())));
    let mut state = session
        .write()
        .expect("private UI session lock must not be poisoned");
    if private_ui_session_should_rotate(&state, &current_binding) {
        *state = new_private_ui_session(current_binding);
    }
    state.clone()
}

pub(crate) fn revoke_private_ui_session() {
    let current_binding = current_private_vault_binding();
    let session = PRIVATE_UI_SESSION
        .get_or_init(|| RwLock::new(new_private_ui_session(current_binding.clone())));
    let mut state = session
        .write()
        .expect("private UI session lock must not be poisoned");
    *state = new_private_ui_session(current_binding);
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
    })
}
