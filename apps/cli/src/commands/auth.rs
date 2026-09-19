//! Account, device and vault-link commands plus hosted revocation sync.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use reqwest::Client as HttpClient;
use std::time::Duration;

use ciphervault_local_store::AccountStore;

use crate::util::current_device_identity;

pub(crate) fn cmd_auth_init(name: Option<String>) -> Result<()> {
    let account = AccountStore::create(name.as_deref(), None)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "CipherVault account created.".bold().green());
    println!("  Account ID:   {}", account.account_id().yellow());
    println!("  Display name: {}", account.record().display_name);
    println!("  Public key:   {}", account.public_key_hex().cyan());
    println!("  Metadata:     {}", AccountStore::default_path().display());
    println!(
        "\nThe account is a control-plane identity. Vault keys and the offline recovery secret remain local to each vault."
    );
    Ok(())
}

pub(crate) fn cmd_auth_login() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let device = current_device_identity().ok();
    // An account can be logged in before any vault is linked. Bind the
    // session to a device only when that device is already enrolled for the
    // current vault; `vault link` performs the enrollment step.
    let device_id = device
        .as_ref()
        .and_then(|(vault_id, device_id, device_pk)| {
            (account.is_vault_linked(vault_id) && account.is_device_active(device_id, device_pk))
                .then_some(device_id.as_str())
        });
    let status = account
        .login(device_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!(
        "{}",
        "CipherVault account session established.".bold().green()
    );
    println!("  Account ID: {}", status.account_id.yellow());
    if let Some(device_id) = status.device_id_hex {
        println!("  Device:     {}", device_id.cyan());
        println!("  Session:    device-bound (30 minutes)");
    } else {
        println!("  Session:    account-only (link a vault to bind this device)");
    }
    let endpoint = std::env::var("CIPHERVAULT_ACCOUNT_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| account.hosted_endpoint().map(str::to_owned));
    println!(
        "  Hosted endpoint: {}",
        endpoint
            .as_deref()
            .unwrap_or("not connected; run `ciphervault auth connect`")
    );
    Ok(())
}

pub(crate) fn hosted_endpoint_value(raw: &str) -> Result<String> {
    let endpoint = raw.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        bail!("Hosted account endpoint is empty");
    }
    let parsed = reqwest::Url::parse(endpoint)
        .with_context(|| format!("Invalid hosted account endpoint '{endpoint}'"))?;
    if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") {
        bail!("Hosted account endpoint must use HTTPS (or localhost for development)");
    }
    if parsed.host_str().is_none() {
        bail!("Hosted account endpoint must include a host");
    }
    Ok(endpoint.to_string())
}

pub(crate) async fn cmd_auth_connect(
    endpoint_raw: &str,
    label: &str,
    vault_alias: &str,
) -> Result<()> {
    let endpoint = hosted_endpoint_value(endpoint_raw)?;
    let vault_alias = vault_alias.trim();
    if vault_alias.is_empty() {
        bail!("Hosted vault alias cannot be empty");
    }
    let mut account =
        AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (vault_id, device_id, device_pk) = current_device_identity().context(
        "a vault is required for hosted device enrollment; run this from a CipherVault vault",
    )?;
    let client = HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("ciphervault/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let register = client
        .post(format!("{endpoint}/register"))
        .json(&serde_json::json!({
            "display_name": account.record().display_name,
            "account_public_key_hex": account.public_key_hex(),
        }))
        .send()
        .await
        .context("registering the account with the hosted CipherVault service")?;
    if register.status() != reqwest::StatusCode::CREATED
        && register.status() != reqwest::StatusCode::CONFLICT
    {
        let status = register.status();
        let body = register.text().await.unwrap_or_default();
        bail!("hosted account registration failed ({status}): {body}");
    }

    let challenge_response = client
        .post(format!(
            "{endpoint}/{}/devices/challenge",
            account.account_id()
        ))
        .json(&serde_json::json!({
            "device_id_hex": device_id,
            "public_key_hex": device_pk,
            "label": label,
        }))
        .send()
        .await
        .context("requesting hosted device enrollment challenge")?;
    let challenge_status = challenge_response.status();
    let challenge: serde_json::Value = challenge_response
        .json()
        .await
        .context("decoding hosted device enrollment challenge")?;
    if !challenge_status.is_success() {
        bail!(
            "hosted device challenge failed ({}): {}",
            challenge_status,
            challenge
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    let challenge_id = challenge
        .get("challenge_id")
        .and_then(serde_json::Value::as_str)
        .context("hosted device challenge did not include challenge_id")?;
    let nonce_hex = challenge
        .get("nonce_hex")
        .and_then(serde_json::Value::as_str)
        .context("hosted device challenge did not include nonce_hex")?;
    let signing_bytes = serde_json::to_vec(&(
        account.account_id(),
        Some(device_id.as_str()),
        Some(device_pk.as_str()),
        challenge_id,
        nonce_hex,
    ))?;
    let signature = account
        .sign_challenge(b"account_device_enrollment", &signing_bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let enrollment = client
        .post(format!("{endpoint}/{}/devices", account.account_id()))
        .json(&serde_json::json!({
            "device_id_hex": device_id,
            "public_key_hex": device_pk,
            "label": label,
            "challenge_id": challenge_id,
            "proof_signature_hex": hex::encode(signature),
        }))
        .send()
        .await
        .context("enrolling the device with the hosted CipherVault service")?;
    let enrollment_status = enrollment.status();
    let enrollment_body: serde_json::Value = enrollment
        .json()
        .await
        .context("decoding hosted device enrollment response")?;
    if !enrollment_status.is_success() {
        bail!(
            "hosted device enrollment failed ({}): {}",
            enrollment_status,
            enrollment_body
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    account
        .set_hosted_endpoint(Some(&endpoint))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    // Finish the bootstrap with a short-lived browser handoff. The account
    // key signs the normal hosted login challenge locally; only the resulting
    // one-time handoff URL is shown to the user, never the private key or the
    // managed session token.
    let login_challenge_response = client
        .post(format!("{endpoint}/sessions/challenge"))
        .json(&serde_json::json!({
            "account_id": account.account_id(),
            "device_id_hex": device_id,
        }))
        .send()
        .await
        .context("requesting hosted browser-login challenge")?;
    let login_challenge_status = login_challenge_response.status();
    let login_challenge: serde_json::Value = login_challenge_response
        .json()
        .await
        .context("decoding hosted browser-login challenge")?;
    if !login_challenge_status.is_success() {
        bail!(
            "hosted browser-login challenge failed ({}): {}",
            login_challenge_status,
            login_challenge
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    let login_challenge_id = login_challenge
        .get("challenge_id")
        .and_then(serde_json::Value::as_str)
        .context("hosted browser-login challenge did not include challenge_id")?;
    let login_nonce_hex = login_challenge
        .get("nonce_hex")
        .and_then(serde_json::Value::as_str)
        .context("hosted browser-login challenge did not include nonce_hex")?;
    let login_signing_bytes = serde_json::to_vec(&(
        account.account_id(),
        Some(device_id.as_str()),
        Option::<&str>::None,
        login_challenge_id,
        login_nonce_hex,
    ))?;
    let login_signature = account
        .sign_challenge(b"account_login", &login_signing_bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let login_response = client
        .post(format!("{endpoint}/sessions/login"))
        .json(&serde_json::json!({
            "challenge_id": login_challenge_id,
            "signature_hex": hex::encode(login_signature),
        }))
        .send()
        .await
        .context("creating hosted browser-login session")?;
    let login_status = login_response.status();
    let login: serde_json::Value = login_response
        .json()
        .await
        .context("decoding hosted browser-login session")?;
    if !login_status.is_success() {
        bail!(
            "hosted browser-login failed ({}): {}",
            login_status,
            login
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    let login_token = login
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("hosted browser-login response did not include a session token")?;
    let vault_link_response = client
        .post(format!("{endpoint}/{}/vaults", account.account_id()))
        .bearer_auth(login_token)
        .json(&serde_json::json!({
            "vault_id_hex": vault_id,
            "alias": vault_alias,
            "role": "owner",
        }))
        .send()
        .await
        .context("linking the vault to the hosted account")?;
    if !vault_link_response.status().is_success()
        && vault_link_response.status() != reqwest::StatusCode::CONFLICT
    {
        let status = vault_link_response.status();
        let body = vault_link_response.text().await.unwrap_or_default();
        bail!("hosted vault link failed ({status}): {body}");
    }
    let handoff_response = client
        .post(format!("{endpoint}/sessions/handoff"))
        .bearer_auth(login_token)
        .send()
        .await
        .context("creating hosted browser handoff")?;
    let handoff_status = handoff_response.status();
    let handoff: serde_json::Value = handoff_response
        .json()
        .await
        .context("decoding hosted browser handoff")?;
    if !handoff_status.is_success() {
        bail!(
            "hosted browser handoff failed ({}): {}",
            handoff_status,
            handoff
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    let handoff_code = handoff
        .get("handoff_code")
        .and_then(serde_json::Value::as_str)
        .context("hosted browser handoff did not include a code")?;
    let dashboard_url = std::env::var("CIPHERVAULT_DASHBOARD_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "https://vault.cipherv.online/".to_string());
    let browser_url = format!(
        "{}?ciphervault_handoff={handoff_code}",
        dashboard_url.trim_end_matches('/')
    );
    println!(
        "{}",
        "CipherVault account connected to hosted service."
            .bold()
            .green()
    );
    println!("  Account ID: {}", account.account_id().yellow());
    println!("  Device:     {}", device_id.cyan());
    println!("  Endpoint:   {}", endpoint);
    println!(
        "\nOpen this one-time browser link within two minutes to finish hosted sign-in:\n  {}",
        browser_url
    );
    Ok(())
}

pub(crate) fn cmd_auth_logout() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    account
        .logout()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "CipherVault account session revoked.".green());
    Ok(())
}

pub(crate) fn cmd_auth_status() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let session = account.session_status();
    println!("{}", "CipherVault account".bold().cyan());
    println!("  Account ID:   {}", account.account_id().yellow());
    println!("  Display name: {}", account.record().display_name);
    println!("  Public key:   {}", account.public_key_hex());
    println!(
        "  Hosted endpoint: {}",
        account.hosted_endpoint().unwrap_or("not connected")
    );
    println!("  Metadata:     {}", AccountStore::default_path().display());
    println!("  Devices:      {}", account.record().devices.len());
    println!("  Vault links:  {}", account.record().vaults.len());
    println!(
        "  Session:      {}",
        if session.authenticated {
            "authenticated"
        } else {
            "signed out"
        }
    );
    if let Some(expires) = session.expires_at_utc {
        println!("  Session expiry: {}", expires);
    }
    Ok(())
}

pub(crate) fn cmd_device_list() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if account.record().devices.is_empty() {
        println!(
            "No devices are enrolled in account {}.",
            account.account_id()
        );
        return Ok(());
    }
    println!("Devices for {}:", account.account_id().yellow());
    for device in &account.record().devices {
        let state = if device.revoked_at_utc.is_some() {
            "REVOKED"
        } else {
            "ACTIVE"
        };
        println!(
            "  {}  {}  {}  {}",
            device.device_id_hex.cyan(),
            state,
            device.label,
            device.public_key_hex
        );
    }
    Ok(())
}

pub(crate) async fn sync_hosted_device_revocation(
    account: &AccountStore,
    device_id: &str,
) -> Result<()> {
    let endpoint = std::env::var("CIPHERVAULT_ACCOUNT_ENDPOINT")
        .context("CIPHERVAULT_ACCOUNT_ENDPOINT is not configured")?;
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        bail!("CIPHERVAULT_ACCOUNT_ENDPOINT is empty");
    }

    // The hosted service only accepts a short-lived bearer session. Obtain it
    // with the account key without persisting or transmitting the private key.
    // If a current vault device is available, bind the session to that device;
    // otherwise use an account-only session for administrative revocation.
    let current_device = current_device_identity().ok().map(|(_, id, _)| id);
    let challenge_response = HttpClient::new()
        .post(format!("{endpoint}/v1/sessions/challenge"))
        .json(&serde_json::json!({
            "account_id": account.account_id(),
            "device_id_hex": current_device,
        }))
        .send()
        .await
        .context("requesting hosted account login challenge")?
        .error_for_status()
        .context("hosted account login challenge was rejected")?;
    let challenge: serde_json::Value = challenge_response
        .json()
        .await
        .context("decoding hosted account login challenge")?;
    let challenge_id = challenge
        .get("challenge_id")
        .and_then(serde_json::Value::as_str)
        .context("hosted login challenge did not include challenge_id")?;
    let nonce_hex = challenge
        .get("nonce_hex")
        .and_then(serde_json::Value::as_str)
        .context("hosted login challenge did not include nonce_hex")?;
    let signing_bytes = serde_json::to_vec(&(
        account.account_id(),
        current_device.as_deref(),
        Option::<&str>::None,
        challenge_id,
        nonce_hex,
    ))?;
    let signature = account
        .sign_challenge(b"account_login", &signing_bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let session_response = HttpClient::new()
        .post(format!("{endpoint}/v1/sessions"))
        .json(&serde_json::json!({
            "challenge_id": challenge_id,
            "signature_hex": hex::encode(signature),
        }))
        .send()
        .await
        .context("requesting hosted account session")?
        .error_for_status()
        .context("hosted account session was rejected")?;
    let session: serde_json::Value = session_response
        .json()
        .await
        .context("decoding hosted account session")?;
    let token = session
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("hosted account session did not include a token")?;
    HttpClient::new()
        .post(format!(
            "{endpoint}/v1/accounts/{}/devices/{}/revoke",
            account.account_id(),
            device_id
        ))
        .bearer_auth(token)
        .send()
        .await
        .context("requesting hosted device revocation")?
        .error_for_status()
        .context("hosted device revocation was rejected")?;
    Ok(())
}

pub(crate) async fn cmd_device_revoke(device_id: &str) -> Result<()> {
    let mut account =
        AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let changed = account
        .revoke_device(device_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if !changed {
        bail!(
            "Device '{}' is not enrolled or is already revoked.",
            device_id
        );
    }
    println!(
        "{}",
        "Device revoked and local account session invalidated.".green()
    );
    if std::env::var_os("CIPHERVAULT_ACCOUNT_ENDPOINT").is_some() {
        match sync_hosted_device_revocation(&account, device_id).await {
            Ok(()) => println!("Hosted account session and operator bindings revoked."),
            Err(error) => eprintln!(
                "{} Hosted revocation could not be confirmed: {error}",
                "Warning:".yellow()
            ),
        }
    }
    Ok(())
}

pub(crate) fn cmd_vault_link(alias: &str) -> Result<()> {
    let mut account =
        AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (vault_id, device_id, device_pk) = current_device_identity()?;
    account
        .register_device(&device_id, &device_pk, alias)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    account
        .link_vault(&vault_id, alias, "owner")
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    // Linking a vault establishes the device binding for the local account
    // session. This does not transmit vault keys or plaintext.
    account
        .login(Some(&device_id))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "Vault linked to CipherVault account.".bold().green());
    println!("  Vault ID: {}", vault_id.yellow());
    println!("  Device:   {}", device_id.cyan());
    println!("  Role:     owner");
    Ok(())
}

pub(crate) fn cmd_vault_unlink() -> Result<()> {
    let mut account =
        AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (vault_id, _, _) = current_device_identity()?;
    let changed = account
        .unlink_vault(&vault_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if !changed {
        bail!("Vault '{}' is not linked to this account.", vault_id);
    }
    account
        .logout()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "Vault unlinked from CipherVault account.".green());
    Ok(())
}
