//! Shared database accessors for account reads.

use rusqlite::{params, Connection, OptionalExtension};

use crate::b64_encode;
use crate::state::{
    AccountView, DeviceView, MembershipView, VaultLinkView, WebAuthnCredentialView,
};

pub(crate) fn account_exists(db: &Connection, account_id: &str) -> Result<bool, rusqlite::Error> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE account_id = ?1)",
        params![account_id],
        |row| row.get(0),
    )
}

pub(crate) fn account_view(
    db: &Connection,
    account_id: &str,
) -> Result<Option<AccountView>, rusqlite::Error> {
    let Some(account) = db
        .query_row(
            "SELECT display_name, account_public_key_hex, created_at_utc FROM accounts WHERE account_id = ?1",
            params![account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            },
        )
        .optional()? else {
        return Ok(None);
    };
    let mut devices = Vec::new();
    let mut device_statement = db.prepare(
        "SELECT device_id_hex, public_key_hex, label, enrolled_at_utc, last_seen_at_utc, revoked_at_utc
         FROM devices WHERE account_id = ?1 ORDER BY enrolled_at_utc",
    )?;
    let mut rows = device_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        devices.push(DeviceView {
            device_id_hex: row.get(0)?,
            public_key_hex: row.get(1)?,
            label: row.get(2)?,
            enrolled_at_utc: row.get::<_, i64>(3)? as u64,
            last_seen_at_utc: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
            revoked_at_utc: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        });
    }
    let mut vaults = Vec::new();
    let mut vault_statement = db.prepare(
        "SELECT vault_id_hex, alias, role, linked_at_utc
         FROM vault_links WHERE account_id = ?1 ORDER BY linked_at_utc",
    )?;
    let mut rows = vault_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        vaults.push(VaultLinkView {
            vault_id_hex: row.get(0)?,
            alias: row.get(1)?,
            role: row.get(2)?,
            linked_at_utc: row.get::<_, i64>(3)? as u64,
        });
    }
    let mut webauthn_credentials = Vec::new();
    let mut credential_statement = db.prepare(
        "SELECT credential_id_hex, device_id_hex, algorithm, sign_count, created_at_utc, last_used_at_utc, revoked_at_utc
         FROM webauthn_credentials WHERE account_id = ?1 ORDER BY created_at_utc",
    )?;
    let mut rows = credential_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        let credential_id_hex: String = row.get(0)?;
        let credential_id = hex::decode(&credential_id_hex).unwrap_or_default();
        webauthn_credentials.push(WebAuthnCredentialView {
            credential_id_b64: b64_encode(&credential_id),
            device_id_hex: row.get(1)?,
            algorithm: row.get(2)?,
            sign_count: row.get::<_, i64>(3)? as u32,
            created_at_utc: row.get::<_, i64>(4)? as u64,
            last_used_at_utc: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
            revoked_at_utc: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
        });
    }
    let (totp_enabled, totp_last_used_at_utc) = db
        .query_row(
            "SELECT enabled, last_used_at_utc FROM totp_credentials
             WHERE account_id = ?1 AND revoked_at_utc IS NULL",
            params![account_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? != 0,
                    row.get::<_, Option<i64>>(1)?.map(|value| value as u64),
                ))
            },
        )
        .optional()?
        .unwrap_or((false, None));
    let mut memberships = Vec::new();
    let mut membership_statement = db.prepare(
        "SELECT account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc, revoked_at_utc
         FROM memberships WHERE account_id = ?1 OR member_account_id = ?1 ORDER BY invited_at_utc",
    )?;
    let mut rows = membership_statement.query(params![account_id])?;
    while let Some(row) = rows.next()? {
        memberships.push(MembershipView {
            account_id: row.get(0)?,
            member_account_id: row.get(1)?,
            role: row.get(2)?,
            status: row.get(3)?,
            invited_at_utc: row.get::<_, i64>(4)? as u64,
            accepted_at_utc: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
            revoked_at_utc: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
        });
    }
    Ok(Some(AccountView {
        account_id: account_id.to_string(),
        display_name: account.0,
        account_public_key_hex: account.1,
        created_at_utc: account.2,
        devices,
        vaults,
        webauthn_credentials,
        totp_enabled,
        totp_last_used_at_utc,
        memberships,
    }))
}
