//! Scoped-secret context mirror and metadata/binding caches (schema v5).

use super::*;

/// Active scoped context (single-row mirror of the server-side selection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedContext {
    pub tenant_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub updated_at_utc: i64,
}

/// Cached secret metadata row. Values are never cached locally in schema v5;
/// ciphertext caching arrives with offline bundles in Phase 7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSecretMeta {
    pub secret_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub repository_binding_id: Option<String>,
    pub service_id: Option<String>,
    pub name: String,
    pub secret_type: String,
    pub current_version: i64,
    pub status: String,
    pub updated_at_utc: i64,
}

/// Cached repository-binding row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedBinding {
    pub binding_id: String,
    pub project_id: String,
    pub provider: String,
    pub external_repo_id: String,
    pub repo_full_name: String,
    pub repo_url: String,
    pub status: String,
    pub updated_at_utc: i64,
}

impl LocalVaultStore {
    /// Stores the active scoped context (single row, id = 1).
    pub fn set_scoped_context(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        project_id: &str,
        environment_id: &str,
    ) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "INSERT INTO scoped_context (id, tenant_id, workspace_id, project_id, environment_id, updated_at_utc)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET tenant_id = excluded.tenant_id,
                workspace_id = excluded.workspace_id, project_id = excluded.project_id,
                environment_id = excluded.environment_id, updated_at_utc = excluded.updated_at_utc",
            params![
                tenant_id,
                workspace_id,
                project_id,
                environment_id,
                unix_now() as i64
            ],
        )?;
        Ok(())
    }

    /// Returns the active scoped context, if any.
    pub fn get_scoped_context(&self) -> Result<Option<ScopedContext>, LocalStoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT tenant_id, workspace_id, project_id, environment_id, updated_at_utc
                 FROM scoped_context WHERE id = 1",
                [],
                |row| {
                    Ok(ScopedContext {
                        tenant_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        project_id: row.get(2)?,
                        environment_id: row.get(3)?,
                        updated_at_utc: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// Inserts or refreshes one cached secret metadata row, keyed by
    /// `(project_id, environment_id, name)`.
    pub fn upsert_cached_secret(&self, meta: &CachedSecretMeta) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "INSERT INTO scoped_secret_cache (secret_id, tenant_id, project_id, environment_id,
                 repository_binding_id, service_id, name, secret_type, current_version, status,
                 updated_at_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(project_id, environment_id, name) DO UPDATE SET secret_id = excluded.secret_id,
                tenant_id = excluded.tenant_id, repository_binding_id = excluded.repository_binding_id,
                service_id = excluded.service_id, secret_type = excluded.secret_type,
                current_version = excluded.current_version, status = excluded.status,
                updated_at_utc = excluded.updated_at_utc",
            params![
                meta.secret_id,
                meta.tenant_id,
                meta.project_id,
                meta.environment_id,
                meta.repository_binding_id,
                meta.service_id,
                meta.name,
                meta.secret_type,
                meta.current_version,
                meta.status,
                unix_now() as i64
            ],
        )?;
        Ok(())
    }

    /// Looks up one cached secret by scope and name.
    pub fn get_cached_secret(
        &self,
        project_id: &str,
        environment_id: &str,
        name: &str,
    ) -> Result<Option<CachedSecretMeta>, LocalStoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT secret_id, tenant_id, project_id, environment_id, repository_binding_id,
                        service_id, name, secret_type, current_version, status, updated_at_utc
                 FROM scoped_secret_cache
                 WHERE project_id = ?1 AND environment_id = ?2 AND name = ?3",
                params![project_id, environment_id, name],
                |row| {
                    Ok(CachedSecretMeta {
                        secret_id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        project_id: row.get(2)?,
                        environment_id: row.get(3)?,
                        repository_binding_id: row.get(4)?,
                        service_id: row.get(5)?,
                        name: row.get(6)?,
                        secret_type: row.get(7)?,
                        current_version: row.get(8)?,
                        status: row.get(9)?,
                        updated_at_utc: row.get(10)?,
                    })
                },
            )
            .optional()?)
    }

    /// Inserts or refreshes one cached repository binding.
    pub fn upsert_cached_binding(&self, binding: &CachedBinding) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "INSERT INTO scoped_binding_cache (binding_id, project_id, provider, external_repo_id,
                 repo_full_name, repo_url, status, updated_at_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(project_id, provider, external_repo_id) DO UPDATE SET
                binding_id = excluded.binding_id, repo_full_name = excluded.repo_full_name,
                repo_url = excluded.repo_url, status = excluded.status,
                updated_at_utc = excluded.updated_at_utc",
            params![
                binding.binding_id,
                binding.project_id,
                binding.provider,
                binding.external_repo_id,
                binding.repo_full_name,
                binding.repo_url,
                binding.status,
                unix_now() as i64
            ],
        )?;
        Ok(())
    }

    /// Looks up one cached binding by project and durable provider identity.
    pub fn get_cached_binding(
        &self,
        project_id: &str,
        provider: &str,
        external_repo_id: &str,
    ) -> Result<Option<CachedBinding>, LocalStoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT binding_id, project_id, provider, external_repo_id, repo_full_name,
                        repo_url, status, updated_at_utc
                 FROM scoped_binding_cache
                 WHERE project_id = ?1 AND provider = ?2 AND external_repo_id = ?3",
                params![project_id, provider, external_repo_id],
                |row| {
                    Ok(CachedBinding {
                        binding_id: row.get(0)?,
                        project_id: row.get(1)?,
                        provider: row.get(2)?,
                        external_repo_id: row.get(3)?,
                        repo_full_name: row.get(4)?,
                        repo_url: row.get(5)?,
                        status: row.get(6)?,
                        updated_at_utc: row.get(7)?,
                    })
                },
            )
            .optional()?)
    }

    /// Drops cached secrets and bindings for one project (context-switch
    /// cleanup). Returns the total rows removed.
    pub fn clear_scoped_cache(&self, project_id: &str) -> Result<usize, LocalStoreError> {
        self.conn.execute(
            "DELETE FROM scoped_secret_cache WHERE project_id = ?1",
            params![project_id],
        )?;
        let secrets = self.conn.changes() as usize;
        self.conn.execute(
            "DELETE FROM scoped_binding_cache WHERE project_id = ?1",
            params![project_id],
        )?;
        let bindings = self.conn.changes() as usize;
        Ok(secrets + bindings)
    }
}
