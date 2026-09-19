//! Signed bootstrap lists (DON Phase 2): first-contact peers for the swarm.
//!
//! Fleet operators distribute a JSON bootstrap list signed with the fleet
//! key. A node loads the list only when the signature verifies against its
//! pinned `--p2p-bootstrap-signer` key; a missing file, a signer mismatch, a
//! bad signature, or an unparsable addr refuses to boot — fail closed.
//! Explicit `--p2p-bootstrap` addrs remain trusted operator intent and are
//! unaffected.

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

/// Only this list version is accepted; bump on format change.
pub const BOOTSTRAP_LIST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapList {
    pub version: u32,
    pub addrs: Vec<String>,
    pub signer_pk_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("bootstrap list io: {0}")]
    Io(String),
    #[error("bootstrap list parse: {0}")]
    Parse(String),
    #[error("bootstrap list invalid: {0}")]
    Invalid(String),
}

impl BootstrapList {
    pub fn unsigned(addrs: Vec<String>) -> Self {
        Self {
            version: BOOTSTRAP_LIST_VERSION,
            addrs,
            signer_pk_hex: String::new(),
            signature_hex: String::new(),
        }
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ciphervault-bootstrap-list-v1:");
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.addrs.join(",").as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.signer_pk_hex.as_bytes());
        bytes
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        self.signer_pk_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = self.signing_bytes();
        let sig = ciphervault_crypto::signatures::sign_with_domain(
            signing_key,
            b"swarm_bootstrap_list",
            &msg,
        );
        self.signature_hex = hex::encode(sig);
    }

    /// Verifies the list against the pinned fleet signer key and returns the
    /// parsed multiaddrs. Any failure — version, signer, signature, addr
    /// syntax — is an error; there is no partial trust.
    pub fn verify(&self, pinned_signer_pk_hex: &str) -> Result<Vec<Multiaddr>, BootstrapError> {
        if self.version != BOOTSTRAP_LIST_VERSION {
            return Err(BootstrapError::Invalid(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if !self
            .signer_pk_hex
            .eq_ignore_ascii_case(pinned_signer_pk_hex)
        {
            return Err(BootstrapError::Invalid("signer key mismatch".to_string()));
        }
        let pk_bytes =
            hex::decode(&self.signer_pk_hex).map_err(|e| BootstrapError::Invalid(e.to_string()))?;
        if pk_bytes.len() != 32 {
            return Err(BootstrapError::Invalid(
                "signer key must be 32 bytes".to_string(),
            ));
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let sig_bytes =
            hex::decode(&self.signature_hex).map_err(|e| BootstrapError::Invalid(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(BootstrapError::Invalid(
                "signature must be 64 bytes".to_string(),
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        ciphervault_crypto::signatures::verify_with_domain(
            &pk_arr,
            b"swarm_bootstrap_list",
            &self.signing_bytes(),
            &sig_arr,
        )
        .map_err(|_| BootstrapError::Invalid("signature verification failed".to_string()))?;
        self.addrs
            .iter()
            .map(|addr| {
                addr.parse::<Multiaddr>()
                    .map_err(|e| BootstrapError::Invalid(format!("bad addr {addr:?}: {e}")))
            })
            .collect()
    }

    /// Loads a JSON list file and verifies it against the pinned signer.
    pub fn load_verified(
        path: &Path,
        pinned_signer_pk_hex: &str,
    ) -> Result<Vec<Multiaddr>, BootstrapError> {
        let bytes = fs::read(path).map_err(|e| BootstrapError::Io(e.to_string()))?;
        let list: BootstrapList =
            serde_json::from_slice(&bytes).map_err(|e| BootstrapError::Parse(e.to_string()))?;
        list.verify(pinned_signer_pk_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_list() -> (BootstrapList, String) {
        let key = ciphervault_crypto::generate_signing_key();
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        let peer_id = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut list = BootstrapList::unsigned(vec![
            format!("/ip4/192.0.2.1/tcp/9101/p2p/{peer_id}"),
            "/dns/seed.example/tcp/9101".to_string(),
        ]);
        list.sign(&key);
        (list, pk_hex)
    }

    #[test]
    fn roundtrip_verifies_and_parses() {
        let (list, pk_hex) = signed_list();
        let addrs = list.verify(&pk_hex).expect("valid list verifies");
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn tampered_addr_rejected() {
        let (mut list, pk_hex) = signed_list();
        list.addrs[0] = "/ip4/198.51.100.9/tcp/9101".to_string();
        assert!(list.verify(&pk_hex).is_err());
    }

    #[test]
    fn wrong_signer_rejected() {
        let (list, _) = signed_list();
        let other = ciphervault_crypto::generate_signing_key();
        let other_pk = hex::encode(other.verifying_key().to_bytes());
        assert!(list.verify(&other_pk).is_err());
    }

    #[test]
    fn bad_addr_rejected() {
        let key = ciphervault_crypto::generate_signing_key();
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        let mut list = BootstrapList::unsigned(vec!["::not-a-multiaddr::".to_string()]);
        list.sign(&key);
        assert!(list.verify(&pk_hex).is_err());
    }

    #[test]
    fn version_mismatch_rejected() {
        let (mut list, pk_hex) = signed_list();
        list.version = 999;
        assert!(list.verify(&pk_hex).is_err());
    }

    #[test]
    fn json_file_roundtrip() {
        let (list, pk_hex) = signed_list();
        let bytes = serde_json::to_vec_pretty(&list).unwrap();
        let dir = std::env::temp_dir().join(format!("cv-bootstrap-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bootstrap.json");
        fs::write(&path, &bytes).unwrap();
        let addrs = BootstrapList::load_verified(&path, &pk_hex).expect("file verifies");
        assert_eq!(addrs.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }
}
