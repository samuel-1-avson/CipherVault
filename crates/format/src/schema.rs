use serde::{Deserialize, Serialize};

use crate::canonical::{compute_digest, to_canonical_cbor};
use crate::error::FormatError;
use ciphervault_crypto::signatures::{sign_with_domain, verify_with_domain};
use ciphervault_crypto::{HardwareSecurityModule, HsmSlot};
use ed25519_dalek::SigningKey;

pub const PROTOCOL_VERSION: u32 = 1;

/// Genesis record establishing a new vault.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GenesisRecord {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub recovery_signing_pk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub recovery_encryption_pk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub policy_digest: Vec<u8>,
    pub created_at_utc: u64,
    #[serde(with = "serde_bytes")]
    pub creation_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl GenesisRecord {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        to_canonical_cbor(&unsigned)
    }

    pub fn sign(&mut self, recovery_sk: &SigningKey) -> Result<(), FormatError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = sign_with_domain(recovery_sk, b"genesis_record", &unsigned);
        self.signature = sig.to_vec();
        Ok(())
    }

    pub fn verify(&self) -> Result<(), FormatError> {
        if self.recovery_signing_pk.len() != 32 || self.signature.len() != 64 {
            return Err(FormatError::MalformedRecord(
                "Invalid key or signature length in genesis".into(),
            ));
        }
        let unsigned = self.unsigned_bytes()?;
        let mut pk = [0u8; 32];
        let mut sig = [0u8; 64];
        pk.copy_from_slice(&self.recovery_signing_pk);
        sig.copy_from_slice(&self.signature);
        verify_with_domain(&pk, b"genesis_record", &unsigned, &sig)
            .map_err(FormatError::CryptoError)
    }
}

/// Device authorization certificate signed by the recovery authority.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DeviceCertificate {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub certificate_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_signing_pk: Vec<u8>,
    pub permissions: u32,
    pub authority_generation: u64,
    pub issued_at_utc: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl DeviceCertificate {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        to_canonical_cbor(&unsigned)
    }

    pub fn sign(&mut self, recovery_sk: &SigningKey) -> Result<(), FormatError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = sign_with_domain(recovery_sk, b"device_certificate", &unsigned);
        self.signature = sig.to_vec();
        Ok(())
    }

    pub fn verify(&self, recovery_pk_bytes: &[u8; 32]) -> Result<(), FormatError> {
        if self.signature.len() != 64 {
            return Err(FormatError::MalformedRecord(
                "Invalid signature length in device cert".into(),
            ));
        }
        let unsigned = self.unsigned_bytes()?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.signature);
        verify_with_domain(recovery_pk_bytes, b"device_certificate", &unsigned, &sig)
            .map_err(FormatError::CryptoError)
    }
}

/// Epoch envelope wrapping a VaultEpochKey to the recovery public key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EpochEnvelope {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "serde_bytes")]
    pub recipient_fingerprint: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sealed_epoch_key: Vec<u8>,
    pub created_at_utc: u64,
    #[serde(with = "serde_bytes")]
    pub signer_device_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl EpochEnvelope {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        to_canonical_cbor(&unsigned)
    }

    pub fn sign(&mut self, device_sk: &SigningKey) -> Result<(), FormatError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = sign_with_domain(device_sk, b"epoch_envelope", &unsigned);
        self.signature = sig.to_vec();
        Ok(())
    }

    pub fn verify(&self, device_pk_bytes: &[u8; 32]) -> Result<(), FormatError> {
        if self.signature.len() != 64 {
            return Err(FormatError::MalformedRecord(
                "Invalid signature length in epoch envelope".into(),
            ));
        }
        let unsigned = self.unsigned_bytes()?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.signature);
        verify_with_domain(device_pk_bytes, b"epoch_envelope", &unsigned, &sig)
            .map_err(FormatError::CryptoError)
    }
}

/// Chunk wire object stored on operators.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChunkWireObject {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub file_version_id: Vec<u8>,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub declared_padded_length: u32,
    pub key_epoch: u64,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>, // nonce (24) + ciphertext + tag (16)
}

impl ChunkWireObject {
    /// Computes the AAD that must bind this chunk.
    pub fn compute_aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.version.to_le_bytes());
        aad.extend_from_slice(&self.vault_id);
        aad.extend_from_slice(&self.file_version_id);
        aad.extend_from_slice(&self.chunk_index.to_le_bytes());
        aad.extend_from_slice(&self.total_chunks.to_le_bytes());
        aad.extend_from_slice(&self.declared_padded_length.to_le_bytes());
        aad.extend_from_slice(&self.key_epoch.to_le_bytes());
        aad
    }

    /// Computes the content identifier (SHA-256 digest of wire representation).
    pub fn compute_cid(&self) -> Result<[u8; 32], FormatError> {
        let bytes = to_canonical_cbor(self)?;
        Ok(compute_digest(&bytes))
    }
}

/// Confidential file entry inside the encrypted manifest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManifestFileEntry {
    #[serde(with = "serde_bytes")]
    pub file_id: Vec<u8>,
    pub relative_path: String,
    #[serde(with = "serde_bytes")]
    pub file_version_id: Vec<u8>,
    pub raw_length: u64,
    pub padded_length: u64,
    #[serde(with = "serde_bytes")]
    pub plaintext_sha256: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub file_version_key: Vec<u8>,
    pub chunk_cids: Vec<Vec<u8>>,
    pub is_deleted: bool,
}

/// Snapshot manifest listing all files and chunk keys.
/// Encrypted under epoch-derived manifest key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SnapshotManifest {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "serde_bytes")]
    pub snapshot_id: Vec<u8>,
    pub files: Vec<ManifestFileEntry>,
}

/// Snapshot record signing a snapshot state and pointing to the encrypted manifest CID.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SnapshotRecord {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub snapshot_id: Vec<u8>,
    pub parent_snapshot_ids: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub device_id: Vec<u8>,
    pub device_counter: u64,
    pub authority_generation: u64,
    pub epoch: u64,
    #[serde(with = "serde_bytes")]
    pub encrypted_manifest_cid: Vec<u8>,
    pub encrypted_manifest_len: u64,
    pub advisory_timestamp_utc: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SnapshotRecord {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        to_canonical_cbor(&unsigned)
    }

    pub fn sign(&mut self, device_sk: &SigningKey) -> Result<(), FormatError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = sign_with_domain(device_sk, b"snapshot_record", &unsigned);
        self.signature = sig.to_vec();
        Ok(())
    }

    pub fn sign_with_hsm(
        &mut self,
        hsm: &dyn HardwareSecurityModule,
        slot: HsmSlot,
    ) -> Result<(), FormatError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = hsm
            .sign_message(slot, b"snapshot_record", &unsigned)
            .map_err(FormatError::CryptoError)?;
        self.signature = sig.to_vec();
        Ok(())
    }

    pub fn verify(&self, device_pk_bytes: &[u8; 32]) -> Result<(), FormatError> {
        if self.signature.len() != 64 {
            return Err(FormatError::MalformedRecord(
                "Invalid signature length in snapshot record".into(),
            ));
        }
        let unsigned = self.unsigned_bytes()?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.signature);
        verify_with_domain(device_pk_bytes, b"snapshot_record", &unsigned, &sig)
            .map_err(FormatError::CryptoError)
    }

    pub fn compute_record_cid(&self) -> Result<[u8; 32], FormatError> {
        let bytes = to_canonical_cbor(self)?;
        Ok(compute_digest(&bytes))
    }
}

/// Recovery closure representing all objects needed for a full restore.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RecoveryClosure {
    #[serde(with = "serde_bytes")]
    pub snapshot_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub snapshot_record_cid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub manifest_cid: Vec<u8>,
    pub envelope_ids: Vec<Vec<u8>>,
    pub chunk_cids: Vec<Vec<u8>>,
    pub total_bytes: u64,
}

impl RecoveryClosure {
    pub fn compute_base_closure_digest(&self) -> Result<[u8; 32], FormatError> {
        let bytes = to_canonical_cbor(self)?;
        Ok(compute_digest(&bytes))
    }
}

/// Persisted inventory of the exact objects and discovery records needed to recover a snapshot.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoverySet {
    pub closure: RecoveryClosure,
    pub locator: [u8; 32],
    pub records: Vec<Vec<u8>>,
}

/// Head record representing the latest signed snapshot branch pointer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HeadRecord {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub snapshot_id: Vec<u8>,
    pub parent_snapshot_ids: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub closure_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_id: Vec<u8>,
    pub device_counter: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl HeadRecord {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        to_canonical_cbor(&unsigned)
    }

    pub fn sign(&mut self, device_sk: &SigningKey) -> Result<(), FormatError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = sign_with_domain(device_sk, b"head_record", &unsigned);
        self.signature = sig.to_vec();
        Ok(())
    }

    pub fn sign_with_hsm(
        &mut self,
        hsm: &dyn HardwareSecurityModule,
        slot: HsmSlot,
    ) -> Result<(), FormatError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = hsm
            .sign_message(slot, b"head_record", &unsigned)
            .map_err(FormatError::CryptoError)?;
        self.signature = sig.to_vec();
        Ok(())
    }

    pub fn verify(&self, device_pk_bytes: &[u8; 32]) -> Result<(), FormatError> {
        if self.signature.len() != 64 {
            return Err(FormatError::MalformedRecord(
                "Invalid signature length in head record".into(),
            ));
        }
        let unsigned = self.unsigned_bytes()?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.signature);
        verify_with_domain(device_pk_bytes, b"head_record", &unsigned, &sig)
            .map_err(FormatError::CryptoError)
    }
}

/// Evidence of an on-chain checkpoint commitment published to Arbitrum.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CheckpointEvidence {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub head_record_cid: Vec<u8>,
    pub chain_id: u64,
    #[serde(with = "serde_bytes")]
    pub contract_address: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub tx_hash: Vec<u8>,
    pub block_number: u64,
    pub timestamp_utc: u64,
}

impl CheckpointEvidence {
    pub fn compute_commitment(salt: &[u8; 32], head_record_cid: &[u8; 32]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"CIPHERVAULT-ANCHOR-V1");
        hasher.update(salt);
        hasher.update(head_record_cid);
        hasher.finalize().into()
    }

    pub fn new(
        salt: [u8; 32],
        head_record_cid: [u8; 32],
        chain_id: u64,
        contract_address: [u8; 20],
        tx_hash: [u8; 32],
        block_number: u64,
        timestamp_utc: u64,
    ) -> Self {
        let commitment = Self::compute_commitment(&salt, &head_record_cid);
        Self {
            version: PROTOCOL_VERSION,
            commitment: commitment.to_vec(),
            salt: salt.to_vec(),
            head_record_cid: head_record_cid.to_vec(),
            chain_id,
            contract_address: contract_address.to_vec(),
            tx_hash: tx_hash.to_vec(),
            block_number,
            timestamp_utc,
        }
    }

    pub fn verify_commitment(&self) -> bool {
        if self.salt.len() != 32 || self.head_record_cid.len() != 32 || self.commitment.len() != 32
        {
            return false;
        }
        let mut salt_arr = [0u8; 32];
        let mut head_arr = [0u8; 32];
        salt_arr.copy_from_slice(&self.salt);
        head_arr.copy_from_slice(&self.head_record_cid);
        let expected = Self::compute_commitment(&salt_arr, &head_arr);
        self.commitment == expected.as_slice()
    }
}

/// Placement update record documenting object audit and repair operations.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PlacementUpdate {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub closure_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub object_cid: Vec<u8>,
    pub source_operator: String,
    pub target_operator: String,
    pub updated_at_utc: u64,
    pub verified_readback: bool,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}
