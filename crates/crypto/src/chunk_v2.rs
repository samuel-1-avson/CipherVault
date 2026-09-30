//! Version 2 opaque chunk addressing. See snapshot/CHUNK_PROTOCOL_V2.md.
//! All derivations use HKDF-SHA256 with independent domains and fixed-width inputs.
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const SALT: &[u8] = b"CipherVault-ChunkWire-v2/HKDF-SHA256";

fn expand<const N: usize>(
    secret: &[u8; 32],
    domain: &[u8],
    vault: &[u8; 32],
    epoch: u64,
    binding: &[u8; 32],
) -> [u8; N] {
    let hkdf = Hkdf::<Sha256>::new(Some(SALT), secret);
    let mut info = Vec::with_capacity(2 + domain.len() + 72);
    info.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    info.extend_from_slice(domain);
    info.extend_from_slice(vault);
    info.extend_from_slice(&epoch.to_le_bytes());
    info.extend_from_slice(binding);
    let mut result = [0u8; N];
    // N is always 24 or 32, well within HKDF-SHA256's output limit.
    hkdf.expand(&info, &mut result)
        .expect("fixed-size HKDF output");
    result
}

pub fn derive_v2_chunk_domain_key(epoch_key: &[u8; 32], vault: &[u8; 32], epoch: u64) -> [u8; 32] {
    expand(epoch_key, b"chunk-domain-key", vault, epoch, &[0; 32])
}

pub fn derive_v2_file_version_id(
    domain_key: &[u8; 32],
    vault: &[u8; 32],
    epoch: u64,
    digest: &[u8; 32],
) -> [u8; 32] {
    expand(domain_key, b"opaque-file-id", vault, epoch, digest)
}

pub fn derive_v2_chunk_id(
    domain_key: &[u8; 32],
    vault: &[u8; 32],
    epoch: u64,
    digest: &[u8; 32],
) -> [u8; 32] {
    expand(domain_key, b"opaque-chunk-id", vault, epoch, digest)
}

pub fn derive_v2_chunk_key_nonce(
    domain_key: &[u8; 32],
    vault: &[u8; 32],
    epoch: u64,
    opaque_id: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, [u8; 24]) {
    (
        Zeroizing::new(expand(
            domain_key,
            b"chunk-aead-key",
            vault,
            epoch,
            opaque_id,
        )),
        expand(domain_key, b"chunk-aead-nonce", vault, epoch, opaque_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domains_vaults_epochs_and_secrets_are_isolated() {
        let key = derive_v2_chunk_domain_key(&[1; 32], &[2; 32], 3);
        let id = derive_v2_chunk_id(&key, &[2; 32], 3, &[4; 32]);
        assert_ne!(id, derive_v2_file_version_id(&key, &[2; 32], 3, &[4; 32]));
        assert_ne!(id, derive_v2_chunk_id(&key, &[5; 32], 3, &[4; 32]));
        assert_ne!(id, derive_v2_chunk_id(&key, &[2; 32], 4, &[4; 32]));
        assert_ne!(id, derive_v2_chunk_id(&[9; 32], &[2; 32], 3, &[4; 32]));
        let (aead, _) = derive_v2_chunk_key_nonce(&key, &[2; 32], 3, &id);
        assert_ne!(aead.as_ref(), id.as_slice());
    }
}
