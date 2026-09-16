//! Pure-Rust Content-Defined Chunking using FastCDC Gear-hash algorithm.
//!
//! Provides deterministic, content-defined boundaries with dual-mask normalized
//! distribution, resolving the byte-shift boundary problem of fixed-size chunking.

const fn generate_gear_matrix() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state = 0x853c49e6748fea9bu64;
    let mut i = 0;
    while i < 256 {
        // SplitMix64 generator for high-entropy deterministic matrix
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
}

pub const GEAR_MATRIX: [u64; 256] = generate_gear_matrix();

pub const DEFAULT_MIN_SIZE: usize = 4 * 1024; // 4 KiB
pub const DEFAULT_AVG_SIZE: usize = 16 * 1024; // 16 KiB
pub const DEFAULT_MAX_SIZE: usize = 64 * 1024; // 64 KiB

/// Configuration parameters for FastCDC content-defined chunking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastCdcConfig {
    pub min_size: usize,
    pub avg_size: usize,
    pub max_size: usize,
    pub mask_s: u64,
    pub mask_l: u64,
}

impl FastCdcConfig {
    /// Creates a new FastCDC configuration with normalized dual masks.
    pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        assert!(min_size > 0, "min_size must be positive");
        assert!(min_size <= avg_size, "min_size must be <= avg_size");
        assert!(avg_size <= max_size, "avg_size must be <= max_size");

        let bits = avg_size.next_power_of_two().trailing_zeros();
        let mask_s = (1u64 << (bits + 1)).saturating_sub(1);
        let mask_l = (1u64 << (bits.saturating_sub(1))).saturating_sub(1);

        Self {
            min_size,
            avg_size,
            max_size,
            mask_s,
            mask_l,
        }
    }
}

impl Default for FastCdcConfig {
    fn default() -> Self {
        Self::new(DEFAULT_MIN_SIZE, DEFAULT_AVG_SIZE, DEFAULT_MAX_SIZE)
    }
}

/// Named chunking profiles: `small` (2/8/32 KiB) for tiny secret files,
/// `default` (4/16/64 KiB), and `large` (16/64/256 KiB) for big blobs.
/// Unknown names fall back to `default` so a typo never breaks snapshots.
pub fn config_from_profile(profile: &str) -> FastCdcConfig {
    match profile.trim().to_ascii_lowercase().as_str() {
        "small" => FastCdcConfig::new(2 * 1024, 8 * 1024, 32 * 1024),
        "large" => FastCdcConfig::new(16 * 1024, 64 * 1024, 256 * 1024),
        _ => FastCdcConfig::default(),
    }
}

/// Chunking profile from `CIPHERVAULT_CHUNK_PROFILE`, defaulting to `default`.
pub fn config_from_env() -> FastCdcConfig {
    match std::env::var("CIPHERVAULT_CHUNK_PROFILE") {
        Ok(profile) => config_from_profile(&profile),
        Err(_) => FastCdcConfig::default(),
    }
}

/// Chunks a contiguous slice into content-defined slices using FastCDC.
pub fn fastcdc_chunk<'a>(data: &'a [u8], config: &FastCdcConfig) -> Vec<&'a [u8]> {
    if data.is_empty() {
        return Vec::new();
    }

    let min_size = config.min_size;
    let avg_size = config.avg_size;
    let max_size = config.max_size;
    let mask_s = config.mask_s;
    let mask_l = config.mask_l;

    let mut chunks = Vec::new();
    let mut cursor = 0;

    while cursor < data.len() {
        let remaining = data.len() - cursor;
        if remaining <= min_size {
            chunks.push(&data[cursor..]);
            break;
        }

        let max_chunk = remaining.min(max_size);
        let normal_split = remaining.min(avg_size);
        let mut cut_point = max_chunk;
        let mut hash = 0u64;

        // Phase 1: Small mask from min_size to avg_size (lower probability of early cut)
        let mut i = min_size;
        while i < normal_split {
            let byte = data[cursor + i];
            hash = (hash << 1).wrapping_add(GEAR_MATRIX[byte as usize]);
            if (hash & mask_s) == 0 {
                cut_point = i + 1;
                break;
            }
            i += 1;
        }

        // Phase 2: Large mask from avg_size to max_size (higher probability of cut before max_size)
        if cut_point == max_chunk && normal_split < max_chunk {
            while i < max_chunk {
                let byte = data[cursor + i];
                hash = (hash << 1).wrapping_add(GEAR_MATRIX[byte as usize]);
                if (hash & mask_l) == 0 {
                    cut_point = i + 1;
                    break;
                }
                i += 1;
            }
        }

        chunks.push(&data[cursor..cursor + cut_point]);
        cursor += cut_point;
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fastcdc_empty_and_sub_min() {
        let config = FastCdcConfig::default();
        assert!(fastcdc_chunk(&[], &config).is_empty());

        let small = vec![42u8; 100];
        let chunks = fastcdc_chunk(&small, &config);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], &small[..]);
    }

    #[test]
    fn test_fastcdc_bounds_enforcement() {
        let config = FastCdcConfig::default();
        // 256 KiB buffer
        let size = 256 * 1024;
        let mut data = vec![0u8; size];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 256) as u8;
        }

        let chunks = fastcdc_chunk(&data, &config);
        assert!(chunks.len() > 1);

        let mut total_len = 0;
        for (idx, chunk) in chunks.iter().enumerate() {
            total_len += chunk.len();
            assert!(chunk.len() <= config.max_size);
            // All chunks except possibly the last must be >= min_size
            if idx + 1 < chunks.len() {
                assert!(
                    chunk.len() >= config.min_size,
                    "Chunk {} len {} < min {}",
                    idx,
                    chunk.len(),
                    config.min_size
                );
            }
        }
        assert_eq!(total_len, size);
    }

    #[test]
    fn test_fastcdc_determinism() {
        let config = FastCdcConfig::default();
        let data = (0..100_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let chunks1 = fastcdc_chunk(&data, &config);
        let chunks2 = fastcdc_chunk(&data, &config);
        assert_eq!(chunks1, chunks2);
    }

    #[test]
    fn test_fastcdc_boundary_shift_resistance() {
        let config = FastCdcConfig::default();
        // Generate a ~250 KiB synthetic config file
        let mut base_data = Vec::new();
        for i in 0..5000 {
            base_data.extend_from_slice(
                format!("CONFIG_KEY_{:04}=SECRET_VALUE_LINE_NUMBER_{:04}\n", i, i).as_bytes(),
            );
        }
        let base_chunks = fastcdc_chunk(&base_data, &config);
        assert!(
            base_chunks.len() >= 10,
            "Expected at least 10 chunks, got {}",
            base_chunks.len()
        );

        // Insert a small 30-byte variable in the middle
        let mut modified_data = base_data.clone();
        let insertion_point = base_data.len() / 2;
        let insertion_content = b"INSERTED_SECURITY_FLAG=TRUE_NEW\n";
        modified_data.splice(
            insertion_point..insertion_point,
            insertion_content.iter().copied(),
        );

        let modified_chunks = fastcdc_chunk(&modified_data, &config);

        // Content-defined chunking should preserve the majority of chunk boundaries:
        // Chunks well before the insertion and chunks well after the insertion should match!
        let mut identical_chunks = 0;
        for m_chunk in &modified_chunks {
            if base_chunks.iter().any(|b_chunk| b_chunk == m_chunk) {
                identical_chunks += 1;
            }
        }

        let preservation_ratio = identical_chunks as f64 / base_chunks.len() as f64;
        assert!(
            preservation_ratio >= 0.80,
            "Expected at least 80% boundary preservation, got {:.2}% ({} / {})",
            preservation_ratio * 100.0,
            identical_chunks,
            base_chunks.len()
        );
    }

    #[test]
    fn test_chunk_profiles_select_expected_sizes() {
        let small = config_from_profile("small");
        assert_eq!(
            (small.min_size, small.avg_size, small.max_size),
            (2048, 8192, 32768)
        );
        let large = config_from_profile(" LARGE ");
        assert_eq!(
            (large.min_size, large.avg_size, large.max_size),
            (16384, 65536, 262144)
        );
        assert_eq!(config_from_profile("nope"), FastCdcConfig::default());
        let data = vec![0xABu8; 200_000];
        for chunk in fastcdc_chunk(&data, &small) {
            assert!(chunk.len() <= small.max_size);
        }
    }
}
