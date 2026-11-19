//! Tile and entry-bundle paths of a tiled log
//! (`c2sp.org/tlog-tiles@v1.0.0`).
//!
//! A log serves its Merkle tree as tiles of up to 256 hashes:
//! `tile/<L>/<N>[.p/<W>]`, where `<L>` is the tile level (0 to 63), `<N>`
//! the tile index written as zero-padded three-digit path elements, all but
//! the last prefixed with `x` (index 1234067 is `x001/x234/067`), and
//! `.p/<W>` marks a partial tile of `W` hashes (1 to 255). Entry bundles
//! use the same scheme under `tile/entries/`.
//!
//! The paths here are relative to the log's URL prefix. Parsing accepts
//! only the canonical form, so each tile has exactly one path.

use crate::encoding::parse_decimal_u64;

/// Tree levels covered by one tile.
pub const TILE_HEIGHT: u32 = 8;

/// Hashes (or entries) in a full tile.
pub const TILE_WIDTH: u16 = 256;

/// The highest tile level.
pub const MAX_TILE_LEVEL: u8 = 63;

/// What a tile holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TileKind {
    /// Merkle tree hashes. At level 0 these are leaf hashes; at level `l`
    /// each is the root of a full tile at level `l - 1`.
    Hashes(u8),
    /// An entry bundle: the entries whose leaf hashes form the level-0
    /// tile with the same index.
    Entries,
}

/// Why a tile reference or path is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TileError {
    /// The level is above [`MAX_TILE_LEVEL`].
    #[error("tile level {0} is above {MAX_TILE_LEVEL}")]
    LevelTooHigh(u8),
    /// The width is outside `1..=256`.
    #[error("tile width must be 1 to 256, got {0}")]
    InvalidWidth(u16),
    /// The path is not a canonical tile path.
    #[error("malformed tile path: {0}")]
    Malformed(&'static str),
}

/// One tile or entry bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tile {
    kind: TileKind,
    index: u64,
    width: u16,
}

impl Tile {
    /// The hash tile `index` at `level`, holding `width` hashes (256 for a
    /// full tile).
    pub fn hashes(level: u8, index: u64, width: u16) -> Result<Self, TileError> {
        if level > MAX_TILE_LEVEL {
            return Err(TileError::LevelTooHigh(level));
        }
        Self::build(TileKind::Hashes(level), index, width)
    }

    /// The entry bundle `index`, holding `width` entries (256 for a full
    /// bundle).
    pub fn entries(index: u64, width: u16) -> Result<Self, TileError> {
        Self::build(TileKind::Entries, index, width)
    }

    fn build(kind: TileKind, index: u64, width: u16) -> Result<Self, TileError> {
        if width == 0 || width > TILE_WIDTH {
            return Err(TileError::InvalidWidth(width));
        }
        Ok(Self { kind, index, width })
    }

    /// What the tile holds.
    pub fn kind(&self) -> TileKind {
        self.kind
    }

    /// The tile index within its level.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The number of hashes or entries in the tile.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Whether the tile has fewer than 256 hashes or entries.
    pub fn is_partial(&self) -> bool {
        self.width < TILE_WIDTH
    }

    /// The tile's path, relative to the log prefix.
    pub fn path(&self) -> String {
        let mut path = match self.kind {
            TileKind::Hashes(level) => format!("tile/{level}/"),
            TileKind::Entries => "tile/entries/".to_owned(),
        };
        path.push_str(&encode_index(self.index));
        if self.is_partial() {
            path.push_str(&format!(".p/{}", self.width));
        }
        path
    }

    /// Parses a canonical tile path, relative to the log prefix.
    pub fn parse_path(path: &str) -> Result<Self, TileError> {
        let rest = path
            .strip_prefix("tile/")
            .ok_or(TileError::Malformed("path must start with tile/"))?;
        let (kind, rest) = rest
            .split_once('/')
            .ok_or(TileError::Malformed("missing tile index"))?;
        let kind = if kind == "entries" {
            TileKind::Entries
        } else {
            let level = parse_decimal_u64(kind)
                .and_then(|level| u8::try_from(level).ok())
                .ok_or(TileError::Malformed(
                    "tile level must be a canonical decimal",
                ))?;
            if level > MAX_TILE_LEVEL {
                return Err(TileError::LevelTooHigh(level));
            }
            TileKind::Hashes(level)
        };
        let (index, width) = match rest.split_once(".p/") {
            Some((index, width)) => {
                let width = parse_decimal_u64(width)
                    .and_then(|width| u16::try_from(width).ok())
                    .filter(|width| (1..TILE_WIDTH).contains(width))
                    .ok_or(TileError::Malformed("partial width must be 1 to 255"))?;
                (index, width)
            }
            None => (rest, TILE_WIDTH),
        };
        let index = parse_index(index)?;
        Self::build(kind, index, width)
    }
}

/// The tile index `index` as zero-padded three-digit path elements, all
/// but the last prefixed with `x`.
pub fn encode_index(index: u64) -> String {
    let mut groups = Vec::with_capacity(7);
    let mut rest = index;
    loop {
        groups.push(rest % 1000);
        rest /= 1000;
        if rest == 0 {
            break;
        }
    }
    let last = groups.len() - 1;
    let mut out = String::with_capacity(5 * groups.len());
    for (i, group) in groups.iter().rev().enumerate() {
        if i > 0 {
            out.push('/');
        }
        if i < last {
            out.push('x');
        }
        out.push_str(&format!("{group:03}"));
    }
    out
}

fn parse_index(text: &str) -> Result<u64, TileError> {
    const BAD: TileError =
        TileError::Malformed("tile index must be canonical x-prefixed three-digit elements");
    let elements: Vec<&str> = text.split('/').collect();
    let last = elements.len() - 1;
    let mut index: u64 = 0;
    for (i, element) in elements.iter().enumerate() {
        let digits = if i < last {
            element.strip_prefix('x').ok_or(BAD)?
        } else {
            element
        };
        if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BAD);
        }
        if i == 0 && i < last && digits == "000" {
            return Err(BAD); // a leading zero element is not canonical
        }
        let group: u64 = digits.parse().map_err(|_| BAD)?;
        index = index
            .checked_mul(1000)
            .and_then(|index| index.checked_add(group))
            .ok_or(BAD)?;
    }
    Ok(index)
}

/// The number of full tiles at `level` in a tree of `tree_size` leaves:
/// `floor(tree_size / 256^(level + 1))`.
pub fn full_tile_count(level: u8, tree_size: u64) -> u64 {
    let shift = TILE_HEIGHT * (u32::from(level) + 1);
    tree_size.checked_shr(shift).unwrap_or(0)
}

/// The width of the partial tile at `level` in a tree of `tree_size`
/// leaves, `floor(tree_size / 256^level) mod 256`. Zero means the level
/// has no partial tile.
pub fn partial_tile_width(level: u8, tree_size: u64) -> u16 {
    let shift = TILE_HEIGHT * u32::from(level);
    (tree_size.checked_shr(shift).unwrap_or(0) & 0xff) as u16
}
