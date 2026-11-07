use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("Genesis error: {0}")]
    InvalidGenesis(String),

    #[error("Invalid block height: expected {expected}, found {found}")]
    InvalidHeight { expected: u64, found: u64 },

    #[error("Invalid previous block hash: expected {expected}, found {found}")]
    InvalidPrevHash { expected: String, found: String },

    #[error("Invalid transaction Merkle root: expected {expected}, found {found}")]
    InvalidMerkleRoot { expected: String, found: String },

    #[error("Invalid cumulative state root: expected {expected}, found {found}")]
    InvalidStateRoot { expected: String, found: String },

    #[error("Non-monotonic timestamp: block timestamp {block} <= previous block timestamp {prev}")]
    InvalidTimestamp { block: u64, prev: u64 },

    #[error("Invalid block proposer: {0}")]
    InvalidProposer(String),

    #[error("Cryptographic signature failure: {0}")]
    InvalidSignature(String),

    #[error(
        "Insufficient quorum: required {required} validator signatures, but collected {actual}"
    )]
    InsufficientQuorum { required: usize, actual: usize },

    #[error("Unauthorized validator: public key {0} is not in the active validator set")]
    UnauthorizedValidator(String),

    #[error("Duplicate validator signature from {0}")]
    DuplicateValidatorSignature(String),

    #[error("Commitment integrity error: computed SHA-256 {computed} != declared {declared}")]
    CommitmentMismatch { computed: String, declared: String },

    #[error("Invalid Merkle inclusion proof: {0}")]
    InvalidInclusionProof(String),

    #[error("Block height {0} not found")]
    BlockNotFound(u64),

    #[error(
        "Fork detected at height {height}: certified {existing} conflicts with incoming {incoming}"
    )]
    ForkDetected {
        height: u64,
        existing: String,
        incoming: String,
    },

    #[error("Commitment {0} not found in sovereign chain state")]
    CommitmentNotFound(String),

    #[error(
        "Stale transaction nonce: got {nonce} but last committed nonce for {pubkey} is {last}"
    )]
    StaleNonce {
        pubkey: String,
        nonce: u64,
        last: u64,
    },

    #[error("Invalid validator rotation: {0}")]
    InvalidRotation(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
