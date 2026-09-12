// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// @title CipherVaultRegistry
/// @notice Minimal, non-custodial, immutable commitment registry for CipherVault on Arbitrum One.
/// @dev Records first-seen block numbers for opaque salted cryptographic commitments.
/// Stores zero plaintexts, zero vault IDs, zero filenames, and zero user keys.
contract CipherVaultRegistry {
    /// @notice Emitted when a new commitment is first published to the registry.
    /// @param commitment Domain-separated SHA-256 digest of salt and head-record CID.
    /// @param publisher Address of the transaction sender (payer / relayer).
    /// @param blockNumber L2 block number when the commitment was first recorded.
    /// @param timestamp Block timestamp when recorded.
    event CommitmentPublished(
        bytes32 indexed commitment,
        address indexed publisher,
        uint256 blockNumber,
        uint256 timestamp
    );

    /// @notice Maps commitment to the block number where it was first seen (0 if unseen).
    mapping(bytes32 => uint256) public firstSeenBlock;

    /// @notice Publishes an opaque salted commitment to the registry.
    /// @dev Idempotent: repeated submissions of the same commitment succeed without
    /// overwriting the original first-seen block number or re-emitting the event.
    /// @param commitment The 32-byte commitment digest. Must not be zero.
    function publish(bytes32 commitment) external {
        require(commitment != bytes32(0), "Invalid commitment: zero digest");

        if (firstSeenBlock[commitment] == 0) {
            firstSeenBlock[commitment] = block.number;
            emit CommitmentPublished(commitment, msg.sender, block.number, block.timestamp);
        }
    }

    /// @notice Queries the first-seen block number for a commitment.
    /// @param commitment The 32-byte commitment digest to query.
    /// @return The block number where first published, or 0 if not yet published.
    function getFirstSeenBlock(bytes32 commitment) external view returns (uint256) {
        return firstSeenBlock[commitment];
    }
}
