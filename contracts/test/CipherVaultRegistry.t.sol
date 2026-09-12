// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import "../CipherVaultRegistry.sol";

// Minimal test harness compatible with Foundry forge / test runners
contract CipherVaultRegistryTest {
    CipherVaultRegistry registry;

    event CommitmentPublished(
        bytes32 indexed commitment,
        address indexed publisher,
        uint256 blockNumber,
        uint256 timestamp
    );

    function setUp() public {
        registry = new CipherVaultRegistry();
    }

    function testPublishNewCommitment() public {
        bytes32 commitment = keccak256("test_commitment_1");
        assert(registry.getFirstSeenBlock(commitment) == 0);

        registry.publish(commitment);

        uint256 seen = registry.getFirstSeenBlock(commitment);
        assert(seen == block.number);
    }

    function testIdempotentDuplicatePublish() public {
        bytes32 commitment = keccak256("test_commitment_2");
        registry.publish(commitment);
        uint256 initialBlock = registry.getFirstSeenBlock(commitment);

        // Second submission should succeed and preserve initialBlock
        registry.publish(commitment);
        assert(registry.getFirstSeenBlock(commitment) == initialBlock);
    }

    function testZeroCommitmentReverts() public {
        bytes32 zeroCommitment = bytes32(0);
        try registry.publish(zeroCommitment) {
            revert("Should have reverted on zero commitment");
        } catch Error(string memory reason) {
            assert(keccak256(bytes(reason)) == keccak256(bytes("Invalid commitment: zero digest")));
        }
    }
}
