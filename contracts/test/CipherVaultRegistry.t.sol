// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import "../CipherVaultRegistry.sol";

interface Vm {
    function expectEmit(
        bool checkTopic1,
        bool checkTopic2,
        bool checkTopic3,
        bool checkData
    ) external;
}

// Minimal test harness compatible with Foundry forge / test runners
contract CipherVaultRegistryTest {
    CipherVaultRegistry registry;

    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

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

    function testMultipleCommitmentsIndependent() public {
        bytes32 a = keccak256("multi_a");
        bytes32 b = keccak256("multi_b");
        bytes32 c = keccak256("multi_c");
        registry.publish(a);
        registry.publish(b);
        registry.publish(c);
        assert(registry.getFirstSeenBlock(a) == block.number);
        assert(registry.getFirstSeenBlock(b) == block.number);
        assert(registry.getFirstSeenBlock(c) == block.number);
        // Re-publishing one leaves the others untouched.
        registry.publish(b);
        assert(registry.getFirstSeenBlock(a) == block.number);
        assert(registry.getFirstSeenBlock(c) == block.number);
    }

    function testUnknownCommitmentFirstSeenZero() public {
        assert(registry.getFirstSeenBlock(keccak256("never_published")) == 0);
    }

    function testTriplePublishPreservesFirstSeen() public {
        bytes32 commitment = keccak256("triple_publish");
        registry.publish(commitment);
        uint256 firstSeen = registry.getFirstSeenBlock(commitment);
        registry.publish(commitment);
        registry.publish(commitment);
        assert(registry.getFirstSeenBlock(commitment) == firstSeen);
    }

    function testPublishEmitsCommitmentPublished() public {
        bytes32 commitment = keccak256("emitted_commitment");
        vm.expectEmit(true, true, false, true);
        emit CommitmentPublished(commitment, address(this), block.number, block.timestamp);
        registry.publish(commitment);
    }

    function testFuzz_NonZeroCommitmentPublish(bytes32 commitment) public {
        if (commitment == bytes32(0)) {
            return;
        }
        assert(registry.getFirstSeenBlock(commitment) == 0);
        registry.publish(commitment);
        assert(registry.getFirstSeenBlock(commitment) == block.number);
    }
}
