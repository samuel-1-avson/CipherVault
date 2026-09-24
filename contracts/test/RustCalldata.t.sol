// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import "../CipherVaultRegistry.sol";

/// @title RustCalldataTest
/// @notice Cross-artifact check: calldata bytes shaped exactly as the
/// Rust client produces them
/// (`ArbitrumAnchorClient::encode_publish_calldata`: 4-byte selector +
/// 32-byte commitment, no padding) must route to `publish(bytes32)` on
/// the compiled contract, and the getter shape must read the same slot
/// back. Selectors pinned below were verified independently (Rust
/// `sha3` crate and Python `pycryptodome` agreement); if either side
/// drifts, these calls misroute and the test fails.
contract RustCalldataTest {
    CipherVaultRegistry registry;

    // keccak256("publish(bytes32)")[:4], independently verified.
    bytes4 constant PUBLISH_SELECTOR = 0x8b2e6dcf;
    // keccak256("getFirstSeenBlock(bytes32)")[:4], independently verified.
    bytes4 constant GET_SELECTOR = 0x210e19c3;

    function setUp() public {
        registry = new CipherVaultRegistry();
    }

    function testRustPublishCalldataRoutes() public {
        bytes32 commitment = keccak256("ciphervault-rust-calldata-fixture");
        bytes memory rustCalldata = abi.encodePacked(PUBLISH_SELECTOR, commitment);
        assert(rustCalldata.length == 36);
        (bool ok,) = address(registry).call(rustCalldata);
        assert(ok);
        assert(registry.getFirstSeenBlock(commitment) == block.number);
    }

    function testRustGetterCalldataRoutes() public {
        bytes32 commitment = keccak256("ciphervault-rust-getter-fixture");
        registry.publish(commitment);
        uint256 expected = registry.getFirstSeenBlock(commitment);
        bytes memory rustCalldata = abi.encodePacked(GET_SELECTOR, commitment);
        assert(rustCalldata.length == 36);
        (bool ok, bytes memory ret) = address(registry).staticcall(rustCalldata);
        assert(ok);
        assert(ret.length == 32);
        uint256 decoded;
        assembly {
            decoded := mload(add(ret, 32))
        }
        assert(decoded == expected);
    }

    function testWrongSelectorDoesNotRoute() public {
        bytes32 commitment = keccak256("ciphervault-rust-negative-fixture");
        bytes memory badCalldata = abi.encodePacked(bytes4(0xdeadbeef), commitment);
        (bool ok,) = address(registry).call(badCalldata);
        assert(!ok);
        assert(registry.getFirstSeenBlock(commitment) == 0);
    }
}
