// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import "../CipherVaultRegistry.sol";

interface Vm {
    function startBroadcast() external;
    function stopBroadcast() external;
}

/// @title DeployRegistry
/// @notice Foundry deployment script for CipherVaultRegistry on Arbitrum One or Arbitrum Sepolia.
contract DeployRegistry {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (CipherVaultRegistry registry) {
        vm.startBroadcast();
        registry = new CipherVaultRegistry();
        vm.stopBroadcast();
    }
}
