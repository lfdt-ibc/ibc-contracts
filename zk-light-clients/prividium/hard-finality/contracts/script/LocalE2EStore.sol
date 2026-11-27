// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice Test-only source-chain direct-word store.
/// The IBC value mapping is deliberately the first state variable, so its
/// Solidity mapping base slot is zero as frozen by the local SourceProfile.
contract LocalE2EStore {
    mapping(bytes32 applicationKey => bytes32 value) private values;

    function set(bytes32 applicationKey, bytes32 value) external {
        values[applicationKey] = value;
    }

    function clear(bytes32 applicationKey) external {
        delete values[applicationKey];
    }

    function get(bytes32 applicationKey) external view returns (bytes32) {
        return values[applicationKey];
    }
}
