// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import { ILineaLightClientErrors } from "../errors/ILineaLightClientErrors.sol";
import { ILineaLightClientMsgs } from "../msgs/ILineaLightClientMsgs.sol";

import { Memory } from "@openzeppelin-contracts/utils/Memory.sol";
import { SafeCast } from "@openzeppelin-contracts/utils/math/SafeCast.sol";
import { RLP } from "@openzeppelin-contracts/utils/RLP.sol";

/// @title BeaconBlock
/// @notice BeaconBlock is a library that provides the Maru beacon block encodings the Linea light client verifies.
/// @dev Mirrors the RLP serializers of Maru, Linea's consensus client:
/// https://github.com/Consensys/linea-monorepo/tree/main/maru/serialization/src/main/kotlin/maru/serialization/rlp
library BeaconBlock {
    using RLP for *;

    /// @notice RLP prefix of a validator, which is a list holding one 20-byte address.
    bytes2 private constant VALIDATOR_PREFIX = 0xd594;

    /// @notice Fields of an execution payload that make up a consensus state.
    /// @param blockNumber Execution block number.
    /// @param timestamp Execution payload timestamp in seconds.
    /// @param stateRoot Root of the execution state trie.
    struct ExecutionPayload {
        uint64 blockNumber;
        uint64 timestamp;
        bytes32 stateRoot;
    }

    /// @notice Computes the hash of a beacon block header, which is the digest its commit seals sign.
    /// @param header The beacon block header.
    /// @return The keccak256 hash of the RLP-encoded header.
    function hash(ILineaLightClientMsgs.BeaconBlockHeader memory header) internal pure returns (bytes32) {
        return keccak256(encode(header, header.stateRoot));
    }

    /// @notice Computes the beacon state root that a header with the given validator set must carry.
    /// @dev The beacon state is `[header, validators]`, where the header has a zero state root to avoid a circular
    /// dependency, so the header state root commits to the validator set of its block.
    /// @param header The beacon block header.
    /// @param validators The validator set, in strictly ascending order as Maru serializes it.
    /// @return The keccak256 hash of the RLP-encoded beacon state.
    function computeStateRoot(
        ILineaLightClientMsgs.BeaconBlockHeader memory header,
        address[] memory validators
    )
        internal
        pure
        returns (bytes32)
    {
        bytes[] memory validatorItems = new bytes[](validators.length);
        for (uint256 i = 0; i < validators.length; ++i) {
            validatorItems[i] = abi.encodePacked(VALIDATOR_PREFIX, validators[i]);
        }

        bytes[] memory state = new bytes[](2);
        state[0] = encode(header, bytes32(0));
        state[1] = validatorItems.encode();
        return keccak256(state.encode());
    }

    /// @notice RLP-encodes a beacon block header with the given state root.
    /// @dev Maru writes the number, round and timestamp as fixed-width 8, 4 and 8-byte strings instead of minimal RLP
    /// integers, so the encoding has a fixed length of 146 bytes.
    /// @param header The beacon block header.
    /// @param stateRoot_ The state root to encode in place of `header.stateRoot`.
    /// @return The RLP list `[number, round, timestamp, [proposer], parentRoot, stateRoot, bodyRoot]`.
    function encode(
        ILineaLightClientMsgs.BeaconBlockHeader memory header,
        bytes32 stateRoot_
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            hex"f890",
            hex"88",
            header.number,
            hex"84",
            header.round,
            hex"88",
            header.timestamp,
            VALIDATOR_PREFIX,
            header.proposer,
            hex"a0",
            header.parentRoot,
            hex"a0",
            stateRoot_,
            hex"a0",
            header.bodyRoot
        );
    }

    /// @notice Decodes the execution payload fields of an RLP-encoded beacon block body.
    /// @dev The body is `[prevCommitSeals, executionPayload]` and the execution payload is `[parentHash, feeRecipient,
    /// stateRoot, receiptsRoot, logsBloom, prevRandao, blockNumber, gasLimit, gasUsed, timestamp, ...]`.
    /// @param bodyRlp RLP-encoded beacon block body.
    /// @return payload Decoded execution payload fields.
    function decodeExecutionPayload(bytes memory bodyRlp) internal pure returns (ExecutionPayload memory payload) {
        Memory.Slice[] memory bodyItems = bodyRlp.decodeList();
        require(bodyItems.length == 2, ILineaLightClientErrors.InvalidBodyFormat(bodyItems.length));

        Memory.Slice[] memory payloadItems = bodyItems[1].readList();
        require(payloadItems.length > 9, ILineaLightClientErrors.InvalidExecutionPayloadFormat(payloadItems.length));

        payload.stateRoot = payloadItems[2].readBytes32();
        payload.blockNumber = SafeCast.toUint64(payloadItems[6].readUint256());
        payload.timestamp = SafeCast.toUint64(payloadItems[9].readUint256());
    }
}
