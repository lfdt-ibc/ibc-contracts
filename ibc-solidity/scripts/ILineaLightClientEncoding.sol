// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import { ILineaLightClientMsgs } from "../contracts/light-clients/linea/msgs/ILineaLightClientMsgs.sol";

/// @title Linea Light Client Encoding Schema
/// @notice Generation-only interface exposing the types hidden inside the light client's bytes payloads.
/// @dev Never deployed or implemented by the light client. Pack function inputs without a selector to obtain
/// abi.encode. Matching outputs generate typed decoders for the same payloads.
interface ILineaLightClientEncoding {
    /// @notice Exposes the client state encoding.
    /// @param state The client state.
    function clientState(ILineaLightClientMsgs.ClientState calldata state)
        external
        pure
        returns (ILineaLightClientMsgs.ClientState memory);

    /// @notice Exposes the consensus state preimage encoding.
    /// @param state The consensus state.
    function consensusState(ILineaLightClientMsgs.ConsensusState calldata state)
        external
        pure
        returns (ILineaLightClientMsgs.ConsensusState memory);

    /// @notice Exposes the update payload encoding.
    /// @param message The update message.
    function updateClient(ILineaLightClientMsgs.MsgUpdateClient calldata message)
        external
        pure
        returns (ILineaLightClientMsgs.MsgUpdateClient memory);

    /// @notice Exposes the conflicting consensus states misbehaviour payload encoding.
    /// @param message The misbehaviour message.
    function conflictingConsensusStatesMisbehaviour(
        ILineaLightClientMsgs.MsgConflictingConsensusStatesMisbehaviour calldata message
    )
        external
        pure
        returns (ILineaLightClientMsgs.MsgConflictingConsensusStatesMisbehaviour memory);

    /// @notice Exposes the conflicting headers misbehaviour payload encoding.
    /// @param message The misbehaviour message.
    function conflictingHeadersMisbehaviour(ILineaLightClientMsgs.MsgConflictingHeadersMisbehaviour calldata message)
        external
        pure
        returns (ILineaLightClientMsgs.MsgConflictingHeadersMisbehaviour memory);

    /// @notice Exposes the misbehaviour envelope encoding accepted by `misbehaviour(bytes)`.
    /// @param message The misbehaviour envelope.
    function submitMisbehaviour(ILineaLightClientMsgs.MsgSubmitMisbehaviour calldata message)
        external
        pure
        returns (ILineaLightClientMsgs.MsgSubmitMisbehaviour memory);

    /// @notice Exposes the membership and non-membership proof encoding.
    /// @param proof The proof with its consensus state preimage.
    function membershipProof(ILineaLightClientMsgs.MembershipProof calldata proof)
        external
        pure
        returns (ILineaLightClientMsgs.MembershipProof memory);

    /// @notice Exposes the nested account proof encoding.
    /// @param nodes The ordered RLP trie nodes.
    function proofNodes(bytes[] calldata nodes) external pure returns (bytes[] memory);
}
