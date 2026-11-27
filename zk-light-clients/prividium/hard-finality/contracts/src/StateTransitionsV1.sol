// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.24 <0.9.0;

import {PrividiumTypes} from "./PrividiumTypes.sol";

library StateTransitionsV1 {
    error UnknownNextCommitteeHasNonzeroRoot();
    error KnownNextCommitteeHasZeroRoot();
    error ZeroFinalizedBeaconSlot();
    error ZeroFinalizedBeaconHeaderRoot();
    error ZeroCurrentSyncCommitteeRoot();
    error ConflictingAcceptedBatch(
        uint64 l1BatchNumber,
        uint64 currentL2BlockNumber,
        uint64 proposedL2BlockNumber,
        bytes32 currentRoot,
        bytes32 proposedRoot,
        uint64 currentTimestamp,
        uint64 proposedTimestamp
    );

    enum BatchAcceptance {
        Inserted,
        NoOp
    }

    function validateTrustState(PrividiumTypes.ConsensusTrustState memory state) internal pure {
        if (state.finalizedBeaconSlot == 0) revert ZeroFinalizedBeaconSlot();
        if (state.finalizedBeaconHeaderRoot == bytes32(0)) {
            revert ZeroFinalizedBeaconHeaderRoot();
        }
        if (state.currentSyncCommitteeRoot == bytes32(0)) {
            revert ZeroCurrentSyncCommitteeRoot();
        }
        if (!state.nextSyncCommitteeKnown && state.nextSyncCommitteeRoot != bytes32(0)) {
            revert UnknownNextCommitteeHasNonzeroRoot();
        }
        if (state.nextSyncCommitteeKnown && state.nextSyncCommitteeRoot == bytes32(0)) {
            revert KnownNextCommitteeHasZeroRoot();
        }
    }

    /// Must be called only after the Settlement proof and public bindings pass.
    function acceptBatch(
        mapping(uint64 => PrividiumTypes.AcceptedBatchState) storage acceptedBatches,
        uint64 batchNumber,
        uint64 l2BlockNumber,
        bytes32 root,
        uint64 l2BatchTimestamp
    ) internal returns (BatchAcceptance) {
        PrividiumTypes.AcceptedBatchState storage current = acceptedBatches[batchNumber];
        if (!current.exists) {
            current.l2BlockNumber = l2BlockNumber;
            current.root = root;
            current.l2BatchTimestamp = l2BatchTimestamp;
            current.exists = true;
            return BatchAcceptance.Inserted;
        }
        if (
            current.l2BlockNumber != l2BlockNumber || current.root != root
                || current.l2BatchTimestamp != l2BatchTimestamp
        ) {
            revert ConflictingAcceptedBatch(
                batchNumber,
                current.l2BlockNumber,
                l2BlockNumber,
                current.root,
                root,
                current.l2BatchTimestamp,
                l2BatchTimestamp
            );
        }
        return BatchAcceptance.NoOp;
    }
}
