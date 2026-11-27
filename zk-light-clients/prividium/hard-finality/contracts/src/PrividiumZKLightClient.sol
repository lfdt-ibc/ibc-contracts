// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.24 <0.9.0;

import {PrividiumTypes} from "./PrividiumTypes.sol";
import {PublicValuesV1} from "./PublicValuesV1.sol";
import {StateTransitionsV1} from "./StateTransitionsV1.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {ILightClient} from "@ibc-contracts/interfaces/ILightClient.sol";
import {ILightClientMsgs} from "@ibc-contracts/msgs/ILightClientMsgs.sol";

contract PrividiumZKLightClient is ILightClient {
    using StateTransitionsV1 for mapping(uint64 => PrividiumTypes.AcceptedBatchState);

    uint256 private constant MAX_COMPOSITE_UPDATES = 9;

    bytes32 public immutable SOURCE_PROFILE_ID;
    bytes32 public immutable TRUST_UPDATE_VKEY;
    bytes32 public immutable SETTLEMENT_UPDATE_VKEY;
    bytes32 public immutable MEMBERSHIP_VKEY;
    bytes32 public immutable NON_MEMBERSHIP_VKEY;
    address public immutable IBC_STORE;
    uint32 public immutable ABSENCE_PROFILE_ID;
    ISP1Verifier public immutable SP1_VERIFIER;
    address public immutable IBC_ROUTER;

    PrividiumTypes.ConsensusTrustState private consensusTrust;
    mapping(uint64 => PrividiumTypes.AcceptedBatchState) private acceptedBatches;
    mapping(bytes32 => PrividiumTypes.AcceptedMembershipBatch) private acceptedMembershipBatches;

    error UnauthorizedCaller(address actual);
    error ZeroConfiguration();
    error DuplicateVerificationKey();
    error CurrentTrustDigestMismatch(bytes32 expected, bytes32 actual);
    error UnknownBatch(uint64 batchNumber);
    error WrongBatchRoot(uint64 batchNumber, bytes32 expected, bytes32 actual);
    error WrongProofHeight();
    error WrongIbcStore(address actual);
    error WrongPathDigest(bytes32 expected, bytes32 actual);
    error WrongValueHash(bytes32 expected, bytes32 actual);
    error WrongRequestDigest(bytes32 expected, bytes32 actual);
    error WrongAbsenceProfile(uint32 actual);
    error UnsupportedPathShape();
    error UnsupportedMisbehaviour();
    error InvalidCompositeUpdateSequence();
    error InvalidMembershipBatchSize(uint32 actual);
    error UnknownMembershipBatch(bytes32 batchId);
    error WrongMembershipBatchHeight(uint64 expected, uint64 actual);
    error WrongMembershipL1Batch(uint64 expected, uint64 actual);
    error InvalidMembershipClaim(bytes32 batchId, uint32 entryIndex);

    event TrustUpdated(uint64 finalizedBeaconSlot, bytes32 finalizedBeaconHeaderRoot);
    event BatchAccepted(
        uint64 indexed l2BlockNumber,
        uint64 indexed l1BatchNumber,
        bytes32 indexed nativeRoot,
        uint64 l2BatchTimestamp
    );
    event MembershipBatchAccepted(
        bytes32 indexed batchId,
        uint64 indexed proofHeight,
        uint64 l1BatchNumber,
        bytes32 prividiumNativeRoot,
        uint32 entryCount,
        bytes32 batchRoot
    );

    modifier onlyRouter() {
        if (msg.sender != IBC_ROUTER) revert UnauthorizedCaller(msg.sender);
        _;
    }

    constructor(
        bytes32 sourceProfileId,
        PrividiumTypes.ConsensusTrustState memory initialTrust,
        address ibcStore,
        uint32 absenceProfileId,
        bytes32 trustUpdateVkey,
        bytes32 settlementUpdateVkey,
        bytes32 membershipVkey,
        bytes32 nonMembershipVkey,
        address verifier,
        address router
    ) {
        if (
            sourceProfileId == 0 || ibcStore == address(0) || absenceProfileId == 0
                || verifier == address(0) || router == address(0) || trustUpdateVkey == 0
                || settlementUpdateVkey == 0 || membershipVkey == 0 || nonMembershipVkey == 0
        ) revert ZeroConfiguration();
        if (
            trustUpdateVkey == settlementUpdateVkey || trustUpdateVkey == membershipVkey
                || trustUpdateVkey == nonMembershipVkey || settlementUpdateVkey == membershipVkey
                || settlementUpdateVkey == nonMembershipVkey || membershipVkey == nonMembershipVkey
        ) revert DuplicateVerificationKey();
        StateTransitionsV1.validateTrustState(initialTrust);
        SOURCE_PROFILE_ID = sourceProfileId;
        IBC_STORE = ibcStore;
        ABSENCE_PROFILE_ID = absenceProfileId;
        TRUST_UPDATE_VKEY = trustUpdateVkey;
        SETTLEMENT_UPDATE_VKEY = settlementUpdateVkey;
        MEMBERSHIP_VKEY = membershipVkey;
        NON_MEMBERSHIP_VKEY = nonMembershipVkey;
        SP1_VERIFIER = ISP1Verifier(verifier);
        IBC_ROUTER = router;
        consensusTrust = initialTrust;
    }

    function getConsensusTrustState()
        external
        view
        returns (PrividiumTypes.ConsensusTrustState memory)
    {
        return consensusTrust;
    }

    function getAcceptedBatch(uint64 l1BatchNumber)
        external
        view
        returns (bytes32 root, uint64 l2BatchTimestamp, bool exists)
    {
        PrividiumTypes.AcceptedBatchState storage state = acceptedBatches[l1BatchNumber];
        return (state.root, state.l2BatchTimestamp, state.exists);
    }

    function getAcceptedL2Block(uint64 l1BatchNumber) external view returns (uint64) {
        return acceptedBatches[l1BatchNumber].l2BlockNumber;
    }

    function getAcceptedMembershipBatch(bytes32 batchId)
        external
        view
        returns (
            uint64 proofHeight,
            uint64 l1BatchNumber,
            bytes32 prividiumNativeRoot,
            uint32 entryCount,
            bytes32 batchRoot,
            bool exists
        )
    {
        PrividiumTypes.AcceptedMembershipBatch storage batch = acceptedMembershipBatches[batchId];
        return (
            batch.proofHeight,
            batch.l1BatchNumber,
            batch.prividiumNativeRoot,
            batch.entryCount,
            batch.batchRoot,
            batch.exists
        );
    }

    function getClientState() external view override returns (bytes memory) {
        return abi.encode(consensusTrust);
    }

    function updateClient(bytes calldata updateMsg)
        external
        override
        onlyRouter
        returns (ILightClientMsgs.UpdateResult)
    {
        PrividiumTypes.UpdateProofEnvelope memory envelope =
            PublicValuesV1.decodeUpdateEnvelope(updateMsg);
        if (envelope.kind == PrividiumTypes.UpdateKind.TrustUpdate) {
            return _trustUpdate(envelope);
        }
        if (envelope.kind == PrividiumTypes.UpdateKind.CompositeUpdate) {
            return _compositeUpdate(envelope.publicValues);
        }
        return _settlementUpdate(envelope);
    }

    function _compositeUpdate(bytes memory encodedUpdates)
        private
        returns (ILightClientMsgs.UpdateResult)
    {
        bytes[] memory encoded = PublicValuesV1.decodeCompositeUpdates(encodedUpdates);
        if (encoded.length > MAX_COMPOSITE_UPDATES) revert InvalidCompositeUpdateSequence();
        ILightClientMsgs.UpdateResult aggregate = ILightClientMsgs.UpdateResult.NoOp;
        for (uint256 index = 0; index < encoded.length; ++index) {
            PrividiumTypes.UpdateProofEnvelope memory item =
                PublicValuesV1.decodeUpdateEnvelope(encoded[index]);
            ILightClientMsgs.UpdateResult result;
            if (index + 1 == encoded.length) {
                if (item.kind != PrividiumTypes.UpdateKind.SettlementUpdate) {
                    revert InvalidCompositeUpdateSequence();
                }
                result = _settlementUpdate(item);
            } else {
                if (item.kind != PrividiumTypes.UpdateKind.TrustUpdate) {
                    revert InvalidCompositeUpdateSequence();
                }
                result = _trustUpdate(item);
            }
            if (result == ILightClientMsgs.UpdateResult.Update) {
                aggregate = ILightClientMsgs.UpdateResult.Update;
            }
        }
        return aggregate;
    }

    function _trustUpdate(PrividiumTypes.UpdateProofEnvelope memory envelope)
        private
        returns (ILightClientMsgs.UpdateResult)
    {
        PrividiumTypes.TrustUpdatePublicValues memory value =
            PublicValuesV1.decodeTrustUpdate(envelope.publicValues);
        PublicValuesV1.validateV1(
            value.schemaVersion, value.programVersion, value.sourceProfileId, SOURCE_PROFILE_ID
        );
        bytes32 currentDigest = PublicValuesV1.consensusTrustDigest(consensusTrust);
        if (value.previousConsensusTrustDigest != currentDigest) {
            revert CurrentTrustDigestMismatch(currentDigest, value.previousConsensusTrustDigest);
        }
        PrividiumTypes.ConsensusTrustState memory next = PrividiumTypes.ConsensusTrustState({
            finalizedBeaconSlot: value.newFinalizedBeaconSlot,
            finalizedBeaconHeaderRoot: value.newFinalizedBeaconHeaderRoot,
            currentSyncCommitteeRoot: value.newCurrentSyncCommitteeRoot,
            nextSyncCommitteeRoot: value.newNextSyncCommitteeRoot,
            nextSyncCommitteeKnown: value.newNextSyncCommitteeKnown
        });
        StateTransitionsV1.validateTrustState(next);
        SP1_VERIFIER.verifyProof(TRUST_UPDATE_VKEY, envelope.publicValues, envelope.proofBytes);
        if (PublicValuesV1.consensusTrustDigest(next) == currentDigest) {
            return ILightClientMsgs.UpdateResult.NoOp;
        }
        consensusTrust = next;
        emit TrustUpdated(next.finalizedBeaconSlot, next.finalizedBeaconHeaderRoot);
        return ILightClientMsgs.UpdateResult.Update;
    }

    function _settlementUpdate(PrividiumTypes.UpdateProofEnvelope memory envelope)
        private
        returns (ILightClientMsgs.UpdateResult)
    {
        PrividiumTypes.SettlementPublicValues memory value =
            PublicValuesV1.decodeSettlement(envelope.publicValues);
        PublicValuesV1.validateSettlementV3(
            value.schemaVersion, value.programVersion, value.sourceProfileId, SOURCE_PROFILE_ID
        );
        bytes32 currentDigest = PublicValuesV1.consensusTrustDigest(consensusTrust);
        if (value.previousConsensusTrustDigest != currentDigest) {
            revert CurrentTrustDigestMismatch(currentDigest, value.previousConsensusTrustDigest);
        }
        SP1_VERIFIER.verifyProof(SETTLEMENT_UPDATE_VKEY, envelope.publicValues, envelope.proofBytes);
        StateTransitionsV1.BatchAcceptance result = acceptedBatches.acceptBatch(
            value.l1BatchNumber,
            value.l2BlockNumber,
            value.prividiumNativeRoot,
            value.l2BatchTimestamp
        );
        if (result == StateTransitionsV1.BatchAcceptance.Inserted) {
            emit BatchAccepted(
                value.l2BlockNumber,
                value.l1BatchNumber,
                value.prividiumNativeRoot,
                value.l2BatchTimestamp
            );
            return ILightClientMsgs.UpdateResult.Update;
        }
        return ILightClientMsgs.UpdateResult.NoOp;
    }

    function verifyMembership(ILightClientMsgs.MsgVerifyMembership calldata msg_)
        external
        override
        onlyRouter
        returns (uint256)
    {
        if (msg_.proofHeight.revisionNumber != 0 || msg_.proofHeight.revisionHeight == 0) {
            revert WrongProofHeight();
        }
        uint64 proofHeight = msg_.proofHeight.revisionHeight;
        PrividiumTypes.MembershipBatchProofEnvelope memory envelope =
            PublicValuesV1.decodeMembershipBatchProofEnvelope(msg_.proof);
        if (
            envelope.entryCount == 0
                || envelope.entryCount > PrividiumTypes.MAX_MEMBERSHIP_BATCH_ENTRIES
        ) revert InvalidMembershipBatchSize(envelope.entryCount);
        PrividiumTypes.AcceptedBatchState storage accepted = acceptedBatches[envelope.l1BatchNumber];
        if (!accepted.exists) revert UnknownBatch(envelope.l1BatchNumber);
        if (proofHeight > accepted.l2BlockNumber) revert WrongProofHeight();

        PrividiumTypes.MembershipPublicValues memory expected = PrividiumTypes.MembershipPublicValues({
            schemaVersion: PrividiumTypes.SCHEMA_VERSION_V1,
            programVersion: PrividiumTypes.PACKET_PROGRAM_VERSION_V2,
            sourceProfileId: SOURCE_PROFILE_ID,
            proofHeight: proofHeight,
            l1BatchNumber: envelope.l1BatchNumber,
            prividiumNativeRoot: accepted.root,
            ibcStore: IBC_STORE,
            entryCount: envelope.entryCount,
            batchRoot: envelope.batchRoot,
            requestDigest: bytes32(0)
        });
        expected.requestDigest = PublicValuesV1.membershipRequestDigest(expected);
        bytes32 batchId = expected.requestDigest;

        if (envelope.mode == PrividiumTypes.MEMBERSHIP_ENVELOPE_FULL) {
            PrividiumTypes.MembershipPublicValues memory value =
                PublicValuesV1.decodeMembership(envelope.publicValues);
            PublicValuesV1.validatePacketV2(
                value.schemaVersion, value.programVersion, value.sourceProfileId, SOURCE_PROFILE_ID
            );
            if (value.proofHeight != proofHeight) {
                revert WrongMembershipBatchHeight(value.proofHeight, proofHeight);
            }
            if (value.l1BatchNumber != envelope.l1BatchNumber) {
                revert WrongMembershipL1Batch(envelope.l1BatchNumber, value.l1BatchNumber);
            }
            _bindBatch(value.l1BatchNumber, accepted.root, value.prividiumNativeRoot);
            if (value.ibcStore != IBC_STORE) revert WrongIbcStore(value.ibcStore);
            if (value.entryCount != envelope.entryCount) {
                revert InvalidMembershipBatchSize(value.entryCount);
            }
            if (value.batchRoot != envelope.batchRoot) {
                revert InvalidMembershipClaim(batchId, envelope.entryIndex);
            }
            if (value.requestDigest != batchId) {
                revert WrongRequestDigest(batchId, value.requestDigest);
            }
            SP1_VERIFIER.verifyProof(MEMBERSHIP_VKEY, envelope.publicValues, envelope.proofBytes);
            _storeMembershipBatch(batchId, value);
        } else if (!acceptedMembershipBatches[batchId].exists) {
            revert UnknownMembershipBatch(batchId);
        }

        bytes32 leaf = PublicValuesV1.membershipLeaf(
            envelope.entryIndex, _pathDigest(msg_.path), keccak256(msg_.value)
        );
        if (!PublicValuesV1.verifyMembershipClaim(
                envelope.batchRoot,
                envelope.entryCount,
                envelope.entryIndex,
                leaf,
                envelope.siblings
            )) revert InvalidMembershipClaim(batchId, envelope.entryIndex);
        return accepted.l2BatchTimestamp;
    }

    function _storeMembershipBatch(
        bytes32 batchId,
        PrividiumTypes.MembershipPublicValues memory value
    ) private {
        PrividiumTypes.AcceptedMembershipBatch storage current = acceptedMembershipBatches[batchId];
        if (current.exists) return;
        current.proofHeight = value.proofHeight;
        current.l1BatchNumber = value.l1BatchNumber;
        current.prividiumNativeRoot = value.prividiumNativeRoot;
        current.entryCount = value.entryCount;
        current.batchRoot = value.batchRoot;
        current.exists = true;
        emit MembershipBatchAccepted(
            batchId,
            value.proofHeight,
            value.l1BatchNumber,
            value.prividiumNativeRoot,
            value.entryCount,
            value.batchRoot
        );
    }

    function verifyNonMembership(ILightClientMsgs.MsgVerifyNonMembership calldata msg_)
        external
        view
        override
        onlyRouter
        returns (uint256)
    {
        if (msg_.proofHeight.revisionNumber != 0 || msg_.proofHeight.revisionHeight == 0) {
            revert WrongProofHeight();
        }
        PrividiumTypes.SP1ProofEnvelope memory envelope =
            PublicValuesV1.decodeProofEnvelope(msg_.proof);
        PrividiumTypes.NonMembershipPublicValues memory value =
            PublicValuesV1.decodeNonMembership(envelope.publicValues);
        PrividiumTypes.AcceptedBatchState storage accepted = acceptedBatches[value.l1BatchNumber];
        if (!accepted.exists) revert UnknownBatch(value.l1BatchNumber);
        if (
            value.proofHeight != msg_.proofHeight.revisionHeight
                || value.proofHeight > accepted.l2BlockNumber
        ) revert WrongProofHeight();
        PublicValuesV1.validatePacketV2(
            value.schemaVersion, value.programVersion, value.sourceProfileId, SOURCE_PROFILE_ID
        );
        _bindBatch(value.l1BatchNumber, accepted.root, value.prividiumNativeRoot);
        if (value.ibcStore != IBC_STORE) revert WrongIbcStore(value.ibcStore);
        bytes32 pathDigest = _pathDigest(msg_.path);
        if (value.pathDigest != pathDigest) revert WrongPathDigest(pathDigest, value.pathDigest);
        if (value.absenceProfileId != ABSENCE_PROFILE_ID) {
            revert WrongAbsenceProfile(value.absenceProfileId);
        }
        bytes32 requestDigest = PublicValuesV1.nonMembershipRequestDigest(value);
        if (value.requestDigest != requestDigest) {
            revert WrongRequestDigest(requestDigest, value.requestDigest);
        }
        SP1_VERIFIER.verifyProof(NON_MEMBERSHIP_VKEY, envelope.publicValues, envelope.proofBytes);
        return accepted.l2BatchTimestamp;
    }

    function _bindBatch(uint64 batchNumber, bytes32 expectedRoot, bytes32 provenRoot) private pure {
        if (expectedRoot != provenRoot) {
            revert WrongBatchRoot(batchNumber, expectedRoot, provenRoot);
        }
    }

    function _pathDigest(bytes[] calldata path) private pure returns (bytes32) {
        // Pinned Eureka shape: one raw ICS24 terminal path. Router registration must use a
        // single empty Merkle-prefix element so prefixing preserves this one-element shape.
        if (path.length != 1 || path[0].length == 0) revert UnsupportedPathShape();
        return keccak256(path[0]);
    }

    function misbehaviour(bytes calldata) external pure override {
        revert UnsupportedMisbehaviour();
    }
}
