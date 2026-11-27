// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";
import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PublicValuesV1} from "../src/PublicValuesV1.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {ILightClient} from "@ibc-contracts/interfaces/ILightClient.sol";
import {IICS02ClientMsgs} from "@ibc-contracts/msgs/IICS02ClientMsgs.sol";
import {ILightClientMsgs} from "@ibc-contracts/msgs/ILightClientMsgs.sol";

contract MockVerifier is ISP1Verifier {
    bool public reject;
    bytes32 public expectedVkey;
    bytes32 public rejectedVkey;

    function setReject(bool value) external {
        reject = value;
    }

    function setExpectedVkey(bytes32 value) external {
        expectedVkey = value;
    }

    function setRejectedVkey(bytes32 value) external {
        rejectedVkey = value;
    }

    function verifyProof(bytes32 vkey, bytes calldata, bytes calldata) external view override {
        require(!reject, "rejected proof");
        require(vkey != rejectedVkey, "rejected vkey");
        require(expectedVkey == bytes32(0) || vkey == expectedVkey, "wrong vkey");
    }
}

contract UnauthorizedCaller {
    function update(PrividiumZKLightClient client, bytes calldata message) external returns (bool) {
        (bool success,) = address(client).call(abi.encodeCall(ILightClient.updateClient, (message)));
        return success;
    }
}

contract PrividiumZKLightClientTest {
    bytes32 private constant PROFILE = keccak256("synthetic-local");
    bytes32 private constant TRUST_VKEY = bytes32(uint256(1));
    bytes32 private constant SETTLEMENT_VKEY = bytes32(uint256(2));
    bytes32 private constant MEMBERSHIP_VKEY = bytes32(uint256(3));
    bytes32 private constant NON_MEMBERSHIP_VKEY = bytes32(uint256(4));
    address private constant STORE = address(0x4444);
    uint64 private constant BATCH_TIMESTAMP = 1_700_000_000;

    MockVerifier private verifier;
    PrividiumZKLightClient private client;
    PrividiumTypes.ConsensusTrustState private initial;

    function setUp() public {
        verifier = new MockVerifier();
        initial = PrividiumTypes.ConsensusTrustState({
            finalizedBeaconSlot: 1,
            finalizedBeaconHeaderRoot: bytes32(uint256(11)),
            currentSyncCommitteeRoot: bytes32(uint256(12)),
            nextSyncCommitteeRoot: bytes32(uint256(13)),
            nextSyncCommitteeKnown: true
        });
        client = new PrividiumZKLightClient(
            PROFILE,
            initial,
            STORE,
            1,
            TRUST_VKEY,
            SETTLEMENT_VKEY,
            MEMBERSHIP_VKEY,
            NON_MEMBERSHIP_VKEY,
            address(verifier),
            address(this)
        );
    }

    function testTrustUpdateAndVerifierBeforeWrite() public {
        bytes memory message = _trustMessage(2, bytes32(uint256(21)));
        verifier.setReject(true);
        (bool success,) = address(client).call(abi.encodeCall(ILightClient.updateClient, (message)));
        require(!success, "invalid proof accepted");
        require(client.getConsensusTrustState().finalizedBeaconSlot == 1, "state written early");

        verifier.setReject(false);
        require(
            client.updateClient(message) == ILightClientMsgs.UpdateResult.Update,
            "trust update failed"
        );
        require(client.getConsensusTrustState().finalizedBeaconSlot == 2, "trust not updated");
    }

    function testSettlementIsIdempotentAndRejectsConflict() public {
        bytes32 root = bytes32(uint256(0xCAFE));
        bytes memory message = _settlementMessage(7, root);
        require(
            client.updateClient(message) == ILightClientMsgs.UpdateResult.Update,
            "batch insertion failed"
        );
        require(
            client.updateClient(message) == ILightClientMsgs.UpdateResult.NoOp,
            "identical batch was not idempotent"
        );
        (bytes32 stored, uint64 storedTimestamp, bool exists) = client.getAcceptedBatch(7);
        require(exists && stored == root, "wrong accepted root");
        require(storedTimestamp == BATCH_TIMESTAMP, "wrong accepted timestamp");
        require(client.getAcceptedL2Block(7) == 17, "wrong authenticated L2 block");

        (bool success,) = address(client)
            .call(
                abi.encodeCall(
                    ILightClient.updateClient, (_settlementMessage(7, bytes32(uint256(9))))
                )
            );
        require(!success, "conflicting batch accepted");

        (bool timestampConflict,) = address(client)
            .call(
                abi.encodeCall(
                    ILightClient.updateClient,
                    (_settlementMessageAtTimestamp(7, root, BATCH_TIMESTAMP + 1))
                )
            );
        require(!timestampConflict, "conflicting batch timestamp accepted");
    }

    function testCompositeUpdateAppliesTrustThenSettlementAtomically() public {
        bytes32 root = bytes32(uint256(0xABCD));
        PrividiumTypes.ConsensusTrustState memory next = initial;
        next.finalizedBeaconSlot = 2;
        next.finalizedBeaconHeaderRoot = bytes32(uint256(21));
        bytes memory message = _compositeMessage(
            _trustMessage(2, next.finalizedBeaconHeaderRoot),
            _settlementMessageForTrust(9, root, next)
        );

        require(
            client.updateClient(message) == ILightClientMsgs.UpdateResult.Update,
            "composite update failed"
        );
        require(client.getConsensusTrustState().finalizedBeaconSlot == 2, "trust not advanced");
        (bytes32 stored,, bool exists) = client.getAcceptedBatch(9);
        require(exists && stored == root, "Settlement was not accepted");
    }

    function testCompositeUpdateRollsBackTrustWhenSettlementFails() public {
        PrividiumTypes.ConsensusTrustState memory next = initial;
        next.finalizedBeaconSlot = 2;
        next.finalizedBeaconHeaderRoot = bytes32(uint256(21));
        verifier.setRejectedVkey(SETTLEMENT_VKEY);
        bytes memory message = _compositeMessage(
            _trustMessage(2, next.finalizedBeaconHeaderRoot),
            _settlementMessageForTrust(10, bytes32(uint256(0xABCD)), next)
        );

        (bool success,) = address(client).call(abi.encodeCall(ILightClient.updateClient, (message)));
        require(!success, "invalid Settlement accepted");
        require(
            client.getConsensusTrustState().finalizedBeaconSlot == 1, "trust was not rolled back"
        );
        (,, bool exists) = client.getAcceptedBatch(10);
        require(!exists, "failed composite stored a batch");
    }

    function testCompositeUpdateRejectsWrongOrderingAndNestedBundles() public {
        bytes32 root = bytes32(uint256(0xABCD));
        bytes memory trust = _trustMessage(2, bytes32(uint256(21)));
        bytes memory settlement = _settlementMessage(11, root);

        require(
            !_updateSucceeds(_compositeMessage(settlement, trust)),
            "Settlement before Trust Update accepted"
        );
        bytes[] memory one = new bytes[](1);
        one[0] = settlement;
        bytes memory undersized = abi.encode(
            uint8(PrividiumTypes.UpdateKind.CompositeUpdate), abi.encode(one), bytes("")
        );
        require(!_updateSucceeds(undersized), "one-element composite accepted");

        bytes memory nested = _compositeMessage(trust, settlement);
        require(
            !_updateSucceeds(_compositeMessage(nested, settlement)), "nested composite accepted"
        );

        bytes[] memory oversized = new bytes[](10);
        for (uint256 index = 0; index < oversized.length; ++index) {
            oversized[index] = trust;
        }
        bytes memory oversizedMessage = abi.encode(
            uint8(PrividiumTypes.UpdateKind.CompositeUpdate), abi.encode(oversized), bytes("")
        );
        require(!_updateSucceeds(oversizedMessage), "oversized composite accepted");
    }

    function testSettlementRejectsProgramVersionOne() public {
        bytes32 root = bytes32(uint256(0xCAFE));
        (bool success,) = address(client)
            .call(
                abi.encodeCall(
                    ILightClient.updateClient,
                    (_settlementMessageAtVersion(7, root, BATCH_TIMESTAMP, 1))
                )
            );
        require(!success, "Settlement program version 1 accepted");
        (,, bool exists) = client.getAcceptedBatch(7);
        require(!exists, "version-mismatched Settlement changed state");
    }

    function testUnauthorizedCallerAndTrailingEnvelopeFail() public {
        bytes memory message = _trustMessage(2, bytes32(uint256(21)));
        UnauthorizedCaller caller = new UnauthorizedCaller();
        require(!caller.update(client, message), "unauthorized update accepted");

        bytes memory trailing = bytes.concat(message, hex"00");
        (bool success,) =
            address(client).call(abi.encodeCall(ILightClient.updateClient, (trailing)));
        require(!success, "trailing envelope accepted");
        require(client.getConsensusTrustState().finalizedBeaconSlot == 1, "state changed");
    }

    function testMembershipBindsRouteBatchPathValueAndTimestamp() public {
        bytes32 root = bytes32(uint256(0xCAFE));
        client.updateClient(_settlementMessage(7, root));
        verifier.setExpectedVkey(MEMBERSHIP_VKEY);

        ILightClientMsgs.MsgVerifyMembership memory message = _membershipMessage(7, root);
        require(client.verifyMembership(message) == 1_700_000_000, "wrong timestamp");

        message.path[0] = bytes("wrong-path");
        (bool wrongPath,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!wrongPath, "wrong path accepted");

        message = _membershipMessage(7, root);
        message.value = abi.encodePacked(bytes32(uint256(0x9999)));
        (bool wrongValue,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!wrongValue, "wrong value accepted");

        message = _membershipMessage(8, root);
        (bool unknownBatch,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!unknownBatch, "unknown batch accepted");

        message = _membershipMessage(7, root);
        message.proofHeight.revisionHeight = 18;
        (bool futureHeight,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!futureHeight, "proof height newer than authenticated state accepted");

        message = _membershipMessage(7, root);
        message.proofHeight.revisionHeight = 16;
        (bool mismatchedHeight,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!mismatchedHeight, "proof accepted under a different historical height");
    }

    function testMembershipRejectsUnsupportedRouterPathShapes() public {
        bytes32 root = bytes32(uint256(0xCAFE));
        client.updateClient(_settlementMessage(7, root));
        verifier.setExpectedVkey(MEMBERSHIP_VKEY);

        ILightClientMsgs.MsgVerifyMembership memory message = _membershipMessage(7, root);
        message.path = new bytes[](0);
        (bool emptyPath,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!emptyPath, "empty path accepted");

        message = _membershipMessage(7, root);
        message.path[0] = bytes("");
        (bool emptyTerminalPath,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!emptyTerminalPath, "empty terminal path accepted");

        message = _membershipMessage(7, root);
        bytes[] memory multiplePathElements = new bytes[](2);
        multiplePathElements[0] = bytes("membership-path");
        multiplePathElements[1] = bytes("unexpected-prefix");
        message.path = multiplePathElements;
        (bool multiplePaths,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!multiplePaths, "multiple path elements accepted");
    }

    function testSharedMembershipBatchVerifiesCompactBranches() public {
        uint64 batchNumber = 30;
        bytes32 nativeRoot = bytes32(uint256(0xCAFE));
        client.updateClient(_settlementMessage(batchNumber, nativeRoot));
        verifier.setExpectedVkey(MEMBERSHIP_VKEY);
        _registerSharedMembershipBatch(batchNumber, nativeRoot);
        bytes32 firstLeaf = PublicValuesV1.membershipLeaf(
            0,
            keccak256(bytes("membership-path-0")),
            keccak256(abi.encodePacked(bytes32(uint256(0x1111))))
        );
        ILightClientMsgs.MsgVerifyMembership memory message =
            _sharedMembershipClaim(batchNumber, firstLeaf);
        require(client.verifyMembership(message) == BATCH_TIMESTAMP, "shared claim failed");

        message = _sharedMembershipClaim(batchNumber, bytes32(uint256(0xBAD)));
        (bool wrongBranch,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (message)));
        require(!wrongBranch, "wrong Membership branch accepted");
    }

    function testMembershipEnvelopeModesFailClosed() public {
        uint64 batch = 40;
        bytes32 root = bytes32(uint256(0xCAFE));
        client.updateClient(_settlementMessage(batch, root));
        verifier.setExpectedVkey(MEMBERSHIP_VKEY);

        ILightClientMsgs.MsgVerifyMembership memory full = _membershipMessage(batch, root);
        PrividiumTypes.MembershipBatchProofEnvelope memory envelope =
            abi.decode(full.proof, (PrividiumTypes.MembershipBatchProofEnvelope));

        envelope.mode = PrividiumTypes.MEMBERSHIP_ENVELOPE_CACHED;
        envelope.publicValues = bytes("");
        envelope.proofBytes = bytes("");
        full.proof = abi.encode(envelope);
        (bool cachedBeforeFull,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (full)));
        require(!cachedBeforeFull, "CACHED envelope accepted before FULL");

        envelope.mode = 3;
        full.proof = abi.encode(envelope);
        (bool unknownMode,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (full)));
        require(!unknownMode, "unknown Membership envelope mode accepted");

        envelope.mode = PrividiumTypes.MEMBERSHIP_ENVELOPE_CACHED;
        envelope.publicValues = hex"01";
        full.proof = abi.encode(envelope);
        (bool cachedPayload,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (full)));
        require(!cachedPayload, "CACHED envelope accepted an SP1 payload");

        ILightClientMsgs.MsgVerifyMembership memory valid = _membershipMessage(batch, root);
        require(client.verifyMembership(valid) == BATCH_TIMESTAMP, "FULL envelope failed");
        envelope = abi.decode(valid.proof, (PrividiumTypes.MembershipBatchProofEnvelope));
        envelope.mode = PrividiumTypes.MEMBERSHIP_ENVELOPE_CACHED;
        envelope.publicValues = bytes("");
        envelope.proofBytes = bytes("");
        valid.proof = abi.encode(envelope);
        require(client.verifyMembership(valid) == BATCH_TIMESTAMP, "CACHED retry failed");
    }

    function testPacketProofsRequireSettlementAndOrderedExecutionIsAtomic() public {
        bytes32 root = bytes32(uint256(0xCAFE));
        ILightClientMsgs.MsgVerifyMembership memory membership = _membershipMessage(20, root);
        ILightClientMsgs.MsgVerifyNonMembership memory nonMembership =
            _nonMembershipMessage(22, root, 1);

        (bool membershipBeforeSettlement,) =
            address(client).call(abi.encodeCall(ILightClient.verifyMembership, (membership)));
        require(!membershipBeforeSettlement, "Membership accepted before Settlement");
        (bool nonMembershipBeforeSettlement,) =
            address(client).call(abi.encodeCall(ILightClient.verifyNonMembership, (nonMembership)));
        require(!nonMembershipBeforeSettlement, "Non-Membership accepted before Settlement");

        (bool orderedMembership,) = address(this)
            .call(
                abi.encodeCall(
                    this.executeSettlementThenMembership, (_settlementMessage(20, root), membership)
                )
            );
        require(orderedMembership, "ordered Settlement and Membership failed");

        ILightClientMsgs.MsgVerifyMembership memory wrongRoot =
            _membershipMessage(21, bytes32(uint256(0xBAD)));
        (bool failedAtomicCall,) = address(this)
            .call(
                abi.encodeCall(
                    this.executeSettlementThenMembership, (_settlementMessage(21, root), wrongRoot)
                )
            );
        require(!failedAtomicCall, "wrong-root Membership accepted");
        (,, bool failedBatchExists) = client.getAcceptedBatch(21);
        require(!failedBatchExists, "failed atomic call retained Settlement state");

        (bool orderedNonMembership,) = address(this)
            .call(
                abi.encodeCall(
                    this.executeSettlementThenNonMembership,
                    (_settlementMessage(22, root), nonMembership)
                )
            );
        require(orderedNonMembership, "ordered Settlement and Non-Membership failed");
    }

    function executeSettlementThenMembership(
        bytes calldata settlement,
        ILightClientMsgs.MsgVerifyMembership calldata membership
    ) external {
        require(msg.sender == address(this), "test helper caller");
        client.updateClient(settlement);
        client.verifyMembership(membership);
    }

    function executeSettlementThenNonMembership(
        bytes calldata settlement,
        ILightClientMsgs.MsgVerifyNonMembership calldata nonMembership
    ) external {
        require(msg.sender == address(this), "test helper caller");
        client.updateClient(settlement);
        client.verifyNonMembership(nonMembership);
    }

    function testNonMembershipUsesDedicatedVkeyAndAbsenceProfile() public {
        bytes32 root = bytes32(uint256(0xCAFE));
        client.updateClient(_settlementMessage(7, root));
        verifier.setExpectedVkey(NON_MEMBERSHIP_VKEY);

        ILightClientMsgs.MsgVerifyNonMembership memory message = _nonMembershipMessage(7, root, 1);
        require(client.verifyNonMembership(message) == 1_700_000_000, "wrong timestamp");

        message = _nonMembershipMessage(7, root, 2);
        (bool wrongProfile,) =
            address(client).call(abi.encodeCall(ILightClient.verifyNonMembership, (message)));
        require(!wrongProfile, "wrong absence profile accepted");

        verifier.setExpectedVkey(MEMBERSHIP_VKEY);
        message = _nonMembershipMessage(7, root, 1);
        (bool wrongRoute,) =
            address(client).call(abi.encodeCall(ILightClient.verifyNonMembership, (message)));
        require(!wrongRoute, "non-membership used membership vkey");
    }

    function testVerifierFailureLeavesTimestampStateUnchanged() public {
        verifier.setReject(true);
        (bool proofAccepted,) = address(client)
            .call(
                abi.encodeCall(
                    ILightClient.updateClient, (_settlementMessage(8, bytes32(uint256(8))))
                )
            );
        require(!proofAccepted, "rejected proof accepted");
        (,, bool exists) = client.getAcceptedBatch(8);
        require(!exists, "batch written before proof verification");
    }

    function testConstructorRejectsNonCanonicalUnknownNextCommittee() public {
        PrividiumTypes.ConsensusTrustState memory invalid = initial;
        invalid.nextSyncCommitteeKnown = false;
        invalid.nextSyncCommitteeRoot = bytes32(uint256(1));
        bool rejected;
        try new PrividiumZKLightClient(
            PROFILE,
            invalid,
            STORE,
            1,
            TRUST_VKEY,
            SETTLEMENT_VKEY,
            MEMBERSHIP_VKEY,
            NON_MEMBERSHIP_VKEY,
            address(verifier),
            address(this)
        ) returns (
            PrividiumZKLightClient
        ) {
            rejected = false;
        } catch {
            rejected = true;
        }
        require(rejected, "non-canonical initial trust accepted");
    }

    function testConstructorRejectsZeroRequiredTrustFieldsAndKnownZeroNextCommittee() public {
        PrividiumTypes.ConsensusTrustState memory invalid = initial;
        invalid.finalizedBeaconSlot = 0;
        require(_constructorRejects(invalid), "zero finalized slot accepted");

        invalid = initial;
        invalid.finalizedBeaconHeaderRoot = bytes32(0);
        require(_constructorRejects(invalid), "zero finalized root accepted");

        invalid = initial;
        invalid.currentSyncCommitteeRoot = bytes32(0);
        require(_constructorRejects(invalid), "zero current committee accepted");

        invalid = initial;
        invalid.nextSyncCommitteeRoot = bytes32(0);
        invalid.nextSyncCommitteeKnown = true;
        require(_constructorRejects(invalid), "known zero next committee accepted");
    }

    function _constructorRejects(PrividiumTypes.ConsensusTrustState memory trust)
        private
        returns (bool)
    {
        try new PrividiumZKLightClient(
            PROFILE,
            trust,
            STORE,
            1,
            TRUST_VKEY,
            SETTLEMENT_VKEY,
            MEMBERSHIP_VKEY,
            NON_MEMBERSHIP_VKEY,
            address(verifier),
            address(this)
        ) returns (
            PrividiumZKLightClient
        ) {
            return false;
        } catch {
            return true;
        }
    }

    function _trustMessage(uint64 slot, bytes32 headerRoot) private view returns (bytes memory) {
        PrividiumTypes.TrustUpdatePublicValues memory value = PrividiumTypes.TrustUpdatePublicValues({
            schemaVersion: 1,
            programVersion: 1,
            sourceProfileId: PROFILE,
            previousConsensusTrustDigest: PublicValuesV1.consensusTrustDigest(initial),
            lastSignatureSlot: slot + 1,
            newFinalizedBeaconSlot: slot,
            newFinalizedBeaconHeaderRoot: headerRoot,
            newCurrentSyncCommitteeRoot: initial.currentSyncCommitteeRoot,
            newNextSyncCommitteeRoot: initial.nextSyncCommitteeRoot,
            newNextSyncCommitteeKnown: true
        });
        return abi.encode(uint8(PrividiumTypes.UpdateKind.TrustUpdate), abi.encode(value), hex"01");
    }

    function _settlementMessage(uint64 batch, bytes32 root) private view returns (bytes memory) {
        return _settlementMessageAtTimestamp(batch, root, BATCH_TIMESTAMP);
    }

    function _settlementMessageAtTimestamp(uint64 batch, bytes32 root, uint64 timestamp)
        private
        view
        returns (bytes memory)
    {
        return _settlementMessageAtVersion(batch, root, timestamp, 3);
    }

    function _settlementMessageAtVersion(
        uint64 batch,
        bytes32 root,
        uint64 timestamp,
        uint32 programVersion
    ) private view returns (bytes memory) {
        return _settlementMessageForTrustAtVersion(batch, root, timestamp, programVersion, initial);
    }

    function _settlementMessageForTrust(
        uint64 batch,
        bytes32 root,
        PrividiumTypes.ConsensusTrustState memory trust
    ) private pure returns (bytes memory) {
        return _settlementMessageForTrustAtVersion(batch, root, BATCH_TIMESTAMP, 3, trust);
    }

    function _settlementMessageForTrustAtVersion(
        uint64 batch,
        bytes32 root,
        uint64 timestamp,
        uint32 programVersion,
        PrividiumTypes.ConsensusTrustState memory trust
    ) private pure returns (bytes memory) {
        PrividiumTypes.SettlementPublicValues memory
            value =
            PrividiumTypes.SettlementPublicValues({
                schemaVersion: 1,
                programVersion: programVersion,
                sourceProfileId: PROFILE,
                previousConsensusTrustDigest: PublicValuesV1.consensusTrustDigest(trust),
                l2BlockNumber: batch + 10,
                l1BatchNumber: batch,
                prividiumNativeRoot: root,
                l2BatchTimestamp: timestamp
            });
        return
            abi.encode(
                uint8(PrividiumTypes.UpdateKind.SettlementUpdate), abi.encode(value), hex"01"
            );
    }

    function _compositeMessage(bytes memory first, bytes memory settlement)
        private
        pure
        returns (bytes memory)
    {
        bytes[] memory updates = new bytes[](2);
        updates[0] = first;
        updates[1] = settlement;
        return abi.encode(
            uint8(PrividiumTypes.UpdateKind.CompositeUpdate), abi.encode(updates), bytes("")
        );
    }

    function _updateSucceeds(bytes memory message) private returns (bool success) {
        (success,) = address(client).call(abi.encodeCall(ILightClient.updateClient, (message)));
    }

    function _membershipMessage(uint64 batch, bytes32 root)
        private
        returns (ILightClientMsgs.MsgVerifyMembership memory message)
    {
        bytes memory logicalPath = bytes("membership-path");
        bytes memory expectedValue = abi.encodePacked(bytes32(uint256(0x1234)));
        PrividiumTypes.MembershipPublicValues memory value = PrividiumTypes.MembershipPublicValues({
            schemaVersion: 1,
            programVersion: 2,
            sourceProfileId: PROFILE,
            proofHeight: batch + 10,
            l1BatchNumber: batch,
            prividiumNativeRoot: root,
            ibcStore: STORE,
            entryCount: 1,
            batchRoot: PublicValuesV1.membershipLeaf(
                0, keccak256(logicalPath), keccak256(expectedValue)
            ),
            requestDigest: bytes32(0)
        });
        value.requestDigest = PublicValuesV1.membershipRequestDigest(value);
        bytes[] memory path = new bytes[](1);
        path[0] = logicalPath;
        bytes32[] memory siblings = new bytes32[](0);
        message = ILightClientMsgs.MsgVerifyMembership({
            proof: abi.encode(
                PrividiumTypes.MembershipBatchProofEnvelope({
                    mode: PrividiumTypes.MEMBERSHIP_ENVELOPE_FULL,
                    publicValues: abi.encode(value),
                    proofBytes: hex"01",
                    l1BatchNumber: batch,
                    batchRoot: value.batchRoot,
                    entryCount: 1,
                    entryIndex: 0,
                    siblings: siblings
                })
            ),
            proofHeight: IICS02ClientMsgs.Height({revisionNumber: 0, revisionHeight: batch + 10}),
            path: path,
            value: expectedValue
        });
    }

    function _registerSharedMembershipBatch(uint64 batch, bytes32 root) private {
        bytes32 firstLeaf = PublicValuesV1.membershipLeaf(
            0,
            keccak256(bytes("membership-path-0")),
            keccak256(abi.encodePacked(bytes32(uint256(0x1111))))
        );
        bytes32 secondLeaf = PublicValuesV1.membershipLeaf(
            1,
            keccak256(bytes("membership-path-1")),
            keccak256(abi.encodePacked(bytes32(uint256(0x2222))))
        );
        PrividiumTypes.MembershipPublicValues memory value = PrividiumTypes.MembershipPublicValues({
            schemaVersion: 1,
            programVersion: 2,
            sourceProfileId: PROFILE,
            proofHeight: batch + 10,
            l1BatchNumber: batch,
            prividiumNativeRoot: root,
            ibcStore: STORE,
            entryCount: 2,
            batchRoot: PublicValuesV1.membershipNode(firstLeaf, secondLeaf),
            requestDigest: bytes32(0)
        });
        value.requestDigest = PublicValuesV1.membershipRequestDigest(value);
        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = secondLeaf;
        bytes[] memory path = new bytes[](1);
        path[0] = bytes("membership-path-0");
        client.verifyMembership(
            ILightClientMsgs.MsgVerifyMembership({
                proof: abi.encode(
                    PrividiumTypes.MembershipBatchProofEnvelope({
                        mode: PrividiumTypes.MEMBERSHIP_ENVELOPE_FULL,
                        publicValues: abi.encode(value),
                        proofBytes: hex"01",
                        l1BatchNumber: batch,
                        batchRoot: value.batchRoot,
                        entryCount: 2,
                        entryIndex: 0,
                        siblings: siblings
                    })
                ),
                proofHeight: IICS02ClientMsgs.Height({
                    revisionNumber: 0, revisionHeight: batch + 10
                }),
                path: path,
                value: abi.encodePacked(bytes32(uint256(0x1111)))
            })
        );
    }

    function _sharedMembershipClaim(uint64 batch, bytes32 sibling)
        private
        pure
        returns (ILightClientMsgs.MsgVerifyMembership memory message)
    {
        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = sibling;
        bytes32 secondLeaf = PublicValuesV1.membershipLeaf(
            1,
            keccak256(bytes("membership-path-1")),
            keccak256(abi.encodePacked(bytes32(uint256(0x2222))))
        );
        bytes[] memory path = new bytes[](1);
        path[0] = bytes("membership-path-1");
        message = ILightClientMsgs.MsgVerifyMembership({
            proof: abi.encode(
                PrividiumTypes.MembershipBatchProofEnvelope({
                    mode: PrividiumTypes.MEMBERSHIP_ENVELOPE_CACHED,
                    publicValues: bytes(""),
                    proofBytes: bytes(""),
                    l1BatchNumber: batch,
                    batchRoot: PublicValuesV1.membershipNode(sibling, secondLeaf),
                    entryCount: 2,
                    entryIndex: 1,
                    siblings: siblings
                })
            ),
            proofHeight: IICS02ClientMsgs.Height({revisionNumber: 0, revisionHeight: batch + 10}),
            path: path,
            value: abi.encodePacked(bytes32(uint256(0x2222)))
        });
    }

    function _nonMembershipMessage(uint64 batch, bytes32 root, uint32 absenceProfile)
        private
        pure
        returns (ILightClientMsgs.MsgVerifyNonMembership memory message)
    {
        bytes memory logicalPath = bytes("non-membership-path");
        PrividiumTypes.NonMembershipPublicValues memory value =
            PrividiumTypes.NonMembershipPublicValues({
                schemaVersion: 1,
                programVersion: 2,
                sourceProfileId: PROFILE,
                proofHeight: batch + 10,
                l1BatchNumber: batch,
                prividiumNativeRoot: root,
                ibcStore: STORE,
                pathDigest: keccak256(logicalPath),
                solidityStorageSlot: bytes32(uint256(3)),
                nativeTreeKey: bytes32(uint256(4)),
                absenceProfileId: absenceProfile,
                requestDigest: bytes32(0)
            });
        value.requestDigest = PublicValuesV1.nonMembershipRequestDigest(value);
        bytes[] memory path = new bytes[](1);
        path[0] = logicalPath;
        message = ILightClientMsgs.MsgVerifyNonMembership({
            proof: abi.encode(
                PrividiumTypes.SP1ProofEnvelope({
                    publicValues: abi.encode(value), proofBytes: hex"01"
                })
            ),
            proofHeight: IICS02ClientMsgs.Height({revisionNumber: 0, revisionHeight: batch + 10}),
            path: path
        });
    }
}
