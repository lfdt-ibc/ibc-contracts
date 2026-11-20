// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.24 <0.9.0;

import {PrividiumTypes} from "./PrividiumTypes.sol";

library PublicValuesV1 {
    uint256 internal constant TRUST_UPDATE_BYTES = 10 * 32;
    uint256 internal constant SETTLEMENT_BYTES = 8 * 32;
    uint256 internal constant MEMBERSHIP_BYTES = 10 * 32;
    uint256 internal constant NON_MEMBERSHIP_BYTES = 12 * 32;
    bytes32 internal constant MEMBERSHIP_LEAF_DOMAIN = "PRIVIDIUM_MEMBERSHIP_LEAF_V1____";
    bytes32 internal constant MEMBERSHIP_NODE_DOMAIN = "PRIVIDIUM_MEMBERSHIP_NODE_V1____";

    error WrongPublicValuesLength(uint256 expected, uint256 actual);
    error NonCanonicalEncoding();
    error EmptyPublicValues();
    error EmptyProof();
    error UnknownUpdateKind(uint8 kind);
    error InvalidCompositeUpdate();
    error WrongSchemaVersion(uint32 actual);
    error WrongProgramVersion(uint32 actual);
    error WrongSourceProfile(bytes32 actual);
    error UnsupportedMembershipEnvelopeMode(uint8 mode);
    error InvalidMembershipEnvelopePayload();

    function decodeTrustUpdate(bytes memory encoded)
        internal
        pure
        returns (PrividiumTypes.TrustUpdatePublicValues memory value)
    {
        _requireLength(encoded, TRUST_UPDATE_BYTES);
        value = abi.decode(encoded, (PrividiumTypes.TrustUpdatePublicValues));
        _requireCanonical(encoded, abi.encode(value));
    }

    function decodeSettlement(bytes memory encoded)
        internal
        pure
        returns (PrividiumTypes.SettlementPublicValues memory value)
    {
        _requireLength(encoded, SETTLEMENT_BYTES);
        value = abi.decode(encoded, (PrividiumTypes.SettlementPublicValues));
        _requireCanonical(encoded, abi.encode(value));
    }

    function decodeMembership(bytes memory encoded)
        internal
        pure
        returns (PrividiumTypes.MembershipPublicValues memory value)
    {
        _requireLength(encoded, MEMBERSHIP_BYTES);
        value = abi.decode(encoded, (PrividiumTypes.MembershipPublicValues));
        _requireCanonical(encoded, abi.encode(value));
    }

    function decodeNonMembership(bytes memory encoded)
        internal
        pure
        returns (PrividiumTypes.NonMembershipPublicValues memory value)
    {
        _requireLength(encoded, NON_MEMBERSHIP_BYTES);
        value = abi.decode(encoded, (PrividiumTypes.NonMembershipPublicValues));
        _requireCanonical(encoded, abi.encode(value));
    }

    function decodeUpdateEnvelope(bytes memory encoded)
        internal
        pure
        returns (PrividiumTypes.UpdateProofEnvelope memory value)
    {
        (uint8 rawKind, bytes memory publicValues, bytes memory proofBytes) =
            abi.decode(encoded, (uint8, bytes, bytes));
        if (rawKind > uint8(PrividiumTypes.UpdateKind.CompositeUpdate)) {
            revert UnknownUpdateKind(rawKind);
        }
        if (publicValues.length == 0) revert EmptyPublicValues();
        if (rawKind == uint8(PrividiumTypes.UpdateKind.CompositeUpdate)) {
            if (proofBytes.length != 0) revert InvalidCompositeUpdate();
        } else if (proofBytes.length == 0) {
            revert EmptyProof();
        }
        _requireCanonical(encoded, abi.encode(rawKind, publicValues, proofBytes));
        value = PrividiumTypes.UpdateProofEnvelope({
            kind: PrividiumTypes.UpdateKind(rawKind),
            publicValues: publicValues,
            proofBytes: proofBytes
        });
    }

    function decodeCompositeUpdates(bytes memory encoded)
        internal
        pure
        returns (bytes[] memory updates)
    {
        updates = abi.decode(encoded, (bytes[]));
        if (updates.length < 2) revert InvalidCompositeUpdate();
        _requireCanonical(encoded, abi.encode(updates));
    }

    function decodeProofEnvelope(bytes memory encoded)
        internal
        pure
        returns (PrividiumTypes.SP1ProofEnvelope memory value)
    {
        value = abi.decode(encoded, (PrividiumTypes.SP1ProofEnvelope));
        if (value.publicValues.length == 0) revert EmptyPublicValues();
        if (value.proofBytes.length == 0) revert EmptyProof();
        _requireCanonical(encoded, abi.encode(value));
    }

    function validateV1(
        uint32 schemaVersion,
        uint32 programVersion,
        bytes32 sourceProfileId,
        bytes32 expectedSourceProfileId
    ) internal pure {
        _validate(
            schemaVersion,
            programVersion,
            sourceProfileId,
            expectedSourceProfileId,
            PrividiumTypes.PROGRAM_VERSION_V1
        );
    }

    function validateSettlementV3(
        uint32 schemaVersion,
        uint32 programVersion,
        bytes32 sourceProfileId,
        bytes32 expectedSourceProfileId
    ) internal pure {
        _validate(
            schemaVersion,
            programVersion,
            sourceProfileId,
            expectedSourceProfileId,
            PrividiumTypes.SETTLEMENT_PROGRAM_VERSION_V3
        );
    }

    function validatePacketV2(
        uint32 schemaVersion,
        uint32 programVersion,
        bytes32 sourceProfileId,
        bytes32 expectedSourceProfileId
    ) internal pure {
        _validate(
            schemaVersion,
            programVersion,
            sourceProfileId,
            expectedSourceProfileId,
            PrividiumTypes.PACKET_PROGRAM_VERSION_V2
        );
    }

    function _validate(
        uint32 schemaVersion,
        uint32 programVersion,
        bytes32 sourceProfileId,
        bytes32 expectedSourceProfileId,
        uint32 expectedProgramVersion
    ) private pure {
        if (schemaVersion != PrividiumTypes.SCHEMA_VERSION_V1) {
            revert WrongSchemaVersion(schemaVersion);
        }
        if (programVersion != expectedProgramVersion) {
            revert WrongProgramVersion(programVersion);
        }
        if (sourceProfileId != expectedSourceProfileId) {
            revert WrongSourceProfile(sourceProfileId);
        }
    }

    function consensusTrustDigest(PrividiumTypes.ConsensusTrustState memory state)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                state.finalizedBeaconSlot,
                state.finalizedBeaconHeaderRoot,
                state.currentSyncCommitteeRoot,
                state.nextSyncCommitteeRoot,
                state.nextSyncCommitteeKnown
            )
        );
    }

    function membershipRequestDigest(PrividiumTypes.MembershipPublicValues memory value)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                value.schemaVersion,
                value.programVersion,
                value.sourceProfileId,
                value.proofHeight,
                value.l1BatchNumber,
                value.prividiumNativeRoot,
                value.ibcStore,
                value.entryCount,
                value.batchRoot
            )
        );
    }

    function membershipLeaf(uint32 index, bytes32 pathDigest, bytes32 valueHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(MEMBERSHIP_LEAF_DOMAIN, index, pathDigest, valueHash));
    }

    function membershipNode(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return keccak256(abi.encode(MEMBERSHIP_NODE_DOMAIN, left, right));
    }

    function decodeMembershipBatchProofEnvelope(bytes calldata encoded)
        internal
        pure
        returns (PrividiumTypes.MembershipBatchProofEnvelope memory value)
    {
        value = abi.decode(encoded, (PrividiumTypes.MembershipBatchProofEnvelope));
        bytes memory canonical = abi.encode(value);
        if (canonical.length != encoded.length || keccak256(canonical) != keccak256(encoded)) {
            revert NonCanonicalEncoding();
        }
        if (value.mode == PrividiumTypes.MEMBERSHIP_ENVELOPE_FULL) {
            if (value.publicValues.length == 0) revert EmptyPublicValues();
            if (value.proofBytes.length == 0) revert EmptyProof();
        } else if (value.mode == PrividiumTypes.MEMBERSHIP_ENVELOPE_CACHED) {
            if (value.publicValues.length != 0 || value.proofBytes.length != 0) {
                revert InvalidMembershipEnvelopePayload();
            }
        } else {
            revert UnsupportedMembershipEnvelopeMode(value.mode);
        }
    }

    function verifyMembershipClaim(
        bytes32 expectedRoot,
        uint32 entryCount,
        uint32 entryIndex,
        bytes32 leaf,
        bytes32[] memory siblings
    ) internal pure returns (bool) {
        if (entryCount == 0 || entryIndex >= entryCount) return false;
        uint256 width = 1;
        uint256 depth;
        while (width < entryCount) {
            width <<= 1;
            ++depth;
        }
        if (siblings.length != depth) return false;
        bytes32 current = leaf;
        uint256 position = entryIndex;
        for (uint256 index; index < siblings.length; ++index) {
            current = position & 1 == 0
                ? membershipNode(current, siblings[index])
                : membershipNode(siblings[index], current);
            position >>= 1;
        }
        return current == expectedRoot;
    }

    function nonMembershipRequestDigest(PrividiumTypes.NonMembershipPublicValues memory value)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                value.schemaVersion,
                value.programVersion,
                value.sourceProfileId,
                value.proofHeight,
                value.l1BatchNumber,
                value.prividiumNativeRoot,
                value.ibcStore,
                value.pathDigest,
                value.solidityStorageSlot,
                value.nativeTreeKey,
                value.absenceProfileId
            )
        );
    }

    function _requireLength(bytes memory encoded, uint256 expected) private pure {
        if (encoded.length != expected) {
            revert WrongPublicValuesLength(expected, encoded.length);
        }
    }

    function _requireCanonical(bytes memory original, bytes memory reencoded) private pure {
        if (original.length != reencoded.length || keccak256(original) != keccak256(reencoded)) {
            revert NonCanonicalEncoding();
        }
    }
}
