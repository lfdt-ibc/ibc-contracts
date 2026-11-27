// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.24 <0.9.0;

library PrividiumTypes {
    uint32 internal constant SCHEMA_VERSION_V1 = 1;
    uint32 internal constant PROGRAM_VERSION_V1 = 1;
    uint32 internal constant PACKET_PROGRAM_VERSION_V2 = 2;
    uint32 internal constant SETTLEMENT_PROGRAM_VERSION_V3 = 3;
    uint32 internal constant MAX_MEMBERSHIP_BATCH_ENTRIES = 64;
    uint8 internal constant MEMBERSHIP_ENVELOPE_FULL = 1;
    uint8 internal constant MEMBERSHIP_ENVELOPE_CACHED = 2;

    enum UpdateKind {
        TrustUpdate,
        SettlementUpdate,
        CompositeUpdate
    }

    struct ConsensusTrustState {
        uint64 finalizedBeaconSlot;
        bytes32 finalizedBeaconHeaderRoot;
        bytes32 currentSyncCommitteeRoot;
        bytes32 nextSyncCommitteeRoot;
        bool nextSyncCommitteeKnown;
    }

    struct AcceptedBatchState {
        uint64 l2BlockNumber;
        bytes32 root;
        uint64 l2BatchTimestamp;
        bool exists;
    }

    struct AcceptedMembershipBatch {
        uint64 proofHeight;
        uint64 l1BatchNumber;
        bytes32 prividiumNativeRoot;
        uint32 entryCount;
        bytes32 batchRoot;
        bool exists;
    }

    struct UpdateProofEnvelope {
        UpdateKind kind;
        bytes publicValues;
        bytes proofBytes;
    }

    struct SP1ProofEnvelope {
        bytes publicValues;
        bytes proofBytes;
    }

    struct TrustUpdatePublicValues {
        uint32 schemaVersion;
        uint32 programVersion;
        bytes32 sourceProfileId;
        bytes32 previousConsensusTrustDigest;
        uint64 lastSignatureSlot;
        uint64 newFinalizedBeaconSlot;
        bytes32 newFinalizedBeaconHeaderRoot;
        bytes32 newCurrentSyncCommitteeRoot;
        bytes32 newNextSyncCommitteeRoot;
        bool newNextSyncCommitteeKnown;
    }

    struct SettlementPublicValues {
        uint32 schemaVersion;
        uint32 programVersion;
        bytes32 sourceProfileId;
        bytes32 previousConsensusTrustDigest;
        uint64 l2BlockNumber;
        uint64 l1BatchNumber;
        bytes32 prividiumNativeRoot;
        uint64 l2BatchTimestamp;
    }

    struct MembershipPublicValues {
        uint32 schemaVersion;
        uint32 programVersion;
        bytes32 sourceProfileId;
        uint64 proofHeight;
        uint64 l1BatchNumber;
        bytes32 prividiumNativeRoot;
        address ibcStore;
        uint32 entryCount;
        bytes32 batchRoot;
        bytes32 requestDigest;
    }

    struct NonMembershipPublicValues {
        uint32 schemaVersion;
        uint32 programVersion;
        bytes32 sourceProfileId;
        uint64 proofHeight;
        uint64 l1BatchNumber;
        bytes32 prividiumNativeRoot;
        address ibcStore;
        bytes32 pathDigest;
        bytes32 solidityStorageSlot;
        bytes32 nativeTreeKey;
        uint32 absenceProfileId;
        bytes32 requestDigest;
    }

    struct MembershipBatchProofEnvelope {
        uint8 mode;
        bytes publicValues;
        bytes proofBytes;
        uint64 l1BatchNumber;
        bytes32 batchRoot;
        uint32 entryCount;
        uint32 entryIndex;
        bytes32[] siblings;
    }
}
