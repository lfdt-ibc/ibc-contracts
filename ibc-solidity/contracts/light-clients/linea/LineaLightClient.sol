// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import { ECDSA } from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import { RLP } from "@openzeppelin-contracts/utils/RLP.sol";
import { TrieProof } from "../utils/TrieProof.sol";
import { Memory } from "@openzeppelin-contracts/utils/Memory.sol";
import { TransientSlot } from "@openzeppelin-contracts/utils/TransientSlot.sol";
import { Math } from "@openzeppelin-contracts/utils/math/Math.sol";
import { SlotDerivation } from "@openzeppelin-contracts/utils/SlotDerivation.sol";

import { ILightClient } from "../../interfaces/ILightClient.sol";
import { ILightClientMsgs } from "../../msgs/ILightClientMsgs.sol";
import { IICS02ClientMsgs } from "../../msgs/IICS02ClientMsgs.sol";
import { ILineaLightClientMsgs } from "./msgs/ILineaLightClientMsgs.sol";
import { ILineaLightClientErrors } from "./errors/ILineaLightClientErrors.sol";
import { ILineaLightClient } from "./interfaces/ILineaLightClient.sol";

import { BeaconBlock } from "./utils/BeaconBlock.sol";
import { ICS26ManagedLightClient } from "../utils/ICS26ManagedLightClient.sol";

/// @title Linea Light Client
/// @notice Verifies Linea beacon block headers sealed by its Maru QBFT validators and ICS26 router storage proofs.
/// @dev Maru runs QBFT over beacon blocks that carry an execution payload. Consensus states are keyed by the execution
/// block number and hold the execution timestamp and state root, since those are what the counterparty router and
/// `eth_getProof` use. The beacon block header links them to the commit seals through its body root.
contract LineaLightClient is ILineaLightClient, ILineaLightClientErrors, ICS26ManagedLightClient {
    using TransientSlot for TransientSlot.Bytes32Slot;
    using BeaconBlock for ILineaLightClientMsgs.BeaconBlockHeader;

    /// @notice ERC-7201 storage slot used by `IBCStoreUpgradeable` commitments.
    /// @dev keccak256(abi.encode(uint256(keccak256("ibc.storage.IBCStore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IBCSTORE_STORAGE_SLOT = 0x1260944489272988d9df285149b5aa1b0f48f2136d6f416159f840a3e0747600;
    /// @notice Maximum allowed trusting period.
    uint64 private constant MAX_TRUSTING_PERIOD = 30 days;
    /// @notice Maximum allowed clock drift.
    /// @dev Covers the host `block.timestamp` lagging the time of inclusion by up to one Ethereum slot
    uint64 private constant MAX_CLOCK_DRIFT = 12 seconds;
    /// @notice Length of a compact ECDSA signature (r||s||v).
    uint256 private constant ECDSA_SIGNATURE_LENGTH = 65;

    /// @notice Current client state.
    ILineaLightClientMsgs.ClientState private clientState;
    /// @notice Keccak256 hash of trusted consensus states by revision height.
    mapping(uint64 revisionHeight => bytes32 consensusStateHash) private consensusStateHashes;

    /// @notice Creates a Linea light client from an initial trusted client and consensus state.
    /// @dev `initialConsensusState` is trusted at `initialClientState.latestHeight`.
    /// @param initialClientState Initial client state. Must not be frozen and must use revision number `0`.
    /// @param initialConsensusState Initial trusted consensus state at `initialClientState.latestHeight`.
    /// @param ics26Router The ICS26Router that may drive this client and whose authority controls pausing.
    constructor(
        ILineaLightClientMsgs.ClientState memory initialClientState,
        ILineaLightClientMsgs.ConsensusState memory initialConsensusState,
        address ics26Router
    )
        ICS26ManagedLightClient(ics26Router)
    {
        IICS02ClientMsgs.Height memory latestHeight = initialClientState.latestHeight;
        ILineaLightClientMsgs.TrustThreshold memory trustLevel = initialClientState.trustLevel;
        uint64 trustingPeriod = initialClientState.trustingPeriod;
        uint64 timestamp = initialConsensusState.timestamp;

        require(initialClientState.ibcRouter != address(0), InvalidIbcRouter());
        require(latestHeight.revisionNumber == 0, InvalidRevisionNumber(latestHeight.revisionNumber));
        require(latestHeight.revisionHeight != 0, InvalidHeaderHeight());
        require(!initialClientState.isFrozen, FrozenClientState());
        require(trustingPeriod != 0 && trustingPeriod <= MAX_TRUSTING_PERIOD, InvalidTrustingPeriod(trustingPeriod));
        require(
            initialClientState.maxClockDrift <= MAX_CLOCK_DRIFT, InvalidMaxClockDrift(initialClientState.maxClockDrift)
        );
        require(
            trustLevel.denominator != 0 && 3 * uint256(trustLevel.numerator) >= trustLevel.denominator
                && 3 * uint256(trustLevel.numerator) <= 2 * uint256(trustLevel.denominator),
            InvalidTrustLevel(trustLevel.numerator, trustLevel.denominator)
        );

        require(timestamp != 0, InvalidHeaderTimestamp());
        require(
            initialConsensusState.stateRoot != bytes32(0)
                && initialConsensusState.stateRoot != TrieProof.EMPTY_ROOT_HASH,
            InvalidStateRoot(initialConsensusState.stateRoot)
        );
        _validateValidators(initialConsensusState.validators);
        require(
            uint256(timestamp) + trustingPeriod > block.timestamp,
            ConsensusStateExpired(timestamp, block.timestamp, trustingPeriod)
        );
        require(
            block.timestamp + initialClientState.maxClockDrift >= timestamp,
            HeaderFromFuture(block.timestamp, timestamp, initialClientState.maxClockDrift)
        );

        clientState = initialClientState;
        consensusStateHashes[latestHeight.revisionHeight] = keccak256(abi.encode(initialConsensusState));
    }

    /// @inheritdoc ILightClient
    function getClientState() external view returns (bytes memory) {
        return abi.encode(clientState);
    }

    /// @inheritdoc ILineaLightClient
    function getConsensusStateHash(uint64 revisionHeight) external view returns (bytes32) {
        bytes32 consensusStateHash = consensusStateHashes[revisionHeight];
        require(consensusStateHash != bytes32(0), ConsensusStateNotFound(revisionHeight));
        return consensusStateHash;
    }

    /// @inheritdoc ILightClient
    function updateClient(bytes calldata updateMsg)
        external
        notFrozen
        whenNotPaused
        onlyICS26Router
        returns (ILightClientMsgs.UpdateResult)
    {
        ILineaLightClientMsgs.MsgUpdateClient memory msg_ =
            abi.decode(updateMsg, (ILineaLightClientMsgs.MsgUpdateClient));
        (uint64 height, ILineaLightClientMsgs.ConsensusState memory newConsensusState) = _verifyHeader(msg_);
        // Checked here rather than in `_verifyHeader` so `misbehaviour` can still use future headers as evidence.
        require(
            block.timestamp + clientState.maxClockDrift >= newConsensusState.timestamp,
            HeaderFromFuture(block.timestamp, newConsensusState.timestamp, clientState.maxClockDrift)
        );

        if (_freezeOnConflict(
                msg_.trustedHeight.revisionHeight, msg_.consensusStatePreimage, height, newConsensusState
            )) {
            return ILightClientMsgs.UpdateResult.Misbehaviour;
        }

        bytes32 newHash = keccak256(abi.encode(newConsensusState));
        if (consensusStateHashes[height] == newHash) {
            return ILightClientMsgs.UpdateResult.NoOp;
        }
        if (_freezeOnStoredConflict(height, newHash)) {
            return ILightClientMsgs.UpdateResult.Misbehaviour;
        }

        consensusStateHashes[height] = newHash;

        if (height > clientState.latestHeight.revisionHeight) {
            clientState.latestHeight.revisionHeight = height;
        }

        return ILightClientMsgs.UpdateResult.Update;
    }

    /// @inheritdoc ILightClient
    function verifyMembership(ILightClientMsgs.MsgVerifyMembership calldata msg_)
        external
        notFrozen
        whenNotPaused
        onlyICS26Router
        returns (uint256)
    {
        require(msg_.proofHeight.revisionNumber == 0, InvalidRevisionNumber(msg_.proofHeight.revisionNumber));
        require(msg_.value.length == 32, InvalidValueLength(32, msg_.value.length));

        (address counterpartyRouter, bytes memory storageKey) = _parseMerklePath(msg_.path);

        ILineaLightClientMsgs.MembershipProof memory proof =
            abi.decode(msg_.proof, (ILineaLightClientMsgs.MembershipProof));
        _requireTrustedConsensusState(msg_.proofHeight.revisionHeight, proof.consensusStatePreimage);

        bytes32 storageRoot = _verifiedStorageRoot(
            msg_.proofHeight.revisionHeight,
            counterpartyRouter,
            proof.consensusStatePreimage.stateRoot,
            proof.accountProofNodes
        );

        bytes memory traversedValue = TrieProof.traverse(storageRoot, storageKey, proof.proofNodes);

        bytes32 actualValue = RLP.decodeBytes32(traversedValue);
        bytes32 expectedValue = bytes32(msg_.value);
        require(actualValue == expectedValue, InvalidCommitmentValue(expectedValue, actualValue));

        return proof.consensusStatePreimage.timestamp;
    }

    /// @inheritdoc ILightClient
    function verifyNonMembership(ILightClientMsgs.MsgVerifyNonMembership calldata msg_)
        external
        notFrozen
        whenNotPaused
        onlyICS26Router
        returns (uint256)
    {
        require(msg_.proofHeight.revisionNumber == 0, InvalidRevisionNumber(msg_.proofHeight.revisionNumber));

        (address counterpartyRouter, bytes memory storageKey) = _parseMerklePath(msg_.path);

        ILineaLightClientMsgs.MembershipProof memory proof =
            abi.decode(msg_.proof, (ILineaLightClientMsgs.MembershipProof));
        _requireTrustedConsensusState(msg_.proofHeight.revisionHeight, proof.consensusStatePreimage);

        bytes32 storageRoot = _verifiedStorageRoot(
            msg_.proofHeight.revisionHeight,
            counterpartyRouter,
            proof.consensusStatePreimage.stateRoot,
            proof.accountProofNodes
        );

        require(TrieProof.verifyExclusion(storageRoot, storageKey, proof.proofNodes), InvalidExclusionProof());

        return proof.consensusStatePreimage.timestamp;
    }

    /// @inheritdoc ILightClient
    /// @dev Only callable through the router's permissionless `submitMisbehaviour`: evidence is either already stored
    /// consensus states or headers that pass the same signature and trust checks as `updateClient`, so freezing
    /// requires genuine validator misbehaviour. Allowed while paused, so a paused client can still be frozen.
    function misbehaviour(bytes calldata misbehaviourMsg) external notFrozen onlyICS26Router {
        ILineaLightClientMsgs.MsgSubmitMisbehaviour memory msg_ =
            abi.decode(misbehaviourMsg, (ILineaLightClientMsgs.MsgSubmitMisbehaviour));
        if (msg_.misbehaviourType == ILineaLightClientMsgs.MisbehaviourType.ConflictingConsensusStates) {
            _conflictingConsensusStatesMisbehaviour(
                abi.decode(msg_.misbehaviour, (ILineaLightClientMsgs.MsgConflictingConsensusStatesMisbehaviour))
            );
        } else {
            _conflictingHeadersMisbehaviour(
                abi.decode(msg_.misbehaviour, (ILineaLightClientMsgs.MsgConflictingHeadersMisbehaviour))
            );
        }
    }

    /// @notice Parses the Merkle path for a commitment proof.
    /// @param path The Merkle path, which must be of [counterpartyRouter, storageSlot, commitmentPath] form, where
    /// `counterpartyRouter` is the raw 20-byte router address and `storageSlot` is `IBCSTORE_STORAGE_SLOT`.
    /// @return counterpartyRouter The counterparty router address, must match the client state's `ibcRouter`.
    /// @return storageKey The key used in the contract storage trie.
    function _parseMerklePath(bytes[] calldata path) private view returns (address, bytes memory) {
        require(path.length == 3, InvalidPathLength(3, path.length));
        require(path[0].length == 20, InvalidPathElementLength(20, path[0].length));
        require(path[1].length == 32, InvalidPathElementLength(32, path[1].length));

        bytes32 namespaceSlot = bytes32(path[1]);
        require(namespaceSlot == IBCSTORE_STORAGE_SLOT, StorageSlotMismatch(IBCSTORE_STORAGE_SLOT, namespaceSlot));

        address counterpartyRouter = address(bytes20(path[0]));
        address ibcRouter = clientState.ibcRouter;
        require(counterpartyRouter == ibcRouter, CounterpartyRouterMismatch(ibcRouter, counterpartyRouter));

        bytes32 storageSlot = _commitmentStorageSlot(path[2]);
        bytes memory storageKey = abi.encodePacked(keccak256(abi.encodePacked(storageSlot)));

        return (counterpartyRouter, storageKey);
    }

    /// @notice Freezes the client if two stored consensus states violate time monotonicity or the minimum block time.
    /// @param msg_ The conflicting consensus states misbehaviour message.
    function _conflictingConsensusStatesMisbehaviour(
        ILineaLightClientMsgs.MsgConflictingConsensusStatesMisbehaviour memory msg_
    )
        private
    {
        require(msg_.height1.revisionNumber == 0, InvalidRevisionNumber(msg_.height1.revisionNumber));
        require(msg_.height2.revisionNumber == 0, InvalidRevisionNumber(msg_.height2.revisionNumber));

        // Stored consensus states remain valid evidence after their trusting period.
        _requireStoredConsensusState(msg_.height1.revisionHeight, msg_.consensusStatePreimage1);
        _requireStoredConsensusState(msg_.height2.revisionHeight, msg_.consensusStatePreimage2);

        require(
            _freezeOnConflict(
                msg_.height1.revisionHeight,
                msg_.consensusStatePreimage1,
                msg_.height2.revisionHeight,
                msg_.consensusStatePreimage2
            ),
            NoMisbehaviourDetected()
        );
    }

    /// @notice Freezes the client if two validly signed headers prove a double sign, time non-monotonicity, or a
    /// sub-second block time.
    /// @dev Each header is first checked against its own trusted consensus state and any consensus state stored at its
    /// height, as in `updateClient`, and only then against the other header. If the first header is misbehaviour on its
    /// own, the second header is not verified.
    /// @param msg_ The conflicting headers misbehaviour message.
    function _conflictingHeadersMisbehaviour(ILineaLightClientMsgs.MsgConflictingHeadersMisbehaviour memory msg_)
        private
    {
        (uint64 height1, ILineaLightClientMsgs.ConsensusState memory consensusState1) = _verifyHeader(msg_.update1);
        if (_freezeOnConflict(
                msg_.update1.trustedHeight.revisionHeight, msg_.update1.consensusStatePreimage, height1, consensusState1
            )) {
            return;
        }
        if (_freezeOnStoredConflict(height1, keccak256(abi.encode(consensusState1)))) {
            return;
        }

        (uint64 height2, ILineaLightClientMsgs.ConsensusState memory consensusState2) = _verifyHeader(msg_.update2);
        if (_freezeOnConflict(
                msg_.update2.trustedHeight.revisionHeight, msg_.update2.consensusStatePreimage, height2, consensusState2
            )) {
            return;
        }
        if (_freezeOnStoredConflict(height2, keccak256(abi.encode(consensusState2)))) {
            return;
        }

        require(_freezeOnConflict(height1, consensusState1, height2, consensusState2), NoMisbehaviourDetected());
    }

    /// @notice Freezes the client if a different consensus state is already stored at `height`.
    /// @param height The height of the consensus state.
    /// @param hash The keccak256 hash of the consensus state.
    /// @return frozen True if a different consensus state is stored at `height` and the client was frozen.
    function _freezeOnStoredConflict(uint64 height, bytes32 hash) private returns (bool frozen) {
        bytes32 existingHash = consensusStateHashes[height];
        if (existingHash != bytes32(0) && existingHash != hash) {
            clientState.isFrozen = true;
            emit DoubleSign(height, existingHash, hash);
            return true;
        }

        return false;
    }

    /// @notice Freezes the client if two consensus states conflict.
    /// @dev At the same height, differing consensus states are a double sign. At different heights, a lower consensus
    /// state whose timestamp is not less than the higher one's is time non-monotonicity, and timestamps that increase
    /// by less than the height difference are a sub-second block time, since execution timestamps are in whole seconds
    /// and strictly increase with every block. Validator sets are not compared: a Maru fork can replace the whole set
    /// in one block.
    /// @param heightA The height of the first consensus state.
    /// @param a The first consensus state.
    /// @param heightB The height of the second consensus state.
    /// @param b The second consensus state.
    /// @return frozen True if the consensus states conflict and the client was frozen.
    function _freezeOnConflict(
        uint64 heightA,
        ILineaLightClientMsgs.ConsensusState memory a,
        uint64 heightB,
        ILineaLightClientMsgs.ConsensusState memory b
    )
        private
        returns (bool frozen)
    {
        if (heightA == heightB) {
            bytes32 hashA = keccak256(abi.encode(a));
            bytes32 hashB = keccak256(abi.encode(b));
            if (hashA != hashB) {
                clientState.isFrozen = true;
                emit DoubleSign(heightA, hashA, hashB);
                return true;
            }
        } else {
            // Order by height so that heightA < heightB.
            if (heightA > heightB) {
                (heightA, a, heightB, b) = (heightB, b, heightA, a);
            }
            if (a.timestamp >= b.timestamp) {
                clientState.isFrozen = true;
                emit TimeNonMonotonicity(heightB, heightA, b.timestamp, a.timestamp);
                return true;
            }

            // Blocks are at least one second apart, so `b.timestamp - a.timestamp >= heightB - heightA`.
            if (b.timestamp - a.timestamp < heightB - heightA) {
                clientState.isFrozen = true;
                emit SubSecondBlockTime(heightB, heightA, b.timestamp, a.timestamp);
                return true;
            }
        }

        return false;
    }

    /// @notice Counts the validators that are in both of two validator sets.
    /// @dev Assumes both sets are strictly ascending. Commit seal signers are checked in `_recoverSigners`, and
    /// validator sets in `_validateValidators` before any set is trusted.
    /// @param a The first validator set.
    /// @param b The second validator set.
    /// @return common The size of the intersection of `a` and `b`.
    function _commonValidators(address[] memory a, address[] memory b) private pure returns (uint256 common) {
        uint256 i = 0;
        uint256 j = 0;
        while (i < a.length && j < b.length) {
            if (a[i] == b[j]) {
                ++common;
                ++i;
                ++j;
            } else if (a[i] < b[j]) {
                ++i;
            } else {
                ++j;
            }
        }
    }

    /// @notice Verifies a header against its trusted consensus state and derives its consensus state.
    /// @dev Does not check clock drift, so callers that store the result must check it themselves. This is
    /// deliberate: `misbehaviour` must accept validly signed headers from the future, as they can still prove
    /// misbehaviour.
    /// @param msg_ The header with its body, validator set, commit seals and trusted consensus state preimage.
    /// @return height The execution block number carried by the header.
    /// @return consensusState The consensus state derived from the header.
    function _verifyHeader(ILineaLightClientMsgs.MsgUpdateClient memory msg_)
        private
        view
        returns (uint64 height, ILineaLightClientMsgs.ConsensusState memory consensusState)
    {
        require(msg_.trustedHeight.revisionNumber == 0, InvalidRevisionNumber(msg_.trustedHeight.revisionNumber));

        bytes32 bodyRoot = keccak256(msg_.bodyRlp);
        require(bodyRoot == msg_.header.bodyRoot, BodyRootMismatch(msg_.header.bodyRoot, bodyRoot));
        BeaconBlock.ExecutionPayload memory payload = BeaconBlock.decodeExecutionPayload(msg_.bodyRlp);
        require(payload.blockNumber != 0, InvalidHeaderHeight());
        require(payload.timestamp != 0, InvalidHeaderTimestamp());
        require(
            payload.stateRoot != bytes32(0) && payload.stateRoot != TrieProof.EMPTY_ROOT_HASH,
            InvalidStateRoot(payload.stateRoot)
        );

        _validateValidators(msg_.validators);
        bytes32 beaconStateRoot = msg_.header.computeStateRoot(msg_.validators);
        require(
            beaconStateRoot == msg_.header.stateRoot, BeaconStateRootMismatch(msg_.header.stateRoot, beaconStateRoot)
        );
        require(
            payload.blockNumber > msg_.trustedHeight.revisionHeight,
            InvalidTrustedHeight(msg_.trustedHeight.revisionHeight, payload.blockNumber)
        );

        _requireTrustedConsensusState(msg_.trustedHeight.revisionHeight, msg_.consensusStatePreimage);

        address[] memory signers = _recoverSigners(msg_.header.hash(), msg_.commitSeals);
        address[] memory trustedValidators = msg_.consensusStatePreimage.validators;
        _requireTrustLevel(_commonValidators(signers, trustedValidators), trustedValidators.length);
        _checkValidatorQuorum(signers, msg_.validators);

        return (
            payload.blockNumber,
            ILineaLightClientMsgs.ConsensusState({
                timestamp: payload.timestamp, stateRoot: payload.stateRoot, validators: msg_.validators
            })
        );
    }

    /// @notice Returns the storage root for a revision height, verifying the account proof if provided.
    /// @dev If the account proof is empty, the storage root is retrieved from a transient cache
    /// which can only be populated by a previous call to this function with a non-empty account proof.
    /// @param revisionHeight The revision height for the storage root.
    /// @param counterpartyRouter The counterparty router address.
    /// @param stateRoot The header state root.
    /// @param accountProofNodes The ordered, RLP-encoded MPT nodes from the state trie proving the account.
    /// @return The storage root for the revision height.
    function _verifiedStorageRoot(
        uint64 revisionHeight,
        address counterpartyRouter,
        bytes32 stateRoot,
        bytes[] memory accountProofNodes
    )
        private
        returns (bytes32)
    {
        if (accountProofNodes.length == 0) {
            return _getCachedStorageRoot(counterpartyRouter, revisionHeight);
        }

        bytes32 storageRoot = _verifyAccountProof(counterpartyRouter, stateRoot, accountProofNodes);
        require(storageRoot != bytes32(0) && storageRoot != TrieProof.EMPTY_ROOT_HASH, InvalidStorageRoot(storageRoot));
        _cacheStorageRoot(counterpartyRouter, revisionHeight, storageRoot);
        return storageRoot;
    }

    /// @notice Verifies the tracked account proof against a header state root.
    /// @param account The account address being proven.
    /// @param stateRoot The header state root.
    /// @param proofNodes The ordered, RLP-encoded MPT nodes from the state trie proving the account.
    /// @return The proven account storage root.
    function _verifyAccountProof(
        address account,
        bytes32 stateRoot,
        bytes[] memory proofNodes
    )
        private
        pure
        returns (bytes32)
    {
        bytes memory accountKey = abi.encodePacked(keccak256(abi.encodePacked(account)));
        bytes memory accountRlp = TrieProof.traverse(stateRoot, accountKey, proofNodes);
        Memory.Slice[] memory accountItems = RLP.decodeList(accountRlp);
        return RLP.readBytes32(accountItems[2]);
    }

    /// @notice Computes the storage slot used for an IBC commitment path.
    /// @dev `commitments` is the first field of `IBCStoreStorage`, so the mapping is rooted at the namespace slot.
    /// @dev Equals to keccak256(abi.encode(keccak256(rawPath), IBCSTORE_STORAGE_SLOT))
    /// @param rawPath Raw commitment path bytes.
    /// @return The storage slot for the commitment.
    function _commitmentStorageSlot(bytes memory rawPath) private pure returns (bytes32) {
        return SlotDerivation.deriveMapping(IBCSTORE_STORAGE_SLOT, keccak256(rawPath));
    }

    /// @notice Recovers commit seal signers for a digest, requiring them to be sorted.
    /// @dev Seals must be ordered by recovered signer in strictly ascending order, which also rejects duplicates.
    /// Seals must use 27/28 recovery ids; relayers convert Maru's 0/1 ids before submitting.
    /// @param digest The commit seal digest.
    /// @param seals The commit seals to recover.
    /// @return signers The recovered signer addresses, in strictly ascending order.
    function _recoverSigners(bytes32 digest, bytes[] memory seals) private pure returns (address[] memory signers) {
        require(seals.length != 0, EmptyCommitSeals());

        signers = new address[](seals.length);
        signers[0] = _recoverSigner(digest, seals[0]);
        require(signers[0] != address(0), InvalidCommitSeal());
        for (uint256 i = 1; i < seals.length; ++i) {
            signers[i] = _recoverSigner(digest, seals[i]);
            require(signers[i - 1] < signers[i], UnsortedCommitSealSigners(i - 1));
        }
    }

    /// @notice Recovers one commit seal signer.
    /// @param digest The commit seal digest.
    /// @param seal The 65-byte ECDSA commit seal (r||s||v).
    /// @return The recovered signer address.
    function _recoverSigner(bytes32 digest, bytes memory seal) private pure returns (address) {
        require(seal.length == ECDSA_SIGNATURE_LENGTH, InvalidECDSASignatureLength(seal.length));
        return ECDSA.recover(digest, seal);
    }

    /// @notice Checks that enough trusted validators signed.
    /// @dev Requires `ceil(n * trustLevel)` trusted validators to have signed, capped at `floor(2n / 3)`, and always
    /// more than a third (`floor(n / 3) + 1`) so that at least one honest trusted validator signed. The
    /// more-than-a-third floor takes precedence over the cap, so a single trusted validator must always sign.
    /// @param actual The number of trusted signers.
    /// @param trustedCount The trusted validator set size.
    function _requireTrustLevel(uint256 actual, uint256 trustedCount) private view {
        ILineaLightClientMsgs.TrustThreshold memory trustLevel = clientState.trustLevel;

        // Always require more than 1/3 of the trusted validators for BFT safety
        uint256 lowerBound = trustedCount / 3 + 1;
        // Never require more than floor(2n / 3), so that a single validator change cannot stall updates: after one
        // removal or addition, any quorum on the new set still holds at least that many trusted seals.
        uint256 upperBound = 2 * trustedCount / 3;

        uint256 required = Math.mulDiv(trustedCount, trustLevel.numerator, trustLevel.denominator, Math.Rounding.Ceil);
        required = Math.min(required, upperBound);
        required = Math.max(required, lowerBound);

        require(actual >= required, InsufficientTrustedValidatorOverlap(actual, required));
    }

    /// @notice Checks that signers meet quorum for the submitted header validator set.
    /// @dev Assumes both sets are strictly ascending. Checked in `_recoverSigners` and `_validateValidators`.
    /// @param signers The recovered commit seal signers.
    /// @param validators The validator set from the submitted header.
    function _checkValidatorQuorum(address[] memory signers, address[] memory validators) private pure {
        uint256 j = 0;
        for (uint256 i = 0; i < signers.length; ++i) {
            while (j < validators.length && validators[j] < signers[i]) {
                ++j;
            }
            require(j < validators.length && validators[j] == signers[i], UnknownCommitSealSigner(signers[i]));
            ++j;
        }

        uint256 required = _bftThreshold(validators.length);
        require(signers.length >= required, InsufficientValidatorQuorum(signers.length, required));
    }

    /// @notice Computes the BFT threshold `ceil(2n / 3)` used for the commit-seal quorum check.
    /// @param n The validator set size.
    /// @return The minimum number of matching signers.
    function _bftThreshold(uint256 n) private pure returns (uint256) {
        return Math.ceilDiv(2 * n, 3);
    }

    /// @notice Validates that a validator set is non-empty, unique, and sorted.
    /// @param validators The validator set to validate.
    function _validateValidators(address[] memory validators) private pure {
        require(validators.length != 0, EmptyValidatorSet());
        require(validators[0] != address(0), InvalidValidatorAddress(address(0)));
        for (uint256 i = 1; i < validators.length; ++i) {
            require(validators[i - 1] < validators[i], UnsortedValidatorSet(i - 1));
        }
    }

    /// @notice Reverts unless the given consensus state matches the stored hash and is within the trusting period.
    /// @param revisionHeight The consensus state revision height.
    /// @param preimage The consensus state preimage to check.
    function _requireTrustedConsensusState(
        uint64 revisionHeight,
        ILineaLightClientMsgs.ConsensusState memory preimage
    )
        private
        view
    {
        _requireStoredConsensusState(revisionHeight, preimage);
        require(
            uint256(preimage.timestamp) + clientState.trustingPeriod > block.timestamp,
            ConsensusStateExpired(preimage.timestamp, block.timestamp, clientState.trustingPeriod)
        );
    }

    /// @notice Reverts unless the given consensus state matches the stored hash at the height.
    /// @param revisionHeight The consensus state revision height.
    /// @param preimage The consensus state preimage to check.
    function _requireStoredConsensusState(
        uint64 revisionHeight,
        ILineaLightClientMsgs.ConsensusState memory preimage
    )
        private
        view
    {
        bytes32 consensusStateHash = consensusStateHashes[revisionHeight];
        require(consensusStateHash != bytes32(0), ConsensusStateNotFound(revisionHeight));

        bytes32 preimageHash = keccak256(abi.encode(preimage));
        require(consensusStateHash == preimageHash, ConsensusStatePreimageMismatch(consensusStateHash, preimageHash));
    }

    /// @notice Caches a storage root for a revision height in a transient slot.
    /// @param ibcRouter The ICS26 router address whose storageRoot was proven.
    /// @param revisionHeight The revision height for the storage root.
    /// @param storageRoot The storage root to cache.
    function _cacheStorageRoot(address ibcRouter, uint64 revisionHeight, bytes32 storageRoot) private {
        _cacheKey(ibcRouter, revisionHeight).tstore(storageRoot);
    }

    /// @notice Retrieves a cached storage root for a revision height from a transient slot.
    /// @param ibcRouter The ICS26 router address whose storageRoot was proven.
    /// @param revisionHeight The revision height for the storage root.
    /// @return The cached storage root, reverting if not found.
    function _getCachedStorageRoot(address ibcRouter, uint64 revisionHeight) private view returns (bytes32) {
        bytes32 storageRoot = _cacheKey(ibcRouter, revisionHeight).tload();
        require(storageRoot != bytes32(0), StorageRootNotInCache(revisionHeight));
        return storageRoot;
    }

    /// @notice Computes a transient slot cache key for a revision height.
    /// @param ibcRouter The ICS26 router address whose storageRoot was proven.
    /// @param revisionHeight The revision height for the cache key.
    /// @return The cache key.
    function _cacheKey(address ibcRouter, uint64 revisionHeight) private pure returns (TransientSlot.Bytes32Slot) {
        return TransientSlot.asBytes32(keccak256(abi.encode(ibcRouter, revisionHeight)));
    }

    /// @notice Reverts if the client is frozen. A frozen client can never be unfrozen.
    modifier notFrozen() {
        require(!clientState.isFrozen, FrozenClientState());
        _;
    }
}
