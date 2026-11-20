// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

// solhint-disable gas-custom-errors,gas-calldata-parameters,gas-struct-packing

import { Test } from "forge-std/Test.sol";
import { ERC1967Utils } from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Utils.sol";
import { RLP } from "@openzeppelin-contracts/utils/RLP.sol";

import { IICS02ClientMsgs } from "../../../contracts/msgs/IICS02ClientMsgs.sol";
import { IICS26RouterMsgs } from "../../../contracts/msgs/IICS26RouterMsgs.sol";
import { ILightClientMsgs } from "../../../contracts/msgs/ILightClientMsgs.sol";
import { ILineaLightClientMsgs } from "../../../contracts/light-clients/linea/msgs/ILineaLightClientMsgs.sol";
import { ILineaLightClient } from "../../../contracts/light-clients/linea/interfaces/ILineaLightClient.sol";

import { LineaLightClient } from "../../../contracts/light-clients/linea/LineaLightClient.sol";
import { BeaconBlock } from "../../../contracts/light-clients/linea/utils/BeaconBlock.sol";
import { ICS24Host } from "../../../contracts/utils/ICS24Host.sol";
import { IBCStoreUpgradeable } from "../../../contracts/utils/IBCStoreUpgradeable.sol";
import { SimWorldState } from "../../besu-bft/utils/SimWorldState.sol";

/// @title Maru Sim Suite
/// @notice In-process Linea chain simulator: manages validator keys, produces and seals Maru beacon blocks, and keeps
/// a world state whose roots and MPT proofs the Linea light client accepts.
/// @dev Beacon and execution block numbers are equal. Storage writes made while the tip is height `h` land in block
/// `h + 1`. `commit` warps the EVM clock forward to the committed timestamp so light client clock-drift checks pass
/// by default.
contract MaruSimSuite is Test, SimWorldState {
    using BeaconBlock for ILineaLightClientMsgs.BeaconBlockHeader;

    /// @dev `number`, `timestamp` and `stateRoot` are the execution payload fields. `seal` derives `header`,
    /// `bodyRlp` and `commitSeals` from the other fields, so edit those before sealing.
    struct Block {
        uint64 number;
        uint64 timestamp;
        bytes32 stateRoot;
        uint32 round;
        address[] validators;
        ILineaLightClientMsgs.BeaconBlockHeader header;
        bytes bodyRlp;
        bytes[] commitSeals;
    }

    address public immutable IBC_ROUTER;
    uint64 public blockPeriod = 1;

    Block[] private _chain;
    address[] private _validators;
    mapping(address validator => uint256 key) private _keys;
    uint256 private _validatorCount;

    constructor() {
        IBC_ROUTER = makeAddr("sim-ibc-router");
        _createAccount(IBC_ROUTER, 1, keccak256("sim-ibc-router-code"), 0);
        // A real router is an ERC-1967 proxy, so its storage trie is never empty.
        _setStorage(IBC_ROUTER, ERC1967Utils.IMPLEMENTATION_SLOT, bytes32(uint256(keccak256("sim-ibc-router-impl"))), 0);
        _chain.push();
        _chain[0].timestamp = uint64(vm.getBlockTimestamp());
        _chain[0].stateRoot = stateRootAt(0);
    }

    // ---------------------------------------------------------------- validators

    /// @notice Creates a validator key; it seals blocks from the next produced block on.
    function addValidator() public returns (address validator) {
        uint256 key;
        (validator, key) = makeAddrAndKey(string.concat("validator-", vm.toString(++_validatorCount)));
        _keys[validator] = key;
        _validators.push(validator);
        for (uint256 i = _validators.length - 1; i > 0 && _validators[i - 1] > validator; --i) {
            (_validators[i], _validators[i - 1]) = (_validators[i - 1], _validators[i]);
        }
    }

    function addValidators(uint256 count) external returns (address[] memory added) {
        added = new address[](count);
        for (uint256 i = 0; i < count; ++i) {
            added[i] = addValidator();
        }
    }

    function removeValidator(address validator) external {
        uint256 n = _validators.length;
        for (uint256 i = 0; i < n; ++i) {
            if (_validators[i] == validator) {
                for (; i + 1 < n; ++i) {
                    _validators[i] = _validators[i + 1];
                }
                _validators.pop();
                return;
            }
        }
        revert("unknown validator");
    }

    /// @notice Sorted validator set that seals the next produced block.
    function validators() external view returns (address[] memory) {
        return _validators;
    }

    function validatorKey(address validator) external view returns (uint256) {
        return _keys[validator];
    }

    // ---------------------------------------------------------------- world state

    function setStorage(address account, bytes32 slot, bytes32 value) external {
        _setStorage(account, slot, value, tipHeight() + 1);
    }

    /// @notice Writes an ICS24 commitment into the router's IBC store; zero deletes it.
    function setCommitment(bytes memory path, bytes32 value) public {
        _setStorage(IBC_ROUTER, commitmentSlot(path), value, tipHeight() + 1);
    }

    function commitPacket(IICS26RouterMsgs.Packet memory packet) external {
        setCommitment(
            ICS24Host.packetCommitmentPathCalldata(packet.sourceClient, packet.sequence),
            ICS24Host.packetCommitmentBytes32(packet)
        );
    }

    /// @notice Mirrors the commitment stored under `path` by a real router into the simulated state.
    function syncCommitment(IBCStoreUpgradeable router, bytes memory path) external {
        setCommitment(path, router.getCommitment(keccak256(path)));
    }

    // ---------------------------------------------------------------- blocks

    function tipHeight() public view returns (uint64) {
        return uint64(_chain.length - 1);
    }

    function blockAt(uint64 height) external view returns (Block memory) {
        return _chain[height];
    }

    /// @notice Honest unsealed draft of the block following the tip.
    function nextBlock() public view returns (Block memory b) {
        b.number = tipHeight() + 1;
        b.timestamp = _chain[tipHeight()].timestamp + blockPeriod;
        b.stateRoot = stateRootAt(b.number);
        b.validators = _validators;
    }

    /// @notice Seals `b` with every validator listed in it.
    function seal(Block memory b) public view returns (Block memory) {
        return seal(b, b.validators);
    }

    function seal(Block memory b, address[] memory signers) public view returns (Block memory) {
        uint256[] memory keys = new uint256[](signers.length);
        for (uint256 i = 0; i < signers.length; ++i) {
            keys[i] = _keys[signers[i]];
            require(keys[i] != 0, "unknown signer");
        }
        return sealWithKeys(b, keys);
    }

    /// @notice Builds the beacon block of `b` on top of the tip and seals it with arbitrary private keys, e.g. to add
    /// unknown or duplicate signers.
    /// @dev Seals are ordered by signer address, as the light client requires.
    function sealWithKeys(Block memory b, uint256[] memory keys) public view returns (Block memory) {
        Block storage tip = _chain[tipHeight()];
        b.bodyRlp = _bodyRlp(b, tip.commitSeals);
        b.header = ILineaLightClientMsgs.BeaconBlockHeader({
            number: b.number,
            round: b.round,
            timestamp: b.timestamp,
            proposer: b.validators[b.number % b.validators.length],
            parentRoot: tip.header.hash(),
            stateRoot: bytes32(0),
            bodyRoot: keccak256(b.bodyRlp)
        });
        b.header.stateRoot = b.header.computeStateRoot(b.validators);

        bytes32 digest = b.header.hash();
        b.commitSeals = new bytes[](keys.length);
        for (uint256 i = 1; i < keys.length; ++i) {
            for (uint256 j = i; j > 0 && vm.addr(keys[j - 1]) > vm.addr(keys[j]); --j) {
                (keys[j - 1], keys[j]) = (keys[j], keys[j - 1]);
            }
        }
        for (uint256 i = 0; i < keys.length; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            b.commitSeals[i] = abi.encodePacked(r, s, v);
        }
        return b;
    }

    /// @notice Appends a sealed block as the new tip without validating it, and warps the clock forward to it.
    function commit(Block memory b) public {
        require(b.number == _chain.length, "not next height");
        _chain.push(b);
        if (vm.getBlockTimestamp() < b.timestamp) {
            vm.warp(b.timestamp);
        }
    }

    function produceBlock() public returns (Block memory b) {
        b = seal(nextBlock());
        commit(b);
    }

    function produceBlocks(uint256 count) external {
        for (uint256 i = 0; i < count; ++i) {
            produceBlock();
        }
    }

    // ---------------------------------------------------------------- light client glue

    /// @notice Deploys the light client, trusting the current tip, driven by `ics26Router`.
    function deployLightClient(
        uint64 trustingPeriod,
        uint64 maxClockDrift,
        ILineaLightClientMsgs.TrustThreshold memory trustLevel,
        address ics26Router
    )
        external
        returns (ILineaLightClient)
    {
        uint64 height = tipHeight();
        ILineaLightClientMsgs.ClientState memory clientState = ILineaLightClientMsgs.ClientState({
            ibcRouter: IBC_ROUTER,
            latestHeight: IICS02ClientMsgs.Height({ revisionNumber: 0, revisionHeight: height }),
            trustingPeriod: trustingPeriod,
            maxClockDrift: maxClockDrift,
            isFrozen: false,
            trustLevel: trustLevel
        });
        return new LineaLightClient(clientState, consensusState(height), ics26Router);
    }

    function consensusState(uint64 height) public view returns (ILineaLightClientMsgs.ConsensusState memory) {
        Block storage b = _chain[height];
        return ILineaLightClientMsgs.ConsensusState(b.timestamp, b.stateRoot, b.validators);
    }

    /// @notice `updateClient` payload submitting the committed block at `height` against `trustedHeight`.
    function updateMsg(uint64 trustedHeight, uint64 height) external view returns (bytes memory) {
        return updateMsg(trustedHeight, _chain[height]);
    }

    /// @notice `updateClient` payload submitting any sealed block (committed or not) against `trustedHeight`.
    function updateMsg(uint64 trustedHeight, Block memory b) public view returns (bytes memory) {
        return abi.encode(
            ILineaLightClientMsgs.MsgUpdateClient(
                b.header, b.bodyRlp, b.validators, b.commitSeals, _height(trustedHeight), consensusState(trustedHeight)
            )
        );
    }

    /// @notice The `[IBC_ROUTER, IBCSTORE_STORAGE_SLOT, ""]` merkle prefix a router must register for the light client.
    function merklePrefix() public view returns (bytes[] memory prefix) {
        prefix = new bytes[](3);
        prefix[0] = abi.encodePacked(IBC_ROUTER);
        prefix[1] = abi.encodePacked(IBCSTORE_STORAGE_SLOT);
        prefix[2] = "";
    }

    function membershipMsg(
        uint64 height,
        bytes memory path
    )
        external
        view
        returns (ILightClientMsgs.MsgVerifyMembership memory)
    {
        bytes32 value = _storageAt(IBC_ROUTER, commitmentSlot(path), height);
        require(value != bytes32(0), "no commitment at height");
        return ILightClientMsgs.MsgVerifyMembership(
            _proof(height, path), _height(height), ICS24Host.prefixedPath(merklePrefix(), path), abi.encodePacked(value)
        );
    }

    function nonMembershipMsg(
        uint64 height,
        bytes memory path
    )
        external
        view
        returns (ILightClientMsgs.MsgVerifyNonMembership memory)
    {
        require(_storageAt(IBC_ROUTER, commitmentSlot(path), height) == bytes32(0), "commitment exists at height");
        return ILightClientMsgs.MsgVerifyNonMembership(
            _proof(height, path), _height(height), ICS24Host.prefixedPath(merklePrefix(), path)
        );
    }

    function _proof(uint64 height, bytes memory path) private view returns (bytes memory) {
        (bytes[] memory accountNodes, bytes[] memory storageNodes) = _proofs(IBC_ROUTER, commitmentSlot(path), height);
        return abi.encode(ILineaLightClientMsgs.MembershipProof(consensusState(height), accountNodes, storageNodes));
    }

    /// @dev Maru's beacon block body `[prevCommitSeals, executionPayload]` with an empty transaction list. Integers
    /// are fixed-width 8-byte strings, as Maru writes them.
    function _bodyRlp(Block memory b, bytes[] memory prevCommitSeals) private pure returns (bytes memory) {
        bytes[] memory seals = new bytes[](prevCommitSeals.length);
        bytes[] memory seal_ = new bytes[](1);
        for (uint256 i = 0; i < seals.length; ++i) {
            seal_[0] = RLP.encode(prevCommitSeals[i]);
            seals[i] = RLP.encode(seal_);
        }

        bytes[] memory payload = new bytes[](14);
        payload[0] = RLP.encode(abi.encodePacked(bytes32(0))); // parentHash
        payload[1] = RLP.encode(abi.encodePacked(address(0))); // feeRecipient
        payload[2] = RLP.encode(abi.encodePacked(b.stateRoot));
        payload[3] = RLP.encode(abi.encodePacked(bytes32(0))); // receiptsRoot
        payload[4] = RLP.encode(new bytes(256)); // logsBloom
        payload[5] = RLP.encode(abi.encodePacked(bytes32(0))); // prevRandao
        payload[6] = RLP.encode(abi.encodePacked(b.number));
        payload[7] = RLP.encode(abi.encodePacked(uint64(30_000_000))); // gasLimit
        payload[8] = RLP.encode(abi.encodePacked(uint64(0))); // gasUsed
        payload[9] = RLP.encode(abi.encodePacked(b.timestamp));
        payload[10] = RLP.encode(bytes("")); // extraData
        payload[11] = RLP.encode(bytes(hex"07")); // baseFeePerGas
        payload[12] = RLP.encode(abi.encodePacked(keccak256(abi.encode(b.number, b.stateRoot)))); // blockHash
        payload[13] = RLP.encode(new bytes[](0)); // transactions

        bytes[] memory body = new bytes[](2);
        body[0] = RLP.encode(seals);
        body[1] = RLP.encode(payload);
        return RLP.encode(body);
    }

    function _height(uint64 height) private pure returns (IICS02ClientMsgs.Height memory) {
        return IICS02ClientMsgs.Height(0, height);
    }
}
