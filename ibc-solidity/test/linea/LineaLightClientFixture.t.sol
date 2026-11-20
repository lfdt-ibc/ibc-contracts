// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

// solhint-disable gas-small-strings

import { Test } from "forge-std/Test.sol";
import { stdJson } from "forge-std/StdJson.sol";

import { IICS02ClientMsgs } from "../../contracts/msgs/IICS02ClientMsgs.sol";
import { ILightClientMsgs } from "../../contracts/msgs/ILightClientMsgs.sol";
import { ILineaLightClient } from "../../contracts/light-clients/linea/interfaces/ILineaLightClient.sol";
import { ILineaLightClientMsgs } from "../../contracts/light-clients/linea/msgs/ILineaLightClientMsgs.sol";
import { ILineaLightClientErrors } from "../../contracts/light-clients/linea/errors/ILineaLightClientErrors.sol";

import { LineaLightClient } from "../../contracts/light-clients/linea/LineaLightClient.sol";
import { ICS24Host } from "../../contracts/utils/ICS24Host.sol";

/// @dev Runs the light client on beacon blocks and proofs captured from a live network of Maru, Linea's consensus
/// client, and a Besu execution client. `just solidity::generate-fixtures-linea` regenerates the fixture.
contract LineaLightClientFixtureTest is Test {
    using stdJson for string;

    /// @dev ERC-7201 namespace of `IBCStoreUpgradeable`.
    bytes32 internal constant IBCSTORE_STORAGE_SLOT =
        0x1260944489272988d9df285149b5aa1b0f48f2136d6f416159f840a3e0747600;

    string internal json;
    ILineaLightClient internal client;
    address internal ics26Router = makeAddr("ics26Router");

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/linea/fixtures/maru.json"));

        ILineaLightClientMsgs.ConsensusState memory initialState =
            abi.decode(json.readBytes(".initialConsensusState"), (ILineaLightClientMsgs.ConsensusState));
        vm.warp(initialState.timestamp);
        client = new LineaLightClient(
            ILineaLightClientMsgs.ClientState({
                ibcRouter: json.readAddress(".routerAddress"),
                latestHeight: IICS02ClientMsgs.Height(0, uint64(json.readUint(".initialTrustedHeight"))),
                trustingPeriod: uint64(json.readUint(".trustingPeriod")),
                maxClockDrift: uint64(json.readUint(".maxClockDrift")),
                isFrozen: false,
                trustLevel: ILineaLightClientMsgs.TrustThreshold(2, 3)
            }),
            initialState,
            ics26Router
        );
    }

    function test_updateClient() public {
        string[2] memory updates = [".adjacentUpdate", ".nonAdjacentUpdate"];
        for (uint256 i = 0; i < updates.length; ++i) {
            assertEq(uint8(_update(updates[i])), uint8(ILightClientMsgs.UpdateResult.Update), updates[i]);
            assertEq(
                client.getConsensusStateHash(_height(updates[i])),
                keccak256(json.readBytes(string.concat(updates[i], ".consensusState"))),
                updates[i]
            );
        }

        ILineaLightClientMsgs.ClientState memory clientState =
            abi.decode(client.getClientState(), (ILineaLightClientMsgs.ClientState));
        assertEq(clientState.latestHeight.revisionHeight, _height(".nonAdjacentUpdate"));
        assertEq(uint8(_update(".nonAdjacentUpdate")), uint8(ILightClientMsgs.UpdateResult.NoOp));
    }

    /// @dev The fixture's conflicting update is the non-adjacent block re-sealed over another execution state root.
    function test_updateClient_freezesOnDoubleSign() public {
        _update(".nonAdjacentUpdate");
        assertEq(uint8(_update(".conflictingUpdate")), uint8(ILightClientMsgs.UpdateResult.Misbehaviour));
        assertTrue(abi.decode(client.getClientState(), (ILineaLightClientMsgs.ClientState)).isFrozen);
    }

    /// @dev The update binds the full body, so no transaction byte of it can be changed.
    function test_updateClient_revertTamperedBody() public {
        ILineaLightClientMsgs.MsgUpdateClient memory update =
            abi.decode(json.readBytes(".nonAdjacentUpdate.updateMsg"), (ILineaLightClientMsgs.MsgUpdateClient));
        update.bodyRlp[update.bodyRlp.length - 1] ^= 0x01;

        vm.expectRevert(
            abi.encodeWithSelector(
                ILineaLightClientErrors.BodyRootMismatch.selector, update.header.bodyRoot, keccak256(update.bodyRlp)
            )
        );
        vm.prank(ics26Router);
        client.updateClient(abi.encode(update));
    }

    function test_verifyMembership() public {
        _update(".nonAdjacentUpdate");
        ILightClientMsgs.MsgVerifyMembership memory msg_ = _membershipMsg();

        vm.startPrank(ics26Router);
        assertEq(client.verifyMembership(msg_), _timestamp(".nonAdjacentUpdate"));

        bytes32 value = bytes32(msg_.value);
        msg_.value = abi.encodePacked(~value);
        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.InvalidCommitmentValue.selector, ~value, value));
        client.verifyMembership(msg_);
        vm.stopPrank();
    }

    function test_verifyNonMembership() public {
        _update(".nonAdjacentUpdate");
        ILightClientMsgs.MsgVerifyNonMembership memory msg_ = _nonMembershipMsg();

        vm.startPrank(ics26Router);
        assertEq(client.verifyNonMembership(msg_), _timestamp(".nonAdjacentUpdate"));

        // The packet commitment exists, so the same proof height cannot prove its absence.
        msg_.proof = json.readBytes(".membership.proof");
        msg_.path = _path(".membership.path");
        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.InvalidExclusionProof.selector));
        client.verifyNonMembership(msg_);
        vm.stopPrank();
    }

    /// @dev Submits the fixture update under `key` at the time of its block.
    function _update(string memory key) internal returns (ILightClientMsgs.UpdateResult) {
        if (vm.getBlockTimestamp() < _timestamp(key)) {
            vm.warp(_timestamp(key));
        }
        vm.prank(ics26Router);
        return client.updateClient(json.readBytes(string.concat(key, ".updateMsg")));
    }

    function _membershipMsg() internal view returns (ILightClientMsgs.MsgVerifyMembership memory) {
        return ILightClientMsgs.MsgVerifyMembership({
            proof: json.readBytes(".membership.proof"),
            proofHeight: IICS02ClientMsgs.Height(0, uint64(json.readUint(".membership.proofHeight"))),
            path: _path(".membership.path"),
            value: json.readBytes(".membership.value")
        });
    }

    function _nonMembershipMsg() internal view returns (ILightClientMsgs.MsgVerifyNonMembership memory) {
        return ILightClientMsgs.MsgVerifyNonMembership({
            proof: json.readBytes(".nonMembership.proof"),
            proofHeight: IICS02ClientMsgs.Height(0, uint64(json.readUint(".nonMembership.proofHeight"))),
            path: _path(".nonMembership.path")
        });
    }

    function _height(string memory key) internal view returns (uint64) {
        return uint64(json.readUint(string.concat(key, ".height")));
    }

    function _timestamp(string memory key) internal view returns (uint64) {
        return abi.decode(json.readBytes(string.concat(key, ".consensusState")), (ILineaLightClientMsgs.ConsensusState))
        .timestamp;
    }

    /// @dev The fixture path under `key`, prefixed with `[router, IBCSTORE_STORAGE_SLOT, ""]`.
    function _path(string memory key) internal view returns (bytes[] memory) {
        bytes[] memory prefix = new bytes[](3);
        prefix[0] = abi.encodePacked(json.readAddress(".routerAddress"));
        prefix[1] = abi.encodePacked(IBCSTORE_STORAGE_SLOT);
        return ICS24Host.prefixedPath(prefix, json.readBytes(key));
    }
}
