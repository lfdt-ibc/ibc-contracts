// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

// solhint-disable gas-small-strings

import { stdJson } from "forge-std/StdJson.sol";
import { ILightClientMsgs } from "../../contracts/msgs/ILightClientMsgs.sol";
import { ILightClient } from "../../contracts/interfaces/ILightClient.sol";
import { LineaLightClientFixtureTest } from "../linea/LineaLightClientFixture.t.sol";

contract LineaBenchmark is LineaLightClientFixtureTest {
    using stdJson for string;

    string internal constant SNAPSHOT_GROUP = "Linea";

    function testBenchmark_UpdateClient_Adjacent() public {
        _benchmarkUpdate(".adjacentUpdate", "update.adjacent");
    }

    function testBenchmark_UpdateClient_NonAdjacent() public {
        _benchmarkUpdate(".nonAdjacentUpdate", "update.non_adjacent");
    }

    function testBenchmark_VerifyMembership() public {
        _update(".nonAdjacentUpdate");
        ILightClientMsgs.MsgVerifyMembership memory message = _membershipMsg();

        vm.prank(ics26Router);
        uint256 timestamp = client.verifyMembership(message);
        vm.snapshotGasLastFrame(SNAPSHOT_GROUP, "verify_membership.gas");
        vm.snapshotValue(
            SNAPSHOT_GROUP,
            "verify_membership.calldata",
            abi.encodeCall(ILightClient.verifyMembership, (message)).length
        );

        assertEq(timestamp, _timestamp(".nonAdjacentUpdate"));
    }

    function testBenchmark_VerifyNonMembership() public {
        _update(".nonAdjacentUpdate");
        ILightClientMsgs.MsgVerifyNonMembership memory message = _nonMembershipMsg();

        vm.prank(ics26Router);
        uint256 timestamp = client.verifyNonMembership(message);
        vm.snapshotGasLastFrame(SNAPSHOT_GROUP, "verify_non_membership.gas");
        vm.snapshotValue(
            SNAPSHOT_GROUP,
            "verify_non_membership.calldata",
            abi.encodeCall(ILightClient.verifyNonMembership, (message)).length
        );

        assertEq(timestamp, _timestamp(".nonAdjacentUpdate"));
    }

    function _benchmarkUpdate(string memory key, string memory name) internal {
        bytes memory update = json.readBytes(string.concat(key, ".updateMsg"));
        vm.warp(_timestamp(key));

        vm.prank(ics26Router);
        client.updateClient(update);
        vm.snapshotGasLastFrame(SNAPSHOT_GROUP, string.concat(name, ".gas"));
        vm.snapshotValue(
            SNAPSHOT_GROUP, string.concat(name, ".calldata"), abi.encodeCall(ILightClient.updateClient, (update)).length
        );
    }
}
