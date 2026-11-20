// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";
import {PublicValuesV1} from "../src/PublicValuesV1.sol";
import {IICS02ClientMsgs} from "@ibc-contracts/msgs/IICS02ClientMsgs.sol";
import {ILightClientMsgs} from "@ibc-contracts/msgs/ILightClientMsgs.sol";

/// @notice Submits one real Membership proof against an already accepted
/// settlement batch and asserts the exact authenticated source timestamp.
contract SubmitMembershipE2E is Script {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        PrividiumZKLightClient client = PrividiumZKLightClient(vm.envAddress("CLIENT_ADDRESS"));
        require(client.IBC_ROUTER() == vm.addr(privateKey), "broadcaster is not router");

        bytes memory publicValues = vm.envBytes("MEMBERSHIP_PUBLIC_VALUES");
        PrividiumTypes.MembershipPublicValues memory values =
            PublicValuesV1.decodeMembership(publicValues);
        (bytes32 acceptedRoot, uint64 acceptedTimestamp, bool exists) =
            client.getAcceptedBatch(values.l1BatchNumber);
        require(exists, "Membership batch is not accepted");
        require(acceptedRoot == values.prividiumNativeRoot, "wrong accepted root");

        ILightClientMsgs.MsgVerifyMembership memory message = _message(publicValues, values);

        vm.startBroadcast(privateKey);
        uint256 returnedTimestamp = client.verifyMembership(message);
        vm.stopBroadcast();

        require(returnedTimestamp == acceptedTimestamp, "wrong Membership timestamp");
        console2.log("Membership proof accepted for batch", values.l1BatchNumber);
        console2.log("Authenticated source timestamp", returnedTimestamp);
        console2.logBytes32(values.prividiumNativeRoot);
    }

    function _message(
        bytes memory publicValues,
        PrividiumTypes.MembershipPublicValues memory values
    ) private view returns (ILightClientMsgs.MsgVerifyMembership memory) {
        bytes memory proofBytes = vm.envBytes("MEMBERSHIP_PROOF");
        bytes memory logicalPath = vm.envBytes("MEMBERSHIP_PATH");
        bytes memory expectedValue = vm.envBytes("MEMBERSHIP_VALUE");
        require(logicalPath.length != 0, "empty Membership path");
        require(expectedValue.length == 32, "Membership value is not bytes32");
        bytes[] memory path = new bytes[](1);
        path[0] = logicalPath;
        bytes memory envelope = abi.encode(
            PrividiumTypes.SP1ProofEnvelope({publicValues: publicValues, proofBytes: proofBytes})
        );
        return ILightClientMsgs.MsgVerifyMembership({
            proof: envelope,
            proofHeight: IICS02ClientMsgs.Height({
                revisionNumber: 0, revisionHeight: values.proofHeight
            }),
            path: path,
            value: expectedValue
        });
    }
}
