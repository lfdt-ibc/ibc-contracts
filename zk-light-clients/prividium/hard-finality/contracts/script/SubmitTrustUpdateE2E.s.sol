// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";
import {PublicValuesV1} from "../src/PublicValuesV1.sol";
import {ILightClientMsgs} from "@ibc-contracts/msgs/ILightClientMsgs.sol";

/// @notice Submits one real trust-update proof and asserts the exact post-state encoded in its
/// public values. Run the invalid-proof eth_call before this script, while the previous trust
/// digest still matches the fixture.
contract SubmitTrustUpdateE2E is Script {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address sender = vm.addr(privateKey);
        PrividiumZKLightClient client = PrividiumZKLightClient(vm.envAddress("CLIENT_ADDRESS"));
        require(client.IBC_ROUTER() == sender, "broadcaster is not router");

        bytes memory publicValues = vm.envBytes("TRUST_PUBLIC_VALUES");
        bytes memory proof = vm.envBytes("TRUST_PROOF");
        PrividiumTypes.TrustUpdatePublicValues memory values =
            PublicValuesV1.decodeTrustUpdate(publicValues);

        PrividiumTypes.ConsensusTrustState memory beforeState = client.getConsensusTrustState();
        require(
            PublicValuesV1.consensusTrustDigest(beforeState) == values.previousConsensusTrustDigest,
            "client is not at proof previous state"
        );

        bytes memory updateMessage =
            abi.encode(uint8(PrividiumTypes.UpdateKind.TrustUpdate), publicValues, proof);
        vm.startBroadcast(privateKey);
        ILightClientMsgs.UpdateResult result = client.updateClient(updateMessage);
        vm.stopBroadcast();
        require(result == ILightClientMsgs.UpdateResult.Update, "trust update was not applied");

        PrividiumTypes.ConsensusTrustState memory afterState = client.getConsensusTrustState();
        require(afterState.finalizedBeaconSlot == values.newFinalizedBeaconSlot, "wrong slot");
        require(
            afterState.finalizedBeaconHeaderRoot == values.newFinalizedBeaconHeaderRoot,
            "wrong finalized root"
        );
        require(
            afterState.currentSyncCommitteeRoot == values.newCurrentSyncCommitteeRoot,
            "wrong current committee"
        );
        require(
            afterState.nextSyncCommitteeRoot == values.newNextSyncCommitteeRoot,
            "wrong next committee"
        );
        require(
            afterState.nextSyncCommitteeKnown == values.newNextSyncCommitteeKnown,
            "wrong next committee flag"
        );

        console2.log("Trust update accepted at slot", afterState.finalizedBeaconSlot);
        console2.logBytes32(afterState.finalizedBeaconHeaderRoot);
    }
}
