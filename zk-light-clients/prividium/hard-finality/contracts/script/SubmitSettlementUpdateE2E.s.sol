// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";
import {PublicValuesV1} from "../src/PublicValuesV1.sol";
import {ILightClientMsgs} from "@ibc-contracts/msgs/ILightClientMsgs.sol";

/// @notice Submits one real settlement-update proof and asserts that its exact
/// batch/root pair was added without changing the consensus trust state.
contract SubmitSettlementUpdateE2E is Script {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address sender = vm.addr(privateKey);
        PrividiumZKLightClient client = PrividiumZKLightClient(vm.envAddress("CLIENT_ADDRESS"));
        require(client.IBC_ROUTER() == sender, "broadcaster is not router");

        bytes memory publicValues = vm.envBytes("SETTLEMENT_PUBLIC_VALUES");
        bytes memory proof = vm.envBytes("SETTLEMENT_PROOF");
        PrividiumTypes.SettlementPublicValues memory values =
            PublicValuesV1.decodeSettlement(publicValues);

        PrividiumTypes.ConsensusTrustState memory beforeTrust = client.getConsensusTrustState();
        bytes32 beforeDigest = PublicValuesV1.consensusTrustDigest(beforeTrust);
        require(
            beforeDigest == values.previousConsensusTrustDigest,
            "client is not at proof previous trust state"
        );
        (,, bool existedBefore) = client.getAcceptedBatch(values.l1BatchNumber);
        require(!existedBefore, "batch already accepted");

        bytes memory updateMessage =
            abi.encode(uint8(PrividiumTypes.UpdateKind.SettlementUpdate), publicValues, proof);
        vm.startBroadcast(privateKey);
        ILightClientMsgs.UpdateResult result = client.updateClient(updateMessage);
        vm.stopBroadcast();
        require(result == ILightClientMsgs.UpdateResult.Update, "settlement update was not applied");

        (bytes32 acceptedRoot, uint64 acceptedTimestamp, bool exists) =
            client.getAcceptedBatch(values.l1BatchNumber);
        require(exists, "batch was not recorded");
        require(acceptedRoot == values.prividiumNativeRoot, "wrong accepted root");
        require(acceptedTimestamp == values.l2BatchTimestamp, "wrong accepted timestamp");
        require(
            PublicValuesV1.consensusTrustDigest(client.getConsensusTrustState()) == beforeDigest,
            "settlement update changed trust"
        );

        console2.log("Settlement batch accepted", values.l1BatchNumber);
        console2.logBytes32(acceptedRoot);
        console2.log("Authenticated L2 batch timestamp", acceptedTimestamp);
    }
}
