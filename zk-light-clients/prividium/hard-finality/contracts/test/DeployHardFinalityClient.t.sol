// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {DeployHardFinalityClient} from "../script/DeployHardFinalityClient.s.sol";
import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";

contract DeploymentTestRouter {}

contract DeploymentTestVerifier {
    bytes32 public constant VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;
}

contract DeploymentTestGateway {
    bytes32 private constant VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;
    address private immutable verifier;

    constructor(address verifier_) {
        verifier = verifier_;
    }

    function routes(bytes4 selector) external view returns (address, bool) {
        require(selector == bytes4(VERIFIER_HASH), "wrong selector");
        return (verifier, true);
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}

contract DeployHardFinalityClientTest is Test {
    bytes32 private constant PROFILE = bytes32(uint256(11));
    bytes32 private constant TRUST_VKEY = bytes32(uint256(21));
    bytes32 private constant SETTLEMENT_VKEY = bytes32(uint256(22));
    bytes32 private constant MEMBERSHIP_VKEY = bytes32(uint256(23));
    bytes32 private constant NON_MEMBERSHIP_VKEY = bytes32(uint256(24));

    function testProductionScriptUsesReviewedRouterGatewayVkeysAndTrust() public {
        DeploymentTestRouter router = new DeploymentTestRouter();
        DeploymentTestVerifier verifier = new DeploymentTestVerifier();
        DeploymentTestGateway gateway = new DeploymentTestGateway(address(verifier));

        vm.setEnv("PRIVATE_KEY", vm.toString(uint256(0xA11CE)));
        vm.setEnv("DESTINATION_CHAIN_ID", vm.toString(block.chainid));
        vm.setEnv("SOURCE_PROFILE_ID", vm.toString(PROFILE));
        vm.setEnv("INITIAL_FINALIZED_SLOT", "123");
        vm.setEnv("INITIAL_FINALIZED_ROOT", vm.toString(bytes32(uint256(31))));
        vm.setEnv("INITIAL_CURRENT_COMMITTEE_ROOT", vm.toString(bytes32(uint256(32))));
        vm.setEnv("INITIAL_NEXT_COMMITTEE_ROOT", vm.toString(bytes32(0)));
        vm.setEnv("INITIAL_NEXT_COMMITTEE_KNOWN", "false");
        vm.setEnv("IBC_STORE_ADDRESS", vm.toString(address(0x4444)));
        vm.setEnv("ABSENCE_PROFILE_ID", "1");
        vm.setEnv("TRUST_UPDATE_VKEY", vm.toString(TRUST_VKEY));
        vm.setEnv("SETTLEMENT_UPDATE_VKEY", vm.toString(SETTLEMENT_VKEY));
        vm.setEnv("MEMBERSHIP_VKEY", vm.toString(MEMBERSHIP_VKEY));
        vm.setEnv("NON_MEMBERSHIP_VKEY", vm.toString(NON_MEMBERSHIP_VKEY));
        vm.setEnv("SP1_VERIFIER_GATEWAY", vm.toString(address(gateway)));
        vm.setEnv("IBC_ROUTER", vm.toString(address(router)));

        PrividiumZKLightClient client = new DeployHardFinalityClient().run();

        assertEq(client.SOURCE_PROFILE_ID(), PROFILE);
        assertEq(client.IBC_STORE(), address(0x4444));
        assertEq(client.ABSENCE_PROFILE_ID(), 1);
        assertEq(client.TRUST_UPDATE_VKEY(), TRUST_VKEY);
        assertEq(client.SETTLEMENT_UPDATE_VKEY(), SETTLEMENT_VKEY);
        assertEq(client.MEMBERSHIP_VKEY(), MEMBERSHIP_VKEY);
        assertEq(client.NON_MEMBERSHIP_VKEY(), NON_MEMBERSHIP_VKEY);
        assertEq(address(client.SP1_VERIFIER()), address(gateway));
        assertEq(client.IBC_ROUTER(), address(router));
        PrividiumTypes.ConsensusTrustState memory trust = client.getConsensusTrustState();
        assertEq(trust.finalizedBeaconSlot, 123);
        assertEq(trust.finalizedBeaconHeaderRoot, bytes32(uint256(31)));
        assertEq(trust.currentSyncCommitteeRoot, bytes32(uint256(32)));
        assertEq(trust.nextSyncCommitteeRoot, bytes32(0));
        assertFalse(trust.nextSyncCommitteeKnown);
    }
}
