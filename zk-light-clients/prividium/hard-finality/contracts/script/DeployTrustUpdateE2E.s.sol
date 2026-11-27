// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {SP1Verifier} from "@sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";

import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";
import {PublicValuesV1} from "../src/PublicValuesV1.sol";

/// @notice Deploys the exact SP1 Groth16 route used by the v6.7.0 proof artifact and a
/// connected local E2E client. The broadcaster EOA is used as the Router; the
/// source IBC store is an explicit input.
contract DeployTrustUpdateE2E is Script {
    bytes32 internal constant EXPECTED_VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;

    struct DeploymentConfig {
        uint256 privateKey;
        address deployer;
        bytes32 sourceProfileId;
        PrividiumTypes.ConsensusTrustState initialTrust;
        bytes32 trustUpdateVkey;
        bytes32 settlementUpdateVkey;
        bytes32 membershipVkey;
        bytes32 nonMembershipVkey;
        uint32 absenceProfileId;
        address ibcStore;
    }

    function run() external {
        DeploymentConfig memory config = _loadAndValidateConfig();
        _deploy(config);
    }

    function _loadAndValidateConfig() private view returns (DeploymentConfig memory config) {
        config.privateKey = vm.envUint("PRIVATE_KEY");
        config.deployer = vm.addr(config.privateKey);
        config.sourceProfileId = vm.envBytes32("SOURCE_PROFILE_ID");
        config.initialTrust = PrividiumTypes.ConsensusTrustState({
            finalizedBeaconSlot: uint64(vm.envUint("INITIAL_FINALIZED_SLOT")),
            finalizedBeaconHeaderRoot: vm.envBytes32("INITIAL_FINALIZED_ROOT"),
            currentSyncCommitteeRoot: vm.envBytes32("INITIAL_CURRENT_COMMITTEE_ROOT"),
            nextSyncCommitteeRoot: vm.envBytes32("INITIAL_NEXT_COMMITTEE_ROOT"),
            nextSyncCommitteeKnown: vm.envBool("INITIAL_NEXT_COMMITTEE_KNOWN")
        });
        config.trustUpdateVkey = vm.envBytes32("TRUST_UPDATE_VKEY");
        config.settlementUpdateVkey = vm.envBytes32("SETTLEMENT_UPDATE_VKEY");
        config.membershipVkey = vm.envBytes32("MEMBERSHIP_VKEY");
        config.nonMembershipVkey = vm.envBytes32("NON_MEMBERSHIP_VKEY");
        config.absenceProfileId = uint32(vm.envUint("ABSENCE_PROFILE_ID"));
        config.ibcStore = vm.envAddress("IBC_STORE_ADDRESS");

        bytes memory publicValues = vm.envBytes("TRUST_PUBLIC_VALUES");
        bytes memory proof = vm.envBytes("TRUST_PROOF");
        PrividiumTypes.TrustUpdatePublicValues memory values =
            PublicValuesV1.decodeTrustUpdate(publicValues);
        require(values.sourceProfileId == config.sourceProfileId, "fixture/profile mismatch");
        require(
            values.previousConsensusTrustDigest
                == PublicValuesV1.consensusTrustDigest(config.initialTrust),
            "fixture/initial trust mismatch"
        );
        // The gateway route is deliberately the leading four bytes of the verifier hash.
        // forge-lint: disable-next-line(unsafe-typecast)
        require(_selector(proof) == bytes4(EXPECTED_VERIFIER_HASH), "wrong proof verifier route");
    }

    function _deploy(DeploymentConfig memory config) private {
        vm.startBroadcast(config.privateKey);
        SP1Verifier verifier = new SP1Verifier();
        SP1VerifierGateway gateway = new SP1VerifierGateway(config.deployer);
        gateway.addRoute(address(verifier));
        PrividiumZKLightClient client = new PrividiumZKLightClient(
            config.sourceProfileId,
            config.initialTrust,
            config.ibcStore,
            config.absenceProfileId,
            config.trustUpdateVkey,
            config.settlementUpdateVkey,
            config.membershipVkey,
            config.nonMembershipVkey,
            address(gateway),
            config.deployer
        );
        vm.stopBroadcast();

        require(verifier.VERIFIER_HASH() == EXPECTED_VERIFIER_HASH, "unexpected verifier hash");
        // forge-lint: disable-next-line(unsafe-typecast)
        (address routedVerifier, bool frozen) = gateway.routes(bytes4(EXPECTED_VERIFIER_HASH));
        require(routedVerifier == address(verifier) && !frozen, "gateway route mismatch");

        PrividiumTypes.ConsensusTrustState memory deployedTrust = client.getConsensusTrustState();
        require(
            PublicValuesV1.consensusTrustDigest(deployedTrust)
                == PublicValuesV1.consensusTrustDigest(config.initialTrust),
            "deployed trust mismatch"
        );

        console2.log("SP1Verifier", address(verifier));
        console2.log("SP1VerifierGateway", address(gateway));
        console2.log("PrividiumZKLightClient", address(client));
        console2.log("Router/deployer", config.deployer);
    }

    function _selector(bytes memory proof) private pure returns (bytes4 selector) {
        require(proof.length >= 4, "proof too short");
        assembly ("memory-safe") {
            selector := mload(add(proof, 0x20))
        }
    }
}
