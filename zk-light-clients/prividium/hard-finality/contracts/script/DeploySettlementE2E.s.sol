// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {SP1Verifier} from "@sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";

import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";
import {PublicValuesV1} from "../src/PublicValuesV1.sol";

/// @notice Deploys a fresh client at the settlement fixture's bootstrap trust state.
/// Unlike DeployTrustUpdateE2E, this setup script does not require an earlier
/// trust-update proof because settlement verification does not mutate trust.
contract DeploySettlementE2E is Script {
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
        // The gateway route is deliberately the leading four bytes of the verifier hash.
        // forge-lint: disable-next-line(unsafe-typecast)
        (address routedVerifier, bool frozen) = gateway.routes(bytes4(EXPECTED_VERIFIER_HASH));
        require(routedVerifier == address(verifier) && !frozen, "gateway route mismatch");
        require(
            PublicValuesV1.consensusTrustDigest(client.getConsensusTrustState())
                == PublicValuesV1.consensusTrustDigest(config.initialTrust),
            "deployed trust mismatch"
        );

        console2.log("SP1Verifier", address(verifier));
        console2.log("SP1VerifierGateway", address(gateway));
        console2.log("PrividiumZKLightClient", address(client));
        console2.log("Router/deployer", config.deployer);
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

        require(config.sourceProfileId != bytes32(0), "zero profile ID");
        require(config.initialTrust.finalizedBeaconHeaderRoot != bytes32(0), "zero trust root");
        require(config.initialTrust.currentSyncCommitteeRoot != bytes32(0), "zero committee root");
        require(config.trustUpdateVkey != bytes32(0), "zero trust vkey");
        require(config.settlementUpdateVkey != bytes32(0), "zero settlement vkey");
        require(config.membershipVkey != bytes32(0), "zero membership vkey");
        require(config.nonMembershipVkey != bytes32(0), "zero non-membership vkey");
        require(config.ibcStore != address(0), "zero IBC store");
    }
}
