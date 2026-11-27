// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {PrividiumTypes} from "../src/PrividiumTypes.sol";
import {PrividiumZKLightClient} from "../src/PrividiumZKLightClient.sol";
import {PublicValuesV1} from "../src/PublicValuesV1.sol";

interface ISP1VerifierGatewayRoutes {
    function routes(bytes4 selector) external view returns (address verifier, bool frozen);
}

interface ISP1VerifierHash {
    function VERIFIER_HASH() external view returns (bytes32);
}

/// @notice Deploys the production settlement-backed hard-finality light client against an existing
/// ICS26 Router and an existing SP1 verifier gateway.
contract DeployHardFinalityClient is Script {
    bytes32 internal constant EXPECTED_VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;

    struct DeploymentConfig {
        uint256 privateKey;
        uint256 destinationChainId;
        bytes32 sourceProfileId;
        PrividiumTypes.ConsensusTrustState initialTrust;
        address ibcStore;
        uint32 absenceProfileId;
        bytes32 trustUpdateVkey;
        bytes32 settlementUpdateVkey;
        bytes32 membershipVkey;
        bytes32 nonMembershipVkey;
        address verifierGateway;
        address router;
    }

    function run() external returns (PrividiumZKLightClient client) {
        DeploymentConfig memory config = _loadAndValidateConfig();
        _validateDestination(config);

        vm.startBroadcast(config.privateKey);
        client = new PrividiumZKLightClient(
            config.sourceProfileId,
            config.initialTrust,
            config.ibcStore,
            config.absenceProfileId,
            config.trustUpdateVkey,
            config.settlementUpdateVkey,
            config.membershipVkey,
            config.nonMembershipVkey,
            config.verifierGateway,
            config.router
        );
        vm.stopBroadcast();

        _validateDeployment(client, config);
        console2.log("PrividiumZKLightClient", address(client));
        console2.log("ICS26 Router", config.router);
        console2.log("SP1 verifier gateway", config.verifierGateway);
        console2.log("Deployer", vm.addr(config.privateKey));
    }

    function _loadAndValidateConfig() private view returns (DeploymentConfig memory config) {
        config.privateKey = vm.envUint("PRIVATE_KEY");
        config.destinationChainId = vm.envUint("DESTINATION_CHAIN_ID");
        config.sourceProfileId = vm.envBytes32("SOURCE_PROFILE_ID");
        config.initialTrust = PrividiumTypes.ConsensusTrustState({
            finalizedBeaconSlot: uint64(vm.envUint("INITIAL_FINALIZED_SLOT")),
            finalizedBeaconHeaderRoot: vm.envBytes32("INITIAL_FINALIZED_ROOT"),
            currentSyncCommitteeRoot: vm.envBytes32("INITIAL_CURRENT_COMMITTEE_ROOT"),
            nextSyncCommitteeRoot: vm.envBytes32("INITIAL_NEXT_COMMITTEE_ROOT"),
            nextSyncCommitteeKnown: vm.envBool("INITIAL_NEXT_COMMITTEE_KNOWN")
        });
        config.ibcStore = vm.envAddress("IBC_STORE_ADDRESS");
        config.absenceProfileId = uint32(vm.envUint("ABSENCE_PROFILE_ID"));
        config.trustUpdateVkey = vm.envBytes32("TRUST_UPDATE_VKEY");
        config.settlementUpdateVkey = vm.envBytes32("SETTLEMENT_UPDATE_VKEY");
        config.membershipVkey = vm.envBytes32("MEMBERSHIP_VKEY");
        config.nonMembershipVkey = vm.envBytes32("NON_MEMBERSHIP_VKEY");
        config.verifierGateway = vm.envAddress("SP1_VERIFIER_GATEWAY");
        config.router = vm.envAddress("IBC_ROUTER");

        require(config.privateKey != 0, "zero private key");
        require(config.destinationChainId != 0, "zero destination chain ID");
        require(config.sourceProfileId != bytes32(0), "zero SourceProfile ID");
        require(config.ibcStore != address(0), "zero IBC store");
        require(config.absenceProfileId != 0, "zero absence profile");
        require(config.verifierGateway != address(0), "zero verifier gateway");
        require(config.router != address(0), "zero Router");
    }

    function _validateDestination(DeploymentConfig memory config) private view {
        require(block.chainid == config.destinationChainId, "destination chain ID mismatch");
        require(config.router.code.length != 0, "Router has no code");
        require(config.verifierGateway.code.length != 0, "verifier gateway has no code");

        (address verifier,) =
            ISP1VerifierGatewayRoutes(config.verifierGateway).routes(bytes4(EXPECTED_VERIFIER_HASH));
        require(verifier != address(0) && verifier.code.length != 0, "missing verifier route");
        require(
            ISP1VerifierHash(verifier).VERIFIER_HASH() == EXPECTED_VERIFIER_HASH,
            "wrong verifier route"
        );
    }

    function _validateDeployment(PrividiumZKLightClient client, DeploymentConfig memory config)
        private
        view
    {
        require(client.SOURCE_PROFILE_ID() == config.sourceProfileId, "profile readback mismatch");
        require(client.IBC_STORE() == config.ibcStore, "IBC store readback mismatch");
        require(
            client.ABSENCE_PROFILE_ID() == config.absenceProfileId,
            "absence profile readback mismatch"
        );
        require(client.TRUST_UPDATE_VKEY() == config.trustUpdateVkey, "trust VKey mismatch");
        require(
            client.SETTLEMENT_UPDATE_VKEY() == config.settlementUpdateVkey,
            "settlement VKey mismatch"
        );
        require(client.MEMBERSHIP_VKEY() == config.membershipVkey, "membership VKey mismatch");
        require(
            client.NON_MEMBERSHIP_VKEY() == config.nonMembershipVkey, "non-membership VKey mismatch"
        );
        require(address(client.SP1_VERIFIER()) == config.verifierGateway, "gateway mismatch");
        require(client.IBC_ROUTER() == config.router, "Router mismatch");
        require(
            PublicValuesV1.consensusTrustDigest(client.getConsensusTrustState())
                == PublicValuesV1.consensusTrustDigest(config.initialTrust),
            "initial trust readback mismatch"
        );
    }
}
