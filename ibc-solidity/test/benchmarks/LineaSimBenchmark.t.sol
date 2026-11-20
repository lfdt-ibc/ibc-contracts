// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { ILightClient } from "../../contracts/interfaces/ILightClient.sol";
import { ILightClientMsgs } from "../../contracts/msgs/ILightClientMsgs.sol";
import { ILineaLightClient } from "../../contracts/light-clients/linea/interfaces/ILineaLightClient.sol";
import { ILineaLightClientMsgs } from "../../contracts/light-clients/linea/msgs/ILineaLightClientMsgs.sol";
import { ICS24Host } from "../../contracts/utils/ICS24Host.sol";
import { MaruSimSuite } from "../linea/utils/MaruSimSuite.sol";

/// @dev Gas of the Linea light client against simulated Maru chains of increasing block size, validator count and
/// store size.
contract LineaSimBenchmark is Test {
    string internal constant SNAPSHOT_GROUP = "LineaSim";

    address internal ics26Router = makeAddr("ics26Router");

    /// @dev Scales the transaction bytes of the block, which the update carries in full as part of the body.
    function testBenchmark_UpdateClient_TransactionBytes() public {
        uint256[5] memory sizes = [uint256(0), 1024, 16_384, 131_072, 1_048_576];
        for (uint256 i = 0; i < sizes.length; ++i) {
            (MaruSimSuite sim, ILineaLightClient client) = _setUp(1);
            MaruSimSuite.Block memory b = sim.nextBlock();
            if (sizes[i] != 0) {
                b.transactions = new bytes[](1);
                b.transactions[0] = _transaction(sizes[i]);
            }
            bytes memory update = sim.updateMsg(2, sim.seal(b));

            _benchmarkUpdate(client, update, string.concat("update.transaction_bytes_", vm.toString(sizes[i])));
        }
    }

    function testBenchmark_UpdateClient_ValidatorCount() public {
        uint256[7] memory counts = [uint256(1), 4, 7, 16, 32, 64, 100];
        for (uint256 i = 0; i < counts.length; ++i) {
            (MaruSimSuite sim, ILineaLightClient client) = _setUp(counts[i]);
            sim.produceBlock();
            bytes memory update = sim.updateMsg(2, 3);

            _benchmarkUpdate(client, update, string.concat("update.validators_", vm.toString(counts[i])));
        }
    }

    /// @dev Scales the world state trie (accounts, router included) and the router's storage trie (commitments).
    function testBenchmark_VerifyMembership_TrieSizes() public {
        uint256[4] memory sizes = [uint256(1), 16, 128, 1024];
        for (uint256 a = 0; a < sizes.length; ++a) {
            for (uint256 c = 0; c < sizes.length; ++c) {
                (MaruSimSuite sim, ILineaLightClient client) = _setUp(1);
                sim.addAccounts(sizes[a] - 1);
                for (uint64 seq = 1; seq <= sizes[c]; ++seq) {
                    sim.setCommitment(
                        ICS24Host.packetCommitmentPathCalldata("client-0", seq), keccak256(abi.encode(seq))
                    );
                }
                sim.produceBlock();
                bytes memory update = sim.updateMsg(2, 3);
                vm.startPrank(ics26Router);
                client.updateClient(update);
                ILightClientMsgs.MsgVerifyMembership memory message =
                    sim.membershipMsg(3, ICS24Host.packetCommitmentPathCalldata("client-0", 1));
                string memory name = string.concat(
                    "verify_membership.accounts_", vm.toString(sizes[a]), ".commitments_", vm.toString(sizes[c])
                );

                client.verifyMembership(message);
                vm.stopPrank();
                vm.snapshotGasLastFrame(SNAPSHOT_GROUP, string.concat(name, ".gas"));
                vm.snapshotValue(
                    SNAPSHOT_GROUP,
                    string.concat(name, ".calldata"),
                    abi.encodeCall(ILightClient.verifyMembership, (message)).length
                );
            }
        }
    }

    function _setUp(uint256 validatorCount) internal returns (MaruSimSuite sim, ILineaLightClient client) {
        sim = new MaruSimSuite();
        sim.addValidators(validatorCount);
        sim.produceBlocks(2);
        client = sim.deployLightClient(1 days, 10, ILineaLightClientMsgs.TrustThreshold(2, 3), ics26Router);
    }

    function _benchmarkUpdate(ILineaLightClient client, bytes memory update, string memory name) internal {
        vm.prank(ics26Router);
        client.updateClient(update);
        vm.snapshotGasLastFrame(SNAPSHOT_GROUP, string.concat(name, ".gas"));
        vm.snapshotValue(
            SNAPSHOT_GROUP, string.concat(name, ".calldata"), abi.encodeCall(ILightClient.updateClient, (update)).length
        );
    }

    /// @dev A transaction of `length` non-zero bytes, as signed transactions are mostly non-zero.
    function _transaction(uint256 length) internal pure returns (bytes memory transaction) {
        transaction = new bytes(length);
        for (uint256 i = 0; i < length; ++i) {
            transaction[i] = 0xff;
        }
    }
}
