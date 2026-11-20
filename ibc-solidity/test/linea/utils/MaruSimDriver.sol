// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

// solhint-disable immutable-vars-naming

import { IICS02ClientMsgs } from "../../../contracts/msgs/IICS02ClientMsgs.sol";
import { ILightClientMsgs } from "../../../contracts/msgs/ILightClientMsgs.sol";
import { ILineaLightClientMsgs } from "../../../contracts/light-clients/linea/msgs/ILineaLightClientMsgs.sol";

import { ILightClient } from "../../../contracts/interfaces/ILightClient.sol";
import { ICS26Router } from "../../../contracts/ICS26Router.sol";
import { IBCStoreUpgradeable } from "../../../contracts/utils/IBCStoreUpgradeable.sol";
import { Math } from "@openzeppelin-contracts/utils/math/Math.sol";
import { ILightClientDriver } from "../../solidity-ibc/integration/drivers/ILightClientDriver.sol";
import { LightClientDriverTest } from "../../solidity-ibc/integration/drivers/LightClientDriverTest.sol";
import { MaruSimSuite } from "./MaruSimSuite.sol";

/// @notice Drives a Linea light client that tracks a single-validator `MaruSimSuite` chain mirroring the counterparty
/// router.
/// @dev Each proof mirrors the proven commitment into the sim, produces a block and updates the client to it. Blocks
/// are stamped with the EVM clock, so the proven counterparty time is the current time as timeouts expect.
contract MaruSimDriver is ILightClientDriver {
    MaruSimSuite public immutable sim;
    ILightClient public immutable lightClient;
    IBCStoreUpgradeable private immutable _counterpartyRouter;

    constructor(ICS26Router host, ICS26Router counterparty) {
        sim = new MaruSimSuite();
        sim.addValidator();
        _produceBlock();
        lightClient = sim.deployLightClient(1 days, 10, ILineaLightClientMsgs.TrustThreshold(2, 3), address(host));
        _counterpartyRouter = counterparty;
    }

    /// @inheritdoc ILightClientDriver
    function merklePrefix() external view returns (bytes[] memory) {
        return sim.merklePrefix();
    }

    /// @inheritdoc ILightClientDriver
    function prove(bytes calldata path)
        external
        returns (bytes memory updateMsg, bytes memory proof, IICS02ClientMsgs.Height memory proofHeight)
    {
        sim.syncCommitment(_counterpartyRouter, path);
        uint64 height = _produceBlock();
        updateMsg = sim.updateMsg(_latestHeight(), height);

        if (_counterpartyRouter.getCommitment(keccak256(path)) != 0) {
            ILightClientMsgs.MsgVerifyMembership memory msg_ = sim.membershipMsg(height, path);
            return (updateMsg, msg_.proof, msg_.proofHeight);
        }
        ILightClientMsgs.MsgVerifyNonMembership memory nonMsg = sim.nonMembershipMsg(height, path);
        return (updateMsg, nonMsg.proof, nonMsg.proofHeight);
    }

    /// @dev Trusts the client's own latest height, so an update that was never submitted cannot leave the next one
    /// pointing at a height the client does not store.
    function _latestHeight() private view returns (uint64) {
        return abi.decode(lightClient.getClientState(), (ILineaLightClientMsgs.ClientState)).latestHeight.revisionHeight;
    }

    /// @dev Stamps the block with the current time, or one second after the tip if that is later, so the sim only
    /// warps the clock when several blocks land in the same second.
    function _produceBlock() private returns (uint64) {
        MaruSimSuite.Block memory b = sim.nextBlock();
        b.timestamp = uint64(Math.max(sim.blockAt(sim.tipHeight()).timestamp + 1, block.timestamp));
        sim.commit(sim.seal(b));
        return b.number;
    }
}

abstract contract WithMaruSim is LightClientDriverTest {
    function _newDriver(ICS26Router host, ICS26Router counterparty) internal override returns (ILightClientDriver) {
        return new MaruSimDriver(host, counterparty);
    }
}
