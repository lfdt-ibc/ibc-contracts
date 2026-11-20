// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { AccessManager } from "@openzeppelin-contracts/access/manager/AccessManager.sol";
import { IAccessManaged } from "@openzeppelin-contracts/access/manager/IAccessManaged.sol";
import { ERC1967Utils } from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Utils.sol";
import { Pausable } from "@openzeppelin-contracts/utils/Pausable.sol";
import { Math } from "@openzeppelin-contracts/utils/math/Math.sol";

import { IICS02ClientMsgs } from "../../contracts/msgs/IICS02ClientMsgs.sol";
import { IICS26RouterMsgs } from "../../contracts/msgs/IICS26RouterMsgs.sol";
import { ILightClientMsgs } from "../../contracts/msgs/ILightClientMsgs.sol";
import { ILineaLightClient } from "../../contracts/light-clients/linea/interfaces/ILineaLightClient.sol";
import { ILineaLightClientMsgs } from "../../contracts/light-clients/linea/msgs/ILineaLightClientMsgs.sol";
import { ILineaLightClientErrors } from "../../contracts/light-clients/linea/errors/ILineaLightClientErrors.sol";
import { IICS26ManagedLightClient } from "../../contracts/interfaces/IICS26ManagedLightClient.sol";
import { IICS26ManagedLightClientErrors } from "../../contracts/errors/IICS26ManagedLightClientErrors.sol";
import { IBCRolesLib } from "../../contracts/utils/IBCRolesLib.sol";
import { ICS24Host } from "../../contracts/utils/ICS24Host.sol";

import { TrieProof } from "../../contracts/light-clients/utils/TrieProof.sol";
import { BeaconBlock } from "../../contracts/light-clients/linea/utils/BeaconBlock.sol";
import { MaruSimSuite } from "./utils/MaruSimSuite.sol";

contract MaruSimSuiteTest is Test {
    uint64 internal constant TRUSTING_PERIOD = 1 days;
    uint64 internal constant MAX_CLOCK_DRIFT = 10;

    MaruSimSuite internal sim;
    ILineaLightClient internal client;
    address internal ics26Router = makeAddr("ics26Router");

    function setUp() public {
        sim = _setUp(4);
    }

    function _setUp(uint256 validatorCount) internal returns (MaruSimSuite s) {
        s = new MaruSimSuite();
        s.addValidators(validatorCount);
        s.produceBlocks(2);
        client = s.deployLightClient(
            TRUSTING_PERIOD, MAX_CLOCK_DRIFT, ILineaLightClientMsgs.TrustThreshold(2, 3), ics26Router
        );
    }

    function test_honestChain() public {
        uint256[3] memory counts = [uint256(1), 4, 16];
        for (uint256 c = 0; c < counts.length; ++c) {
            MaruSimSuite s = _setUp(counts[c]);
            s.produceBlocks(2);
            vm.startPrank(ics26Router);
            assertEq(uint8(client.updateClient(s.updateMsg(2, 3))), uint8(ILightClientMsgs.UpdateResult.Update));
            assertEq(uint8(client.updateClient(s.updateMsg(3, 4))), uint8(ILightClientMsgs.UpdateResult.Update));
            assertEq(uint8(client.updateClient(s.updateMsg(2, 4))), uint8(ILightClientMsgs.UpdateResult.NoOp));
            vm.stopPrank();
        }
    }

    /// @dev Filling in an older height after a newer one stores it without moving `latestHeight` back.
    function test_backfillKeepsLatestHeight() public {
        sim.produceBlocks(2);
        vm.startPrank(ics26Router);
        client.updateClient(sim.updateMsg(2, 4));
        assertEq(uint8(client.updateClient(sim.updateMsg(2, 3))), uint8(ILightClientMsgs.UpdateResult.Update));
        vm.stopPrank();

        ILineaLightClientMsgs.ClientState memory state =
            abi.decode(client.getClientState(), (ILineaLightClientMsgs.ClientState));
        assertEq(state.latestHeight.revisionHeight, 4);
        assertEq(client.getConsensusStateHash(3), keccak256(abi.encode(sim.consensusState(3))));
    }

    /// @dev A block committed after a QBFT round change is sealed over a header with a non-zero round.
    function test_roundChange() public {
        sim = _setUp(1);
        MaruSimSuite.Block memory b = sim.nextBlock();
        b.round = 3;
        bytes memory update = sim.updateMsg(2, sim.seal(b));
        vm.prank(ics26Router);
        assertEq(uint8(client.updateClient(update)), uint8(ILightClientMsgs.UpdateResult.Update));
    }

    function test_updateClient_revertMalformedBlock() public {
        bytes memory encoded = sim.updateMsg(2, sim.seal(sim.nextBlock()));
        ILineaLightClientMsgs.MsgUpdateClient memory update =
            abi.decode(encoded, (ILineaLightClientMsgs.MsgUpdateClient));

        bytes32 bodyRoot = update.header.bodyRoot;
        update.bodyRlp = bytes.concat(update.bodyRlp, hex"00");
        _expectUpdateRevert(
            update,
            abi.encodeWithSelector(
                ILineaLightClientErrors.BodyRootMismatch.selector, bodyRoot, keccak256(update.bodyRlp)
            )
        );

        update.bodyRlp = hex"c0";
        update.header.bodyRoot = keccak256(update.bodyRlp);
        _expectUpdateRevert(update, abi.encodeWithSelector(ILineaLightClientErrors.InvalidBodyFormat.selector, 0));

        update.bodyRlp = hex"c2c0c0";
        update.header.bodyRoot = keccak256(update.bodyRlp);
        _expectUpdateRevert(
            update, abi.encodeWithSelector(ILineaLightClientErrors.InvalidExecutionPayloadFormat.selector, 0)
        );
    }

    function test_updateClient_revertInvalidExecutionPayload() public {
        MaruSimSuite.Block memory b = sim.nextBlock();
        b.number = 0;
        _expectUpdateRevert(b, abi.encodeWithSelector(ILineaLightClientErrors.InvalidHeaderHeight.selector));

        b = sim.nextBlock();
        b.timestamp = 0;
        _expectUpdateRevert(b, abi.encodeWithSelector(ILineaLightClientErrors.InvalidHeaderTimestamp.selector));

        bytes32[2] memory stateRoots = [bytes32(0), TrieProof.EMPTY_ROOT_HASH];
        for (uint256 i = 0; i < stateRoots.length; ++i) {
            b = sim.nextBlock();
            b.stateRoot = stateRoots[i];
            _expectUpdateRevert(
                b, abi.encodeWithSelector(ILineaLightClientErrors.InvalidStateRoot.selector, stateRoots[i])
            );
        }

        b = sim.nextBlock();
        b.number = 2;
        _expectUpdateRevert(b, abi.encodeWithSelector(ILineaLightClientErrors.InvalidTrustedHeight.selector, 2, 2));
    }

    /// @dev The validator set must be the one the header state root commits to, so a relayer cannot shrink it to
    /// lower the quorum or swap in validators of its own.
    function test_updateClient_revertValidatorSetNotInStateRoot() public {
        bytes memory encoded = sim.updateMsg(2, sim.seal(sim.nextBlock()));
        ILineaLightClientMsgs.MsgUpdateClient memory update =
            abi.decode(encoded, (ILineaLightClientMsgs.MsgUpdateClient));

        address[] memory subset = new address[](1);
        subset[0] = update.validators[0];
        update.validators = subset;
        _expectUpdateRevert(
            update,
            abi.encodeWithSelector(
                ILineaLightClientErrors.BeaconStateRootMismatch.selector,
                update.header.stateRoot,
                BeaconBlock.computeStateRoot(update.header, subset)
            )
        );
    }

    function test_accessControl() public {
        (address pauser, address unpauser) = _mockRouterAuthority();
        assertEq(IICS26ManagedLightClient(address(client)).ICS26_ROUTER(), ics26Router);

        sim.produceBlock();
        bytes memory update = sim.updateMsg(2, 3);
        address relayer = makeAddr("relayer");
        bytes memory unauthorized =
            abi.encodeWithSelector(IICS26ManagedLightClientErrors.LightClientUnauthorizedCaller.selector, relayer);
        ILightClientMsgs.MsgVerifyMembership memory membership;
        ILightClientMsgs.MsgVerifyNonMembership memory nonMembership;

        vm.startPrank(relayer);
        vm.expectRevert(unauthorized);
        client.updateClient(update);
        vm.expectRevert(unauthorized);
        client.verifyMembership(membership);
        vm.expectRevert(unauthorized);
        client.verifyNonMembership(nonMembership);
        vm.expectRevert(unauthorized);
        client.misbehaviour("");
        vm.stopPrank();

        vm.prank(pauser);
        IICS26ManagedLightClient(address(client)).pause();
        vm.startPrank(ics26Router);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        client.updateClient(update);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        client.verifyMembership(membership);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        client.verifyNonMembership(nonMembership);
        vm.stopPrank();

        vm.prank(unpauser);
        IICS26ManagedLightClient(address(client)).unpause();
        vm.prank(ics26Router);
        assertEq(uint8(client.updateClient(update)), uint8(ILightClientMsgs.UpdateResult.Update));
    }

    /// @dev Mocks the router's authority with an `AccessManager` that grants the pause roles.
    function _mockRouterAuthority() internal returns (address pauser, address unpauser) {
        AccessManager accessManager = new AccessManager(address(this));
        pauser = makeAddr("pauser");
        unpauser = makeAddr("unpauser");
        accessManager.grantRole(IBCRolesLib.PAUSER_ROLE, pauser, 0);
        accessManager.grantRole(IBCRolesLib.UNPAUSER_ROLE, unpauser, 0);
        vm.mockCall(ics26Router, abi.encodeCall(IAccessManaged.authority, ()), abi.encode(address(accessManager)));
    }

    function _expectUpdateRevert(
        ILineaLightClientMsgs.MsgUpdateClient memory update,
        bytes memory revertData
    )
        internal
    {
        vm.expectRevert(revertData);
        vm.prank(ics26Router);
        client.updateClient(abi.encode(update));
    }

    function _expectUpdateRevert(MaruSimSuite.Block memory b, bytes memory revertData) internal {
        bytes memory update = sim.updateMsg(2, sim.seal(b));
        vm.expectRevert(revertData);
        vm.prank(ics26Router);
        client.updateClient(update);
    }

    function test_doubleSign() public {
        MaruSimSuite.Block memory a = sim.nextBlock();
        MaruSimSuite.Block memory b = sim.nextBlock();
        b.stateRoot = keccak256("equivocation");
        a = sim.seal(a);
        b = sim.seal(b);
        sim.commit(a);

        bytes memory honest = sim.updateMsg(2, a);
        vm.startPrank(ics26Router);
        client.updateClient(honest);
        bytes memory conflicting = sim.updateMsg(2, b);
        assertEq(uint8(client.updateClient(conflicting)), uint8(ILightClientMsgs.UpdateResult.Misbehaviour));

        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.FrozenClientState.selector));
        client.updateClient(honest);
        vm.stopPrank();
    }

    /// @dev A header not strictly newer than its trusted consensus state freezes the client instead of updating it.
    function test_timeNonMonotonicityUpdate() public {
        MaruSimSuite.Block memory h = sim.nextBlock();
        h.timestamp = sim.blockAt(2).timestamp;
        sim.commit(sim.seal(h));
        bytes memory update = sim.updateMsg(2, 3);

        vm.expectEmit(address(client));
        emit ILineaLightClient.TimeNonMonotonicity(3, 2, h.timestamp, h.timestamp);
        vm.startPrank(ics26Router);
        assertEq(uint8(client.updateClient(update)), uint8(ILightClientMsgs.UpdateResult.Misbehaviour));

        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.ConsensusStateNotFound.selector, 3));
        client.getConsensusStateHash(3);
        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.FrozenClientState.selector));
        client.updateClient(update);
        vm.stopPrank();
    }

    /// @dev Blocks are at least one second apart, so a header two blocks after its trusted state that is only one
    /// second newer freezes the client, while one that is two seconds newer updates it.
    function test_subSecondBlockTime() public {
        sim.produceBlock();
        uint64 trustedTimestamp = sim.blockAt(2).timestamp;
        MaruSimSuite.Block memory h = sim.nextBlock();
        h.timestamp = trustedTimestamp + 2;
        bytes memory oneSecondPerBlock = sim.updateMsg(2, sim.seal(h));
        h.timestamp = trustedTimestamp + 1;
        bytes memory subSecondBlocks = sim.updateMsg(2, sim.seal(h));

        vm.startPrank(ics26Router);
        uint256 snapshot = vm.snapshotState();
        assertEq(uint8(client.updateClient(oneSecondPerBlock)), uint8(ILightClientMsgs.UpdateResult.Update));
        vm.revertToState(snapshot);

        vm.expectEmit(address(client));
        emit ILineaLightClient.SubSecondBlockTime(4, 2, trustedTimestamp + 1, trustedTimestamp);
        assertEq(uint8(client.updateClient(subSecondBlocks)), uint8(ILightClientMsgs.UpdateResult.Misbehaviour));
        assertTrue(_isFrozen(client));
        vm.stopPrank();
    }

    /// @dev Each update is only checked against its own trusted height, so a forged height-3 header timestamped
    /// after the honest height-4 header is accepted. Submitting both stored states as misbehaviour freezes the client,
    /// even after both are past their trusting period.
    function test_conflictingConsensusStatesTimeNonMonotonicity() public {
        MaruSimSuite.Block memory forged = sim.nextBlock();
        sim.produceBlocks(2);
        forged.timestamp = sim.blockAt(4).timestamp + 1;
        forged = sim.seal(forged);

        bytes memory honestUpdate = sim.updateMsg(2, 4);
        bytes memory forgedUpdate = sim.updateMsg(2, forged);
        vm.startPrank(ics26Router);
        assertEq(uint8(client.updateClient(honestUpdate)), uint8(ILightClientMsgs.UpdateResult.Update));
        assertEq(uint8(client.updateClient(forgedUpdate)), uint8(ILightClientMsgs.UpdateResult.Update));

        ILineaLightClientMsgs.ConsensusState memory honestState = sim.consensusState(4);
        bytes memory misbehaviour = abi.encode(
            ILineaLightClientMsgs.MsgSubmitMisbehaviour(
                ILineaLightClientMsgs.MisbehaviourType.ConflictingConsensusStates,
                abi.encode(
                    ILineaLightClientMsgs.MsgConflictingConsensusStatesMisbehaviour({
                        height1: IICS02ClientMsgs.Height(0, 3),
                        height2: IICS02ClientMsgs.Height(0, 4),
                        consensusStatePreimage1: _consensusState(forged),
                        consensusStatePreimage2: honestState
                    })
                )
            )
        );

        vm.warp(honestState.timestamp + TRUSTING_PERIOD);
        vm.expectEmit(address(client));
        emit ILineaLightClient.TimeNonMonotonicity(4, 3, honestState.timestamp, forged.timestamp);
        client.misbehaviour(misbehaviour);

        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.FrozenClientState.selector));
        client.misbehaviour(misbehaviour);
        vm.stopPrank();
    }

    /// @dev Two validly signed headers at the same height prove a double sign, whether or not either is stored.
    function test_conflictingHeadersDoubleSign() public {
        MaruSimSuite.Block memory a = sim.seal(sim.nextBlock());
        MaruSimSuite.Block memory b = sim.nextBlock();
        b.stateRoot = keccak256("equivocation");
        b = sim.seal(b);
        bytes memory misbehaviour = _conflictingHeadersMisbehaviour(sim.updateMsg(2, a), sim.updateMsg(2, b));

        uint256 snapshot = vm.snapshotState();
        vm.startPrank(ics26Router);
        for (uint256 stored = 0; stored < 2; ++stored) {
            vm.revertToState(snapshot);
            if (stored == 1) {
                bytes memory update = sim.updateMsg(2, a);
                client.updateClient(update);
            }

            vm.expectEmit(address(client));
            emit ILineaLightClient.DoubleSign(
                3, keccak256(abi.encode(_consensusState(a))), keccak256(abi.encode(_consensusState(b)))
            );
            client.misbehaviour(misbehaviour);
            assertTrue(_isFrozen(client));
        }
        vm.stopPrank();
    }

    /// @dev A header conflicting with the consensus state stored at its height is evidence on its own, as in
    /// `updateClient`, even when paired with a valid later header or with itself.
    function test_conflictingHeadersDoubleSignAgainstStoredState() public {
        MaruSimSuite.Block memory a = sim.nextBlock();
        MaruSimSuite.Block memory b = sim.nextBlock();
        b.stateRoot = keccak256("equivocation");
        a = sim.seal(a);
        b = sim.seal(b);
        sim.commit(a);
        sim.produceBlocks(1);
        bytes memory storedUpdate = sim.updateMsg(2, a);
        bytes memory conflictingUpdate = sim.updateMsg(2, b);
        bytes memory honestUpdate = sim.updateMsg(2, 4);
        vm.startPrank(ics26Router);
        client.updateClient(storedUpdate);

        uint256 snapshot = vm.snapshotState();
        bytes[3] memory misbehaviours = [
            _conflictingHeadersMisbehaviour(conflictingUpdate, honestUpdate),
            _conflictingHeadersMisbehaviour(honestUpdate, conflictingUpdate),
            _conflictingHeadersMisbehaviour(conflictingUpdate, conflictingUpdate)
        ];
        for (uint256 i = 0; i < misbehaviours.length; ++i) {
            vm.revertToState(snapshot);
            vm.expectEmit(address(client));
            emit ILineaLightClient.DoubleSign(
                3, keccak256(abi.encode(_consensusState(a))), keccak256(abi.encode(_consensusState(b)))
            );
            client.misbehaviour(misbehaviours[i]);
            assertTrue(_isFrozen(client));
        }
        vm.stopPrank();
    }

    /// @dev Two validly signed headers whose timestamps do not increase with height freeze the client in either
    /// order, even though neither is stored and the forged header is ahead of the clock.
    function test_conflictingHeadersTimeNonMonotonicity() public {
        MaruSimSuite.Block memory forged = sim.nextBlock();
        sim.produceBlocks(2);
        forged.timestamp = uint64(vm.getBlockTimestamp()) + MAX_CLOCK_DRIFT + 1;
        forged = sim.seal(forged);
        bytes memory forgedUpdate = sim.updateMsg(2, forged);
        bytes memory honestUpdate = sim.updateMsg(2, 4);
        uint64 honestTimestamp = sim.blockAt(4).timestamp;

        uint256 snapshot = vm.snapshotState();
        bytes[2] memory misbehaviours = [
            _conflictingHeadersMisbehaviour(forgedUpdate, honestUpdate),
            _conflictingHeadersMisbehaviour(honestUpdate, forgedUpdate)
        ];
        for (uint256 i = 0; i < misbehaviours.length; ++i) {
            vm.revertToState(snapshot);
            vm.expectEmit(address(client));
            emit ILineaLightClient.TimeNonMonotonicity(4, 3, honestTimestamp, forged.timestamp);
            vm.prank(ics26Router);
            client.misbehaviour(misbehaviours[i]);
            assertTrue(_isFrozen(client));
        }
    }

    /// @dev A header not newer than its own trusted consensus state is evidence on its own, as in `updateClient`,
    /// even when paired with a valid later header or with itself.
    function test_conflictingHeadersTimeNonMonotonicityAgainstTrustedState() public {
        uint64 trustedTimestamp = sim.blockAt(2).timestamp;
        MaruSimSuite.Block memory forged = sim.nextBlock();
        forged.timestamp = trustedTimestamp;
        forged = sim.seal(forged);
        sim.produceBlocks(2);
        bytes memory forgedUpdate = sim.updateMsg(2, forged);
        bytes memory honestUpdate = sim.updateMsg(2, 4);

        uint256 snapshot = vm.snapshotState();
        bytes[3] memory misbehaviours = [
            _conflictingHeadersMisbehaviour(forgedUpdate, honestUpdate),
            _conflictingHeadersMisbehaviour(honestUpdate, forgedUpdate),
            _conflictingHeadersMisbehaviour(forgedUpdate, forgedUpdate)
        ];
        for (uint256 i = 0; i < misbehaviours.length; ++i) {
            vm.revertToState(snapshot);
            vm.expectEmit(address(client));
            emit ILineaLightClient.TimeNonMonotonicity(3, 2, trustedTimestamp, trustedTimestamp);
            vm.prank(ics26Router);
            client.misbehaviour(misbehaviours[i]);
            assertTrue(_isFrozen(client));
        }
    }

    function test_conflictingHeadersMisbehaviourRejections() public {
        address[] memory two = new address[](2);
        (two[0], two[1]) = (sim.validators()[0], sim.validators()[1]);
        bytes memory underSigned = sim.updateMsg(2, sim.seal(sim.nextBlock(), two));
        sim.produceBlocks(2);
        bytes memory update3 = sim.updateMsg(2, 3);
        bytes memory update4 = sim.updateMsg(2, 4);

        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.NoMisbehaviourDetected.selector));
        vm.startPrank(ics26Router);
        client.misbehaviour(_conflictingHeadersMisbehaviour(update3, update3));

        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.NoMisbehaviourDetected.selector));
        client.misbehaviour(_conflictingHeadersMisbehaviour(update4, update3));

        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.InsufficientValidatorQuorum.selector, 2, 3));
        client.misbehaviour(_conflictingHeadersMisbehaviour(update3, underSigned));

        uint64 trustedTimestamp = sim.blockAt(2).timestamp;
        vm.warp(trustedTimestamp + TRUSTING_PERIOD);
        vm.expectRevert(
            abi.encodeWithSelector(
                ILineaLightClientErrors.ConsensusStateExpired.selector,
                trustedTimestamp,
                vm.getBlockTimestamp(),
                TRUSTING_PERIOD
            )
        );
        client.misbehaviour(_conflictingHeadersMisbehaviour(update3, update4));
        vm.stopPrank();

        assertFalse(_isFrozen(client));
    }

    /// @dev A paused client rejects updates but can still be frozen by misbehaviour submitted through the router.
    function test_misbehaviourWhilePaused() public {
        (address pauser,) = _mockRouterAuthority();
        MaruSimSuite.Block memory a = sim.seal(sim.nextBlock());
        MaruSimSuite.Block memory b = sim.nextBlock();
        b.stateRoot = keccak256("equivocation");
        b = sim.seal(b);
        bytes memory update = sim.updateMsg(2, a);
        bytes memory misbehaviour = _conflictingHeadersMisbehaviour(update, sim.updateMsg(2, b));

        vm.prank(pauser);
        IICS26ManagedLightClient(address(client)).pause();

        vm.startPrank(ics26Router);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        client.updateClient(update);

        client.misbehaviour(misbehaviour);
        vm.stopPrank();
        assertTrue(_isFrozen(client));
    }

    function test_timestampFromFuture() public {
        MaruSimSuite.Block memory h = sim.nextBlock();
        h.timestamp = uint64(vm.getBlockTimestamp()) + MAX_CLOCK_DRIFT + 1;
        bytes memory update = sim.updateMsg(2, sim.seal(h));
        vm.expectRevert(
            abi.encodeWithSelector(
                ILineaLightClientErrors.HeaderFromFuture.selector, vm.getBlockTimestamp(), h.timestamp, MAX_CLOCK_DRIFT
            )
        );
        vm.prank(ics26Router);
        client.updateClient(update);
    }

    function test_lowQuorumAndUnknownSigner() public {
        address[] memory two = new address[](2);
        (two[0], two[1]) = (sim.validators()[0], sim.validators()[1]);
        bytes memory update = sim.updateMsg(2, sim.seal(sim.nextBlock(), two));
        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.InsufficientValidatorQuorum.selector, 2, 3));
        vm.startPrank(ics26Router);
        client.updateClient(update);

        uint256[] memory keys = new uint256[](4);
        for (uint256 i = 0; i < 3; ++i) {
            keys[i] = sim.validatorKey(sim.validators()[i]);
        }
        keys[3] = 0xdead;
        update = sim.updateMsg(2, sim.sealWithKeys(sim.nextBlock(), keys));
        vm.expectRevert(
            abi.encodeWithSelector(ILineaLightClientErrors.UnknownCommitSealSigner.selector, vm.addr(0xdead))
        );
        client.updateClient(update);
        vm.stopPrank();
    }

    function test_unsortedOrDuplicateSigners() public {
        MaruSimSuite.Block memory h = sim.seal(sim.nextBlock());
        (h.commitSeals[0], h.commitSeals[1]) = (h.commitSeals[1], h.commitSeals[0]);
        bytes memory update = sim.updateMsg(2, h);
        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.UnsortedCommitSealSigners.selector, 0));
        vm.startPrank(ics26Router);
        client.updateClient(update);

        uint256[] memory keys = new uint256[](4);
        for (uint256 i = 0; i < 3; ++i) {
            keys[i] = sim.validatorKey(sim.validators()[i]);
        }
        keys[3] = keys[2];
        update = sim.updateMsg(2, sim.sealWithKeys(sim.nextBlock(), keys));
        vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.UnsortedCommitSealSigners.selector, 2));
        client.updateClient(update);
        vm.stopPrank();
    }

    /// @dev A Maru fork can replace several validators in one block. Such a header is not misbehaviour and updates
    /// the client as long as enough trusted validators sealed it.
    function test_validatorSetChangeInOneBlock() public {
        address[] memory trusted = sim.validators();
        for (uint256 i = 0; i < 2; ++i) {
            sim.removeValidator(trusted[i]);
            sim.addValidator();
        }
        sim.produceBlock();
        bytes memory update = sim.updateMsg(2, 3);
        vm.startPrank(ics26Router);
        assertEq(uint8(client.updateClient(update)), uint8(ILightClientMsgs.UpdateResult.Update));

        trusted = sim.validators();
        for (uint256 i = 0; i < trusted.length; ++i) {
            sim.removeValidator(trusted[i]);
            sim.addValidator();
        }
        sim.produceBlock();
        update = sim.updateMsg(3, 4);
        vm.expectRevert(
            abi.encodeWithSelector(ILineaLightClientErrors.InsufficientTrustedValidatorOverlap.selector, 0, 2)
        );
        client.updateClient(update);
        vm.stopPrank();
        assertFalse(_isFrozen(client));
    }

    /// @dev Replacing Linea's single validator outright leaves no trusted signer, so the client cannot follow it.
    /// Handing over through a fork in which both validators seal keeps the client updatable.
    function test_singleValidatorHandover() public {
        sim = _setUp(1);
        address old = sim.validators()[0];
        sim.addValidator();
        sim.produceBlock();
        sim.removeValidator(old);
        sim.produceBlock();

        bytes memory direct = sim.updateMsg(2, 4);
        bytes memory overlap = sim.updateMsg(2, 3);
        bytes memory handover = sim.updateMsg(3, 4);
        vm.startPrank(ics26Router);
        vm.expectRevert(
            abi.encodeWithSelector(ILineaLightClientErrors.InsufficientTrustedValidatorOverlap.selector, 0, 1)
        );
        client.updateClient(direct);

        assertEq(uint8(client.updateClient(overlap)), uint8(ILightClientMsgs.UpdateResult.Update));
        assertEq(uint8(client.updateClient(handover)), uint8(ILightClientMsgs.UpdateResult.Update));
        vm.stopPrank();
    }

    /// @dev With 5 trusted validators a 2/3 trust level requires 3 trusted signers (capped from 4) and 1/3 requires 2.
    function test_trustLevel() public {
        sim = _setUp(5);
        ILineaLightClient lenient = sim.deployLightClient(
            TRUSTING_PERIOD, MAX_CLOCK_DRIFT, ILineaLightClientMsgs.TrustThreshold(1, 3), ics26Router
        );

        // Rotating 3 of the 5 validators leaves 2 trusted signers.
        _rotateValidators(3, 3);
        bytes memory update = sim.updateMsg(2, 8);
        vm.startPrank(ics26Router);
        vm.expectRevert(
            abi.encodeWithSelector(ILineaLightClientErrors.InsufficientTrustedValidatorOverlap.selector, 2, 3)
        );
        client.updateClient(update);
        assertEq(uint8(lenient.updateClient(update)), uint8(ILightClientMsgs.UpdateResult.Update));
        vm.stopPrank();
    }

    function test_packetProofs() public {
        IICS26RouterMsgs.Packet memory packet;
        packet.sequence = 7;
        packet.sourceClient = "client-0";
        packet.destClient = "client-1";
        packet.payloads = new IICS26RouterMsgs.Payload[](1);
        packet.payloads[0] = IICS26RouterMsgs.Payload("transfer", "transfer", "1", "json", "hello");
        bytes memory commitmentPath = ICS24Host.packetCommitmentPathCalldata(packet.sourceClient, packet.sequence);
        bytes memory receiptPath = ICS24Host.packetReceiptCommitmentPathCalldata(packet.destClient, packet.sequence);

        sim.commitPacket(packet);
        sim.produceBlock();
        vm.startPrank(ics26Router);
        client.updateClient(sim.updateMsg(2, 3));

        assertEq(client.verifyMembership(sim.membershipMsg(3, commitmentPath)), sim.blockAt(3).timestamp);
        assertEq(client.verifyNonMembership(sim.nonMembershipMsg(3, receiptPath)), sim.blockAt(3).timestamp);
        client.verifyNonMembership(sim.nonMembershipMsg(2, commitmentPath));
        vm.stopPrank();

        sim.setCommitment(commitmentPath, bytes32(0));
        sim.produceBlock();
        vm.startPrank(ics26Router);
        client.updateClient(sim.updateMsg(3, 4));
        client.verifyNonMembership(sim.nonMembershipMsg(4, commitmentPath));
        client.verifyMembership(sim.membershipMsg(3, commitmentPath));
        vm.stopPrank();
    }

    /// @dev An empty router storage trie would let any non-membership proof pass without proof nodes.
    function test_verifyNonMembership_revertEmptyStorageRoot() public {
        bytes memory receiptPath = ICS24Host.packetReceiptCommitmentPathCalldata("client-1", 1);
        sim.setStorage(sim.IBC_ROUTER(), ERC1967Utils.IMPLEMENTATION_SLOT, bytes32(0));
        sim.produceBlock();
        bytes memory update = sim.updateMsg(2, 3);
        ILightClientMsgs.MsgVerifyNonMembership memory nonMembership = sim.nonMembershipMsg(3, receiptPath);

        vm.startPrank(ics26Router);
        client.updateClient(update);
        vm.expectRevert(
            abi.encodeWithSelector(ILineaLightClientErrors.InvalidStorageRoot.selector, TrieProof.EMPTY_ROOT_HASH)
        );
        client.verifyNonMembership(nonMembership);
        vm.stopPrank();
    }

    function _conflictingHeadersMisbehaviour(
        bytes memory update1,
        bytes memory update2
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            ILineaLightClientMsgs.MsgSubmitMisbehaviour(
                ILineaLightClientMsgs.MisbehaviourType.ConflictingHeaders,
                abi.encode(
                    ILineaLightClientMsgs.MsgConflictingHeadersMisbehaviour(
                        abi.decode(update1, (ILineaLightClientMsgs.MsgUpdateClient)),
                        abi.decode(update2, (ILineaLightClientMsgs.MsgUpdateClient))
                    )
                )
            )
        );
    }

    function _consensusState(MaruSimSuite.Block memory h)
        internal
        pure
        returns (ILineaLightClientMsgs.ConsensusState memory)
    {
        return ILineaLightClientMsgs.ConsensusState(h.timestamp, h.stateRoot, h.validators);
    }

    function _isFrozen(ILineaLightClient lc) internal view returns (bool) {
        return abi.decode(lc.getClientState(), (ILineaLightClientMsgs.ClientState)).isFrozen;
    }

    /// @dev Rotates a random part of the trusted set and signs with a random subset of the new set: the update must
    /// succeed iff the signers reach the trust level of the trusted set and a BFT quorum of the new set.
    function testFuzz_updateClient_signerSubset(
        uint256 trustedCount,
        uint256 removed,
        uint256 added,
        uint256 signerMask
    )
        public
    {
        trustedCount = bound(trustedCount, 1, 7);
        removed = bound(removed, 0, trustedCount - 1);
        added = bound(added, 0, 3);
        sim = _setUp(trustedCount);
        _rotateValidators(removed, added);

        address[] memory trusted = sim.consensusState(2).validators;
        address[] memory current = sim.validators();
        uint256 signerCount = 0;
        for (uint256 i = 0; i < current.length; ++i) {
            signerCount += (signerMask >> i) & 1;
        }
        address[] memory signers = new address[](signerCount);
        uint256 overlap = 0;
        uint256 k = 0;
        for (uint256 i = 0; i < current.length; ++i) {
            if ((signerMask >> i) & 1 == 1) {
                signers[k] = current[i];
                ++k;
                if (_contains(trusted, current[i])) {
                    ++overlap;
                }
            }
        }
        bytes memory update = sim.updateMsg(2, sim.seal(sim.nextBlock(), signers));

        uint256 requiredOverlap =
            Math.max(Math.min(Math.ceilDiv(2 * trusted.length, 3), 2 * trusted.length / 3), trusted.length / 3 + 1);
        uint256 requiredQuorum = Math.ceilDiv(2 * current.length, 3);
        vm.startPrank(ics26Router);
        if (signerCount == 0) {
            vm.expectRevert(abi.encodeWithSelector(ILineaLightClientErrors.EmptyCommitSeals.selector));
        } else if (overlap < requiredOverlap) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILineaLightClientErrors.InsufficientTrustedValidatorOverlap.selector, overlap, requiredOverlap
                )
            );
        } else if (signerCount < requiredQuorum) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILineaLightClientErrors.InsufficientValidatorQuorum.selector, signerCount, requiredQuorum
                )
            );
        } else {
            assertEq(uint8(client.updateClient(update)), uint8(ILightClientMsgs.UpdateResult.Update));
            return;
        }
        client.updateClient(update);
    }

    /// @dev Removes the lowest `removed` validators, then adds `added` new ones, producing a block after each change.
    function _rotateValidators(uint256 removed, uint256 added) internal {
        for (uint256 i = 0; i < removed; ++i) {
            sim.removeValidator(sim.validators()[0]);
            sim.produceBlock();
        }
        for (uint256 i = 0; i < added; ++i) {
            sim.addValidator();
            sim.produceBlock();
        }
    }

    function _contains(address[] memory set, address value) internal pure returns (bool) {
        for (uint256 i = 0; i < set.length; ++i) {
            if (set[i] == value) {
                return true;
            }
        }
        return false;
    }
}
