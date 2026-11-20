// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import { Test } from "forge-std/Test.sol";

import { AccessManager } from "@openzeppelin-contracts/access/manager/AccessManager.sol";
import { ERC1967Proxy } from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { ICS26Router } from "@ibc-contracts/ICS26Router.sol";
import { IICS02ClientMsgs } from "@ibc-contracts/msgs/IICS02ClientMsgs.sol";
import { IICS26RouterMsgs } from "@ibc-contracts/msgs/IICS26RouterMsgs.sol";
import { IIBCApp } from "@ibc-contracts/interfaces/IIBCApp.sol";
import { IIBCAppCallbacks } from "@ibc-contracts/msgs/IIBCAppCallbacks.sol";
import { IBCRolesLib } from "@ibc-contracts/utils/IBCRolesLib.sol";
import { ICS24Host } from "@ibc-contracts/utils/ICS24Host.sol";

import { PrividiumTypes } from "@prividium/PrividiumTypes.sol";
import { PrividiumZKLightClient } from "@prividium/PrividiumZKLightClient.sol";
import { PublicValuesV1 } from "@prividium/PublicValuesV1.sol";
import { ISP1Verifier } from "@prividium/interfaces/ISP1Verifier.sol";

contract RouterE2EMockVerifier is ISP1Verifier {
    bool public reject;

    function setReject(bool value) external {
        reject = value;
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata) external view override {
        require(!reject, "rejected proof");
    }
}

contract RouterE2ETestApp is IIBCApp {
    ICS26Router private immutable router;

    uint256 public receiveCount;
    uint256 public timeoutCount;

    error UnauthorizedRouter(address actual);

    constructor(ICS26Router router_) {
        router = router_;
    }

    function sendPacket(IICS26RouterMsgs.MsgSendPacket calldata message) external returns (uint64) {
        return router.sendPacket(message);
    }

    function onRecvPacket(IIBCAppCallbacks.OnRecvPacketCallback calldata)
        external
        returns (bytes memory)
    {
        _onlyRouter();
        ++receiveCount;
        return bytes("prividium-e2e-ack");
    }

    function onAcknowledgementPacket(IIBCAppCallbacks.OnAcknowledgementPacketCallback calldata)
        external
        view
    {
        _onlyRouter();
    }

    function onTimeoutPacket(IIBCAppCallbacks.OnTimeoutPacketCallback calldata) external {
        _onlyRouter();
        ++timeoutCount;
    }

    function _onlyRouter() private view {
        if (msg.sender != address(router)) revert UnauthorizedRouter(msg.sender);
    }
}

contract PrividiumRouterE2ETest is Test {
    bytes32 private constant PROFILE = keccak256("synthetic-local");
    bytes32 private constant TRUST_VKEY = bytes32(uint256(1));
    bytes32 private constant SETTLEMENT_VKEY = bytes32(uint256(2));
    bytes32 private constant MEMBERSHIP_VKEY = bytes32(uint256(3));
    bytes32 private constant NON_MEMBERSHIP_VKEY = bytes32(uint256(4));
    address private constant SOURCE_IBC_STORE = address(0x4444);
    uint64 private constant BATCH_TIMESTAMP = 1_700_000_000;
    string private constant COUNTERPARTY_CLIENT_ID = "prividium-counterparty-0";
    string private constant APP_PORT = "prividium-e2e";

    ICS26Router private router;
    PrividiumZKLightClient private client;
    RouterE2EMockVerifier private verifier;
    RouterE2ETestApp private app;
    PrividiumTypes.ConsensusTrustState private initialTrust;
    string private clientId;

    function setUp() public {
        vm.warp(BATCH_TIMESTAMP - 1_000);

        AccessManager accessManager = new AccessManager(address(this));
        ICS26Router routerLogic = new ICS26Router();
        ERC1967Proxy routerProxy = new ERC1967Proxy(
            address(routerLogic), abi.encodeCall(ICS26Router.initialize, (address(accessManager)))
        );
        router = ICS26Router(address(routerProxy));

        accessManager.setTargetFunctionRole(
            address(router), IBCRolesLib.ics26RelayerSelectors(), IBCRolesLib.RELAYER_ROLE
        );
        accessManager.setTargetFunctionRole(
            address(router),
            IBCRolesLib.ics26IdCustomizerSelectors(),
            IBCRolesLib.ID_CUSTOMIZER_ROLE
        );
        accessManager.grantRole(IBCRolesLib.RELAYER_ROLE, address(this), 0);
        accessManager.grantRole(IBCRolesLib.ID_CUSTOMIZER_ROLE, address(this), 0);

        verifier = new RouterE2EMockVerifier();
        initialTrust = PrividiumTypes.ConsensusTrustState({
            finalizedBeaconSlot: 1,
            finalizedBeaconHeaderRoot: bytes32(uint256(11)),
            currentSyncCommitteeRoot: bytes32(uint256(12)),
            nextSyncCommitteeRoot: bytes32(uint256(13)),
            nextSyncCommitteeKnown: true
        });
        client = new PrividiumZKLightClient(
            PROFILE,
            initialTrust,
            SOURCE_IBC_STORE,
            1,
            TRUST_VKEY,
            SETTLEMENT_VKEY,
            MEMBERSHIP_VKEY,
            NON_MEMBERSHIP_VKEY,
            address(verifier),
            address(router)
        );

        bytes[] memory prefix = new bytes[](1);
        prefix[0] = bytes("");
        clientId = router.addClient(
            IICS02ClientMsgs.CounterpartyInfo({
                clientId: COUNTERPARTY_CLIENT_ID, merklePrefix: prefix
            }),
            address(client)
        );

        app = new RouterE2ETestApp(router);
        router.addIBCApp(APP_PORT, address(app));
    }

    function testRouterRegistersAndUpdatesPrividiumClient() public {
        assertEq(address(router.getClient(clientId)), address(client));
        assertEq(router.getCounterparty(clientId).clientId, COUNTERPARTY_CLIENT_ID);

        router.updateClient(clientId, _settlementMessage(7, bytes32(uint256(0xCAFE))));

        (bytes32 root, uint64 timestamp, bool exists) = client.getAcceptedBatch(7);
        assertTrue(exists);
        assertEq(root, bytes32(uint256(0xCAFE)));
        assertEq(timestamp, BATCH_TIMESTAMP);
        assertEq(client.getAcceptedL2Block(7), 17);
    }

    function testRecvPacketRequiresSettlementThenExecutesMembershipAndCallback() public {
        bytes32 nativeRoot = bytes32(uint256(0xCAFE));
        IICS26RouterMsgs.Packet memory packet = _incomingPacket(1);
        bytes memory membershipProof = _membershipProof(7, 17, nativeRoot, packet);

        IICS26RouterMsgs.MsgRecvPacket memory receiveMessage = IICS26RouterMsgs.MsgRecvPacket({
            packet: packet,
            proofCommitment: membershipProof,
            proofHeight: IICS02ClientMsgs.Height({ revisionNumber: 0, revisionHeight: 17 })
        });

        vm.expectRevert(abi.encodeWithSelector(PrividiumZKLightClient.UnknownBatch.selector, 7));
        router.recvPacket(receiveMessage);

        router.updateClient(clientId, _settlementMessage(7, nativeRoot));
        router.recvPacket(receiveMessage);

        assertEq(app.receiveCount(), 1);
        bytes32 receiptKey = keccak256(
            ICS24Host.packetReceiptCommitmentPathCalldata(packet.destClient, packet.sequence)
        );
        assertTrue(router.getCommitment(receiptKey) != bytes32(0));

        router.recvPacket(receiveMessage);
        assertEq(app.receiveCount(), 1, "duplicate receive called the application twice");
    }

    function testTimeoutPacketExecutesNonMembershipAndDeletesCommitment() public {
        uint64 timeoutTimestamp = BATCH_TIMESTAMP - 100;
        IICS26RouterMsgs.Payload memory payload = _payload();
        uint64 sequence = app.sendPacket(
            IICS26RouterMsgs.MsgSendPacket({
                sourceClient: clientId, timeoutTimestamp: timeoutTimestamp, payload: payload
            })
        );
        IICS26RouterMsgs.Payload[] memory payloads = new IICS26RouterMsgs.Payload[](1);
        payloads[0] = payload;
        IICS26RouterMsgs.Packet memory packet = IICS26RouterMsgs.Packet({
            sequence: sequence,
            sourceClient: clientId,
            destClient: COUNTERPARTY_CLIENT_ID,
            timeoutTimestamp: timeoutTimestamp,
            payloads: payloads
        });

        bytes32 commitmentKey = keccak256(
            ICS24Host.packetCommitmentPathCalldata(packet.sourceClient, packet.sequence)
        );
        assertTrue(router.getCommitment(commitmentKey) != bytes32(0));

        bytes32 nativeRoot = bytes32(uint256(0xBEEF));
        router.updateClient(clientId, _settlementMessage(9, nativeRoot));
        bytes memory timeoutProof = _nonMembershipProof(9, 19, nativeRoot, packet);
        vm.warp(timeoutTimestamp);

        router.timeoutPacket(
            IICS26RouterMsgs.MsgTimeoutPacket({
                packet: packet,
                proofTimeout: timeoutProof,
                proofHeight: IICS02ClientMsgs.Height({ revisionNumber: 0, revisionHeight: 19 })
            })
        );

        assertEq(app.timeoutCount(), 1);
        assertEq(router.getCommitment(commitmentKey), bytes32(0));
    }

    function testRejectedSettlementProofDoesNotWriteThroughRouter() public {
        verifier.setReject(true);
        vm.expectRevert("rejected proof");
        router.updateClient(clientId, _settlementMessage(12, bytes32(uint256(0xDEAD))));

        (,, bool exists) = client.getAcceptedBatch(12);
        assertFalse(exists);
    }

    function _incomingPacket(uint64 sequence)
        private
        view
        returns (IICS26RouterMsgs.Packet memory packet)
    {
        IICS26RouterMsgs.Payload[] memory payloads = new IICS26RouterMsgs.Payload[](1);
        payloads[0] = _payload();
        packet = IICS26RouterMsgs.Packet({
            sequence: sequence,
            sourceClient: COUNTERPARTY_CLIENT_ID,
            destClient: clientId,
            timeoutTimestamp: BATCH_TIMESTAMP + 100,
            payloads: payloads
        });
    }

    function _payload() private pure returns (IICS26RouterMsgs.Payload memory) {
        return IICS26RouterMsgs.Payload({
            sourcePort: APP_PORT,
            destPort: APP_PORT,
            version: "v1",
            encoding: "abi",
            value: hex"1234"
        });
    }

    function _settlementMessage(uint64 batch, bytes32 root) private view returns (bytes memory) {
        PrividiumTypes.SettlementPublicValues memory value = PrividiumTypes.SettlementPublicValues({
            schemaVersion: 1,
            programVersion: 3,
            sourceProfileId: PROFILE,
            previousConsensusTrustDigest: PublicValuesV1.consensusTrustDigest(initialTrust),
            l2BlockNumber: batch + 10,
            l1BatchNumber: batch,
            prividiumNativeRoot: root,
            l2BatchTimestamp: BATCH_TIMESTAMP
        });
        return
            abi.encode(
                uint8(PrividiumTypes.UpdateKind.SettlementUpdate), abi.encode(value), hex"01"
            );
    }

    function _membershipProof(
        uint64 batch,
        uint64 proofHeight,
        bytes32 nativeRoot,
        IICS26RouterMsgs.Packet memory packet
    ) private pure returns (bytes memory) {
        bytes memory path =
            ICS24Host.packetCommitmentPathCalldata(packet.sourceClient, packet.sequence);
        bytes memory expectedValue = abi.encodePacked(ICS24Host.packetCommitmentBytes32(packet));
        bytes32 batchRoot =
            PublicValuesV1.membershipLeaf(0, keccak256(path), keccak256(expectedValue));
        PrividiumTypes.MembershipPublicValues memory value = PrividiumTypes.MembershipPublicValues({
            schemaVersion: 1,
            programVersion: 2,
            sourceProfileId: PROFILE,
            proofHeight: proofHeight,
            l1BatchNumber: batch,
            prividiumNativeRoot: nativeRoot,
            ibcStore: SOURCE_IBC_STORE,
            entryCount: 1,
            batchRoot: batchRoot,
            requestDigest: bytes32(0)
        });
        value.requestDigest = PublicValuesV1.membershipRequestDigest(value);
        bytes32[] memory siblings = new bytes32[](0);
        return abi.encode(
            PrividiumTypes.MembershipBatchProofEnvelope({
                mode: 1,
                publicValues: abi.encode(value),
                proofBytes: hex"01",
                l1BatchNumber: batch,
                batchRoot: batchRoot,
                entryCount: 1,
                entryIndex: 0,
                siblings: siblings
            })
        );
    }

    function _nonMembershipProof(
        uint64 batch,
        uint64 proofHeight,
        bytes32 nativeRoot,
        IICS26RouterMsgs.Packet memory packet
    ) private pure returns (bytes memory) {
        bytes memory path =
            ICS24Host.packetReceiptCommitmentPathCalldata(packet.destClient, packet.sequence);
        PrividiumTypes.NonMembershipPublicValues memory value =
            PrividiumTypes.NonMembershipPublicValues({
                schemaVersion: 1,
                programVersion: 2,
                sourceProfileId: PROFILE,
                proofHeight: proofHeight,
                l1BatchNumber: batch,
                prividiumNativeRoot: nativeRoot,
                ibcStore: SOURCE_IBC_STORE,
                pathDigest: keccak256(path),
                solidityStorageSlot: bytes32(uint256(3)),
                nativeTreeKey: bytes32(uint256(4)),
                absenceProfileId: 1,
                requestDigest: bytes32(0)
            });
        value.requestDigest = PublicValuesV1.nonMembershipRequestDigest(value);
        return abi.encode(
            PrividiumTypes.SP1ProofEnvelope({
                publicValues: abi.encode(value), proofBytes: hex"01"
            })
        );
    }
}
