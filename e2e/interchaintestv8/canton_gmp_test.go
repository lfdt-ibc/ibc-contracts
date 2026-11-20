// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/lfdt-ibc/ibc-contracts/packages/go-abigen/ics26router"
	"github.com/lfdt-ibc/ibc-contracts/packages/go-abigen/ics27gmp"

	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/canton"
	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/e2esuite"
	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/ethereum"
	proofapi "github.com/lfdt-ibc/ibc-contracts/e2e/v8/proofapi"
	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/testvalues"
	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/types/erc20"
	proofapitypes "github.com/lfdt-ibc/ibc-contracts/e2e/v8/types/proofapi"
)

const (
	cantonChainID = "canton"
	// cantonClientOnEth is the client on Ethereum that tracks Canton.
	cantonClientOnEth = "canton-0"
	// ethClientOnCanton is the client on Canton that tracks Ethereum.
	ethClientOnCanton = "eth-0"

	cantonDarDir = "ibc-canton/daml"

	cantonRouterTemplate     = "#ibc:IBC.Router:Router"
	cantonClientTemplate     = "#ibc:IBC.Router:Client"
	cantonCommitmentTemplate = "#ibc:IBC.Router:PacketCommitment"
	cantonGMPAppTemplate     = "#ibc:IBC.GMP:GMPApp"
	cantonMockLCTemplate     = "#ibc:IBC.MockLightClient:MockLightClient"
	cantonCounterTemplate    = "#ibc-test:Test.Counter:Counter"
)

// CantonGMPTestSuite tests ICS27 GMP between Canton and Ethereum, with a light client that
// accepts every proof on both sides.
type CantonGMPTestSuite struct {
	e2esuite.TestSuite

	eth               *ethereum.Ethereum
	contractAddresses ethereum.DeployedContracts
	ics26Contract     *ics26router.Contract
	ics27Contract     *ics27gmp.Contract
	erc20Contract     *erc20.Contract
	deployer          *ecdsa.PrivateKey
	ethUser           *ecdsa.PrivateKey
	ethRelayer        *ecdsa.PrivateKey

	ledger *canton.Client
	// Canton parties.
	operator, gmp, relayer, alice string
	// Canton contracts that are never replaced.
	router, gmpApp string

	ProofApiClient proofapitypes.ProofApiServiceClient
}

func TestWithCantonGMPTestSuite(t *testing.T) {
	suite.Run(t, new(CantonGMPTestSuite))
}

func (s *CantonGMPTestSuite) SetupSuite(ctx context.Context) {
	if os.Getenv(testvalues.EnvKeyRustLog) == "" {
		os.Setenv(testvalues.EnvKeyRustLog, testvalues.EnvValueRustLog_Info)
	}
	// Two Anvil chains is the only setup without Cosmos chains; the second one stays idle.
	os.Setenv(testvalues.EnvKeyEthTestnetType, testvalues.EthTestnetTypeAnvil)
	os.Setenv(testvalues.EnvKeyEthAnvilCount, "2")
	s.TestSuite.SetupSuite(ctx)
	s.eth = s.Eth.Chains[0]

	s.Require().NoError(os.Chdir("../.."))

	s.Require().True(s.Run("Deploy contracts on Ethereum", func() {
		var err error
		s.ethUser, err = s.eth.CreateAndFundUser()
		s.Require().NoError(err)
		s.deployer, err = s.eth.CreateAndFundUser()
		s.Require().NoError(err)
		s.ethRelayer, err = s.eth.CreateAndFundUser()
		s.Require().NoError(err)
		operatorKey, err := s.eth.CreateAndFundUser()
		s.Require().NoError(err)
		os.Setenv(testvalues.EnvKeyOperatorPrivateKey, hex.EncodeToString(crypto.FromECDSA(operatorKey)))
		os.Setenv(testvalues.EnvKeyEthRPC, s.eth.RPC)

		stdout, err := s.eth.ForgeScript(s.deployer, testvalues.E2EDeployScriptPath)
		s.Require().NoError(err)
		s.contractAddresses, err = ethereum.GetEthContractsFromDeployOutput(string(stdout))
		s.Require().NoError(err)

		s.ics26Contract, err = ics26router.NewContract(ethcommon.HexToAddress(s.contractAddresses.Ics26Router), s.eth.RPCClient)
		s.Require().NoError(err)
		s.ics27Contract, err = ics27gmp.NewContract(ethcommon.HexToAddress(s.contractAddresses.Ics27Gmp), s.eth.RPCClient)
		s.Require().NoError(err)
		s.erc20Contract, err = erc20.NewContract(ethcommon.HexToAddress(s.contractAddresses.Erc20), s.eth.RPCClient)
		s.Require().NoError(err)
	}))

	// The counterparty time both mock light clients report, past every timeout used here.
	mockTimestamp := strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10)

	s.Require().True(s.Run("Add mock light client for Canton on Ethereum", func() {
		cmd := exec.Command("forge", "create", "test/solidity-ibc/mocks/DummyLightClient.sol:DummyLightClient",
			"--rpc-url", s.eth.RPC, "--private-key", hex.EncodeToString(crypto.FromECDSA(s.deployer)),
			"--broadcast", "--json", "--constructor-args", "0", mockTimestamp, "false")
		cmd.Dir = testvalues.SolidityProjectDir
		cmd.Stderr = os.Stderr
		stdout, err := cmd.Output()
		s.Require().NoError(err)
		var deployment struct {
			DeployedTo string `json:"deployedTo"`
		}
		s.Require().NoError(json.Unmarshal(stdout[strings.LastIndex(string(stdout), "{"):], &deployment))

		tx, err := s.ics26Contract.AddClient(s.GetTransactOpts(s.deployer, s.eth), cantonClientOnEth,
			ics26router.IICS02ClientMsgsCounterpartyInfo{ClientId: ethClientOnCanton, MerklePrefix: [][]byte{[]byte("")}},
			ethcommon.HexToAddress(deployment.DeployedTo))
		s.Require().NoError(err)
		receipt, err := s.eth.GetTxReciept(ctx, tx.Hash())
		s.Require().NoError(err)
		s.Require().Equal(ethtypes.ReceiptStatusSuccessful, receipt.Status)
	}))

	// Cleanups registered inside a subtest run when that subtest ends, so the processes that
	// must outlive setup are stopped from here.
	var sandbox *canton.Sandbox
	var proofAPIProcess *os.Process
	s.T().Cleanup(func() {
		if proofAPIProcess != nil {
			_ = proofAPIProcess.Kill()
		}
		os.Remove(testvalues.ProofAPIConfigFilePath)
		if sandbox != nil {
			sandbox.Stop()
		}
	})

	s.Require().True(s.Run("Start Canton and set up the IBC contracts", func() {
		var err error
		sandbox, err = canton.StartSandbox(ctx,
			cantonDarDir+"/ibc-api/.daml/dist/ibc-api-0.1.0.dar",
			cantonDarDir+"/ibc/.daml/dist/ibc-0.1.0.dar",
			cantonDarDir+"/ibc-test/.daml/dist/ibc-test-0.1.0.dar",
		)
		s.Require().NoError(err)
		s.ledger = sandbox.Client

		for hint, party := range map[string]*string{
			"operator": &s.operator, "gmp": &s.gmp, "relayer": &s.relayer, "alice": &s.alice,
		} {
			*party, err = s.ledger.AllocateParty(ctx, hint)
			s.Require().NoError(err)
		}

		s.gmpApp = s.cantonCreate(ctx, s.gmp, cantonGMPAppTemplate, map[string]any{
			"gmp": s.gmp, "operator": s.operator, "observers": []string{s.alice, s.relayer},
		})
		router := s.cantonCreate(ctx, s.operator, cantonRouterTemplate, map[string]any{
			"operator": s.operator, "relayers": []string{s.relayer}, "ports": []any{},
		})
		// Adding an app replaces the router contract.
		tx := s.cantonExercise(ctx, s.operator, nil, cantonRouterTemplate, router, "Router_AddApp", map[string]any{
			"portId": "gmpport", "port": map[string]any{"owner": s.gmp, "app": s.gmpApp},
		})
		s.router = tx.Created[0].ContractID

		lightClient := s.cantonCreate(ctx, s.operator, cantonMockLCTemplate, map[string]any{
			"operator": s.operator, "observers": []string{s.relayer}, "timestamp": mockTimestamp,
		})
		s.cantonExercise(ctx, s.operator, nil, cantonRouterTemplate, s.router, "Router_AddClient", map[string]any{
			"clientId": ethClientOnCanton, "counterpartyClientId": cantonClientOnEth,
			"merklePrefix": []string{""}, "lightClient": lightClient,
		})
		s.cantonCreate(ctx, s.alice, cantonCounterTemplate, map[string]any{
			"owner": s.alice, "gmp": s.gmp, "count": "0", "lastCaller": nil,
		})
	}))

	s.Require().True(s.Run("Start Proof API", func() {
		params := proofapi.CantonEthParams{
			CantonChainID: cantonChainID,
			EthChainID:    s.eth.ChainID.String(),
			LedgerAPI:     s.ledger.URL(),
			OperatorParty: s.operator,
			RelayerParty:  s.relayer,
			GMPParty:      s.gmp,
			EthRPC:        s.eth.RPC,
			ICS26Address:  s.contractAddresses.Ics26Router,
			IBCMulticall:  s.contractAddresses.IbcMulticall,
		}
		config := proofapi.NewConfigBuilder().CantonToEth(params).EthToCanton(params).Build()
		s.Require().NoError(config.GenerateConfigFile(testvalues.ProofAPIConfigFilePath))

		var err error
		proofAPIProcess, err = proofapi.StartProofAPI(testvalues.ProofAPIConfigFilePath)
		s.Require().NoError(err)

		s.ProofApiClient, err = proofapi.GetGRPCClient(proofapi.DefaultProofAPIGRPCAddress())
		s.Require().NoError(err)
	}))
}

func (s *CantonGMPTestSuite) cantonCreate(ctx context.Context, party, templateID string, arguments any) string {
	tx, err := s.ledger.Submit(ctx, []string{party}, nil, []any{canton.Create(templateID, arguments)}, nil)
	s.Require().NoError(err)
	return tx.Created[0].ContractID
}

func (s *CantonGMPTestSuite) cantonExercise(
	ctx context.Context, party string, readAs []string, templateID, contractID, choice string, argument any,
) *canton.Transaction {
	tx, err := s.ledger.Submit(ctx, []string{party}, readAs, []any{canton.Exercise(templateID, contractID, choice, argument)}, nil)
	s.Require().NoError(err)
	return tx
}

// cantonContracts returns the arguments of the active contracts of a template visible to `party`.
func (s *CantonGMPTestSuite) cantonContracts(ctx context.Context, party, templateID string) []canton.Contract {
	contracts, err := s.ledger.ActiveContracts(ctx, party, templateID)
	s.Require().NoError(err)
	return contracts
}

// cantonSendCall sends a GMP call from alice on Canton and returns the update id of the send.
func (s *CantonGMPTestSuite) cantonSendCall(ctx context.Context, receiver string, payload []byte, timeout time.Time) string {
	// Every send and receive replaces the client contract, so it is looked up each time.
	clients := s.cantonContracts(ctx, s.relayer, cantonClientTemplate)
	s.Require().Len(clients, 1)

	// Alice is not a stakeholder of the router; she reads it through the GMP party, which
	// works because both parties are hosted on the same participant.
	tx := s.cantonExercise(ctx, s.alice, []string{s.gmp}, cantonGMPAppTemplate, s.gmpApp, "GMPApp_SendCall", map[string]any{
		"sender":           s.alice,
		"routerCid":        s.router,
		"clientCid":        clients[0].ContractID,
		"receiver":         receiver,
		"salt":             "",
		"payload":          hex.EncodeToString(payload),
		"timeoutTimestamp": strconv.FormatInt(timeout.Unix(), 10),
		"memo":             "",
	})
	return tx.UpdateID
}

// relayToEth relays the Canton transactions to Ethereum and returns the receipt.
func (s *CantonGMPTestSuite) relayToEth(ctx context.Context, updateIDs ...string) *ethtypes.Receipt {
	req := &proofapitypes.RelayByTxRequest{
		SrcChain:    cantonChainID,
		DstChain:    s.eth.ChainID.String(),
		SrcClientId: ethClientOnCanton,
		DstClientId: cantonClientOnEth,
	}
	for _, updateID := range updateIDs {
		req.SourceTxIds = append(req.SourceTxIds, []byte(updateID))
	}
	resp, err := s.ProofApiClient.RelayByTx(ctx, req)
	s.Require().NoError(err)

	multicall := ethcommon.HexToAddress(resp.Address)
	receipt, err := s.eth.BroadcastTx(ctx, s.ethRelayer, 15_000_000, &multicall, resp.Tx)
	s.Require().NoError(err)
	s.Require().Equal(ethtypes.ReceiptStatusSuccessful, receipt.Status, fmt.Sprintf("Tx failed: %+v", receipt))
	return receipt
}

// relayToCanton relays Ethereum transactions, or times out Canton transactions, on Canton.
func (s *CantonGMPTestSuite) relayToCanton(ctx context.Context, ethTxHashes [][]byte, timeoutUpdateIDs ...string) *canton.Transaction {
	req := &proofapitypes.RelayByTxRequest{
		SrcChain:    s.eth.ChainID.String(),
		DstChain:    cantonChainID,
		SourceTxIds: ethTxHashes,
		SrcClientId: cantonClientOnEth,
		DstClientId: ethClientOnCanton,
	}
	for _, updateID := range timeoutUpdateIDs {
		req.TimeoutTxIds = append(req.TimeoutTxIds, []byte(updateID))
	}
	resp, err := s.ProofApiClient.RelayByTx(ctx, req)
	s.Require().NoError(err)

	var submission struct {
		Commands           json.RawMessage `json:"commands"`
		DisclosedContracts json.RawMessage `json:"disclosedContracts"`
	}
	s.Require().NoError(json.Unmarshal(resp.Tx, &submission))
	tx, err := s.ledger.Submit(ctx, []string{s.relayer}, nil, submission.Commands, submission.DisclosedContracts)
	s.Require().NoError(err)
	return tx
}

// Test_GMPCalls makes a GMP call in each direction and relays the acknowledgements.
func (s *CantonGMPTestSuite) Test_GMPCalls() {
	ctx := context.Background()
	s.SetupSuite(ctx)

	s.Require().True(s.Run("Canton -> Eth: a Canton party calls an ERC20 through its ICS27 account", func() {
		spender := crypto.PubkeyToAddress(s.ethUser.PublicKey)
		amount := big.NewInt(42)

		erc20Abi, err := abi.JSON(strings.NewReader(erc20.ContractABI))
		s.Require().NoError(err)
		payload, err := erc20Abi.Pack("approve", spender, amount)
		s.Require().NoError(err)

		sendUpdateID := s.cantonSendCall(ctx, s.contractAddresses.Erc20, payload, time.Now().Add(10*time.Minute))
		s.Require().Len(s.cantonContracts(ctx, s.relayer, cantonCommitmentTemplate), 1)

		recvReceipt := s.relayToEth(ctx, sendUpdateID)

		account, err := s.ics27Contract.GetOrComputeAccountAddress(nil, ics27gmp.IICS27GMPMsgsAccountIdentifier{
			ClientId: cantonClientOnEth,
			Sender:   s.alice,
			Salt:     nil,
		})
		s.Require().NoError(err)
		allowance, err := s.erc20Contract.Allowance(nil, account, spender)
		s.Require().NoError(err)
		s.Require().Equal(amount, allowance)

		s.relayToCanton(ctx, [][]byte{recvReceipt.TxHash.Bytes()})
		s.Require().Empty(s.cantonContracts(ctx, s.relayer, cantonCommitmentTemplate))
	}))

	s.Require().True(s.Run("Eth -> Canton: an Ethereum account calls a Daml contract", func() {
		tx, err := s.ics27Contract.SendCall(s.GetTransactOpts(s.ethUser, s.eth), ics27gmp.IICS27GMPMsgsSendCallMsg{
			SourceClient:     cantonClientOnEth,
			Receiver:         s.alice,
			Salt:             nil,
			Payload:          ethcommon.LeftPadBytes(big.NewInt(7).Bytes(), 32),
			TimeoutTimestamp: uint64(time.Now().Add(10 * time.Minute).Unix()),
			Memo:             "",
		})
		s.Require().NoError(err)
		sendReceipt, err := s.eth.GetTxReciept(ctx, tx.Hash())
		s.Require().NoError(err)
		s.Require().Equal(ethtypes.ReceiptStatusSuccessful, sendReceipt.Status)

		recvTx := s.relayToCanton(ctx, [][]byte{sendReceipt.TxHash.Bytes()})

		counters := s.cantonContracts(ctx, s.alice, cantonCounterTemplate)
		s.Require().Len(counters, 1)
		var counter struct {
			Count      string `json:"count"`
			LastCaller struct {
				ClientID string `json:"clientId"`
				Sender   string `json:"sender"`
			} `json:"lastCaller"`
		}
		s.Require().NoError(json.Unmarshal(counters[0].Argument, &counter))
		s.Require().Equal("7", counter.Count)
		s.Require().Equal(ethClientOnCanton, counter.LastCaller.ClientID)
		s.Require().True(strings.EqualFold(crypto.PubkeyToAddress(s.ethUser.PublicKey).Hex(), counter.LastCaller.Sender))

		ackReceipt := s.relayToEth(ctx, recvTx.UpdateID)
		_, err = e2esuite.GetEvmEvent(ackReceipt, s.ics26Contract.ParseAckPacket)
		s.Require().NoError(err)
	}))
}

// Test_Timeout times out a packet sent from Canton that was never received on Ethereum.
func (s *CantonGMPTestSuite) Test_Timeout() {
	ctx := context.Background()
	s.SetupSuite(ctx)

	timeout := time.Now().Add(20 * time.Second)
	sendUpdateID := s.cantonSendCall(ctx, s.contractAddresses.Erc20, []byte{0x01}, timeout)
	s.Require().Len(s.cantonContracts(ctx, s.relayer, cantonCommitmentTemplate), 1)

	time.Sleep(time.Until(timeout) + 2*time.Second)

	s.relayToCanton(ctx, nil, sendUpdateID)
	s.Require().Empty(s.cantonContracts(ctx, s.relayer, cantonCommitmentTemplate))
}
