// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	ibchostv2 "github.com/lfdt-ibc/ibc-go/v11/modules/core/24-host/v2"

	"github.com/lfdt-ibc/ibc-contracts/packages/go-abigen/ics26router"
	"github.com/lfdt-ibc/ibc-contracts/packages/go-abigen/lineamsgs"

	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/chainconfig"
	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/ethereum"
	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/testvalues"
)

type LineaFixtureGenerator struct {
	Enabled bool
}

type GenerateLineaFixtureParams struct {
	SourceChain *ethereum.Ethereum
	// BeaconAPI is the beacon API of the source chain's Maru consensus client.
	BeaconAPI               string
	RouterAddress           ethcommon.Address
	Packet                  ics26router.IICS26RouterMsgsPacket
	InitialTrustedHeight    uint64
	AdjacentUpdateHeight    uint64
	NonAdjacentUpdateHeight uint64
	TrustingPeriod          uint64
	MaxClockDrift           uint64
}

// lineaFixture holds its messages ABI-encoded, as the light client takes them.
type lineaFixture struct {
	RouterAddress        string `json:"routerAddress"`
	TrustingPeriod       uint64 `json:"trustingPeriod"`
	MaxClockDrift        uint64 `json:"maxClockDrift"`
	InitialTrustedHeight uint64 `json:"initialTrustedHeight"`
	// InitialConsensusState is the abi.encode(ConsensusState) trusted at InitialTrustedHeight.
	InitialConsensusState string             `json:"initialConsensusState"`
	AdjacentUpdate        lineaUpdateFixture `json:"adjacentUpdate"`
	NonAdjacentUpdate     lineaUpdateFixture `json:"nonAdjacentUpdate"`
	// ConflictingUpdate is NonAdjacentUpdate re-sealed over a different execution state root.
	ConflictingUpdate lineaUpdateFixture `json:"conflictingUpdate"`
	Membership        lineaProofFixture  `json:"membership"`
	NonMembership     lineaProofFixture  `json:"nonMembership"`
}

type lineaUpdateFixture struct {
	Height uint64 `json:"height"`
	// UpdateMsg is the abi.encode(MsgUpdateClient) against InitialTrustedHeight.
	UpdateMsg string `json:"updateMsg"`
	// ConsensusState is the abi.encode(ConsensusState) the update derives.
	ConsensusState string `json:"consensusState"`
}

type lineaProofFixture struct {
	ProofHeight uint64 `json:"proofHeight"`
	Path        string `json:"path"`
	Value       string `json:"value,omitempty"`
	// Proof is the abi.encode(MembershipProof) against the NonAdjacentUpdate consensus state.
	Proof string `json:"proof"`
}

func NewLineaFixtureGenerator() *LineaFixtureGenerator {
	return &LineaFixtureGenerator{
		Enabled: os.Getenv(testvalues.EnvKeyGenerateLineaLightClientFixtures) == testvalues.EnvValueGenerateFixtures_True,
	}
}

func (g *LineaFixtureGenerator) GenerateAndSaveFixture(ctx context.Context, params GenerateLineaFixtureParams) error {
	if !g.Enabled {
		return nil
	}

	bindings := lineamsgs.NewBindings()
	trusted, err := fetchMaruBlock(ctx, params.BeaconAPI, params.InitialTrustedHeight)
	if err != nil {
		return err
	}
	updateFixture := func(block *maruBlock) lineaUpdateFixture {
		return lineaUpdateFixture{
			Height:         block.payload.BlockNumber,
			UpdateMsg:      encodeHex(block.updateMsg(trusted)),
			ConsensusState: encodeHex(bindings.PackConsensusState(block.consensusState())[4:]),
		}
	}

	adjacent, err := fetchMaruBlock(ctx, params.BeaconAPI, params.AdjacentUpdateHeight)
	if err != nil {
		return err
	}
	nonAdjacent, err := fetchMaruBlock(ctx, params.BeaconAPI, params.NonAdjacentUpdateHeight)
	if err != nil {
		return err
	}
	fixture := lineaFixture{
		RouterAddress:         params.RouterAddress.Hex(),
		TrustingPeriod:        params.TrustingPeriod,
		MaxClockDrift:         params.MaxClockDrift,
		InitialTrustedHeight:  params.InitialTrustedHeight,
		InitialConsensusState: encodeHex(bindings.PackConsensusState(trusted.consensusState())[4:]),
		AdjacentUpdate:        updateFixture(adjacent),
		NonAdjacentUpdate:     updateFixture(nonAdjacent),
	}

	proofFixture := func(path []byte) (lineaProofFixture, error) {
		storageProof, accountProof, err := fetchStorageProof(ctx, params.SourceChain, params.RouterAddress, path, nonAdjacent.payload.BlockNumber)
		if err != nil {
			return lineaProofFixture{}, err
		}
		proof := lineamsgs.ILineaLightClientMsgsMembershipProof{ConsensusStatePreimage: nonAdjacent.consensusState()}
		if proof.AccountProofNodes, err = bindings.UnpackProofNodes(accountProof); err != nil {
			return lineaProofFixture{}, err
		}
		if proof.ProofNodes, err = bindings.UnpackProofNodes(storageProof); err != nil {
			return lineaProofFixture{}, err
		}
		return lineaProofFixture{
			ProofHeight: nonAdjacent.payload.BlockNumber,
			Path:        encodeHex(path),
			Proof:       encodeHex(bindings.PackMembershipProof(proof)[4:]),
		}, nil
	}
	if fixture.Membership, err = proofFixture(ibchostv2.PacketCommitmentKey(params.Packet.SourceClient, params.Packet.Sequence)); err != nil {
		return err
	}
	fixture.Membership.Value = encodeHex(packetCommitment(params.Packet))
	if fixture.NonMembership, err = proofFixture(ibchostv2.PacketReceiptKey(params.Packet.DestClient, params.Packet.Sequence)); err != nil {
		return err
	}

	nonAdjacent.payload.StateRoot = crypto.Keccak256Hash(nonAdjacent.payload.StateRoot[:])
	if err := nonAdjacent.reseal(); err != nil {
		return err
	}
	fixture.ConflictingUpdate = updateFixture(nonAdjacent)

	fixtureBz, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	// The checked-in fixture is intentionally readable by all test processes.
	return os.WriteFile(filepath.Join(testvalues.LineaFixturesDir, "maru.json"), fixtureBz, 0o644) //nolint:gosec
}

// BuildLineaUpdate returns the abi-encoded MsgUpdateClient for the live block at height, without a selector.
func BuildLineaUpdate(ctx context.Context, beaconAPI string, trustedHeight, height uint64) ([]byte, error) {
	return buildLineaUpdate(ctx, beaconAPI, trustedHeight, height, nil)
}

// BuildLineaDoubleSignUpdate re-seals the block at height over a different execution state root with the validator
// key of the Linea fixture, and returns the abi-encoded MsgUpdateClient for it.
func BuildLineaDoubleSignUpdate(ctx context.Context, beaconAPI string, trustedHeight, height uint64) ([]byte, error) {
	return buildLineaUpdate(ctx, beaconAPI, trustedHeight, height, func(block *maruBlock) {
		block.payload.StateRoot = crypto.Keccak256Hash(block.payload.StateRoot[:])
	})
}

// BuildLineaTimestampUpdate re-seals the block at height with timestamp with the validator key of the Linea fixture,
// and returns the abi-encoded MsgUpdateClient for it.
func BuildLineaTimestampUpdate(ctx context.Context, beaconAPI string, trustedHeight, height, timestamp uint64) ([]byte, error) {
	return buildLineaUpdate(ctx, beaconAPI, trustedHeight, height, func(block *maruBlock) {
		block.header.Timestamp = timestamp
		block.payload.Timestamp = timestamp
	})
}

// FetchLineaConsensusState returns the consensus state the light client derives from the live block at height.
func FetchLineaConsensusState(ctx context.Context, beaconAPI string, height uint64) (lineamsgs.ILineaLightClientMsgsConsensusState, error) {
	block, err := fetchMaruBlock(ctx, beaconAPI, height)
	if err != nil {
		return lineamsgs.ILineaLightClientMsgsConsensusState{}, err
	}
	return block.consensusState(), nil
}

func buildLineaUpdate(ctx context.Context, beaconAPI string, trustedHeight, height uint64, mutate func(*maruBlock)) ([]byte, error) {
	trusted, err := fetchMaruBlock(ctx, beaconAPI, trustedHeight)
	if err != nil {
		return nil, err
	}
	block, err := fetchMaruBlock(ctx, beaconAPI, height)
	if err != nil {
		return nil, err
	}
	if mutate != nil {
		mutate(block)
		if err := block.reseal(); err != nil {
			return nil, err
		}
	}
	return block.updateMsg(trusted), nil
}

// maruBlock is a sealed Maru beacon block. Its encodings mirror Maru's RLP serializers, which write integers as
// fixed-width byte strings.
type maruBlock struct {
	header          lineamsgs.ILineaLightClientMsgsBeaconBlockHeader
	prevCommitSeals [][]byte
	payload         maruExecutionPayload
	validators      []ethcommon.Address
	// commitSeals are ordered by signer address and have 27/28 recovery ids, as the light client requires.
	commitSeals [][]byte
}

type maruExecutionPayload struct {
	ParentHash    ethcommon.Hash    `json:"parent_hash"`
	FeeRecipient  ethcommon.Address `json:"fee_recipient"`
	StateRoot     ethcommon.Hash    `json:"state_root"`
	ReceiptsRoot  ethcommon.Hash    `json:"receipts_root"`
	LogsBloom     hexutil.Bytes     `json:"logs_bloom"`
	PrevRandao    ethcommon.Hash    `json:"prev_randao"`
	BlockNumber   uint64            `json:"block_number,string"`
	GasLimit      uint64            `json:"gas_limit,string"`
	GasUsed       uint64            `json:"gas_used,string"`
	Timestamp     uint64            `json:"timestamp,string"`
	ExtraData     hexutil.Bytes     `json:"extra_data"`
	BaseFeePerGas string            `json:"base_fee_per_gas"`
	BlockHash     ethcommon.Hash    `json:"block_hash"`
	Transactions  []hexutil.Bytes   `json:"transactions"`
}

type maruAttestation struct {
	Data struct {
		Slot uint64 `json:"slot,string"`
	} `json:"data"`
	Signature hexutil.Bytes `json:"signature"`
}

// fetchMaruBlock fetches the sealed beacon block that carries the execution block executionHeight.
func fetchMaruBlock(ctx context.Context, beaconAPI string, executionHeight uint64) (*maruBlock, error) {
	head, err := fetchMaruBlockByID(ctx, beaconAPI, "head")
	if err != nil {
		return nil, err
	}
	// Every beacon block carries the next execution block, so the two numbers advance together.
	if executionHeight > head.payload.BlockNumber || head.payload.BlockNumber-executionHeight > head.header.Number {
		return nil, fmt.Errorf("no beacon block carries execution block %d", executionHeight)
	}
	number := head.header.Number - (head.payload.BlockNumber - executionHeight)
	block, err := fetchMaruBlockByID(ctx, beaconAPI, strconv.FormatUint(number, 10))
	if err != nil {
		return nil, err
	}
	if block.payload.BlockNumber != executionHeight {
		return nil, fmt.Errorf("beacon block %d carries execution block %d, want %d", number, block.payload.BlockNumber, executionHeight)
	}
	return block, nil
}

func fetchMaruBlockByID(ctx context.Context, beaconAPI, blockID string) (*maruBlock, error) {
	var blockResp struct {
		Data struct {
			Message struct {
				Slot uint64 `json:"slot,string"`
				Body struct {
					Attestations     []maruAttestation    `json:"attestations"`
					ExecutionPayload maruExecutionPayload `json:"execution_payload"`
				} `json:"body"`
			} `json:"message"`
		} `json:"data"`
	}
	if err := getMaruAPI(ctx, beaconAPI+"/eth/v2/beacon/blocks/"+blockID, &blockResp); err != nil {
		return nil, err
	}
	message := blockResp.Data.Message

	// The block response lacks the round, timestamp and body root of the header.
	var headerResp struct {
		Data struct {
			Message struct {
				Round      uint32            `json:"round,string"`
				Timestamp  uint64            `json:"timestamp,string"`
				Proposer   ethcommon.Address `json:"proposer_index"`
				ParentRoot ethcommon.Hash    `json:"parent_root"`
				StateRoot  ethcommon.Hash    `json:"state_root"`
				BodyRoot   ethcommon.Hash    `json:"body_root"`
			} `json:"message"`
		} `json:"data"`
	}
	if err := getMaruAPI(ctx, fmt.Sprintf("%s/eth/v1/beacon/headers/%d", beaconAPI, message.Slot), &headerResp); err != nil {
		return nil, err
	}
	header := headerResp.Data.Message

	block := &maruBlock{
		header: lineamsgs.ILineaLightClientMsgsBeaconBlockHeader{
			Number:     message.Slot,
			Round:      header.Round,
			Timestamp:  header.Timestamp,
			Proposer:   header.Proposer,
			ParentRoot: header.ParentRoot,
			StateRoot:  header.StateRoot,
			BodyRoot:   header.BodyRoot,
		},
		payload: message.Body.ExecutionPayload,
	}
	// Maru reports the commit seals of the block itself and those of its parent, which the body carries.
	digest := block.headerHash()
	for _, attestation := range message.Body.Attestations {
		if attestation.Data.Slot != message.Slot {
			block.prevCommitSeals = append(block.prevCommitSeals, attestation.Signature)
			continue
		}
		seal := slices.Clone([]byte(attestation.Signature))
		seal[crypto.RecoveryIDOffset] += 27
		block.commitSeals = append(block.commitSeals, seal)
	}
	if bodyRoot := crypto.Keccak256Hash(block.bodyRLP()); bodyRoot != header.BodyRoot {
		return nil, fmt.Errorf("rebuilt body of beacon block %d hashes to %s, want %s", message.Slot, bodyRoot, header.BodyRoot)
	}
	var sortErr error
	slices.SortFunc(block.commitSeals, func(a, b []byte) int {
		signerA, errA := recoverCommitSealSigner(digest, a)
		signerB, errB := recoverCommitSealSigner(digest, b)
		if errA != nil || errB != nil {
			sortErr = fmt.Errorf("recover commit seal signer of beacon block %d", message.Slot)
		}
		return bytes.Compare(signerA[:], signerB[:])
	})
	if sortErr != nil {
		return nil, sortErr
	}

	// Maru looks beacon states up by block root.
	var validatorsResp struct {
		Data []struct {
			Validator struct {
				Pubkey ethcommon.Address `json:"pubkey"`
			} `json:"validator"`
		} `json:"data"`
	}
	if err := getMaruAPI(ctx, fmt.Sprintf("%s/eth/v1/beacon/states/%s/validators", beaconAPI, digest), &validatorsResp); err != nil {
		return nil, err
	}
	for _, validator := range validatorsResp.Data {
		block.validators = append(block.validators, validator.Validator.Pubkey)
	}
	slices.SortFunc(block.validators, func(a, b ethcommon.Address) int { return bytes.Compare(a[:], b[:]) })
	if stateRoot := block.stateRoot(); stateRoot != header.StateRoot {
		return nil, fmt.Errorf("validators of beacon block %d hash to state root %s, want %s", message.Slot, stateRoot, header.StateRoot)
	}

	return block, nil
}

func getMaruAPI(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("query %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("query %s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response of %s: %w", url, err)
	}
	return nil
}

// reseal recomputes the header roots from the body and validators, and seals the header with the validator key of
// the Linea fixture.
func (b *maruBlock) reseal() error {
	key, err := chainconfig.LineaValidatorKey()
	if err != nil {
		return err
	}
	b.header.BodyRoot = crypto.Keccak256Hash(b.bodyRLP())
	b.header.StateRoot = b.stateRoot()
	b.commitSeals = signCommitSeals(b.headerHash(), []*ecdsa.PrivateKey{key})
	return nil
}

func (b *maruBlock) consensusState() lineamsgs.ILineaLightClientMsgsConsensusState {
	return lineamsgs.ILineaLightClientMsgsConsensusState{
		Timestamp:  b.payload.Timestamp,
		StateRoot:  b.payload.StateRoot,
		Validators: b.validators,
	}
}

// updateMsg returns the abi-encoded MsgUpdateClient submitting the block against trusted, without a selector.
func (b *maruBlock) updateMsg(trusted *maruBlock) []byte {
	return lineamsgs.NewBindings().PackUpdateClient(lineamsgs.ILineaLightClientMsgsMsgUpdateClient{
		Header:                 b.header,
		BodyRlp:                b.bodyRLP(),
		Validators:             b.validators,
		CommitSeals:            b.commitSeals,
		TrustedHeight:          lineamsgs.IICS02ClientMsgsHeight{RevisionHeight: trusted.payload.BlockNumber},
		ConsensusStatePreimage: trusted.consensusState(),
	})[4:]
}

// headerHash is the digest the commit seals sign.
func (b *maruBlock) headerHash() ethcommon.Hash {
	return crypto.Keccak256Hash(b.headerRLP(b.header.StateRoot))
}

// stateRoot is the beacon state root the header must carry: the hash of [header, validators], where the header has
// a zero state root.
func (b *maruBlock) stateRoot() ethcommon.Hash {
	validators := make([]any, len(b.validators))
	for i, validator := range b.validators {
		validators[i] = []any{validator.Bytes()}
	}
	return crypto.Keccak256Hash(mustRLP([]any{rlp.RawValue(b.headerRLP(ethcommon.Hash{})), validators}))
}

func (b *maruBlock) headerRLP(stateRoot ethcommon.Hash) []byte {
	return mustRLP([]any{
		binary.BigEndian.AppendUint64(nil, b.header.Number),
		binary.BigEndian.AppendUint32(nil, b.header.Round),
		binary.BigEndian.AppendUint64(nil, b.header.Timestamp),
		[]any{b.header.Proposer.Bytes()},
		b.header.ParentRoot[:],
		stateRoot[:],
		b.header.BodyRoot[:],
	})
}

// bodyRLP encodes the body [prevCommitSeals, executionPayload], which hashes to the header body root.
func (b *maruBlock) bodyRLP() []byte {
	prevCommitSeals := make([]any, len(b.prevCommitSeals))
	for i, seal := range b.prevCommitSeals {
		prevCommitSeals[i] = []any{seal}
	}
	transactions := make([]any, len(b.payload.Transactions))
	for i, transaction := range b.payload.Transactions {
		transactions[i] = []byte(transaction)
	}
	// Maru writes the base fee as Java's BigInteger.toByteArray does: minimal two's complement, so zero is one zero
	// byte and values with the top bit set get a leading zero byte.
	baseFee, ok := new(big.Int).SetString(b.payload.BaseFeePerGas, 10)
	if !ok {
		panic(fmt.Sprintf("invalid base fee %q", b.payload.BaseFeePerGas))
	}
	baseFeeBz := baseFee.Bytes()
	if len(baseFeeBz) == 0 || baseFeeBz[0]&0x80 != 0 {
		baseFeeBz = append([]byte{0}, baseFeeBz...)
	}

	return mustRLP([]any{prevCommitSeals, []any{
		b.payload.ParentHash[:],
		b.payload.FeeRecipient[:],
		b.payload.StateRoot[:],
		b.payload.ReceiptsRoot[:],
		[]byte(b.payload.LogsBloom),
		b.payload.PrevRandao[:],
		binary.BigEndian.AppendUint64(nil, b.payload.BlockNumber),
		binary.BigEndian.AppendUint64(nil, b.payload.GasLimit),
		binary.BigEndian.AppendUint64(nil, b.payload.GasUsed),
		binary.BigEndian.AppendUint64(nil, b.payload.Timestamp),
		[]byte(b.payload.ExtraData),
		baseFeeBz,
		b.payload.BlockHash[:],
		transactions,
	}})
}
