// Code generated via abigen V2 - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package lineamsgs

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = bytes.Equal
	_ = errors.New
	_ = big.NewInt
	_ = common.Big1
	_ = types.BloomLookup
	_ = abi.ConvertType
)

// IICS02ClientMsgsHeight is an auto generated low-level Go binding around an user-defined struct.
type IICS02ClientMsgsHeight struct {
	RevisionNumber uint64
	RevisionHeight uint64
}

// ILineaLightClientMsgsBeaconBlockHeader is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsBeaconBlockHeader struct {
	Number     uint64
	Round      uint32
	Timestamp  uint64
	Proposer   common.Address
	ParentRoot [32]byte
	StateRoot  [32]byte
	BodyRoot   [32]byte
}

// ILineaLightClientMsgsClientState is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsClientState struct {
	IbcRouter      common.Address
	LatestHeight   IICS02ClientMsgsHeight
	TrustingPeriod uint64
	MaxClockDrift  uint64
	IsFrozen       bool
	TrustLevel     ILineaLightClientMsgsTrustThreshold
}

// ILineaLightClientMsgsConsensusState is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsConsensusState struct {
	Timestamp  uint64
	StateRoot  [32]byte
	Validators []common.Address
}

// ILineaLightClientMsgsMembershipProof is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsMembershipProof struct {
	ConsensusStatePreimage ILineaLightClientMsgsConsensusState
	AccountProofNodes      [][]byte
	ProofNodes             [][]byte
}

// ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour struct {
	Height1                 IICS02ClientMsgsHeight
	Height2                 IICS02ClientMsgsHeight
	ConsensusStatePreimage1 ILineaLightClientMsgsConsensusState
	ConsensusStatePreimage2 ILineaLightClientMsgsConsensusState
}

// ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour struct {
	Update1 ILineaLightClientMsgsMsgUpdateClient
	Update2 ILineaLightClientMsgsMsgUpdateClient
}

// ILineaLightClientMsgsMsgSubmitMisbehaviour is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsMsgSubmitMisbehaviour struct {
	MisbehaviourType uint8
	Misbehaviour     []byte
}

// ILineaLightClientMsgsMsgUpdateClient is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsMsgUpdateClient struct {
	Header                 ILineaLightClientMsgsBeaconBlockHeader
	BodyRlp                []byte
	Validators             []common.Address
	CommitSeals            [][]byte
	TrustedHeight          IICS02ClientMsgsHeight
	ConsensusStatePreimage ILineaLightClientMsgsConsensusState
}

// ILineaLightClientMsgsTrustThreshold is an auto generated low-level Go binding around an user-defined struct.
type ILineaLightClientMsgsTrustThreshold struct {
	Numerator   uint8
	Denominator uint8
}

// BindingsMetaData contains all meta data concerning the Bindings contract.
var BindingsMetaData = bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"clientState\",\"inputs\":[{\"name\":\"state\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ClientState\",\"components\":[{\"name\":\"ibcRouter\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"latestHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"trustingPeriod\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"maxClockDrift\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"isFrozen\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"trustLevel\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.TrustThreshold\",\"components\":[{\"name\":\"numerator\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"denominator\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}]}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ClientState\",\"components\":[{\"name\":\"ibcRouter\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"latestHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"trustingPeriod\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"maxClockDrift\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"isFrozen\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"trustLevel\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.TrustThreshold\",\"components\":[{\"name\":\"numerator\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"denominator\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"conflictingConsensusStatesMisbehaviour\",\"inputs\":[{\"name\":\"message\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgConflictingConsensusStatesMisbehaviour\",\"components\":[{\"name\":\"height1\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"height2\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage1\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]},{\"name\":\"consensusStatePreimage2\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgConflictingConsensusStatesMisbehaviour\",\"components\":[{\"name\":\"height1\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"height2\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage1\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]},{\"name\":\"consensusStatePreimage2\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"conflictingHeadersMisbehaviour\",\"inputs\":[{\"name\":\"message\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgConflictingHeadersMisbehaviour\",\"components\":[{\"name\":\"update1\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgUpdateClient\",\"components\":[{\"name\":\"header\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.BeaconBlockHeader\",\"components\":[{\"name\":\"number\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"round\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"proposer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"parentRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"bodyRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"name\":\"bodyRlp\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"commitSeals\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"trustedHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]},{\"name\":\"update2\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgUpdateClient\",\"components\":[{\"name\":\"header\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.BeaconBlockHeader\",\"components\":[{\"name\":\"number\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"round\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"proposer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"parentRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"bodyRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"name\":\"bodyRlp\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"commitSeals\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"trustedHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]}]}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgConflictingHeadersMisbehaviour\",\"components\":[{\"name\":\"update1\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgUpdateClient\",\"components\":[{\"name\":\"header\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.BeaconBlockHeader\",\"components\":[{\"name\":\"number\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"round\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"proposer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"parentRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"bodyRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"name\":\"bodyRlp\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"commitSeals\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"trustedHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]},{\"name\":\"update2\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgUpdateClient\",\"components\":[{\"name\":\"header\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.BeaconBlockHeader\",\"components\":[{\"name\":\"number\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"round\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"proposer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"parentRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"bodyRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"name\":\"bodyRlp\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"commitSeals\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"trustedHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"consensusState\",\"inputs\":[{\"name\":\"state\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"membershipProof\",\"inputs\":[{\"name\":\"proof\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MembershipProof\",\"components\":[{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]},{\"name\":\"accountProofNodes\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"proofNodes\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MembershipProof\",\"components\":[{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]},{\"name\":\"accountProofNodes\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"proofNodes\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"proofNodes\",\"inputs\":[{\"name\":\"nodes\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"submitMisbehaviour\",\"inputs\":[{\"name\":\"message\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgSubmitMisbehaviour\",\"components\":[{\"name\":\"misbehaviourType\",\"type\":\"uint8\",\"internalType\":\"enumILineaLightClientMsgs.MisbehaviourType\"},{\"name\":\"misbehaviour\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgSubmitMisbehaviour\",\"components\":[{\"name\":\"misbehaviourType\",\"type\":\"uint8\",\"internalType\":\"enumILineaLightClientMsgs.MisbehaviourType\"},{\"name\":\"misbehaviour\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"updateClient\",\"inputs\":[{\"name\":\"message\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgUpdateClient\",\"components\":[{\"name\":\"header\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.BeaconBlockHeader\",\"components\":[{\"name\":\"number\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"round\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"proposer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"parentRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"bodyRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"name\":\"bodyRlp\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"commitSeals\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"trustedHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.MsgUpdateClient\",\"components\":[{\"name\":\"header\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.BeaconBlockHeader\",\"components\":[{\"name\":\"number\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"round\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"proposer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"parentRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"bodyRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"name\":\"bodyRlp\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"commitSeals\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"trustedHeight\",\"type\":\"tuple\",\"internalType\":\"structIICS02ClientMsgs.Height\",\"components\":[{\"name\":\"revisionNumber\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"revisionHeight\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"name\":\"consensusStatePreimage\",\"type\":\"tuple\",\"internalType\":\"structILineaLightClientMsgs.ConsensusState\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"stateRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"validators\",\"type\":\"address[]\",\"internalType\":\"address[]\"}]}]}],\"stateMutability\":\"pure\"}]",
	ID:  "Bindings",
}

// Bindings is an auto generated Go binding around an Ethereum contract.
type Bindings struct {
	abi abi.ABI
}

// GetABI returns the ABI associated with this contract binding.
func (c *Bindings) GetABI() abi.ABI {
	return c.abi
}

// NewBindings creates a new instance of Bindings.
func NewBindings() *Bindings {
	parsed, err := BindingsMetaData.ParseABI()
	if err != nil {
		panic(errors.New("invalid ABI: " + err.Error()))
	}
	return &Bindings{abi: *parsed}
}

// Instance creates a wrapper for a deployed contract instance at the given address.
// Use this to create the instance object passed to abigen v2 library functions Call, Transact, etc.
func (c *Bindings) Instance(backend bind.ContractBackend, addr common.Address) *bind.BoundContract {
	return bind.NewBoundContract(addr, c.abi, backend, backend, backend)
}

// PackClientState is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xf22212fc.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function clientState((address,(uint64,uint64),uint64,uint64,bool,(uint8,uint8)) state) pure returns((address,(uint64,uint64),uint64,uint64,bool,(uint8,uint8)))
func (bindings *Bindings) PackClientState(state ILineaLightClientMsgsClientState) []byte {
	enc, err := bindings.abi.Pack("clientState", state)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackClientState is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xf22212fc.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function clientState((address,(uint64,uint64),uint64,uint64,bool,(uint8,uint8)) state) pure returns((address,(uint64,uint64),uint64,uint64,bool,(uint8,uint8)))
func (bindings *Bindings) TryPackClientState(state ILineaLightClientMsgsClientState) ([]byte, error) {
	return bindings.abi.Pack("clientState", state)
}

// UnpackClientState is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0xf22212fc.
//
// Solidity: function clientState((address,(uint64,uint64),uint64,uint64,bool,(uint8,uint8)) state) pure returns((address,(uint64,uint64),uint64,uint64,bool,(uint8,uint8)))
func (bindings *Bindings) UnpackClientState(data []byte) (ILineaLightClientMsgsClientState, error) {
	out, err := bindings.abi.Unpack("clientState", data)
	if err != nil {
		return *new(ILineaLightClientMsgsClientState), err
	}
	out0 := *abi.ConvertType(out[0], new(ILineaLightClientMsgsClientState)).(*ILineaLightClientMsgsClientState)
	return out0, nil
}

// PackConflictingConsensusStatesMisbehaviour is the Go binding used to pack the parameters required for calling
// the contract method with ID 0x9ee3c6b6.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function conflictingConsensusStatesMisbehaviour(((uint64,uint64),(uint64,uint64),(uint64,bytes32,address[]),(uint64,bytes32,address[])) message) pure returns(((uint64,uint64),(uint64,uint64),(uint64,bytes32,address[]),(uint64,bytes32,address[])))
func (bindings *Bindings) PackConflictingConsensusStatesMisbehaviour(message ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour) []byte {
	enc, err := bindings.abi.Pack("conflictingConsensusStatesMisbehaviour", message)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackConflictingConsensusStatesMisbehaviour is the Go binding used to pack the parameters required for calling
// the contract method with ID 0x9ee3c6b6.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function conflictingConsensusStatesMisbehaviour(((uint64,uint64),(uint64,uint64),(uint64,bytes32,address[]),(uint64,bytes32,address[])) message) pure returns(((uint64,uint64),(uint64,uint64),(uint64,bytes32,address[]),(uint64,bytes32,address[])))
func (bindings *Bindings) TryPackConflictingConsensusStatesMisbehaviour(message ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour) ([]byte, error) {
	return bindings.abi.Pack("conflictingConsensusStatesMisbehaviour", message)
}

// UnpackConflictingConsensusStatesMisbehaviour is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0x9ee3c6b6.
//
// Solidity: function conflictingConsensusStatesMisbehaviour(((uint64,uint64),(uint64,uint64),(uint64,bytes32,address[]),(uint64,bytes32,address[])) message) pure returns(((uint64,uint64),(uint64,uint64),(uint64,bytes32,address[]),(uint64,bytes32,address[])))
func (bindings *Bindings) UnpackConflictingConsensusStatesMisbehaviour(data []byte) (ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour, error) {
	out, err := bindings.abi.Unpack("conflictingConsensusStatesMisbehaviour", data)
	if err != nil {
		return *new(ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour), err
	}
	out0 := *abi.ConvertType(out[0], new(ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour)).(*ILineaLightClientMsgsMsgConflictingConsensusStatesMisbehaviour)
	return out0, nil
}

// PackConflictingHeadersMisbehaviour is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xaa077ad7.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function conflictingHeadersMisbehaviour((((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])),((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[]))) message) pure returns((((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])),((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[]))))
func (bindings *Bindings) PackConflictingHeadersMisbehaviour(message ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour) []byte {
	enc, err := bindings.abi.Pack("conflictingHeadersMisbehaviour", message)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackConflictingHeadersMisbehaviour is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xaa077ad7.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function conflictingHeadersMisbehaviour((((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])),((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[]))) message) pure returns((((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])),((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[]))))
func (bindings *Bindings) TryPackConflictingHeadersMisbehaviour(message ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour) ([]byte, error) {
	return bindings.abi.Pack("conflictingHeadersMisbehaviour", message)
}

// UnpackConflictingHeadersMisbehaviour is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0xaa077ad7.
//
// Solidity: function conflictingHeadersMisbehaviour((((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])),((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[]))) message) pure returns((((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])),((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[]))))
func (bindings *Bindings) UnpackConflictingHeadersMisbehaviour(data []byte) (ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour, error) {
	out, err := bindings.abi.Unpack("conflictingHeadersMisbehaviour", data)
	if err != nil {
		return *new(ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour), err
	}
	out0 := *abi.ConvertType(out[0], new(ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour)).(*ILineaLightClientMsgsMsgConflictingHeadersMisbehaviour)
	return out0, nil
}

// PackConsensusState is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xc6fe84b1.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function consensusState((uint64,bytes32,address[]) state) pure returns((uint64,bytes32,address[]))
func (bindings *Bindings) PackConsensusState(state ILineaLightClientMsgsConsensusState) []byte {
	enc, err := bindings.abi.Pack("consensusState", state)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackConsensusState is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xc6fe84b1.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function consensusState((uint64,bytes32,address[]) state) pure returns((uint64,bytes32,address[]))
func (bindings *Bindings) TryPackConsensusState(state ILineaLightClientMsgsConsensusState) ([]byte, error) {
	return bindings.abi.Pack("consensusState", state)
}

// UnpackConsensusState is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0xc6fe84b1.
//
// Solidity: function consensusState((uint64,bytes32,address[]) state) pure returns((uint64,bytes32,address[]))
func (bindings *Bindings) UnpackConsensusState(data []byte) (ILineaLightClientMsgsConsensusState, error) {
	out, err := bindings.abi.Unpack("consensusState", data)
	if err != nil {
		return *new(ILineaLightClientMsgsConsensusState), err
	}
	out0 := *abi.ConvertType(out[0], new(ILineaLightClientMsgsConsensusState)).(*ILineaLightClientMsgsConsensusState)
	return out0, nil
}

// PackMembershipProof is the Go binding used to pack the parameters required for calling
// the contract method with ID 0x723e4e38.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function membershipProof(((uint64,bytes32,address[]),bytes[],bytes[]) proof) pure returns(((uint64,bytes32,address[]),bytes[],bytes[]))
func (bindings *Bindings) PackMembershipProof(proof ILineaLightClientMsgsMembershipProof) []byte {
	enc, err := bindings.abi.Pack("membershipProof", proof)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackMembershipProof is the Go binding used to pack the parameters required for calling
// the contract method with ID 0x723e4e38.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function membershipProof(((uint64,bytes32,address[]),bytes[],bytes[]) proof) pure returns(((uint64,bytes32,address[]),bytes[],bytes[]))
func (bindings *Bindings) TryPackMembershipProof(proof ILineaLightClientMsgsMembershipProof) ([]byte, error) {
	return bindings.abi.Pack("membershipProof", proof)
}

// UnpackMembershipProof is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0x723e4e38.
//
// Solidity: function membershipProof(((uint64,bytes32,address[]),bytes[],bytes[]) proof) pure returns(((uint64,bytes32,address[]),bytes[],bytes[]))
func (bindings *Bindings) UnpackMembershipProof(data []byte) (ILineaLightClientMsgsMembershipProof, error) {
	out, err := bindings.abi.Unpack("membershipProof", data)
	if err != nil {
		return *new(ILineaLightClientMsgsMembershipProof), err
	}
	out0 := *abi.ConvertType(out[0], new(ILineaLightClientMsgsMembershipProof)).(*ILineaLightClientMsgsMembershipProof)
	return out0, nil
}

// PackProofNodes is the Go binding used to pack the parameters required for calling
// the contract method with ID 0x0cab8d85.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function proofNodes(bytes[] nodes) pure returns(bytes[])
func (bindings *Bindings) PackProofNodes(nodes [][]byte) []byte {
	enc, err := bindings.abi.Pack("proofNodes", nodes)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackProofNodes is the Go binding used to pack the parameters required for calling
// the contract method with ID 0x0cab8d85.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function proofNodes(bytes[] nodes) pure returns(bytes[])
func (bindings *Bindings) TryPackProofNodes(nodes [][]byte) ([]byte, error) {
	return bindings.abi.Pack("proofNodes", nodes)
}

// UnpackProofNodes is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0x0cab8d85.
//
// Solidity: function proofNodes(bytes[] nodes) pure returns(bytes[])
func (bindings *Bindings) UnpackProofNodes(data []byte) ([][]byte, error) {
	out, err := bindings.abi.Unpack("proofNodes", data)
	if err != nil {
		return *new([][]byte), err
	}
	out0 := *abi.ConvertType(out[0], new([][]byte)).(*[][]byte)
	return out0, nil
}

// PackSubmitMisbehaviour is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xc8420ce9.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function submitMisbehaviour((uint8,bytes) message) pure returns((uint8,bytes))
func (bindings *Bindings) PackSubmitMisbehaviour(message ILineaLightClientMsgsMsgSubmitMisbehaviour) []byte {
	enc, err := bindings.abi.Pack("submitMisbehaviour", message)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackSubmitMisbehaviour is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xc8420ce9.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function submitMisbehaviour((uint8,bytes) message) pure returns((uint8,bytes))
func (bindings *Bindings) TryPackSubmitMisbehaviour(message ILineaLightClientMsgsMsgSubmitMisbehaviour) ([]byte, error) {
	return bindings.abi.Pack("submitMisbehaviour", message)
}

// UnpackSubmitMisbehaviour is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0xc8420ce9.
//
// Solidity: function submitMisbehaviour((uint8,bytes) message) pure returns((uint8,bytes))
func (bindings *Bindings) UnpackSubmitMisbehaviour(data []byte) (ILineaLightClientMsgsMsgSubmitMisbehaviour, error) {
	out, err := bindings.abi.Unpack("submitMisbehaviour", data)
	if err != nil {
		return *new(ILineaLightClientMsgsMsgSubmitMisbehaviour), err
	}
	out0 := *abi.ConvertType(out[0], new(ILineaLightClientMsgsMsgSubmitMisbehaviour)).(*ILineaLightClientMsgsMsgSubmitMisbehaviour)
	return out0, nil
}

// PackUpdateClient is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xed9d1c26.  This method will panic if any
// invalid/nil inputs are passed.
//
// Solidity: function updateClient(((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])) message) pure returns(((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])))
func (bindings *Bindings) PackUpdateClient(message ILineaLightClientMsgsMsgUpdateClient) []byte {
	enc, err := bindings.abi.Pack("updateClient", message)
	if err != nil {
		panic(err)
	}
	return enc
}

// TryPackUpdateClient is the Go binding used to pack the parameters required for calling
// the contract method with ID 0xed9d1c26.  This method will return an error
// if any inputs are invalid/nil.
//
// Solidity: function updateClient(((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])) message) pure returns(((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])))
func (bindings *Bindings) TryPackUpdateClient(message ILineaLightClientMsgsMsgUpdateClient) ([]byte, error) {
	return bindings.abi.Pack("updateClient", message)
}

// UnpackUpdateClient is the Go binding that unpacks the parameters returned
// from invoking the contract method with ID 0xed9d1c26.
//
// Solidity: function updateClient(((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])) message) pure returns(((uint64,uint32,uint64,address,bytes32,bytes32,bytes32),bytes,address[],bytes[],(uint64,uint64),(uint64,bytes32,address[])))
func (bindings *Bindings) UnpackUpdateClient(data []byte) (ILineaLightClientMsgsMsgUpdateClient, error) {
	out, err := bindings.abi.Unpack("updateClient", data)
	if err != nil {
		return *new(ILineaLightClientMsgsMsgUpdateClient), err
	}
	out0 := *abi.ConvertType(out[0], new(ILineaLightClientMsgsMsgUpdateClient)).(*ILineaLightClientMsgsMsgUpdateClient)
	return out0, nil
}
