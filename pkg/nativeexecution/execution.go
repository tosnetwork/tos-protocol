// Package nativeexecution implements the Phase 5B TVM execution commitment.
// It deliberately lives outside nativeprotocol: Phase 5A canonical CBOR stays
// portable while this package binds it to the exact typed state transition a
// TOS contract executes.
package nativeexecution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const (
	Version              = "tos_native_registry_tvm_v1"
	SignatureAlgorithm   = "ed25519"
	actionMagic          = 0x4e525631 // NRV1
	stateMagic           = 0x4e535631 // NSV1
	signatureMagic       = 0x4e534731 // NSG1
	SubmitOpcode         = 0x4e520001
	MaxExecutionBOCBytes = 49152
)

var addressPattern = regexp.MustCompile(`^(-?(?:0|[1-9][0-9]*)):([0-9a-f]{64})$`)

type ContractIdentity struct {
	Network             nativeprotocol.NetworkDomain
	Address             string
	ActionAnchorAddress string
	AllowedCodeHash     string
}

type Signature struct {
	Version         string
	Algorithm       string
	KeyID           string
	SignatureBase64 string
}

type Execution struct {
	Version                     string
	ContractAddress             string
	ActionAnchorAddress         string
	ContractCodeHash            string
	PortableActionDigest        string
	ActionCellBOCBase64         string
	ActionCellHash              string
	PreviousTVMStateHash        string
	ExpectedTVMStateHash        string
	ExpectedPortableStateDigest string
	AuthoritySignatures         []Signature
	NewOwnerSignatures          []Signature
}

type Unsigned struct {
	Execution Execution
	Action    *cell.Cell
	NextState nativeprotocol.RegistryState
}

// Build derives both logical and TVM states. A client signs the returned
// execution; a relay is not permitted to derive or alter it after signing.
func Build(previous *nativeprotocol.RegistryState, action nativeprotocol.RegistryAction, expectedAuthorityPolicyDigest string, authorityPolicy nativeprotocol.ControllerPolicy, newOwnerPolicy *nativeprotocol.ControllerPolicy, observedUnixSeconds uint64, contract ContractIdentity) (Unsigned, error) {
	if err := validateContract(contract); err != nil {
		return Unsigned{}, err
	}
	canonical, err := nativeprotocol.CanonicalAction(action)
	if err != nil {
		return Unsigned{}, err
	}
	actionDigest, err := nativeprotocol.ActionDigest(action)
	if err != nil {
		return Unsigned{}, err
	}
	policyDigest, err := nativeprotocol.ControllerPolicyDigest(authorityPolicy)
	if err != nil || policyDigest != action.PolicyDigest {
		return Unsigned{}, errors.New("authority policy does not match action")
	}
	if action.Kind == nativeprotocol.ActionTransferCapability {
		if newOwnerPolicy == nil {
			return Unsigned{}, errors.New("transfer requires new-owner policy")
		}
	} else if newOwnerPolicy != nil {
		return Unsigned{}, errors.New("unexpected new-owner policy")
	}
	next, err := nativeprotocol.DeriveNextState(previous, action, expectedAuthorityPolicyDigest, observedUnixSeconds)
	if err != nil {
		return Unsigned{}, err
	}
	portableStateDigest, err := nativeprotocol.StateDigest(next)
	if err != nil {
		return Unsigned{}, err
	}
	previousHash := make([]byte, 32)
	if previous != nil {
		previousCell, err := stateCell(*previous)
		if err != nil {
			return Unsigned{}, err
		}
		copy(previousHash, previousCell.Hash())
	}
	nextCell, err := stateCell(next)
	if err != nil {
		return Unsigned{}, err
	}
	nextHash := nextCell.Hash()
	actionCell, err := buildActionCell(action, canonical, actionDigest, portableStateDigest, previousHash, nextHash, previous, next, authorityPolicy, newOwnerPolicy, contract)
	if err != nil {
		return Unsigned{}, err
	}
	boc := actionCell.ToBOC()
	if len(boc) > MaxExecutionBOCBytes {
		return Unsigned{}, errors.New("native execution BOC exceeds frozen limit")
	}
	return Unsigned{
		Execution: Execution{
			Version: Version, ContractAddress: contract.Address, ActionAnchorAddress: contract.ActionAnchorAddress, ContractCodeHash: contract.AllowedCodeHash,
			PortableActionDigest: actionDigest, ActionCellBOCBase64: base64.RawURLEncoding.EncodeToString(boc),
			ActionCellHash: digest(actionCell.Hash()), PreviousTVMStateHash: digestAllowZero(previousHash),
			ExpectedTVMStateHash: digest(nextHash), ExpectedPortableStateDigest: portableStateDigest,
		},
		Action: actionCell, NextState: next,
	}, nil
}

func Sign(privateKey ed25519.PrivateKey, keyID string, execution Execution) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !validKeyID(keyID) {
		return Signature{}, errors.New("invalid execution signing key")
	}
	message, err := signatureCellHash(keyID, execution)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Version: Version, Algorithm: SignatureAlgorithm, KeyID: keyID, SignatureBase64: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

func Verify(publicKey ed25519.PublicKey, signature Signature, execution Execution) error {
	if len(publicKey) != ed25519.PublicKeySize || signature.Version != Version || signature.Algorithm != SignatureAlgorithm || !validKeyID(signature.KeyID) {
		return errors.New("invalid execution signature metadata")
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature.SignatureBase64)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("invalid execution signature encoding")
	}
	message, err := signatureCellHash(signature.KeyID, execution)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, raw) {
		return errors.New("invalid execution signature")
	}
	return nil
}

// VerifySet requires the TVM signature set to use exactly the same sorted key
// identities as the independently validated Phase 5A semantic set. This keeps
// threshold and purpose evaluation single-sourced in nativeprotocol while
// proving every counted controller also authorized the concrete TVM action.
func VerifySet(policy nativeprotocol.ControllerPolicy, semantic []nativeprotocol.Signature, executionSignatures []Signature, execution Execution) error {
	if len(semantic) != len(executionSignatures) || !SortedSignatures(executionSignatures) {
		return errors.New("execution and semantic signature sets differ")
	}
	keys := make(map[string]nativeprotocol.ControllerKey, len(policy.Controllers))
	for _, key := range policy.Controllers {
		keys[key.KeyID] = key
	}
	for index, signature := range executionSignatures {
		if semantic[index].KeyID != signature.KeyID {
			return errors.New("execution signer identity mismatch")
		}
		key, ok := keys[signature.KeyID]
		if !ok {
			return errors.New("unknown execution signer")
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKeyBase64)
		if err != nil {
			return err
		}
		if err := Verify(ed25519.PublicKey(publicKey), signature, execution); err != nil {
			return err
		}
	}
	return nil
}

func SameUnsigned(left, right Execution) bool {
	return left.Version == right.Version && left.ContractAddress == right.ContractAddress &&
		left.ActionAnchorAddress == right.ActionAnchorAddress &&
		left.ContractCodeHash == right.ContractCodeHash && left.PortableActionDigest == right.PortableActionDigest &&
		left.ActionCellHash == right.ActionCellHash &&
		left.PreviousTVMStateHash == right.PreviousTVMStateHash && left.ExpectedTVMStateHash == right.ExpectedTVMStateHash &&
		left.ExpectedPortableStateDigest == right.ExpectedPortableStateDigest
}

// Validate proves that the BOC, hashes and portable semantics are the exact
// jointly signed values. It does not consult local or chain state.
func Validate(execution Execution, action nativeprotocol.RegistryAction, contract ContractIdentity) error {
	if execution.Version != Version || execution.ContractAddress != contract.Address || execution.ActionAnchorAddress != contract.ActionAnchorAddress || execution.ContractCodeHash != contract.AllowedCodeHash {
		return errors.New("native execution contract binding mismatch")
	}
	if err := validateContract(contract); err != nil {
		return err
	}
	actionDigest, err := nativeprotocol.ActionDigest(action)
	if err != nil || execution.PortableActionDigest != actionDigest {
		return errors.New("native execution portable action mismatch")
	}
	boc, err := base64.RawURLEncoding.DecodeString(execution.ActionCellBOCBase64)
	if err != nil || len(boc) == 0 || len(boc) > MaxExecutionBOCBytes || base64.RawURLEncoding.EncodeToString(boc) != execution.ActionCellBOCBase64 {
		return errors.New("invalid native execution BOC")
	}
	root, err := cell.FromBOC(boc)
	if err != nil || digest(root.Hash()) != execution.ActionCellHash {
		return errors.New("native execution BOC/hash mismatch")
	}
	return nil
}

// MessageBody creates the production contract body. Query identity is the
// first 64 bits of the deterministic action cell hash and therefore stable
// across retries and relayers.
func MessageBody(execution Execution) (*cell.Cell, error) {
	boc, err := base64.RawURLEncoding.DecodeString(execution.ActionCellBOCBase64)
	if err != nil {
		return nil, err
	}
	action, err := cell.FromBOC(boc)
	if err != nil || digest(action.Hash()) != execution.ActionCellHash {
		return nil, errors.New("execution action cell mismatch")
	}
	queryID := uint64(0)
	for _, value := range action.Hash()[:8] {
		queryID = queryID<<8 | uint64(value)
	}
	authority, err := signatureListCell(execution.AuthoritySignatures, execution)
	if err != nil {
		return nil, err
	}
	newOwner, err := signatureListCell(execution.NewOwnerSignatures, execution)
	if err != nil {
		return nil, err
	}
	return cell.BeginCell().MustStoreUInt(SubmitOpcode, 32).MustStoreUInt(queryID, 64).MustStoreRef(action).MustStoreRef(authority).MustStoreRef(newOwner).EndCell(), nil
}

func signatureListCell(signatures []Signature, execution Execution) (*cell.Cell, error) {
	if len(signatures) > 64 || !SortedSignatures(signatures) {
		return nil, errors.New("invalid execution signature list")
	}
	var next *cell.Cell
	for index := len(signatures) - 1; index >= 0; index-- {
		signature := signatures[index]
		raw, err := base64.RawURLEncoding.DecodeString(signature.SignatureBase64)
		if err != nil || len(raw) != 64 {
			return nil, errors.New("invalid execution signature")
		}
		commitment, err := signatureCommitmentCell(signature.KeyID, execution)
		if err != nil {
			return nil, err
		}
		builder := cell.BeginCell().MustStoreSlice(sha256Bytes([]byte(signature.KeyID)), 256).MustStoreSlice(raw, 512).MustStoreRef(commitment)
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
	}
	root := cell.BeginCell().MustStoreUInt(uint64(len(signatures)), 8)
	if next != nil {
		root.MustStoreRef(next)
	}
	return root.EndCell(), nil
}

func buildActionCell(action nativeprotocol.RegistryAction, canonical []byte, actionDigest, stateDigest string, previousHash, nextHash []byte, previous *nativeprotocol.RegistryState, next nativeprotocol.RegistryState, authorityPolicy nativeprotocol.ControllerPolicy, newOwnerPolicy *nativeprotocol.ControllerPolicy, contract ContractIdentity) (*cell.Cell, error) {
	flags := uint64(0)
	if action.CapabilityID != "" {
		flags |= 1
	}
	header := cell.BeginCell().MustStoreUInt(actionMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(kindCode(action.Kind)), 8).MustStoreUInt(flags, 8).
		MustStoreUInt(action.Generation, 64).MustStoreUInt(action.Sequence, 64).
		MustStoreSlice(mustDigest(actionDigest), 256).MustStoreSlice(previousHash, 256).MustStoreSlice(nextHash, 256)
	identity := cell.BeginCell().MustStoreSlice(mustID(action.AgentID, "agent"), 256).
		MustStoreSlice(mustOptionalID(action.CapabilityID, "cap"), 256).
		MustStoreRef(stringCell(action.CapabilityVersion)).MustStoreRef(networkCell(contract.Network, contract.Address, contract.AllowedCodeHash)).EndCell()
	commitments := cell.BeginCell().MustStoreSlice(mustDigest(action.PolicyDigest), 256).
		MustStoreSlice(mustDigest(action.PayloadDigest), 256).MustStoreSlice(mustDigest(stateDigest), 256).
		MustStoreRef(stringCell(action.NonceBase64)).EndCell()
	payload, err := payloadControlCell(action)
	if err != nil {
		return nil, err
	}
	preimage := append([]byte("TOS-PROTOCOL-CBOR\x00\x00\x1d"+nativeprotocol.RegistryActionDomain), canonical...)
	policy, err := policyCell(authorityPolicy)
	if err != nil {
		return nil, err
	}
	var transitionPolicy *nativeprotocol.ControllerPolicy
	switch action.Kind {
	case nativeprotocol.ActionRegisterAgent:
		transitionPolicy = &authorityPolicy
	case nativeprotocol.ActionUpdateAgentPolicy:
		var p nativeprotocol.UpdatePolicyPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		value, err := nativeprotocol.DecodeControllerPolicy(p.NewPolicyCBORBase64, p.NewPolicyDigest)
		if err != nil {
			return nil, err
		}
		transitionPolicy = &value
	case nativeprotocol.ActionInitiateRecovery:
		var p nativeprotocol.InitiateRecoveryPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		value, err := nativeprotocol.DecodeControllerPolicy(p.NewPolicyCBORBase64, p.NewPolicyDigest)
		if err != nil {
			return nil, err
		}
		transitionPolicy = &value
	case nativeprotocol.ActionTransferCapability:
		transitionPolicy = newOwnerPolicy
	}
	newPolicy := cell.BeginCell().EndCell()
	if transitionPolicy != nil {
		newPolicy, err = policyCell(*transitionPolicy)
		if err != nil {
			return nil, err
		}
	}
	nextState, err := stateCell(next)
	if err != nil {
		return nil, err
	}
	statePair := cell.BeginCell().MustStoreBoolBit(previous != nil)
	if previous != nil {
		previousState, err := stateCell(*previous)
		if err != nil {
			return nil, err
		}
		statePair.MustStoreRef(previousState)
	}
	statePair.MustStoreRef(nextState)
	controls := cell.BeginCell().MustStoreRef(payload).MustStoreRef(policy).MustStoreRef(newPolicy).MustStoreRef(statePair.EndCell()).EndCell()
	return header.MustStoreRef(identity).MustStoreRef(commitments).MustStoreRef(controls).MustStoreRef(bytesCell(preimage)).EndCell(), nil
}

func policyCell(policy nativeprotocol.ControllerPolicy) (*cell.Cell, error) {
	_, policyDigest, err := nativeprotocol.EncodeControllerPolicy(policy)
	if err != nil {
		return nil, err
	}
	var next *cell.Cell
	for index := len(policy.Controllers) - 1; index >= 0; index-- {
		key := policy.Controllers[index]
		publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKeyBase64)
		if err != nil {
			return nil, err
		}
		controller := cell.BeginCell().MustStoreSlice(sha256Bytes([]byte(key.KeyID)), 256).MustStoreSlice(publicKey, 256).
			MustStoreUInt(uint64(key.Weight), 32).MustStoreUInt(purposeMask(key.Purposes), 16).MustStoreBoolBit(stringIn(key.KeyID, policy.RecoveryKeyIDs)).
			MustStoreRef(stringCell(key.KeyID))
		if next != nil {
			controller.MustStoreRef(next)
		}
		next = controller.EndCell()
	}
	root := cell.BeginCell().MustStoreUInt(uint64(policy.Threshold), 32).MustStoreUInt(uint64(policy.RecoveryThreshold), 32).
		MustStoreUInt(policy.RecoveryTimelock, 64).MustStoreUInt(uint64(len(policy.Controllers)), 8).MustStoreSlice(mustDigest(policyDigest), 256)
	if next != nil {
		root.MustStoreRef(next)
	}
	return root.EndCell(), nil
}

func purposeMask(values []string) uint64 {
	var mask uint64
	for _, value := range values {
		for index, known := range []string{"agent_control", "delegation", "recovery", "capability_control", "quote", "receipt", "invocation", "funding", "release", "dispute", "settlement"} {
			if value == known {
				mask |= 1 << index
			}
		}
	}
	return mask
}
func stringIn(value string, values []string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}

func stateCell(state nativeprotocol.RegistryState) (*cell.Cell, error) {
	state, err := nativeprotocol.CanonicalState(state)
	if err != nil {
		return nil, err
	}
	portable, err := codec.Marshal(state)
	if err != nil {
		return nil, err
	}
	last := mustDigest(state.LastActionDigest)
	pred := mustOptionalDigest(state.PredecessorStateDigest)
	root := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(objectKindCode(state.ObjectKind), 8).MustStoreBoolBit(state.Tombstoned).
		MustStoreUInt(state.Generation, 64).MustStoreUInt(state.Sequence, 64).
		MustStoreSlice(last, 256).MustStoreSlice(pred, 256)
	identity := cell.BeginCell().MustStoreSlice(mustOptionalID(state.AgentID, "agent"), 256).
		MustStoreSlice(mustOptionalID(state.CapabilityID, "cap"), 256).
		MustStoreSlice(mustOptionalID(state.OwnerAgentID, "agent"), 256).
		MustStoreRef(cell.BeginCell().MustStoreSlice(mustOptionalID(state.CapabilityBootstrapOwnerAgentID, "agent"), 256).EndCell()).EndCell()
	authority := cell.BeginCell().MustStoreSlice(mustOptionalDigest(state.CurrentPolicyDigest), 256).
		MustStoreSlice(mustOptionalDigest(state.AgentBootstrapPolicyDigest), 256).
		MustStoreRef(stringCell(state.AgentNonceBase64)).MustStoreRef(stringCell(state.CapabilityNonceBase64)).EndCell()
	if state.ObjectKind == "agent" {
		policy, err := nativeprotocol.DecodeControllerPolicy(state.CurrentPolicyCBORBase64, state.CurrentPolicyDigest)
		if err != nil {
			return nil, err
		}
		policyValue, err := policyCell(policy)
		if err != nil {
			return nil, err
		}
		authority = cell.BeginCell().MustStoreSlice(mustOptionalDigest(state.CurrentPolicyDigest), 256).
			MustStoreSlice(mustOptionalDigest(state.AgentBootstrapPolicyDigest), 256).
			MustStoreRef(stringCell(state.AgentNonceBase64)).MustStoreRef(stringCell(state.CapabilityNonceBase64)).MustStoreRef(policyValue).EndCell()
	}
	collections := stateCollectionsCell(state)
	portablePreimage := append([]byte("TOS-PROTOCOL-CBOR\x00\x00\x1c"+nativeprotocol.RegistryStateDomain), portable...)
	return root.MustStoreRef(identity).MustStoreRef(authority).MustStoreRef(collections).MustStoreRef(bytesCell(portablePreimage)).EndCell(), nil
}

func stateCollectionsCell(state nativeprotocol.RegistryState) *cell.Cell {
	b := cell.BeginCell().MustStoreUInt(uint64(len(state.DelegationActionDigests)), 16).MustStoreUInt(uint64(len(state.CapabilityVersions)), 16)
	delegations := cell.NewDict(256)
	for _, value := range state.DelegationActionDigests {
		_ = delegations.Set(cell.BeginCell().MustStoreSlice(mustDigest(value), 256).EndCell(), cell.BeginCell().MustStoreBoolBit(true).EndCell())
	}
	versions := cell.NewDict(256)
	for _, value := range state.CapabilityVersions {
		h := sha256.Sum256([]byte(value.Version))
		_ = versions.Set(cell.BeginCell().MustStoreSlice(h[:], 256).EndCell(), cell.BeginCell().MustStoreSlice(mustDigest(value.PayloadDigest), 256).MustStoreBoolBit(value.Revoked).EndCell())
	}
	pending := cell.BeginCell()
	if state.PendingRecovery.InitiationActionDigest != "" {
		policy, err := nativeprotocol.DecodeControllerPolicy(state.PendingRecovery.NewPolicyCBORBase64, state.PendingRecovery.NewPolicyDigest)
		if err != nil {
			panic(err)
		}
		policyValue, err := policyCell(policy)
		if err != nil {
			panic(err)
		}
		pending.MustStoreBoolBit(true).MustStoreSlice(mustDigest(state.PendingRecovery.InitiationActionDigest), 256).
			MustStoreSlice(mustDigest(state.PendingRecovery.NewPolicyDigest), 256).
			MustStoreUInt(state.PendingRecovery.ExecuteAfterUnixSeconds, 64).
			MustStoreRef(stringCell(state.PendingRecovery.NewPolicyCBORBase64)).MustStoreRef(policyValue)
	} else {
		pending.MustStoreBoolBit(false)
	}
	return b.MustStoreDict(delegations).MustStoreDict(versions).MustStoreRef(pending.EndCell()).EndCell()
}

func networkCell(network nativeprotocol.NetworkDomain, contractAddress, codeHash string) *cell.Cell {
	wc, account, err := parseAddress(contractAddress)
	if err != nil {
		panic(err)
	}
	return cell.BeginCell().MustStoreSlice(mustDigest(network.GenesisRootHash), 256).
		MustStoreSlice(mustDigest(network.GenesisFileHash), 256).MustStoreInt(int64(wc), 32).
		MustStoreSlice(account, 256).MustStoreRef(stringCell(network.NetworkID)).
		MustStoreRef(cell.BeginCell().MustStoreSlice(mustDigest(codeHash), 256).EndCell()).EndCell()
}

func payloadControlCell(action nativeprotocol.RegistryAction) (*cell.Cell, error) {
	b := cell.BeginCell().MustStoreUInt(uint64(kindCode(action.Kind)), 8)
	switch action.Kind {
	case nativeprotocol.ActionRegisterAgent:
		var p nativeprotocol.RegisterAgentPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		bootstrap := nativeprotocol.AgentBootstrap{Version: nativeprotocol.Version, Network: action.Network, ObjectNonceBase64: p.ObjectNonceBase64, InitialControllerPolicy: p.InitialPolicyDigest}
		encoded, err := codec.Marshal(bootstrap)
		if err != nil {
			return nil, err
		}
		preimage := append([]byte("TOS-PROTOCOL-CBOR\x00\x00\x16"+nativeprotocol.AgentIDDomain), encoded...)
		b.MustStoreSlice(mustNonce(p.ObjectNonceBase64), 256).MustStoreSlice(mustDigest(p.InitialPolicyDigest), 256).MustStoreRef(stringCell(p.InitialPolicyCBORBase64)).MustStoreRef(bytesCell(preimage)).MustStoreRef(stringCell(p.ObjectNonceBase64))
	case nativeprotocol.ActionUpdateAgentPolicy:
		var p nativeprotocol.UpdatePolicyPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		b.MustStoreSlice(mustDigest(p.NewPolicyDigest), 256).MustStoreRef(stringCell(p.NewPolicyCBORBase64))
	case nativeprotocol.ActionInitiateRecovery:
		var p nativeprotocol.InitiateRecoveryPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		b.MustStoreSlice(mustDigest(p.NewPolicyDigest), 256).MustStoreUInt(p.ExecuteAfterUnixSeconds, 64).MustStoreRef(stringCell(p.NewPolicyCBORBase64))
	case nativeprotocol.ActionRecoverAgent:
		var p nativeprotocol.RecoverAgentPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		b.MustStoreSlice(mustDigest(p.NewPolicyDigest), 256).MustStoreSlice(mustDigest(p.InitiationActionDigest), 256).MustStoreUInt(p.ExecuteAfterUnixSeconds, 64)
	case nativeprotocol.ActionRegisterCapability:
		var p nativeprotocol.RegisterCapabilityPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		bootstrap := nativeprotocol.CapabilityBootstrap{Version: nativeprotocol.Version, Network: action.Network, OwnerAgentID: p.Version.OwnerAgentID, ObjectNonceBase64: p.ObjectNonceBase64}
		encoded, err := codec.Marshal(bootstrap)
		if err != nil {
			return nil, err
		}
		preimage := append([]byte("TOS-PROTOCOL-CBOR\x00\x00\x1b"+nativeprotocol.CapabilityIDDomain), encoded...)
		version, err := capabilityVersionCell(p.Version)
		if err != nil {
			return nil, err
		}
		b.MustStoreSlice(mustNonce(p.ObjectNonceBase64), 256).MustStoreSlice(mustID(p.Version.OwnerAgentID, "agent"), 256).
			MustStoreRef(bytesCell(preimage)).MustStoreRef(stringCell(p.ObjectNonceBase64)).MustStoreRef(version)
	case nativeprotocol.ActionTransferCapability:
		var p nativeprotocol.TransferCapabilityPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		b.MustStoreSlice(mustID(p.CurrentOwnerAgentID, "agent"), 256).MustStoreSlice(mustID(p.NewOwnerAgentID, "agent"), 256).MustStoreSlice(mustDigest(p.NewOwnerPolicyDigest), 256).MustStoreRef(stringCell(p.NewOwnerPolicyCBORBase64))
	case nativeprotocol.ActionRevokeAgent, nativeprotocol.ActionRevokeCapability:
		var p nativeprotocol.RevocationPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		scope := uint64(0)
		if p.Scope == "agent" {
			scope = 1
		} else if p.Scope == "lineage" {
			scope = 2
		} else if p.Scope == "version" {
			scope = 3
		}
		b.MustStoreUInt(scope, 8).MustStoreRef(stringCell(p.Scope)).MustStoreRef(stringCell(p.ReasonCode))
	case nativeprotocol.ActionDelegateAgent:
		var p nativeprotocol.DelegationPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		b.MustStoreUInt(p.ValidFromCheckpoint, 64).MustStoreUInt(p.ValidUntilCheckpoint, 64).
			MustStoreUInt(p.MaxStalenessCheckpoints, 64).MustStoreRef(stringCell(p.DelegateKeyID)).
			MustStoreRef(stringListCell(p.Purposes)).MustStoreRef(stringListCell(p.Resources))
	case nativeprotocol.ActionUpdateCapability:
		var p nativeprotocol.CapabilityVersionPayload
		if err := nativeprotocol.DecodePayload(action, &p); err != nil {
			return nil, err
		}
		version, err := capabilityVersionCell(p)
		if err != nil {
			return nil, err
		}
		b.MustStoreRef(version)
	default:
		return nil, errors.New("unsupported Native typed payload")
	}
	return b.EndCell(), nil
}

func capabilityVersionCell(value nativeprotocol.CapabilityVersionPayload) (*cell.Cell, error) {
	manifest := cell.BeginCell().MustStoreSlice(mustDigest(value.Manifest.Digest), 256).
		MustStoreUInt(value.Manifest.SizeBytes, 64).MustStoreRef(stringCell(value.Manifest.MediaType)).
		MustStoreRef(stringListCell(value.Manifest.Locations)).EndCell()
	var endpointNext *cell.Cell
	for index := len(value.Endpoints) - 1; index >= 0; index-- {
		endpoint := value.Endpoints[index]
		builder := cell.BeginCell().MustStoreSlice(mustDigest(endpoint.EndpointDigest), 256).
			MustStoreRef(stringCell(endpoint.Transport)).MustStoreRef(stringCell(endpoint.RecipientKeyID))
		if endpointNext != nil {
			builder.MustStoreRef(endpointNext)
		}
		endpointNext = builder.EndCell()
	}
	endpoints := cell.BeginCell().MustStoreUInt(uint64(len(value.Endpoints)), 16)
	if endpointNext != nil {
		endpoints.MustStoreRef(endpointNext)
	}
	signers := cell.BeginCell().MustStoreRef(stringListCell(value.QuoteSignerKeyIDs)).
		MustStoreRef(stringListCell(value.ReceiptSignerKeyIDs)).EndCell()
	return cell.BeginCell().MustStoreSlice(mustID(value.OwnerAgentID, "agent"), 256).
		MustStoreUInt(value.ValidFromCheckpoint, 64).MustStoreUInt(value.ValidUntilCheckpoint, 64).
		MustStoreRef(manifest).MustStoreRef(endpoints.EndCell()).MustStoreRef(signers).EndCell(), nil
}

func stringListCell(values []string) *cell.Cell {
	var next *cell.Cell
	for index := len(values) - 1; index >= 0; index-- {
		builder := cell.BeginCell().MustStoreRef(stringCell(values[index]))
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
	}
	root := cell.BeginCell().MustStoreUInt(uint64(len(values)), 16)
	if next != nil {
		root.MustStoreRef(next)
	}
	return root.EndCell()
}

func signatureCellHash(keyID string, execution Execution) ([]byte, error) {
	root, err := signatureCommitmentCell(keyID, execution)
	if err != nil {
		return nil, err
	}
	return root.Hash(), nil
}

func signatureCommitmentCell(keyID string, execution Execution) (*cell.Cell, error) {
	if execution.Version != Version || !validKeyID(keyID) {
		return nil, errors.New("invalid execution signature tuple")
	}
	wc, account, err := parseAddress(execution.ContractAddress)
	if err != nil {
		return nil, err
	}
	anchorWC, anchorAccount, err := parseAddress(execution.ActionAnchorAddress)
	if err != nil {
		return nil, err
	}
	root := cell.BeginCell().MustStoreUInt(signatureMagic, 32).MustStoreUInt(1, 16).
		MustStoreSlice(sha256Bytes([]byte(keyID)), 256).MustStoreInt(int64(wc), 32).
		MustStoreSlice(account, 256).
		MustStoreRef(cell.BeginCell().MustStoreSlice(mustDigest(execution.ContractCodeHash), 256).
			MustStoreSlice(mustDigest(execution.PortableActionDigest), 256).EndCell()).
		MustStoreRef(cell.BeginCell().MustStoreSlice(mustDigest(execution.ActionCellHash), 256).
			MustStoreSlice(mustDigestAllowZero(execution.PreviousTVMStateHash), 256).
			MustStoreSlice(mustDigest(execution.ExpectedTVMStateHash), 256).EndCell()).
		MustStoreRef(cell.BeginCell().MustStoreSlice(mustDigest(execution.ExpectedPortableStateDigest), 256).
			MustStoreInt(int64(anchorWC), 32).MustStoreSlice(anchorAccount, 256).EndCell()).EndCell()
	return root, nil
}

func validateContract(value ContractIdentity) error {
	if err := value.Network.Validate(); err != nil {
		return err
	}
	if _, _, err := parseAddress(value.Address); err != nil {
		return err
	}
	if _, _, err := parseAddress(value.ActionAnchorAddress); err != nil {
		return err
	}
	if _, err := digestBytes(value.AllowedCodeHash, false); err != nil {
		return err
	}
	return nil
}
func parseAddress(value string) (int32, []byte, error) {
	m := addressPattern.FindStringSubmatch(value)
	if len(m) != 3 || m[1] == "-0" {
		return 0, nil, errors.New("noncanonical contract address")
	}
	w, err := strconv.ParseInt(m[1], 10, 32)
	if err != nil {
		return 0, nil, err
	}
	raw, err := hex.DecodeString(m[2])
	return int32(w), raw, err
}
func kindCode(kind nativeprotocol.ActionKind) uint8 {
	all := []nativeprotocol.ActionKind{nativeprotocol.ActionRegisterAgent, nativeprotocol.ActionUpdateAgentPolicy, nativeprotocol.ActionDelegateAgent, nativeprotocol.ActionInitiateRecovery, nativeprotocol.ActionRecoverAgent, nativeprotocol.ActionRevokeAgent, nativeprotocol.ActionRegisterCapability, nativeprotocol.ActionUpdateCapability, nativeprotocol.ActionTransferCapability, nativeprotocol.ActionRevokeCapability}
	for i, value := range all {
		if kind == value {
			return uint8(i + 1)
		}
	}
	return 0
}
func objectKindCode(value string) uint64 {
	if value == "agent" {
		return 1
	}
	return 2
}
func bytesCell(value []byte) *cell.Cell {
	return cell.BeginCell().MustStoreBinarySnake(value).EndCell()
}
func stringCell(value string) *cell.Cell  { return bytesCell([]byte(value)) }
func sha256Bytes(value []byte) []byte     { sum := sha256.Sum256(value); return sum[:] }
func digest(value []byte) string          { return "sha256:" + hex.EncodeToString(value) }
func digestAllowZero(value []byte) string { return digest(value) }
func mustDigest(value string) []byte {
	out, err := digestBytes(value, false)
	if err != nil {
		panic(err)
	}
	return out
}
func mustOptionalDigest(value string) []byte {
	if value == "" {
		return make([]byte, 32)
	}
	return mustDigest(value)
}
func mustDigestAllowZero(value string) []byte {
	out, err := digestBytes(value, true)
	if err != nil {
		panic(err)
	}
	return out
}
func digestBytes(value string, allowZero bool) ([]byte, error) {
	prefix := "sha256:"
	if strings.HasPrefix(value, "tvm-cell-sha256:") {
		prefix = "tvm-cell-sha256:"
	}
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("invalid digest")
	}
	out, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(out) != 32 {
		return nil, errors.New("invalid digest")
	}
	if !allowZero && bytes.Equal(out, make([]byte, 32)) {
		return nil, errors.New("zero digest")
	}
	return out, nil
}
func mustID(value, prefix string) []byte {
	out, err := idBytes(value, prefix)
	if err != nil {
		panic(err)
	}
	return out
}
func mustOptionalID(value, prefix string) []byte {
	if value == "" {
		return make([]byte, 32)
	}
	return mustID(value, prefix)
}
func idBytes(value, prefix string) ([]byte, error) {
	p := prefix + "_"
	if !strings.HasPrefix(value, p) || len(value) != len(p)+64 {
		return nil, errors.New("invalid native id")
	}
	return hex.DecodeString(value[len(p):])
}
func mustNonce(value string) []byte {
	out, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(out) != 32 {
		panic("invalid nonce")
	}
	return out
}
func mustJSON(value interface{}) []byte {
	out, err := codec.Marshal(value)
	if err != nil {
		panic(err)
	}
	return out
}
func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i, c := range []byte(value) {
		if (i == 0 && !isAlphaNum(c)) || (!isAlphaNum(c) && c != '.' && c != '_' && c != ':' && c != '-') {
			return false
		}
	}
	return true
}
func isAlphaNum(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// SortedSignatures rejects duplicates before weighted authorization.
func SortedSignatures(values []Signature) bool {
	return sort.SliceIsSorted(values, func(i, j int) bool { return values[i].KeyID < values[j].KeyID }) && noDuplicateKeys(values)
}
func noDuplicateKeys(values []Signature) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1].KeyID == values[i].KeyID {
			return false
		}
	}
	return true
}

func (e Execution) String() string {
	return fmt.Sprintf("%s/%s", e.PortableActionDigest, e.ActionCellHash)
}
