package nativeexecution

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type DecodedAction struct {
	Action                      nativeprotocol.RegistryAction
	Previous                    *nativeprotocol.RegistryState
	Next                        nativeprotocol.RegistryState
	AuthorityPolicy             nativeprotocol.ControllerPolicy
	NewOwnerPolicy              *nativeprotocol.ControllerPolicy
	Contract                    ContractIdentity
	PreviousTVMStateHash        []byte
	ExpectedTVMStateHash        []byte
	ExpectedPortableStateDigest []byte
}

type DecodedAnchor struct {
	Action                *cell.Cell
	Decoded               DecodedAction
	Completed             bool
	CompletionUnixSeconds uint64
	CompletionLogicalTime uint64
	AuthorityState        *nativeprotocol.RegistryState
	NewOwnerState         *nativeprotocol.RegistryState
	authoritySignatures   *cell.Cell
	newOwnerSignatures    *cell.Cell
}

// IsPristineActionAnchorData recognizes only the deterministic, active
// StateInit data for an Action Anchor whose first delivery did not reach the
// journal-before-forward store. This is not canonical absence: callers may
// resume it only when their enrolled publisher already has the exact durable
// semantic intent.
func IsPristineActionAnchorData(root *cell.Cell, expectedActionID string) bool {
	if root == nil {
		return false
	}
	expected, err := digestBytes(expectedActionID, false)
	if err != nil {
		return false
	}
	s := root.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != objectDataMagic {
		return false
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return false
	}
	kind, err := s.LoadUInt(8)
	if err != nil || kind != ActionAnchorKind {
		return false
	}
	id, err := s.LoadSlice(256)
	if err != nil || !bytes.Equal(id, expected) {
		return false
	}
	if _, err = s.LoadRefCell(); err != nil {
		return false
	}
	hasState, err := s.LoadBoolBit()
	if err != nil || hasState {
		return false
	}
	hasPending, err := s.LoadBoolBit()
	if err != nil || hasPending {
		return false
	}
	hasCompletion, err := s.LoadBoolBit()
	return err == nil && !hasCompletion && s.BitsLeft() == 0 && s.RefsNum() == 0
}

func DecodeActionAnchorData(root *cell.Cell, expectedActionID string) (DecodedAnchor, error) {
	if root == nil {
		return DecodedAnchor{}, errors.New("missing Native Action Anchor data")
	}
	expected, err := digestBytes(expectedActionID, false)
	if err != nil {
		return DecodedAnchor{}, err
	}
	s := root.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != objectDataMagic {
		return DecodedAnchor{}, errors.New("invalid Native object data")
	}
	schema, _ := s.LoadUInt(16)
	kind, _ := s.LoadUInt(8)
	id, _ := s.LoadSlice(256)
	if schema != 1 || kind != ActionAnchorKind || !bytes.Equal(id, expected) {
		return DecodedAnchor{}, errors.New("Native Action Anchor identity mismatch")
	}
	_, _ = s.LoadRefCell()
	hasState, err := s.LoadBoolBit()
	if err != nil || !hasState {
		return DecodedAnchor{}, errors.New("Native Action Anchor has no envelope")
	}
	stored, err := s.LoadRefCell()
	if err != nil {
		return DecodedAnchor{}, err
	}
	hasPending, err := s.LoadBoolBit()
	if err != nil {
		return DecodedAnchor{}, err
	}
	if hasPending {
		_, err = s.LoadRefCell()
		if err != nil {
			return DecodedAnchor{}, err
		}
	}
	hasCompletion, err := s.LoadBoolBit()
	if err != nil || hasCompletion {
		return DecodedAnchor{}, errors.New("Native Action Anchor has invalid object-completion metadata")
	}
	if s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return DecodedAnchor{}, errors.New("Native Action Anchor data contains trailing fields")
	}
	var submission *cell.Cell
	var completionUnixSeconds, completionLogicalTime uint64
	var completionNext, completionPortable []byte
	var authorityState, newOwnerState *nativeprotocol.RegistryState
	if hasPending {
		submission = stored
	} else {
		wrapper := stored.BeginParse()
		completionUnixSeconds, err = wrapper.LoadUInt(64)
		if err != nil || completionUnixSeconds == 0 {
			return DecodedAnchor{}, errors.New("invalid Native completion time")
		}
		completionLogicalTime, err = wrapper.LoadUInt(64)
		if err != nil || completionLogicalTime == 0 {
			return DecodedAnchor{}, errors.New("invalid Native completion logical time")
		}
		submission, err = wrapper.LoadRefCell()
		if err != nil {
			return DecodedAnchor{}, err
		}
		completion, loadErr := wrapper.LoadRefCell()
		if loadErr != nil {
			return DecodedAnchor{}, loadErr
		}
		cs := completion.BeginParse()
		completionNext, _ = cs.LoadSlice(256)
		completionPortable, _ = cs.LoadSlice(256)
		if len(completionNext) != 32 || len(completionPortable) != 32 {
			return DecodedAnchor{}, errors.New("invalid Native completion tuple")
		}
		authorityStateCell, authorityErr := cs.LoadRefCell()
		newOwnerStateCell, newOwnerErr := cs.LoadRefCell()
		if authorityErr != nil || newOwnerErr != nil || cs.BitsLeft() != 0 || cs.RefsNum() != 0 {
			return DecodedAnchor{}, errors.New("invalid Native completion authority evidence")
		}
		if authorityStateCell.BitsSize() != 0 || authorityStateCell.RefsNum() != 0 {
			value, decodeErr := decodeStateCell(authorityStateCell)
			if decodeErr != nil {
				return DecodedAnchor{}, errors.New("invalid Native completion authority state")
			}
			authorityState = &value
		}
		if newOwnerStateCell.BitsSize() != 0 || newOwnerStateCell.RefsNum() != 0 {
			value, decodeErr := decodeStateCell(newOwnerStateCell)
			if decodeErr != nil {
				return DecodedAnchor{}, errors.New("invalid Native completion new-owner state")
			}
			newOwnerState = &value
		}
		if wrapper.BitsLeft() != 0 || wrapper.RefsNum() != 0 {
			return DecodedAnchor{}, errors.New("Native completion wrapper contains trailing fields")
		}
	}
	ss := submission.BeginParse()
	action, err := ss.LoadRefCell()
	if err != nil {
		return DecodedAnchor{}, err
	}
	authoritySignatures, err := ss.LoadRefCell()
	if err != nil {
		return DecodedAnchor{}, errors.New("Native Action Anchor is missing authority signatures")
	}
	newOwnerSignatures, err := ss.LoadRefCell()
	if err != nil || ss.BitsLeft() != 0 || ss.RefsNum() != 0 {
		return DecodedAnchor{}, errors.New("Native Action Anchor has invalid signature envelope")
	}
	decoded, err := DecodeActionCell(action)
	if err != nil {
		return DecodedAnchor{}, err
	}
	if !hasPending && (!bytes.Equal(completionNext, decoded.ExpectedTVMStateHash) || !bytes.Equal(completionPortable, decoded.ExpectedPortableStateDigest)) {
		return DecodedAnchor{}, errors.New("Native completion does not match signed action")
	}
	digest, err := nativeprotocol.ActionDigest(decoded.Action)
	if err != nil || digest != expectedActionID {
		return DecodedAnchor{}, errors.New("Native Action Anchor action mismatch")
	}
	return DecodedAnchor{Action: action, Decoded: decoded, Completed: !hasPending, CompletionUnixSeconds: completionUnixSeconds, CompletionLogicalTime: completionLogicalTime, AuthorityState: authorityState, NewOwnerState: newOwnerState, authoritySignatures: authoritySignatures, newOwnerSignatures: newOwnerSignatures}, nil
}

// DecodeActionCell reconstructs only from consensus cell bytes. It rejects a
// portable preimage or typed-state disagreement; callers still validate live
// authority and transaction inclusion independently.
func DecodeActionCell(root *cell.Cell) (DecodedAction, error) {
	if root == nil {
		return DecodedAction{}, errors.New("missing Native action cell")
	}
	s := root.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != actionMagic {
		return DecodedAction{}, errors.New("invalid Native action magic")
	}
	schema, _ := s.LoadUInt(16)
	if schema != 1 {
		return DecodedAction{}, errors.New("unsupported Native action cell")
	}
	kind, _ := s.LoadUInt(8)
	flags, _ := s.LoadUInt(8)
	_, _ = s.LoadUInt(64)
	_, _ = s.LoadUInt(64)
	actionDigest, _ := s.LoadSlice(256)
	previousHash, _ := s.LoadSlice(256)
	nextHash, _ := s.LoadSlice(256)
	identity, identityErr := s.LoadRefCell()
	commitments, commitmentsErr := s.LoadRefCell()
	controls, err := s.LoadRefCell()
	if err != nil {
		return DecodedAction{}, err
	}
	if identityErr != nil || commitmentsErr != nil {
		return DecodedAction{}, errors.New("invalid Native action identity or commitments")
	}
	portable, err := s.LoadRefCell()
	if err != nil {
		return DecodedAction{}, err
	}
	preimage, err := portable.BeginParse().LoadBinarySnake()
	if err != nil {
		return DecodedAction{}, err
	}
	prefix := []byte("TOS-PROTOCOL-CBOR\x00\x00\x1d" + nativeprotocol.RegistryActionDomain)
	if !bytes.HasPrefix(preimage, prefix) {
		return DecodedAction{}, errors.New("Native action preimage framing mismatch")
	}
	var action nativeprotocol.RegistryAction
	if err := codec.Unmarshal(preimage[len(prefix):], &action); err != nil {
		return DecodedAction{}, err
	}
	digest, err := nativeprotocol.ActionDigest(action)
	if err != nil || !bytes.Equal(mustDigest(digest), actionDigest) {
		return DecodedAction{}, errors.New("Native action digest mismatch")
	}
	cs := controls.BeginParse()
	typedPayload, err := cs.LoadRefCell()
	if err != nil {
		return DecodedAction{}, err
	}
	typedPolicy, err := cs.LoadRefCell()
	if err != nil {
		return DecodedAction{}, err
	}
	typedTransitionPolicy, err := cs.LoadRefCell()
	if err != nil {
		return DecodedAction{}, err
	}
	statePair, err := cs.LoadRefCell()
	if err != nil {
		return DecodedAction{}, err
	}
	ps := statePair.BeginParse()
	hasPrevious, err := ps.LoadBoolBit()
	if err != nil {
		return DecodedAction{}, err
	}
	var previous *nativeprotocol.RegistryState
	if hasPrevious {
		previousCell, err := ps.LoadRefCell()
		if err != nil {
			return DecodedAction{}, err
		}
		value, err := decodeStateCell(previousCell)
		if err != nil {
			return DecodedAction{}, err
		}
		previous = &value
	}
	nextCell, err := ps.LoadRefCell()
	if err != nil {
		return DecodedAction{}, err
	}
	next, err := decodeStateCell(nextCell)
	if err != nil {
		return DecodedAction{}, err
	}
	stateDigest, err := nativeprotocol.StateDigest(next)
	if err != nil {
		return DecodedAction{}, err
	}
	policy, err := decodePolicyCell(typedPolicy)
	if err != nil {
		return DecodedAction{}, err
	}
	var newOwner *nativeprotocol.ControllerPolicy
	if action.Kind == nativeprotocol.ActionTransferCapability {
		value, err := decodePolicyCell(typedTransitionPolicy)
		if err != nil {
			return DecodedAction{}, err
		}
		newOwner = &value
	}
	contract, err := decodeIdentityContract(identity, action, uint8(kind), uint8(flags))
	if err != nil {
		return DecodedAction{}, err
	}
	expectedPayload, err := payloadControlCell(action)
	if err != nil || !bytes.Equal(expectedPayload.Hash(), typedPayload.Hash()) {
		return DecodedAction{}, errors.New("Native typed payload does not match portable action")
	}
	commitmentSlice := commitments.BeginParse()
	policyDigest, _ := commitmentSlice.LoadSlice(256)
	payloadDigest, _ := commitmentSlice.LoadSlice(256)
	portableStateDigest, _ := commitmentSlice.LoadSlice(256)
	if !bytes.Equal(policyDigest, mustDigest(action.PolicyDigest)) || !bytes.Equal(payloadDigest, mustDigest(action.PayloadDigest)) || !bytes.Equal(portableStateDigest, mustDigest(stateDigest)) {
		return DecodedAction{}, errors.New("Native typed commitments do not match portable action or state")
	}
	expected, err := buildActionCell(action, preimage[len(prefix):], digest, stateDigest, previousHash, nextHash, previous, next, policy, newOwner, contract)
	if err != nil || !bytes.Equal(expected.Hash(), root.Hash()) {
		return DecodedAction{}, errors.New("Native typed action is not the canonical portable action representation")
	}
	return DecodedAction{Action: action, Previous: previous, Next: next, AuthorityPolicy: policy, Contract: contract,
		NewOwnerPolicy: newOwner, PreviousTVMStateHash: previousHash, ExpectedTVMStateHash: nextHash,
		ExpectedPortableStateDigest: mustDigest(stateDigest)}, nil
}

// VerifyAnchorSignatures independently verifies the finalized signature
// envelope stored by the Action Anchor. It does not trust a publisher receipt
// or process-local projection and applies the same purpose/threshold rules as
// the portable authorization implementation.
func VerifyAnchorSignatures(anchor DecodedAnchor, actionAnchorAddress string) error {
	if anchor.Action == nil || anchor.authoritySignatures == nil || anchor.newOwnerSignatures == nil {
		return errors.New("Native Action Anchor signature evidence is incomplete")
	}
	execution := Execution{
		Version: Version, ContractAddress: anchor.Decoded.Contract.Address,
		ActionAnchorAddress: actionAnchorAddress, ContractCodeHash: anchor.Decoded.Contract.AllowedCodeHash,
		PortableActionDigest: anchor.Decoded.ActionDigest(), ActionCellBOCBase64: base64.RawURLEncoding.EncodeToString(anchor.Action.ToBOC()),
		ActionCellHash: digest(anchor.Action.Hash()), PreviousTVMStateHash: digestAllowZero(anchor.Decoded.PreviousTVMStateHash),
		ExpectedTVMStateHash: digest(anchor.Decoded.ExpectedTVMStateHash), ExpectedPortableStateDigest: digest(anchor.Decoded.ExpectedPortableStateDigest),
	}
	authority, err := decodeAndVerifySignatureList(anchor.authoritySignatures, anchor.Decoded.AuthorityPolicy, execution)
	if err != nil {
		return fmt.Errorf("verify Native authority signatures: %w", err)
	}
	authorityIDs := signatureKeyIDs(authority)
	if anchor.Decoded.Action.Kind != nativeprotocol.ActionTransferCapability {
		expectedPolicy := anchor.Decoded.Action.PolicyDigest
		if anchor.Decoded.Action.Kind == nativeprotocol.ActionRegisterAgent {
			expectedPolicy = ""
		}
		if err := nativeprotocol.ValidateAuthorizationKeyIDs(anchor.Decoded.Action, expectedPolicy, anchor.Decoded.AuthorityPolicy, authorityIDs); err != nil {
			return err
		}
		if count, err := signatureListCount(anchor.newOwnerSignatures); err != nil || count != 0 {
			return errors.New("unexpected Native new-owner signatures")
		}
		return nil
	}
	if anchor.Decoded.NewOwnerPolicy == nil {
		return errors.New("Native transfer is missing new-owner policy")
	}
	newOwner, err := decodeAndVerifySignatureList(anchor.newOwnerSignatures, *anchor.Decoded.NewOwnerPolicy, execution)
	if err != nil {
		return fmt.Errorf("verify Native new-owner signatures: %w", err)
	}
	var payload nativeprotocol.TransferCapabilityPayload
	if err := nativeprotocol.DecodePayload(anchor.Decoded.Action, &payload); err != nil {
		return err
	}
	return nativeprotocol.ValidateTransferAuthorizationKeyIDs(anchor.Decoded.Action, anchor.Decoded.Action.PolicyDigest,
		anchor.Decoded.AuthorityPolicy, payload.NewOwnerPolicyDigest, *anchor.Decoded.NewOwnerPolicy,
		authorityIDs, signatureKeyIDs(newOwner))
}

func (d DecodedAction) ActionDigest() string {
	value, err := nativeprotocol.ActionDigest(d.Action)
	if err != nil {
		return ""
	}
	return value
}

func signatureKeyIDs(values []Signature) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = values[i].KeyID
	}
	return out
}

func signatureListCount(root *cell.Cell) (uint64, error) {
	if root == nil {
		return 0, errors.New("missing Native signature list")
	}
	s := root.BeginParse()
	count, err := s.LoadUInt(8)
	if err != nil || count > 64 {
		return 0, errors.New("invalid Native signature count")
	}
	if (count == 0 && s.RefsNum() != 0) || (count > 0 && s.RefsNum() != 1) || s.BitsLeft() != 0 {
		return 0, errors.New("invalid Native signature list root")
	}
	return count, nil
}

func decodeAndVerifySignatureList(root *cell.Cell, policy nativeprotocol.ControllerPolicy, execution Execution) ([]Signature, error) {
	count, err := signatureListCount(root)
	if err != nil || count == 0 {
		if err == nil {
			err = errors.New("empty Native authorization")
		}
		return nil, err
	}
	byHash := make(map[string]nativeprotocol.ControllerKey, len(policy.Controllers))
	for _, key := range policy.Controllers {
		byHash[hex.EncodeToString(sha256Bytes([]byte(key.KeyID)))] = key
	}
	cursor, err := root.BeginParse().LoadRefCell()
	if err != nil {
		return nil, err
	}
	result := make([]Signature, 0, count)
	for i := uint64(0); i < count; i++ {
		s := cursor.BeginParse()
		keyHash, keyErr := s.LoadSlice(256)
		raw, signatureErr := s.LoadSlice(512)
		commitment, commitmentErr := s.LoadRefCell()
		if keyErr != nil || signatureErr != nil || commitmentErr != nil {
			return nil, errors.New("invalid Native signature entry")
		}
		key, ok := byHash[hex.EncodeToString(keyHash)]
		if !ok {
			return nil, errors.New("unknown Native signature key")
		}
		expectedCommitment, err := signatureCommitmentCell(key.KeyID, execution)
		if err != nil || !bytes.Equal(commitment.Hash(), expectedCommitment.Hash()) {
			return nil, errors.New("Native signature commitment mismatch")
		}
		signature := Signature{Version: Version, Algorithm: SignatureAlgorithm, KeyID: key.KeyID, SignatureBase64: base64.RawURLEncoding.EncodeToString(raw)}
		publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKeyBase64)
		if err != nil || Verify(ed25519.PublicKey(publicKey), signature, execution) != nil {
			return nil, errors.New("invalid finalized Native signature")
		}
		result = append(result, signature)
		if i+1 < count {
			if s.RefsNum() != 1 {
				return nil, errors.New("truncated Native signature list")
			}
			cursor, err = s.LoadRefCell()
			if err != nil {
				return nil, err
			}
		} else if s.RefsNum() != 0 || s.BitsLeft() != 0 {
			return nil, errors.New("Native signature list contains trailing fields")
		}
	}
	if !SortedSignatures(result) {
		return nil, errors.New("Native signatures are not canonically ordered")
	}
	return result, nil
}

func decodeStateCell(root *cell.Cell) (nativeprotocol.RegistryState, error) {
	s := root.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != stateMagic {
		return nativeprotocol.RegistryState{}, errors.New("invalid Native state magic")
	}
	_, _ = s.LoadUInt(16)
	_, _ = s.LoadUInt(8)
	_, _ = s.LoadBoolBit()
	_, _ = s.LoadUInt(64)
	_, _ = s.LoadUInt(64)
	_, _ = s.LoadSlice(256)
	_, _ = s.LoadSlice(256)
	_, _ = s.LoadRefCell()
	_, _ = s.LoadRefCell()
	_, _ = s.LoadRefCell()
	portable, err := s.LoadRefCell()
	if err != nil {
		return nativeprotocol.RegistryState{}, err
	}
	preimage, err := portable.BeginParse().LoadBinarySnake()
	if err != nil {
		return nativeprotocol.RegistryState{}, err
	}
	prefix := []byte("TOS-PROTOCOL-CBOR\x00\x00\x1c" + nativeprotocol.RegistryStateDomain)
	if !bytes.HasPrefix(preimage, prefix) {
		return nativeprotocol.RegistryState{}, errors.New("Native state preimage framing mismatch")
	}
	var state nativeprotocol.RegistryState
	if err := codec.Unmarshal(preimage[len(prefix):], &state); err != nil {
		return nativeprotocol.RegistryState{}, err
	}
	rebuilt, err := stateCell(state)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nativeprotocol.RegistryState{}, errors.New("Native typed and portable state mismatch")
	}
	expected, err := stateCell(state)
	if err != nil || !bytes.Equal(expected.Hash(), root.Hash()) {
		return nativeprotocol.RegistryState{}, errors.New("Native typed state does not match portable state")
	}
	return state, nil
}

func decodeIdentityContract(root *cell.Cell, action nativeprotocol.RegistryAction, kind, flags uint8) (ContractIdentity, error) {
	s := root.BeginParse()
	agent, _ := s.LoadSlice(256)
	capability, _ := s.LoadSlice(256)
	versionCell, _ := s.LoadRefCell()
	networkCellValue, err := s.LoadRefCell()
	if err != nil || !bytes.Equal(agent, mustID(action.AgentID, "agent")) ||
		!bytes.Equal(capability, mustOptionalID(action.CapabilityID, "cap")) {
		return ContractIdentity{}, errors.New("Native typed identity mismatch")
	}
	version, err := versionCell.BeginParse().LoadBinarySnake()
	if err != nil || string(version) != action.CapabilityVersion || kind != kindCode(action.Kind) || flags != boolFlag(action.CapabilityID != "") {
		return ContractIdentity{}, errors.New("Native typed action header mismatch")
	}
	n := networkCellValue.BeginParse()
	rootHash, _ := n.LoadSlice(256)
	fileHash, _ := n.LoadSlice(256)
	wc, _ := n.LoadInt(32)
	account, _ := n.LoadSlice(256)
	networkIDCell, _ := n.LoadRefCell()
	codeCell, err := n.LoadRefCell()
	if err != nil {
		return ContractIdentity{}, err
	}
	networkID, err := networkIDCell.BeginParse().LoadBinarySnake()
	if err != nil {
		return ContractIdentity{}, err
	}
	codeHash, _ := codeCell.BeginParse().LoadSlice(256)
	contract := ContractIdentity{Network: nativeprotocol.NetworkDomain{NetworkID: string(networkID), GenesisRootHash: "sha256:" + hex.EncodeToString(rootHash), GenesisFileHash: "sha256:" + hex.EncodeToString(fileHash)}, Address: fmt.Sprintf("%d:%s", wc, hex.EncodeToString(account)), AllowedCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(codeHash)}
	if contract.Network != action.Network {
		return ContractIdentity{}, errors.New("Native typed network mismatch")
	}
	actionID, err := nativeprotocol.ActionDigest(action)
	if err != nil {
		return ContractIdentity{}, err
	}
	// The Action Anchor is independently deterministic; it is filled by the
	// caller of the canonical builder after the object identity is known.
	contract.ActionAnchorAddress = ""
	_ = actionID
	return contract, nil
}

func decodePolicyCell(root *cell.Cell) (nativeprotocol.ControllerPolicy, error) {
	if root == nil {
		return nativeprotocol.ControllerPolicy{}, errors.New("missing Native typed policy")
	}
	s := root.BeginParse()
	threshold, _ := s.LoadUInt(32)
	recoveryThreshold, _ := s.LoadUInt(32)
	timelock, _ := s.LoadUInt(64)
	count, _ := s.LoadUInt(8)
	expectedDigest, _ := s.LoadSlice(256)
	policy := nativeprotocol.ControllerPolicy{Threshold: uint32(threshold), RecoveryThreshold: uint32(recoveryThreshold), RecoveryTimelock: timelock}
	var next *cell.Cell
	if count > 0 {
		var err error
		next, err = s.LoadRefCell()
		if err != nil {
			return nativeprotocol.ControllerPolicy{}, err
		}
	}
	for index := uint64(0); index < count; index++ {
		item := next.BeginParse()
		keyHash, _ := item.LoadSlice(256)
		publicKey, _ := item.LoadSlice(256)
		weight, _ := item.LoadUInt(32)
		mask, _ := item.LoadUInt(16)
		recovery, _ := item.LoadBoolBit()
		keyCell, err := item.LoadRefCell()
		if err != nil {
			return nativeprotocol.ControllerPolicy{}, err
		}
		keyRaw, err := keyCell.BeginParse().LoadBinarySnake()
		if err != nil || !bytes.Equal(keyHash, sha256Bytes(keyRaw)) {
			return nativeprotocol.ControllerPolicy{}, errors.New("Native typed policy key mismatch")
		}
		keyID := string(keyRaw)
		key := nativeprotocol.ControllerKey{KeyID: keyID, Algorithm: nativeprotocol.SignatureAlgorithm,
			PublicKeyBase64: base64.RawURLEncoding.EncodeToString(publicKey), Weight: uint32(weight), Purposes: purposesFromMask(mask)}
		policy.Controllers = append(policy.Controllers, key)
		if recovery {
			policy.RecoveryKeyIDs = append(policy.RecoveryKeyIDs, keyID)
		}
		if index+1 < count {
			next, err = item.LoadRefCell()
			if err != nil {
				return nativeprotocol.ControllerPolicy{}, err
			}
		}
	}
	sort.Strings(policy.RecoveryKeyIDs)
	digest, err := nativeprotocol.ControllerPolicyDigest(policy)
	if err != nil || !bytes.Equal(expectedDigest, mustDigest(digest)) {
		return nativeprotocol.ControllerPolicy{}, errors.New("Native typed policy digest mismatch")
	}
	return policy, nil
}

func purposesFromMask(mask uint64) []string {
	known := []string{"agent_control", "delegation", "recovery", "capability_control", "quote", "receipt", "invocation", "funding", "release", "dispute", "settlement"}
	output := make([]string, 0, len(known))
	for index, value := range known {
		if mask&(1<<index) != 0 {
			output = append(output, value)
		}
	}
	sort.Strings(output)
	return output
}

func boolFlag(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func DecodeObjectStateData(root *cell.Cell, expectedObjectID string) (nativeprotocol.RegistryState, bool, error) {
	if root == nil {
		return nativeprotocol.RegistryState{}, false, errors.New("missing Native object data")
	}
	prefix, kind := "agent", uint64(1)
	if len(expectedObjectID) > 4 && expectedObjectID[:4] == "cap_" {
		prefix, kind = "cap", 2
	}
	id, err := idBytes(expectedObjectID, prefix)
	if err != nil {
		return nativeprotocol.RegistryState{}, false, err
	}
	s := root.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != objectDataMagic {
		return nativeprotocol.RegistryState{}, false, errors.New("invalid Native object data")
	}
	schema, _ := s.LoadUInt(16)
	gotKind, _ := s.LoadUInt(8)
	gotID, _ := s.LoadSlice(256)
	if schema != 1 || gotKind != kind || !bytes.Equal(gotID, id) {
		return nativeprotocol.RegistryState{}, false, errors.New("Native object identity mismatch")
	}
	_, _ = s.LoadRefCell()
	found, err := s.LoadBoolBit()
	if err != nil {
		return nativeprotocol.RegistryState{}, false, err
	}
	var stateCell *cell.Cell
	if found {
		stateCell, err = s.LoadRefCell()
		if err != nil {
			return nativeprotocol.RegistryState{}, false, err
		}
	}
	hasPending, err := s.LoadBoolBit()
	if err != nil {
		return nativeprotocol.RegistryState{}, false, err
	}
	if hasPending {
		if _, err := s.LoadRefCell(); err != nil {
			return nativeprotocol.RegistryState{}, false, err
		}
	}
	hasCompletion, err := s.LoadBoolBit()
	if err != nil {
		return nativeprotocol.RegistryState{}, false, err
	}
	if hasCompletion {
		if _, err := s.LoadRefCell(); err != nil {
			return nativeprotocol.RegistryState{}, false, err
		}
	}
	if s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nativeprotocol.RegistryState{}, false, errors.New("Native object data contains trailing fields")
	}
	if !found {
		if hasPending || hasCompletion {
			return nativeprotocol.RegistryState{}, false, errors.New("empty Native object contains operation metadata")
		}
		return nativeprotocol.RegistryState{}, false, nil
	}
	state, err := decodeStateCell(stateCell)
	return state, true, err
}
