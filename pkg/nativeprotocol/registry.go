package nativeprotocol

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

type ActionKind string

const (
	ActionRegisterAgent      ActionKind = "register_agent"
	ActionUpdateAgentPolicy  ActionKind = "update_agent_policy"
	ActionDelegateAgent      ActionKind = "delegate_agent"
	ActionInitiateRecovery   ActionKind = "initiate_recovery"
	ActionRecoverAgent       ActionKind = "recover_agent"
	ActionRevokeAgent        ActionKind = "revoke_agent"
	ActionRegisterCapability ActionKind = "register_capability"
	ActionUpdateCapability   ActionKind = "update_capability"
	ActionTransferCapability ActionKind = "transfer_capability"
	ActionRevokeCapability   ActionKind = "revoke_capability"
)

var (
	accountPattern = regexp.MustCompile(`^-?[0-9]+:[0-9a-f]{64}$`)
	reasonPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type RegisterAgentPayload struct {
	ObjectNonceBase64   string `json:"object_nonce_base64url"`
	InitialPolicyDigest string `json:"initial_policy_digest"`
}
type UpdatePolicyPayload struct {
	NewPolicyDigest string `json:"new_policy_digest"`
}
type DelegationPayload struct {
	DelegateKeyID           string   `json:"delegate_key_id"`
	Purposes                []string `json:"purposes"`
	Resources               []string `json:"resources"`
	ValidFromCheckpoint     uint64   `json:"valid_from_checkpoint"`
	ValidUntilCheckpoint    uint64   `json:"valid_until_checkpoint"`
	MaxStalenessCheckpoints uint64   `json:"max_staleness_checkpoints"`
}
type InitiateRecoveryPayload struct {
	NewPolicyDigest         string `json:"new_policy_digest"`
	ExecuteAfterUnixSeconds uint64 `json:"execute_after_unix_seconds"`
}
type RecoverAgentPayload struct {
	NewPolicyDigest         string         `json:"new_policy_digest"`
	InitiationActionDigest  string         `json:"initiation_action_digest"`
	InitiationReference     ChainReference `json:"initiation_reference"`
	ExecuteAfterUnixSeconds uint64         `json:"execute_after_unix_seconds"`
}
type RevocationPayload struct {
	Scope      string `json:"scope"`
	ReasonCode string `json:"reason_code"`
}
type ManifestReference struct {
	Digest    string   `json:"digest"`
	MediaType string   `json:"media_type"`
	SizeBytes uint64   `json:"size_bytes"`
	Locations []string `json:"locations"`
}
type EndpointReference struct {
	Transport      string `json:"transport"`
	EndpointDigest string `json:"endpoint_digest"`
	RecipientKeyID string `json:"recipient_key_id"`
}
type CapabilityVersionPayload struct {
	OwnerAgentID         string              `json:"owner_agent_id"`
	Manifest             ManifestReference   `json:"manifest"`
	Endpoints            []EndpointReference `json:"endpoints"`
	QuoteSignerKeyIDs    []string            `json:"quote_signer_key_ids"`
	ReceiptSignerKeyIDs  []string            `json:"receipt_signer_key_ids"`
	ValidFromCheckpoint  uint64              `json:"valid_from_checkpoint"`
	ValidUntilCheckpoint uint64              `json:"valid_until_checkpoint"`
}
type TransferCapabilityPayload struct {
	CurrentOwnerAgentID  string `json:"current_owner_agent_id"`
	NewOwnerAgentID      string `json:"new_owner_agent_id"`
	NewOwnerPolicyDigest string `json:"new_owner_policy_digest"`
}

type RegistryAction struct {
	Version             string        `json:"version"`
	Kind                ActionKind    `json:"kind"`
	Network             NetworkDomain `json:"network"`
	AgentID             string        `json:"agent_id"`
	CapabilityID        string        `json:"capability_id"`
	CapabilityVersion   string        `json:"capability_version"`
	Generation          uint64        `json:"generation"`
	Sequence            uint64        `json:"sequence"`
	PreviousStateDigest string        `json:"previous_state_digest"`
	PolicyDigest        string        `json:"policy_digest"`
	PayloadDigest       string        `json:"payload_digest"`
	PayloadCBORBase64   string        `json:"payload_cbor_base64url"`
	NonceBase64         string        `json:"nonce_base64url"`
}

type RegistryEvent struct {
	Version             string        `json:"version"`
	Kind                ActionKind    `json:"kind"`
	Network             NetworkDomain `json:"network"`
	ActionDigest        string        `json:"action_digest"`
	AgentID             string        `json:"agent_id"`
	CapabilityID        string        `json:"capability_id"`
	CapabilityVersion   string        `json:"capability_version"`
	Generation          uint64        `json:"generation"`
	Sequence            uint64        `json:"sequence"`
	PreviousStateDigest string        `json:"previous_state_digest"`
	StateDigest         string        `json:"state_digest"`
}

type ChainReference struct {
	Workchain        int32  `json:"workchain"`
	Account          string `json:"account"`
	LogicalTime      uint64 `json:"logical_time"`
	TransactionHash  string `json:"transaction_hash"`
	ContractCodeHash string `json:"contract_code_hash"`
	EventIndex       uint32 `json:"event_index"`
}
type EventObservation struct {
	Version              string         `json:"version"`
	Network              NetworkDomain  `json:"network"`
	EventDigest          string         `json:"event_digest"`
	Reference            ChainReference `json:"reference"`
	FinalizedCheckpoint  uint64         `json:"finalized_checkpoint"`
	FinalizedRootHash    string         `json:"finalized_root_hash"`
	FinalizedFileHash    string         `json:"finalized_file_hash"`
	BlockUnixSeconds     uint64         `json:"block_unix_seconds"`
	InclusionProofDigest string         `json:"inclusion_proof_digest"`
}

func payloadDomain(kind ActionKind) string {
	return "tos.native.registry-payload." + strings.ReplaceAll(string(kind), "_", "-") + ".v1"
}
func EncodePayload(kind ActionKind, value interface{}) (string, string, error) {
	if !validActionKind(kind) {
		return "", "", fail(CodeCanonicalEncoding, "kind")
	}
	if err := validatePayload(kind, value); err != nil {
		return "", "", err
	}
	raw, err := codec.Marshal(value)
	if err != nil {
		return "", "", err
	}
	digest, err := codec.DigestCanonical(payloadDomain(kind), raw)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), digest, nil
}
func DecodePayload(action RegistryAction, output interface{}) error {
	raw, err := base64.RawURLEncoding.DecodeString(action.PayloadCBORBase64)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != action.PayloadCBORBase64 {
		return fail(CodeCanonicalEncoding, "payload_cbor_base64url")
	}
	digest, err := codec.DigestCanonical(payloadDomain(action.Kind), raw)
	if err != nil || digest != action.PayloadDigest {
		return fail(CodeCanonicalEncoding, "payload_digest")
	}
	if err := codec.Unmarshal(raw, output); err != nil {
		return fail(CodeCanonicalEncoding, "payload")
	}
	return validatePayload(action.Kind, output)
}

func ActionDigest(value RegistryAction) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(RegistryActionDomain, value)
}
func EventDigest(value RegistryEvent) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(RegistryEventDomain, value)
}
func ObservationDigest(value EventObservation) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(EventObservationDomain, value)
}
func CanonicalAction(value RegistryAction) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return codec.Marshal(value)
}

func (a RegistryAction) Validate() error {
	if a.Version != Version {
		return fail(CodeUnsupportedVersion, "version")
	}
	if err := a.Network.Validate(); err != nil {
		return err
	}
	if !validActionKind(a.Kind) || a.Generation == 0 || a.Sequence == 0 || !validDigest(a.PolicyDigest) || !validDigest(a.PayloadDigest) || !validNonce(a.NonceBase64) {
		return fail(CodeCanonicalEncoding, "registry_action")
	}
	if a.Sequence == 1 {
		if a.Kind == ActionRecoverAgent && !validDigest(a.PreviousStateDigest) {
			return fail(CodePredecessorMismatch, "previous_state_digest")
		}
		if a.Kind != ActionRecoverAgent && a.PreviousStateDigest != "" {
			return fail(CodePredecessorMismatch, "previous_state_digest")
		}
	} else if !validDigest(a.PreviousStateDigest) {
		return fail(CodePredecessorMismatch, "previous_state_digest")
	}
	capability := isCapabilityKind(a.Kind)
	if !validID(a.AgentID, "agent") || capability != validID(a.CapabilityID, "cap") {
		return fail(CodeInvalidIdentifier, "registry_action.object")
	}
	if capability {
		if a.Kind == ActionRevokeCapability {
			if a.CapabilityVersion != "" && !validVersion(a.CapabilityVersion) {
				return fail(CodeInvalidIdentifier, "capability_version")
			}
		} else if !validVersion(a.CapabilityVersion) {
			return fail(CodeInvalidIdentifier, "capability_version")
		}
	} else if a.CapabilityID != "" || a.CapabilityVersion != "" {
		return fail(CodeCrossDomainReplay, "registry_action.capability")
	}
	var payload interface{}
	switch a.Kind {
	case ActionRegisterAgent:
		payload = &RegisterAgentPayload{}
	case ActionUpdateAgentPolicy:
		payload = &UpdatePolicyPayload{}
	case ActionDelegateAgent:
		payload = &DelegationPayload{}
	case ActionInitiateRecovery:
		payload = &InitiateRecoveryPayload{}
	case ActionRecoverAgent:
		payload = &RecoverAgentPayload{}
	case ActionRevokeAgent, ActionRevokeCapability:
		payload = &RevocationPayload{}
	case ActionRegisterCapability, ActionUpdateCapability:
		payload = &CapabilityVersionPayload{}
	case ActionTransferCapability:
		payload = &TransferCapabilityPayload{}
	}
	if payload == nil {
		return fail(CodeCanonicalEncoding, "kind")
	}
	if err := DecodePayload(a, payload); err != nil {
		return err
	}
	switch p := payload.(type) {
	case *RegisterAgentPayload:
		if p.InitialPolicyDigest != a.PolicyDigest {
			return fail(CodePolicyUnauthorized, "payload.initial_policy_digest")
		}
		id, err := AgentID(AgentBootstrap{Version: Version, Network: a.Network, ObjectNonceBase64: p.ObjectNonceBase64, InitialControllerPolicy: p.InitialPolicyDigest})
		if err != nil || id != a.AgentID {
			return fail(CodeInvalidIdentifier, "agent_id")
		}
	case *CapabilityVersionPayload:
		if p.OwnerAgentID != a.AgentID {
			return fail(CodeCrossDomainReplay, "payload.owner_agent_id")
		}
	case *TransferCapabilityPayload:
		if p.CurrentOwnerAgentID != a.AgentID {
			return fail(CodeCrossDomainReplay, "payload.current_owner_agent_id")
		}
	}
	return nil
}
func (e RegistryEvent) Validate() error {
	if e.Version != Version {
		return fail(CodeUnsupportedVersion, "version")
	}
	if err := e.Network.Validate(); err != nil {
		return err
	}
	if !validActionKind(e.Kind) || !validDigest(e.ActionDigest) || !validDigest(e.StateDigest) || e.Generation == 0 || e.Sequence == 0 || !validID(e.AgentID, "agent") {
		return fail(CodeCanonicalEncoding, "registry_event")
	}
	if e.Sequence == 1 {
		if e.Kind == ActionRecoverAgent && !validDigest(e.PreviousStateDigest) {
			return fail(CodePredecessorMismatch, "previous_state_digest")
		}
		if e.Kind != ActionRecoverAgent && e.PreviousStateDigest != "" {
			return fail(CodePredecessorMismatch, "previous_state_digest")
		}
	} else if !validDigest(e.PreviousStateDigest) {
		return fail(CodePredecessorMismatch, "previous_state_digest")
	}
	capability := isCapabilityKind(e.Kind)
	if capability != validID(e.CapabilityID, "cap") {
		return fail(CodeInvalidIdentifier, "registry_event.object")
	}
	if capability {
		if e.Kind == ActionRevokeCapability {
			if e.CapabilityVersion != "" && !validVersion(e.CapabilityVersion) {
				return fail(CodeInvalidIdentifier, "capability_version")
			}
		} else if !validVersion(e.CapabilityVersion) {
			return fail(CodeInvalidIdentifier, "capability_version")
		}
	} else if e.CapabilityID != "" || e.CapabilityVersion != "" {
		return fail(CodeCrossDomainReplay, "registry_event.capability")
	}
	return nil
}
func (r ChainReference) Validate() error {
	if !accountPattern.MatchString(r.Account) || r.LogicalTime == 0 || !validDigest(r.TransactionHash) || !strings.HasPrefix(r.ContractCodeHash, "tvm-cell-sha256:") || len(r.ContractCodeHash) != 80 {
		return fail(CodeCanonicalEncoding, "reference")
	}
	raw := strings.TrimPrefix(r.ContractCodeHash, "tvm-cell-sha256:")
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 || strings.ToLower(raw) != raw || allZero(decoded) {
		return fail(CodeCanonicalEncoding, "reference.contract_code_hash")
	}
	return nil
}
func (o EventObservation) Validate() error {
	if o.Version != Version {
		return fail(CodeUnsupportedVersion, "version")
	}
	if err := o.Network.Validate(); err != nil {
		return err
	}
	if !validDigest(o.EventDigest) || o.Reference.Validate() != nil || o.FinalizedCheckpoint == 0 || !validDigest(o.FinalizedRootHash) || !validDigest(o.FinalizedFileHash) || o.BlockUnixSeconds == 0 || !validDigest(o.InclusionProofDigest) {
		return fail(CodeFinalityUnavailable, "event_observation")
	}
	return nil
}
func ValidateEventForAction(a RegistryAction, e RegistryEvent) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if err := e.Validate(); err != nil {
		return err
	}
	digest, _ := ActionDigest(a)
	if digest != e.ActionDigest || a.Kind != e.Kind || a.Network != e.Network || a.AgentID != e.AgentID || a.CapabilityID != e.CapabilityID || a.CapabilityVersion != e.CapabilityVersion || a.Generation != e.Generation || a.Sequence != e.Sequence || a.PreviousStateDigest != e.PreviousStateDigest {
		return fail(CodeCrossDomainReplay, "registry_event.action_tuple")
	}
	return nil
}

func validatePayload(kind ActionKind, value interface{}) error {
	switch kind {
	case ActionRegisterAgent:
		p, ok := asRegister(value)
		if !ok || !validNonce(p.ObjectNonceBase64) || !validDigest(p.InitialPolicyDigest) {
			return fail(CodeCanonicalEncoding, "payload.register_agent")
		}
	case ActionUpdateAgentPolicy:
		p, ok := asPolicy(value)
		if !ok || !validDigest(p.NewPolicyDigest) {
			return fail(CodeCanonicalEncoding, "payload.update_agent_policy")
		}
	case ActionDelegateAgent:
		p, ok := asDelegation(value)
		if !ok || !keyIDPattern.MatchString(p.DelegateKeyID) || !sortedUniquePurposes(p.Purposes) || !sortedUniqueASCII(p.Resources) || p.ValidFromCheckpoint == 0 || p.ValidUntilCheckpoint <= p.ValidFromCheckpoint || p.MaxStalenessCheckpoints == 0 {
			return fail(CodeCanonicalEncoding, "payload.delegation")
		}
	case ActionInitiateRecovery:
		p, ok := asInitiate(value)
		if !ok || !validDigest(p.NewPolicyDigest) || p.ExecuteAfterUnixSeconds == 0 {
			return fail(CodeCanonicalEncoding, "payload.initiate_recovery")
		}
	case ActionRecoverAgent:
		p, ok := asRecover(value)
		if !ok || !validDigest(p.NewPolicyDigest) || !validDigest(p.InitiationActionDigest) || p.InitiationReference.Validate() != nil || p.ExecuteAfterUnixSeconds == 0 {
			return fail(CodeCanonicalEncoding, "payload.recover_agent")
		}
	case ActionRevokeAgent, ActionRevokeCapability:
		p, ok := asRevocation(value)
		if !ok || !reasonPattern.MatchString(p.Scope) || !reasonPattern.MatchString(p.ReasonCode) {
			return fail(CodeCanonicalEncoding, "payload.revocation")
		}
	case ActionRegisterCapability, ActionUpdateCapability:
		p, ok := asCapability(value)
		if !ok || validateCapabilityPayload(p) != nil {
			return fail(CodeCanonicalEncoding, "payload.capability")
		}
	case ActionTransferCapability:
		p, ok := asTransfer(value)
		if !ok || !validID(p.CurrentOwnerAgentID, "agent") || !validID(p.NewOwnerAgentID, "agent") || p.CurrentOwnerAgentID == p.NewOwnerAgentID || !validDigest(p.NewOwnerPolicyDigest) {
			return fail(CodeCanonicalEncoding, "payload.transfer")
		}
	default:
		return fail(CodeCanonicalEncoding, "kind")
	}
	return nil
}

func validateCapabilityPayload(p CapabilityVersionPayload) error {
	if !validID(p.OwnerAgentID, "agent") || !validDigest(p.Manifest.Digest) || p.Manifest.MediaType != "application/vnd.atos.native-capability+json" || p.Manifest.SizeBytes == 0 || p.Manifest.SizeBytes > 1<<20 || !sortedUniqueASCII(p.Manifest.Locations) || len(p.Endpoints) == 0 || p.ValidFromCheckpoint == 0 || p.ValidUntilCheckpoint <= p.ValidFromCheckpoint || !sortedUniqueASCII(p.QuoteSignerKeyIDs) || !sortedUniqueASCII(p.ReceiptSignerKeyIDs) {
		return errors.New("invalid")
	}
	last := ""
	for _, e := range p.Endpoints {
		key := e.Transport + "\x00" + e.EndpointDigest + "\x00" + e.RecipientKeyID
		if key <= last || !reasonPattern.MatchString(e.Transport) || !validDigest(e.EndpointDigest) || !keyIDPattern.MatchString(e.RecipientKeyID) {
			return errors.New("invalid")
		}
		last = key
	}
	return nil
}
func sortedUniqueASCII(v []string) bool {
	if len(v) == 0 {
		return false
	}
	last := ""
	for _, s := range v {
		if s <= last || s == "" || len(s) > 2048 || strings.ContainsRune(s, '\x00') {
			return false
		}
		last = s
	}
	return true
}
func validActionKind(k ActionKind) bool {
	switch k {
	case ActionRegisterAgent, ActionUpdateAgentPolicy, ActionDelegateAgent, ActionInitiateRecovery, ActionRecoverAgent, ActionRevokeAgent, ActionRegisterCapability, ActionUpdateCapability, ActionTransferCapability, ActionRevokeCapability:
		return true
	}
	return false
}
func isCapabilityKind(k ActionKind) bool { return strings.Contains(string(k), "capability") }
func asRegister(v interface{}) (RegisterAgentPayload, bool) {
	switch p := v.(type) {
	case RegisterAgentPayload:
		return p, true
	case *RegisterAgentPayload:
		if p != nil {
			return *p, true
		}
	}
	return RegisterAgentPayload{}, false
}
func asPolicy(v interface{}) (UpdatePolicyPayload, bool) {
	switch p := v.(type) {
	case UpdatePolicyPayload:
		return p, true
	case *UpdatePolicyPayload:
		if p != nil {
			return *p, true
		}
	}
	return UpdatePolicyPayload{}, false
}
func asDelegation(v interface{}) (DelegationPayload, bool) {
	switch p := v.(type) {
	case DelegationPayload:
		return p, true
	case *DelegationPayload:
		if p != nil {
			return *p, true
		}
	}
	return DelegationPayload{}, false
}
func asInitiate(v interface{}) (InitiateRecoveryPayload, bool) {
	switch p := v.(type) {
	case InitiateRecoveryPayload:
		return p, true
	case *InitiateRecoveryPayload:
		if p != nil {
			return *p, true
		}
	}
	return InitiateRecoveryPayload{}, false
}
func asRecover(v interface{}) (RecoverAgentPayload, bool) {
	switch p := v.(type) {
	case RecoverAgentPayload:
		return p, true
	case *RecoverAgentPayload:
		if p != nil {
			return *p, true
		}
	}
	return RecoverAgentPayload{}, false
}
func asRevocation(v interface{}) (RevocationPayload, bool) {
	switch p := v.(type) {
	case RevocationPayload:
		return p, true
	case *RevocationPayload:
		if p != nil {
			return *p, true
		}
	}
	return RevocationPayload{}, false
}
func asCapability(v interface{}) (CapabilityVersionPayload, bool) {
	switch p := v.(type) {
	case CapabilityVersionPayload:
		return p, true
	case *CapabilityVersionPayload:
		if p != nil {
			return *p, true
		}
	}
	return CapabilityVersionPayload{}, false
}
func asTransfer(v interface{}) (TransferCapabilityPayload, bool) {
	switch p := v.(type) {
	case TransferCapabilityPayload:
		return p, true
	case *TransferCapabilityPayload:
		if p != nil {
			return *p, true
		}
	}
	return TransferCapabilityPayload{}, false
}
