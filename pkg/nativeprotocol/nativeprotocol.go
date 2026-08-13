// Package nativeprotocol implements the frozen Phase 5A Native identifiers,
// registry values and purpose-separated semantic signatures. It deliberately
// contains no chain mutation, gateway account or database behavior.
package nativeprotocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

const (
	Version                 = "tos_native_registry_v1"
	AgentIDDomain           = "tos.native.agent-id.v1"
	CapabilityIDDomain      = "tos.native.capability-id.v1"
	ControllerPolicyDomain  = "tos.native.controller-policy.v1"
	RegistryActionDomain    = "tos.native.registry-action.v1"
	RegistryEventDomain     = "tos.native.registry-event.v1"
	SemanticSignatureDomain = "tos.native.semantic-signature.v1"
	SignatureAlgorithm      = "ed25519"
)

var (
	networkPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	idPattern      = regexp.MustCompile(`^(agent|cap)_([0-9a-f]{64})$`)
	keyIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type ErrorCode string

const (
	CodeUnsupportedVersion  ErrorCode = "NATIVE_UNSUPPORTED_VERSION"
	CodeInvalidNetwork      ErrorCode = "NATIVE_INVALID_NETWORK"
	CodeInvalidIdentifier   ErrorCode = "NATIVE_INVALID_IDENTIFIER"
	CodeNoncanonicalURI     ErrorCode = "NATIVE_NONCANONICAL_URI"
	CodeCanonicalEncoding   ErrorCode = "NATIVE_CANONICAL_ENCODING"
	CodeCrossDomainReplay   ErrorCode = "NATIVE_CROSS_DOMAIN_REPLAY"
	CodePredecessorMismatch ErrorCode = "NATIVE_PREDECESSOR_MISMATCH"
	CodePolicyUnauthorized  ErrorCode = "NATIVE_POLICY_UNAUTHORIZED"
	CodeFinalityUnavailable ErrorCode = "NATIVE_FINALITY_UNAVAILABLE"
)

type ProtocolError struct {
	Code  ErrorCode
	Field string
}

func (e *ProtocolError) Error() string        { return string(e.Code) + ": " + e.Field }
func fail(code ErrorCode, field string) error { return &ProtocolError{Code: code, Field: field} }
func ErrorCodeOf(err error) ErrorCode {
	var target *ProtocolError
	if errors.As(err, &target) {
		return target.Code
	}
	return CodeCanonicalEncoding
}

type NetworkDomain struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

type ControllerKey struct {
	KeyID           string   `json:"key_id"`
	Algorithm       string   `json:"algorithm"`
	PublicKeyBase64 string   `json:"public_key_base64url"`
	Weight          uint32   `json:"weight"`
	Purposes        []string `json:"purposes"`
}

type ControllerPolicy struct {
	Threshold        uint32          `json:"threshold"`
	Controllers      []ControllerKey `json:"controllers"`
	RecoveryKeyIDs   []string        `json:"recovery_key_ids"`
	RecoveryTimelock uint64          `json:"recovery_timelock_seconds"`
}

type AgentBootstrap struct {
	Version                 string        `json:"version"`
	Network                 NetworkDomain `json:"network"`
	ObjectNonceBase64       string        `json:"object_nonce_base64url"`
	InitialControllerPolicy string        `json:"initial_controller_policy_digest"`
}

type CapabilityBootstrap struct {
	Version           string        `json:"version"`
	Network           NetworkDomain `json:"network"`
	OwnerAgentID      string        `json:"owner_agent_id"`
	ObjectNonceBase64 string        `json:"object_nonce_base64url"`
}

type ActionKind string

const (
	ActionRegisterAgent      ActionKind = "register_agent"
	ActionUpdateAgentPolicy  ActionKind = "update_agent_policy"
	ActionDelegateAgent      ActionKind = "delegate_agent"
	ActionRecoverAgent       ActionKind = "recover_agent"
	ActionRevokeAgent        ActionKind = "revoke_agent"
	ActionRegisterCapability ActionKind = "register_capability"
	ActionUpdateCapability   ActionKind = "update_capability"
	ActionTransferCapability ActionKind = "transfer_capability"
	ActionRevokeCapability   ActionKind = "revoke_capability"
)

type RegistryAction struct {
	Version             string        `json:"version"`
	Kind                ActionKind    `json:"kind"`
	Network             NetworkDomain `json:"network"`
	AgentID             string        `json:"agent_id"`
	CapabilityID        string        `json:"capability_id"`
	CapabilityVersion   string        `json:"capability_version"`
	Generation          uint64        `json:"generation"`
	Sequence            uint64        `json:"sequence"`
	PreviousEventDigest string        `json:"previous_event_digest"`
	PolicyDigest        string        `json:"policy_digest"`
	PayloadDigest       string        `json:"payload_digest"`
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
	PreviousEventDigest string        `json:"previous_event_digest"`
	FinalizedCheckpoint uint64        `json:"finalized_checkpoint"`
	TransactionIndex    uint32        `json:"transaction_index"`
	EventIndex          uint32        `json:"event_index"`
}

type Signature struct {
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	SignatureBase64 string `json:"signature_base64url"`
}

func (n NetworkDomain) Validate() error {
	if !networkPattern.MatchString(n.NetworkID) || !validDigest(n.GenesisRootHash) || !validDigest(n.GenesisFileHash) {
		return fail(CodeInvalidNetwork, "network")
	}
	return nil
}

func ControllerPolicyDigest(policy ControllerPolicy) (string, error) {
	if err := validateControllerPolicy(policy); err != nil {
		return "", err
	}
	return codec.Digest(ControllerPolicyDomain, policy)
}

func AgentID(value AgentBootstrap) (string, error) {
	if value.Version != Version {
		return "", fail(CodeUnsupportedVersion, "version")
	}
	if err := value.Network.Validate(); err != nil {
		return "", err
	}
	if !validNonce(value.ObjectNonceBase64) || !validDigest(value.InitialControllerPolicy) {
		return "", fail(CodeInvalidIdentifier, "agent_bootstrap")
	}
	digest, err := rawDigest(AgentIDDomain, value)
	if err != nil {
		return "", err
	}
	return "agent_" + hex.EncodeToString(digest), nil
}

func CapabilityID(value CapabilityBootstrap) (string, error) {
	if value.Version != Version {
		return "", fail(CodeUnsupportedVersion, "version")
	}
	if err := value.Network.Validate(); err != nil {
		return "", err
	}
	if !validID(value.OwnerAgentID, "agent") || !validNonce(value.ObjectNonceBase64) {
		return "", fail(CodeInvalidIdentifier, "capability_bootstrap")
	}
	digest, err := rawDigest(CapabilityIDDomain, value)
	if err != nil {
		return "", err
	}
	return "cap_" + hex.EncodeToString(digest), nil
}

func AgentURI(agentID string) (string, error) {
	if !validID(agentID, "agent") {
		return "", fail(CodeInvalidIdentifier, "agent_id")
	}
	return "atos://agent/" + agentID, nil
}

func CapabilityURI(capabilityID, version string) (string, error) {
	if !validID(capabilityID, "cap") || !validVersion(version) {
		return "", fail(CodeInvalidIdentifier, "capability_id_or_version")
	}
	return "atos://capability/" + capabilityID + "/versions/" + version, nil
}

func CapabilityLineageURI(capabilityID string) (string, error) {
	if !validID(capabilityID, "cap") {
		return "", fail(CodeInvalidIdentifier, "capability_id")
	}
	return "atos://capability/" + capabilityID, nil
}

func ParseURI(value string) (kind, objectID, version string, err error) {
	if strings.ContainsAny(value, "?#%\\") || strings.Contains(value, "//") && !strings.HasPrefix(value, "atos://") {
		return "", "", "", fail(CodeNoncanonicalURI, "uri")
	}
	parts := strings.Split(value, "/")
	if len(parts) == 4 && parts[0] == "atos:" && parts[1] == "" && parts[2] == "agent" && validID(parts[3], "agent") {
		return "agent", parts[3], "", nil
	}
	if len(parts) == 4 && parts[0] == "atos:" && parts[1] == "" && parts[2] == "capability" && validID(parts[3], "cap") {
		return "capability", parts[3], "", nil
	}
	if len(parts) == 6 && parts[0] == "atos:" && parts[1] == "" && parts[2] == "capability" && validID(parts[3], "cap") && parts[4] == "versions" && validVersion(parts[5]) {
		return "capability", parts[3], parts[5], nil
	}
	return "", "", "", fail(CodeNoncanonicalURI, "uri")
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

// ValidateEventForAction prevents an observer from attaching a real action
// digest to a different object, version, network or ordering tuple.
func ValidateEventForAction(action RegistryAction, event RegistryEvent) error {
	if err := action.Validate(); err != nil {
		return err
	}
	if err := event.Validate(); err != nil {
		return err
	}
	digest, err := ActionDigest(action)
	if err != nil {
		return err
	}
	if digest != event.ActionDigest || action.Kind != event.Kind || action.Network != event.Network ||
		action.AgentID != event.AgentID || action.CapabilityID != event.CapabilityID ||
		action.CapabilityVersion != event.CapabilityVersion || action.Generation != event.Generation ||
		action.Sequence != event.Sequence || action.PreviousEventDigest != event.PreviousEventDigest {
		return fail(CodeCrossDomainReplay, "registry_event.action_tuple")
	}
	return nil
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
		if a.PreviousEventDigest != "" {
			return fail(CodePredecessorMismatch, "previous_event_digest")
		}
	} else if !validDigest(a.PreviousEventDigest) {
		return fail(CodePredecessorMismatch, "previous_event_digest")
	}
	capabilityAction := strings.Contains(string(a.Kind), "capability")
	if !validID(a.AgentID, "agent") || capabilityAction != validID(a.CapabilityID, "cap") {
		return fail(CodeInvalidIdentifier, "registry_action.object")
	}
	if capabilityAction && a.Kind != ActionRevokeCapability && !validVersion(a.CapabilityVersion) {
		return fail(CodeInvalidIdentifier, "capability_version")
	}
	if capabilityAction && a.Kind == ActionRevokeCapability && a.CapabilityVersion != "" && !validVersion(a.CapabilityVersion) {
		return fail(CodeInvalidIdentifier, "capability_version")
	}
	if !capabilityAction && (a.CapabilityID != "" || a.CapabilityVersion != "") {
		return fail(CodeCrossDomainReplay, "registry_action.capability")
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
	if e.FinalizedCheckpoint == 0 {
		return fail(CodeFinalityUnavailable, "finalized_checkpoint")
	}
	if !validActionKind(e.Kind) || !validDigest(e.ActionDigest) || e.Generation == 0 || e.Sequence == 0 || !validID(e.AgentID, "agent") {
		return fail(CodeCanonicalEncoding, "registry_event")
	}
	if e.Sequence == 1 {
		if e.PreviousEventDigest != "" {
			return fail(CodePredecessorMismatch, "previous_event_digest")
		}
	} else if !validDigest(e.PreviousEventDigest) {
		return fail(CodePredecessorMismatch, "previous_event_digest")
	}
	capabilityEvent := strings.Contains(string(e.Kind), "capability")
	if capabilityEvent != validID(e.CapabilityID, "cap") {
		return fail(CodeInvalidIdentifier, "registry_event.object")
	}
	if capabilityEvent && e.Kind != ActionRevokeCapability && !validVersion(e.CapabilityVersion) {
		return fail(CodeInvalidIdentifier, "capability_version")
	}
	return nil
}

func SignAction(privateKey ed25519.PrivateKey, keyID string, action RegistryAction) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !keyIDPattern.MatchString(keyID) {
		return Signature{}, errors.New("invalid native signing key")
	}
	message, err := actionSigningMessage(action)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Algorithm: SignatureAlgorithm, KeyID: keyID, SignatureBase64: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

func VerifyAction(publicKey ed25519.PublicKey, action RegistryAction, signature Signature) error {
	if len(publicKey) != ed25519.PublicKeySize || signature.Algorithm != SignatureAlgorithm || !keyIDPattern.MatchString(signature.KeyID) {
		return errors.New("invalid native signature metadata")
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature.SignatureBase64)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("invalid native signature encoding")
	}
	message, err := actionSigningMessage(action)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, raw) {
		return fail(CodePolicyUnauthorized, "signature")
	}
	return nil
}

func actionSigningMessage(action RegistryAction) ([]byte, error) {
	canonical, err := CanonicalAction(action)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	var out bytes.Buffer
	out.WriteString("TOS-NATIVE-SEMANTIC-SIGNATURE")
	out.WriteByte(0)
	_ = binary.Write(&out, binary.BigEndian, uint16(len(SemanticSignatureDomain)))
	out.WriteString(SemanticSignatureDomain)
	_ = binary.Write(&out, binary.BigEndian, uint16(len(RegistryActionDomain)))
	out.WriteString(RegistryActionDomain)
	out.Write(digest[:])
	return out.Bytes(), nil
}

func validateControllerPolicy(policy ControllerPolicy) error {
	if policy.Threshold == 0 || len(policy.Controllers) == 0 || len(policy.Controllers) > 64 {
		return errors.New("invalid controller threshold or count")
	}
	var total uint64
	last := ""
	keys := make(map[string]struct{}, len(policy.Controllers))
	for _, controller := range policy.Controllers {
		if !keyIDPattern.MatchString(controller.KeyID) || controller.KeyID <= last || controller.Algorithm != SignatureAlgorithm || controller.Weight == 0 || !validPublicKey(controller.PublicKeyBase64) || !sortedUniquePurposes(controller.Purposes) {
			return errors.New("invalid or non-canonical controller")
		}
		last = controller.KeyID
		keys[controller.KeyID] = struct{}{}
		total += uint64(controller.Weight)
	}
	if uint64(policy.Threshold) > total {
		return errors.New("controller threshold exceeds weight")
	}
	if !sort.StringsAreSorted(policy.RecoveryKeyIDs) {
		return errors.New("recovery keys are not sorted")
	}
	last = ""
	for _, key := range policy.RecoveryKeyIDs {
		if key == last {
			return errors.New("duplicate recovery key")
		}
		if _, ok := keys[key]; !ok {
			return errors.New("unknown recovery key")
		}
		last = key
	}
	return nil
}

func rawDigest(domain string, value interface{}) ([]byte, error) {
	digest, err := codec.Digest(domain, value)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	raw, err := hex.DecodeString(value[7:])
	return err == nil && value == strings.ToLower(value) && !allZero(raw)
}
func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}
func validPublicKey(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == ed25519.PublicKeySize && !allZero(decoded)
}
func validID(value, prefix string) bool {
	match := idPattern.FindStringSubmatch(value)
	return len(match) == 3 && match[1] == prefix
}
func validVersion(value string) bool {
	if !versionPattern.MatchString(value) {
		return false
	}
	// Build metadata does not affect SemVer precedence and therefore creates
	// aliases for an immutable Capability version. V1 forbids it in IDs/URIs.
	if strings.Contains(value, "+") {
		return false
	}
	if dash := strings.IndexByte(value, '-'); dash >= 0 {
		for _, identifier := range strings.Split(value[dash+1:], ".") {
			if len(identifier) > 1 && identifier[0] == '0' {
				allDigits := true
				for _, character := range identifier {
					allDigits = allDigits && character >= '0' && character <= '9'
				}
				if allDigits {
					return false
				}
			}
		}
	}
	return true
}
func validActionKind(kind ActionKind) bool {
	switch kind {
	case ActionRegisterAgent, ActionUpdateAgentPolicy, ActionDelegateAgent, ActionRecoverAgent, ActionRevokeAgent, ActionRegisterCapability, ActionUpdateCapability, ActionTransferCapability, ActionRevokeCapability:
		return true
	}
	return false
}
func sortedUniquePurposes(values []string) bool {
	if len(values) == 0 || !sort.StringsAreSorted(values) {
		return false
	}
	last := ""
	for _, value := range values {
		if value == last || !keyIDPattern.MatchString(value) {
			return false
		}
		last = value
	}
	return true
}
func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func ParseAgentID(value string) error {
	if !validID(value, "agent") {
		return fmt.Errorf("%w", fail(CodeInvalidIdentifier, "agent_id"))
	}
	return nil
}
func ParseCapabilityID(value string) error {
	if !validID(value, "cap") {
		return fmt.Errorf("%w", fail(CodeInvalidIdentifier, "capability_id"))
	}
	return nil
}
