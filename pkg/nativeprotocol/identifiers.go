// Package nativeprotocol implements the frozen Phase 5A Native identifiers,
// registry values and purpose-separated semantic authorization. It contains no
// chain mutation, gateway account or database behavior.
package nativeprotocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
	RegistryStateDomain     = "tos.native.registry-state.v1"
	EventObservationDomain  = "tos.native.event-observation.v1"
	SemanticSignatureDomain = "tos.native.semantic-signature.v1"
	SignatureAlgorithm      = "ed25519"
)

var (
	networkPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	idPattern      = regexp.MustCompile(`^(agent|cap)_([0-9a-f]{64})$`)
	keyIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	purposePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type ErrorCode string

const (
	CodeUnsupportedVersion  ErrorCode = "NATIVE_UNSUPPORTED_VERSION"
	CodeInvalidNetwork      ErrorCode = "NATIVE_INVALID_NETWORK"
	CodeInvalidIdentifier   ErrorCode = "NATIVE_INVALID_IDENTIFIER"
	CodeNoncanonicalURI     ErrorCode = "NATIVE_NONCANONICAL_URI"
	CodeCanonicalEncoding   ErrorCode = "NATIVE_CANONICAL_ENCODING"
	CodeCrossDomainReplay   ErrorCode = "NATIVE_CROSS_DOMAIN_REPLAY"
	CodeSequenceConflict    ErrorCode = "NATIVE_SEQUENCE_CONFLICT"
	CodePredecessorMismatch ErrorCode = "NATIVE_PREDECESSOR_MISMATCH"
	CodePolicyUnauthorized  ErrorCode = "NATIVE_POLICY_UNAUTHORIZED"
	CodePurposeUnauthorized ErrorCode = "NATIVE_PURPOSE_UNAUTHORIZED"
	CodeTimelockPending     ErrorCode = "NATIVE_RECOVERY_TIMELOCK_PENDING"
	CodePermanentlyRevoked  ErrorCode = "NATIVE_PERMANENTLY_REVOKED"
	CodeStaleAuthority      ErrorCode = "NATIVE_STALE_AUTHORITY"
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

func (n NetworkDomain) Validate() error {
	if !networkPattern.MatchString(n.NetworkID) || !validDigest(n.GenesisRootHash) || !validDigest(n.GenesisFileHash) {
		return fail(CodeInvalidNetwork, "network")
	}
	return nil
}

type ControllerKey struct {
	KeyID           string   `json:"key_id"`
	Algorithm       string   `json:"algorithm"`
	PublicKeyBase64 string   `json:"public_key_base64url"`
	Weight          uint32   `json:"weight"`
	Purposes        []string `json:"purposes"`
}
type ControllerPolicy struct {
	Threshold         uint32          `json:"threshold"`
	RecoveryThreshold uint32          `json:"recovery_threshold"`
	Controllers       []ControllerKey `json:"controllers"`
	RecoveryKeyIDs    []string        `json:"recovery_key_ids"`
	RecoveryTimelock  uint64          `json:"recovery_timelock_seconds"`
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

func ControllerPolicyDigest(policy ControllerPolicy) (string, error) {
	if err := ValidateControllerPolicy(policy); err != nil {
		return "", err
	}
	return codec.Digest(ControllerPolicyDomain, policy)
}

// EncodeControllerPolicy returns the exact canonical bytes that registry
// actions carry so a fresh resolver can rebuild authority without a gateway
// policy table.
func EncodeControllerPolicy(policy ControllerPolicy) (string, string, error) {
	if err := ValidateControllerPolicy(policy); err != nil {
		return "", "", err
	}
	raw, err := codec.Marshal(policy)
	if err != nil {
		return "", "", err
	}
	if len(raw) > MaxControllerPolicyBytes {
		return "", "", fail(CodeCanonicalEncoding, "controller_policy.size")
	}
	digest, err := codec.DigestCanonical(ControllerPolicyDomain, raw)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), digest, nil
}

func DecodeControllerPolicy(encoded, expectedDigest string) (ControllerPolicy, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > MaxControllerPolicyBytes || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return ControllerPolicy{}, fail(CodeCanonicalEncoding, "controller_policy.cbor_base64url")
	}
	digest, err := codec.DigestCanonical(ControllerPolicyDomain, raw)
	if err != nil || digest != expectedDigest {
		return ControllerPolicy{}, fail(CodePolicyUnauthorized, "controller_policy.digest")
	}
	var policy ControllerPolicy
	if err := codec.Unmarshal(raw, &policy); err != nil {
		return ControllerPolicy{}, fail(CodeCanonicalEncoding, "controller_policy")
	}
	if err := ValidateControllerPolicy(policy); err != nil {
		return ControllerPolicy{}, err
	}
	return policy, nil
}
func ValidateControllerPolicy(policy ControllerPolicy) error {
	if policy.Threshold == 0 || policy.RecoveryThreshold == 0 || len(policy.Controllers) == 0 || len(policy.Controllers) > 64 {
		return fail(CodeCanonicalEncoding, "controller_policy.threshold")
	}
	var total, recovery uint64
	last := ""
	keys := map[string]ControllerKey{}
	publicKeys := map[string]struct{}{}
	for _, key := range policy.Controllers {
		if !keyIDPattern.MatchString(key.KeyID) || key.KeyID <= last || key.Algorithm != SignatureAlgorithm || key.Weight == 0 || !validPublicKey(key.PublicKeyBase64) || len(key.Purposes) > MaxPurposesPerController || !sortedUniquePurposes(key.Purposes) {
			return fail(CodeCanonicalEncoding, "controller_policy.controllers")
		}
		if _, duplicate := publicKeys[key.PublicKeyBase64]; duplicate {
			return fail(CodeCanonicalEncoding, "controller_policy.duplicate_public_key")
		}
		last = key.KeyID
		keys[key.KeyID] = key
		publicKeys[key.PublicKeyBase64] = struct{}{}
		total += uint64(key.Weight)
	}
	if uint64(policy.Threshold) > total || !sort.StringsAreSorted(policy.RecoveryKeyIDs) {
		return fail(CodeCanonicalEncoding, "controller_policy.threshold")
	}
	last = ""
	for _, id := range policy.RecoveryKeyIDs {
		key, ok := keys[id]
		if !ok || id == last || !contains(key.Purposes, "recovery") {
			return fail(CodeCanonicalEncoding, "controller_policy.recovery_keys")
		}
		last = id
		recovery += uint64(key.Weight)
	}
	if uint64(policy.RecoveryThreshold) > recovery {
		return fail(CodeCanonicalEncoding, "controller_policy.recovery_threshold")
	}
	return nil
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
func AgentURI(id string) (string, error) {
	if !validID(id, "agent") {
		return "", fail(CodeInvalidIdentifier, "agent_id")
	}
	return "atos://agent/" + id, nil
}
func CapabilityLineageURI(id string) (string, error) {
	if !validID(id, "cap") {
		return "", fail(CodeInvalidIdentifier, "capability_id")
	}
	return "atos://capability/" + id, nil
}
func CapabilityURI(id, version string) (string, error) {
	if !validID(id, "cap") || !validVersion(version) {
		return "", fail(CodeInvalidIdentifier, "capability_id_or_version")
	}
	return "atos://capability/" + id + "/versions/" + version, nil
}
func ParseURI(value string) (kind, id, version string, err error) {
	if strings.ContainsAny(value, "?#%\\") {
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

func rawDigest(domain string, value interface{}) ([]byte, error) {
	d, err := codec.Digest(domain, value)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(d, "sha256:"))
}
func validDigest(v string) bool {
	if !strings.HasPrefix(v, "sha256:") || len(v) != 71 {
		return false
	}
	raw, err := hex.DecodeString(v[7:])
	return err == nil && v == strings.ToLower(v) && !allZero(raw)
}
func validNonce(v string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == v
}
func validPublicKey(v string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(raw) == ed25519.PublicKeySize && !allZero(raw) && base64.RawURLEncoding.EncodeToString(raw) == v
}
func validID(v, prefix string) bool {
	m := idPattern.FindStringSubmatch(v)
	return len(m) == 3 && m[1] == prefix
}
func validVersion(v string) bool {
	if !versionPattern.MatchString(v) {
		return false
	}
	if dash := strings.IndexByte(v, '-'); dash >= 0 {
		for _, id := range strings.Split(v[dash+1:], ".") {
			if len(id) > 1 && id[0] == '0' {
				digits := true
				for _, c := range id {
					digits = digits && c >= '0' && c <= '9'
				}
				if digits {
					return false
				}
			}
		}
	}
	return true
}
func sortedUniquePurposes(v []string) bool {
	if len(v) == 0 || !sort.StringsAreSorted(v) {
		return false
	}
	last := ""
	for _, p := range v {
		if p == last || !purposePattern.MatchString(p) {
			return false
		}
		last = p
	}
	return true
}
func contains(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}
func allZero(v []byte) bool {
	for _, b := range v {
		if b != 0 {
			return false
		}
	}
	return true
}
