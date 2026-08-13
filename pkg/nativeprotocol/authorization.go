package nativeprotocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"sort"
)

type Signature struct {
	Version         string `json:"version"`
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	SignatureBase64 string `json:"signature_base64url"`
}

func SignAction(privateKey ed25519.PrivateKey, keyID string, action RegistryAction) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !keyIDPattern.MatchString(keyID) {
		return Signature{}, fail(CodeCanonicalEncoding, "signature.key")
	}
	message, err := actionSigningMessage(Version, SignatureAlgorithm, keyID, action)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Version: Version, Algorithm: SignatureAlgorithm, KeyID: keyID, SignatureBase64: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}
func VerifyAction(publicKey ed25519.PublicKey, action RegistryAction, signature Signature) error {
	if len(publicKey) != ed25519.PublicKeySize || signature.Version != Version || signature.Algorithm != SignatureAlgorithm || !keyIDPattern.MatchString(signature.KeyID) {
		return fail(CodeCanonicalEncoding, "signature.metadata")
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature.SignatureBase64)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fail(CodeCanonicalEncoding, "signature.encoding")
	}
	message, err := actionSigningMessage(signature.Version, signature.Algorithm, signature.KeyID, action)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, raw) {
		return fail(CodePolicyUnauthorized, "signature")
	}
	return nil
}
func actionSigningMessage(version, algorithm, keyID string, action RegistryAction) ([]byte, error) {
	canonical, err := CanonicalAction(action)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	var out bytes.Buffer
	out.WriteString("TOS-NATIVE-SEMANTIC-SIGNATURE")
	out.WriteByte(0)
	write16(&out, SemanticSignatureDomain)
	write16(&out, version)
	write16(&out, algorithm)
	write16(&out, keyID)
	write16(&out, RegistryActionDomain)
	out.Write(digest[:])
	return out.Bytes(), nil
}
func write16(out *bytes.Buffer, value string) {
	_ = binary.Write(out, binary.BigEndian, uint16(len(value)))
	out.WriteString(value)
}

func RequiredPurpose(kind ActionKind) string {
	switch kind {
	case ActionRegisterAgent, ActionUpdateAgentPolicy, ActionRevokeAgent:
		return "agent_control"
	case ActionDelegateAgent:
		return "delegation"
	case ActionInitiateRecovery, ActionRecoverAgent:
		return "recovery"
	case ActionRegisterCapability, ActionUpdateCapability, ActionTransferCapability, ActionRevokeCapability:
		return "capability_control"
	}
	return ""
}

// VerifyAuthorization applies sorted-set, unique-key and weighted-threshold
// rules. Controller policy validation already proves public-key uniqueness, so
// one physical key can contribute weight at most once.
func VerifyAuthorization(action RegistryAction, policy ControllerPolicy, signatures []Signature) error {
	if action.Kind == ActionRegisterAgent {
		var payload RegisterAgentPayload
		if err := DecodePayload(action, &payload); err != nil {
			return err
		}
		digest, err := ControllerPolicyDigest(policy)
		if err != nil || digest != action.PolicyDigest || digest != payload.InitialPolicyDigest {
			return fail(CodePolicyUnauthorized, "initial_controller_policy")
		}
	}
	return verifyAuthorizationForPurpose(action, policy, RequiredPurpose(action.Kind), signatures)
}
func verifyAuthorizationForPurpose(action RegistryAction, policy ControllerPolicy, purpose string, signatures []Signature) error {
	if err := action.Validate(); err != nil {
		return err
	}
	if err := ValidateControllerPolicy(policy); err != nil {
		return err
	}
	if purpose == "" {
		return fail(CodePurposeUnauthorized, "kind")
	}
	if len(signatures) == 0 || !sort.SliceIsSorted(signatures, func(i, j int) bool { return signatures[i].KeyID < signatures[j].KeyID }) {
		return fail(CodeCanonicalEncoding, "signatures.order")
	}
	keys := map[string]ControllerKey{}
	for _, key := range policy.Controllers {
		keys[key.KeyID] = key
	}
	var weight uint64
	last := ""
	for _, signature := range signatures {
		if signature.KeyID == last {
			return fail(CodeCanonicalEncoding, "signatures.duplicate")
		}
		last = signature.KeyID
		key, ok := keys[signature.KeyID]
		if !ok || !contains(key.Purposes, purpose) {
			return fail(CodePurposeUnauthorized, "signature.key_id")
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKeyBase64)
		if err != nil {
			return fail(CodeCanonicalEncoding, "controller.public_key")
		}
		if err := VerifyAction(ed25519.PublicKey(publicKey), action, signature); err != nil {
			return err
		}
		weight += uint64(key.Weight)
	}
	required := uint64(policy.Threshold)
	if purpose == "recovery" {
		required = uint64(policy.RecoveryThreshold)
	}
	if weight < required {
		return fail(CodePolicyUnauthorized, "signatures.threshold")
	}
	return nil
}

// VerifyTransferAuthorization requires independent current-owner authority and
// new-owner acceptance over the identical transfer action.
func VerifyTransferAuthorization(action RegistryAction, currentPolicy, newOwnerPolicy ControllerPolicy, currentSignatures, newOwnerSignatures []Signature) error {
	if action.Kind != ActionTransferCapability {
		return fail(CodePurposeUnauthorized, "kind")
	}
	var payload TransferCapabilityPayload
	if err := DecodePayload(action, &payload); err != nil {
		return err
	}
	newPolicyDigest, err := ControllerPolicyDigest(newOwnerPolicy)
	if err != nil || newPolicyDigest != payload.NewOwnerPolicyDigest {
		return fail(CodePolicyUnauthorized, "payload.new_owner_policy_digest")
	}
	if payload.CurrentOwnerAgentID != action.AgentID {
		return fail(CodeCrossDomainReplay, "payload.current_owner_agent_id")
	}
	if err := verifyAuthorizationForPurpose(action, currentPolicy, "capability_control", currentSignatures); err != nil {
		return err
	}
	return verifyAuthorizationForPurpose(action, newOwnerPolicy, "capability_control", newOwnerSignatures)
}

// ValidateTransition freezes generation/sequence and recovery-timelock rules.
// observedUnixSeconds must come from a finalized TOS block observation.
func ValidateTransition(previous *RegistryEvent, action RegistryAction, observedUnixSeconds uint64) error {
	if err := action.Validate(); err != nil {
		return err
	}
	if previous == nil {
		if (action.Kind != ActionRegisterAgent && action.Kind != ActionRegisterCapability) || action.Generation != 1 || action.Sequence != 1 || action.PreviousStateDigest != "" {
			return fail(CodeSequenceConflict, "registry_action")
		}
		return nil
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	if previous.Network != action.Network || previous.AgentID != action.AgentID || previous.CapabilityID != action.CapabilityID {
		return fail(CodeCrossDomainReplay, "previous_state")
	}
	if action.Kind == ActionRecoverAgent {
		var payload RecoverAgentPayload
		if err := DecodePayload(action, &payload); err != nil {
			return err
		}
		if action.Generation != previous.Generation+1 || action.Sequence != 1 || action.PreviousStateDigest != previous.StateDigest {
			return fail(CodeSequenceConflict, "recovery_generation")
		}
		if observedUnixSeconds == 0 || observedUnixSeconds < payload.ExecuteAfterUnixSeconds {
			return fail(CodeTimelockPending, "recovery.execute_after_unix_seconds")
		}
		return nil
	}
	if action.Generation != previous.Generation || action.Sequence != previous.Sequence+1 || action.PreviousStateDigest != previous.StateDigest {
		return fail(CodeSequenceConflict, "registry_action.sequence")
	}
	return nil
}

// ValidateRecoveryTransition binds execution to the finalized initiation event
// and the old policy's timelock. Wall-clock time is never accepted here.
func ValidateRecoveryTransition(previous RegistryEvent, action RegistryAction, initiation RegistryAction, initiationEvent RegistryEvent, observation EventObservation, oldPolicy ControllerPolicy, executionBlockUnixSeconds uint64) error {
	if initiation.Kind != ActionInitiateRecovery || initiation.AgentID != action.AgentID || initiation.Network != action.Network {
		return fail(CodeCrossDomainReplay, "recovery.initiation")
	}
	initDigest, err := ActionDigest(initiation)
	if err != nil {
		return err
	}
	var recoverPayload RecoverAgentPayload
	var initiatePayload InitiateRecoveryPayload
	if err := DecodePayload(action, &recoverPayload); err != nil {
		return err
	}
	if err := DecodePayload(initiation, &initiatePayload); err != nil {
		return err
	}
	if err := observation.Validate(); err != nil {
		return err
	}
	if err := ValidateEventForAction(initiation, initiationEvent); err != nil {
		return err
	}
	initEventDigest, err := EventDigest(initiationEvent)
	if err != nil || observation.EventDigest != initEventDigest {
		return fail(CodeCrossDomainReplay, "recovery.initiation_observation")
	}
	if recoverPayload.InitiationActionDigest != initDigest || recoverPayload.InitiationReference != observation.Reference || recoverPayload.NewPolicyDigest != initiatePayload.NewPolicyDigest {
		return fail(CodeCrossDomainReplay, "recovery.initiation_tuple")
	}
	executeAfter := observation.BlockUnixSeconds + oldPolicy.RecoveryTimelock
	if executeAfter < observation.BlockUnixSeconds || recoverPayload.ExecuteAfterUnixSeconds != executeAfter || initiatePayload.ExecuteAfterUnixSeconds != executeAfter {
		return fail(CodeTimelockPending, "recovery.execute_after_unix_seconds")
	}
	return ValidateTransition(&previous, action, executionBlockUnixSeconds)
}

// ValidateDelegationAt uses finalized checkpoints only and enforces the frozen
// staleness bound relative to the verifier's observed finalized head.
func ValidateDelegationAt(payload DelegationPayload, checkpoint, observedHead uint64) error {
	if err := validatePayload(ActionDelegateAgent, payload); err != nil {
		return err
	}
	if checkpoint < payload.ValidFromCheckpoint || checkpoint >= payload.ValidUntilCheckpoint {
		return fail(CodePolicyUnauthorized, "delegation.checkpoint")
	}
	if observedHead < checkpoint || observedHead-checkpoint > payload.MaxStalenessCheckpoints {
		return fail(CodeStaleAuthority, "delegation.observed_head")
	}
	return nil
}
