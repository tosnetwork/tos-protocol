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
func VerifyAuthorization(action RegistryAction, expectedPolicyDigest string, policy ControllerPolicy, signatures []Signature) error {
	if err := validateAuthorizationPolicy(action, expectedPolicyDigest, policy); err != nil {
		return err
	}
	keyIDs := make([]string, len(signatures))
	for i := range signatures {
		keyIDs[i] = signatures[i].KeyID
	}
	if err := validateAuthorizationKeyIDs(action, policy, RequiredPurpose(action.Kind), keyIDs); err != nil {
		return err
	}
	keys := map[string]ControllerKey{}
	for _, key := range policy.Controllers {
		keys[key.KeyID] = key
	}
	for _, signature := range signatures {
		key := keys[signature.KeyID]
		publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKeyBase64)
		if err != nil {
			return fail(CodeCanonicalEncoding, "controller.public_key")
		}
		if err := VerifyAction(ed25519.PublicKey(publicKey), action, signature); err != nil {
			return err
		}
	}
	return nil
}

func validateAuthorizationPolicy(action RegistryAction, expectedPolicyDigest string, policy ControllerPolicy) error {
	if action.Kind == ActionTransferCapability {
		return fail(CodePurposeUnauthorized, "transfer.dual_authorization_required")
	}
	policyDigest, err := ControllerPolicyDigest(policy)
	if err != nil {
		return err
	}
	if action.Kind == ActionRegisterAgent {
		if expectedPolicyDigest != "" {
			return fail(CodePolicyUnauthorized, "current_controller_policy")
		}
		var payload RegisterAgentPayload
		if err := DecodePayload(action, &payload); err != nil {
			return err
		}
		if policyDigest != action.PolicyDigest || policyDigest != payload.InitialPolicyDigest {
			return fail(CodePolicyUnauthorized, "initial_controller_policy")
		}
	} else if !validDigest(expectedPolicyDigest) || policyDigest != expectedPolicyDigest || policyDigest != action.PolicyDigest {
		return fail(CodePolicyUnauthorized, "current_controller_policy")
	}
	if action.Kind == ActionRegisterCapability || action.Kind == ActionUpdateCapability {
		var payload CapabilityVersionPayload
		if action.Kind == ActionRegisterCapability {
			var registration RegisterCapabilityPayload
			if err := DecodePayload(action, &registration); err != nil {
				return err
			}
			payload = registration.Version
		} else if err := DecodePayload(action, &payload); err != nil {
			return err
		}
		if err := validateCapabilitySignersForPolicy(payload, policy); err != nil {
			return err
		}
	}
	if action.Kind == ActionDelegateAgent {
		var payload DelegationPayload
		if err := DecodePayload(action, &payload); err != nil {
			return err
		}
		if err := validateDelegationForPolicy(payload, policy); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAuthorizationKeyIDs validates the exact sorted controller set that
// authorized a finalized TVM execution. Cryptographic signature verification
// remains the caller's responsibility; this function single-sources purpose,
// uniqueness and weighted-threshold semantics for the contract and resolver.

func ValidateAuthorizationKeyIDs(action RegistryAction, expectedPolicyDigest string, policy ControllerPolicy, keyIDs []string) error {
	if err := validateAuthorizationPolicy(action, expectedPolicyDigest, policy); err != nil {
		return err
	}
	return validateAuthorizationKeyIDs(action, policy, RequiredPurpose(action.Kind), keyIDs)
}

// ValidateTransferAuthorizationKeyIDs applies the frozen dual-owner policy
// binding and threshold rules to the independently verified finalized TVM
// signer identities.
func ValidateTransferAuthorizationKeyIDs(action RegistryAction, expectedCurrentPolicyDigest string, currentPolicy ControllerPolicy, expectedNewOwnerPolicyDigest string, newOwnerPolicy ControllerPolicy, currentKeyIDs, newOwnerKeyIDs []string) error {
	if action.Kind != ActionTransferCapability {
		return fail(CodePurposeUnauthorized, "kind")
	}
	var payload TransferCapabilityPayload
	if err := DecodePayload(action, &payload); err != nil {
		return err
	}
	currentPolicyDigest, err := ControllerPolicyDigest(currentPolicy)
	if err != nil || !validDigest(expectedCurrentPolicyDigest) || currentPolicyDigest != expectedCurrentPolicyDigest || currentPolicyDigest != action.PolicyDigest {
		return fail(CodePolicyUnauthorized, "current_controller_policy")
	}
	newPolicyDigest, err := ControllerPolicyDigest(newOwnerPolicy)
	if err != nil || !validDigest(expectedNewOwnerPolicyDigest) || newPolicyDigest != expectedNewOwnerPolicyDigest || newPolicyDigest != payload.NewOwnerPolicyDigest {
		return fail(CodePolicyUnauthorized, "payload.new_owner_policy_digest")
	}
	encoded, _, err := EncodeControllerPolicy(newOwnerPolicy)
	if err != nil || encoded != payload.NewOwnerPolicyCBORBase64 {
		return fail(CodePolicyUnauthorized, "payload.new_owner_policy")
	}
	if payload.CurrentOwnerAgentID != action.AgentID {
		return fail(CodeCrossDomainReplay, "payload.current_owner_agent_id")
	}
	if err := validateAuthorizationKeyIDs(action, currentPolicy, "capability_control", currentKeyIDs); err != nil {
		return err
	}
	return validateAuthorizationKeyIDs(action, newOwnerPolicy, "capability_control", newOwnerKeyIDs)
}

func validateAuthorizationKeyIDs(action RegistryAction, policy ControllerPolicy, purpose string, keyIDs []string) error {
	if err := action.Validate(); err != nil {
		return err
	}
	if err := ValidateControllerPolicy(policy); err != nil {
		return err
	}
	if purpose == "" {
		return fail(CodePurposeUnauthorized, "kind")
	}
	if len(keyIDs) == 0 || !sort.StringsAreSorted(keyIDs) {
		return fail(CodeCanonicalEncoding, "signatures.order")
	}
	keys := map[string]ControllerKey{}
	for _, key := range policy.Controllers {
		keys[key.KeyID] = key
	}
	var weight uint64
	last := ""
	for _, keyID := range keyIDs {
		if keyID == last {
			return fail(CodeCanonicalEncoding, "signatures.duplicate")
		}
		last = keyID
		key, ok := keys[keyID]
		if !ok || !contains(key.Purposes, purpose) {
			return fail(CodePurposeUnauthorized, "signature.key_id")
		}
		if purpose == "recovery" && !contains(policy.RecoveryKeyIDs, keyID) {
			return fail(CodePurposeUnauthorized, "signature.recovery_key_id")
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
func VerifyTransferAuthorization(action RegistryAction, expectedCurrentPolicyDigest string, currentPolicy ControllerPolicy, expectedNewOwnerPolicyDigest string, newOwnerPolicy ControllerPolicy, currentSignatures, newOwnerSignatures []Signature) error {
	if action.Kind != ActionTransferCapability {
		return fail(CodePurposeUnauthorized, "kind")
	}
	var payload TransferCapabilityPayload
	if err := DecodePayload(action, &payload); err != nil {
		return err
	}
	currentPolicyDigest, err := ControllerPolicyDigest(currentPolicy)
	if err != nil || !validDigest(expectedCurrentPolicyDigest) || currentPolicyDigest != expectedCurrentPolicyDigest || currentPolicyDigest != action.PolicyDigest {
		return fail(CodePolicyUnauthorized, "current_controller_policy")
	}
	newPolicyDigest, err := ControllerPolicyDigest(newOwnerPolicy)
	if err != nil || !validDigest(expectedNewOwnerPolicyDigest) || newPolicyDigest != expectedNewOwnerPolicyDigest || newPolicyDigest != payload.NewOwnerPolicyDigest {
		return fail(CodePolicyUnauthorized, "payload.new_owner_policy_digest")
	}
	encoded, _, err := EncodeControllerPolicy(newOwnerPolicy)
	if err != nil || encoded != payload.NewOwnerPolicyCBORBase64 {
		return fail(CodePolicyUnauthorized, "payload.new_owner_policy")
	}
	if payload.CurrentOwnerAgentID != action.AgentID {
		return fail(CodeCrossDomainReplay, "payload.current_owner_agent_id")
	}
	if err := verifyAuthorizationForPurpose(action, currentPolicy, "capability_control", currentSignatures); err != nil {
		return err
	}
	return verifyAuthorizationForPurpose(action, newOwnerPolicy, "capability_control", newOwnerSignatures)
}

func verifyAuthorizationForPurpose(action RegistryAction, policy ControllerPolicy, purpose string, signatures []Signature) error {
	keyIDs := make([]string, len(signatures))
	for i := range signatures {
		keyIDs[i] = signatures[i].KeyID
	}
	if err := validateAuthorizationKeyIDs(action, policy, purpose, keyIDs); err != nil {
		return err
	}
	keys := make(map[string]ControllerKey, len(policy.Controllers))
	for _, key := range policy.Controllers {
		keys[key.KeyID] = key
	}
	for _, signature := range signatures {
		publicKey, err := base64.RawURLEncoding.DecodeString(keys[signature.KeyID].PublicKeyBase64)
		if err != nil {
			return fail(CodeCanonicalEncoding, "controller.public_key")
		}
		if err := VerifyAction(ed25519.PublicKey(publicKey), action, signature); err != nil {
			return err
		}
	}
	return nil
}

func validateCapabilitySignersForPolicy(payload CapabilityVersionPayload, policy ControllerPolicy) error {
	keys := make(map[string]ControllerKey, len(policy.Controllers))
	for _, key := range policy.Controllers {
		keys[key.KeyID] = key
	}
	for _, keyID := range payload.QuoteSignerKeyIDs {
		key, ok := keys[keyID]
		if !ok || !contains(key.Purposes, "quote") {
			return fail(CodePurposeUnauthorized, "payload.quote_signer_key_ids")
		}
	}
	for _, keyID := range payload.ReceiptSignerKeyIDs {
		key, ok := keys[keyID]
		if !ok || !contains(key.Purposes, "receipt") {
			return fail(CodePurposeUnauthorized, "payload.receipt_signer_key_ids")
		}
	}
	return nil
}

func validateDelegationForPolicy(payload DelegationPayload, policy ControllerPolicy) error {
	for _, key := range policy.Controllers {
		if key.KeyID != payload.DelegateKeyID {
			continue
		}
		for _, purpose := range payload.Purposes {
			if !contains(key.Purposes, purpose) || purpose == "agent_control" || purpose == "capability_control" || purpose == "delegation" || purpose == "recovery" {
				return fail(CodePurposeUnauthorized, "payload.delegation.purposes")
			}
		}
		return nil
	}
	return fail(CodePurposeUnauthorized, "payload.delegation.delegate_key_id")
}

// DeriveNextState validates the complete logical transition and returns the
// only state digest that the corresponding event may emit. For non-Agent
// bootstrap and all Capability actions, expectedAuthorityPolicyDigest must be
// independently resolved from the controlling Agent's canonical state.
func DeriveNextState(previous *RegistryState, action RegistryAction, expectedAuthorityPolicyDigest string, observedUnixSeconds uint64) (RegistryState, error) {
	if err := action.Validate(); err != nil {
		return RegistryState{}, err
	}
	actionDigest, err := ActionDigest(action)
	if err != nil {
		return RegistryState{}, err
	}
	if previous == nil {
		if action.Generation != 1 || action.Sequence != 1 || action.PreviousStateDigest != "" {
			return RegistryState{}, fail(CodeSequenceConflict, "registry_action")
		}
		switch action.Kind {
		case ActionRegisterAgent:
			if expectedAuthorityPolicyDigest != "" {
				return RegistryState{}, fail(CodePolicyUnauthorized, "current_controller_policy")
			}
			var payload RegisterAgentPayload
			if err := DecodePayload(action, &payload); err != nil {
				return RegistryState{}, err
			}
			state := RegistryState{Version: Version, Network: action.Network, ObjectKind: "agent", AgentID: action.AgentID, Generation: 1, Sequence: 1, LastActionDigest: actionDigest, CurrentPolicyDigest: payload.InitialPolicyDigest, CurrentPolicyCBORBase64: payload.InitialPolicyCBORBase64, DelegationActionDigests: []string{}, CapabilityVersions: []CapabilityVersionState{}, AgentNonceBase64: payload.ObjectNonceBase64, AgentBootstrapPolicyDigest: payload.InitialPolicyDigest}
			if err := state.Validate(); err != nil {
				return RegistryState{}, err
			}
			return CanonicalState(state)
		case ActionRegisterCapability:
			if !validDigest(expectedAuthorityPolicyDigest) || action.PolicyDigest != expectedAuthorityPolicyDigest {
				return RegistryState{}, fail(CodePolicyUnauthorized, "current_controller_policy")
			}
			var payload RegisterCapabilityPayload
			if err := DecodePayload(action, &payload); err != nil {
				return RegistryState{}, err
			}
			state := RegistryState{Version: Version, Network: action.Network, ObjectKind: "capability", CapabilityID: action.CapabilityID, Generation: 1, Sequence: 1, LastActionDigest: actionDigest, OwnerAgentID: payload.Version.OwnerAgentID, CapabilityBootstrapOwnerAgentID: payload.Version.OwnerAgentID, CapabilityNonceBase64: payload.ObjectNonceBase64, CapabilityVersions: []CapabilityVersionState{{Version: action.CapabilityVersion, PayloadDigest: action.PayloadDigest}}, DelegationActionDigests: []string{}}
			if err := state.Validate(); err != nil {
				return RegistryState{}, err
			}
			return CanonicalState(state)
		default:
			return RegistryState{}, fail(CodeSequenceConflict, "registry_action.bootstrap")
		}
	}
	if err := previous.Validate(); err != nil {
		return RegistryState{}, err
	}
	if previous.Tombstoned {
		return RegistryState{}, fail(CodePermanentlyRevoked, "registry_state.tombstone")
	}
	previousDigest, err := StateDigest(*previous)
	if err != nil {
		return RegistryState{}, err
	}
	if previous.Network != action.Network || action.PreviousStateDigest != previousDigest {
		return RegistryState{}, fail(CodePredecessorMismatch, "previous_state_digest")
	}
	if previous.ObjectKind == "agent" {
		if isCapabilityKind(action.Kind) || action.AgentID != previous.AgentID || action.PolicyDigest != previous.CurrentPolicyDigest || expectedAuthorityPolicyDigest != previous.CurrentPolicyDigest {
			return RegistryState{}, fail(CodePolicyUnauthorized, "current_controller_policy")
		}
	} else if !isCapabilityKind(action.Kind) || action.CapabilityID != previous.CapabilityID || action.AgentID != previous.OwnerAgentID || !validDigest(expectedAuthorityPolicyDigest) || action.PolicyDigest != expectedAuthorityPolicyDigest {
		return RegistryState{}, fail(CodePolicyUnauthorized, "current_owner_policy")
	}
	if action.Kind == ActionRecoverAgent || action.Kind == ActionTransferCapability {
		if action.Generation != previous.Generation+1 || action.Sequence != 1 {
			return RegistryState{}, fail(CodeSequenceConflict, "registry_action.generation")
		}
	} else if action.Generation != previous.Generation || action.Sequence != previous.Sequence+1 {
		return RegistryState{}, fail(CodeSequenceConflict, "registry_action.sequence")
	}

	state := cloneState(*previous)
	state.Generation = action.Generation
	state.Sequence = action.Sequence
	state.PredecessorStateDigest = previousDigest
	state.LastActionDigest = actionDigest
	if action.Kind != ActionInitiateRecovery && action.Kind != ActionRecoverAgent {
		state.PendingRecovery = PendingRecovery{}
	}
	switch action.Kind {
	case ActionUpdateAgentPolicy:
		var payload UpdatePolicyPayload
		if err := DecodePayload(action, &payload); err != nil {
			return RegistryState{}, err
		}
		state.CurrentPolicyDigest = payload.NewPolicyDigest
		state.CurrentPolicyCBORBase64 = payload.NewPolicyCBORBase64
		// Delegations are scoped to the policy that authorized them. Rotation
		// invalidates and removes the obsolete generation-local set.
		state.DelegationActionDigests = []string{}
	case ActionDelegateAgent:
		if len(state.DelegationActionDigests) >= MaxDelegationsPerGeneration {
			return RegistryState{}, fail(CodeCanonicalEncoding, "registry_state.delegations.limit")
		}
		state.DelegationActionDigests = insertSortedDigest(state.DelegationActionDigests, actionDigest)
	case ActionInitiateRecovery:
		var payload InitiateRecoveryPayload
		if err := DecodePayload(action, &payload); err != nil {
			return RegistryState{}, err
		}
		state.PendingRecovery = PendingRecovery{InitiationActionDigest: actionDigest, NewPolicyDigest: payload.NewPolicyDigest, NewPolicyCBORBase64: payload.NewPolicyCBORBase64, ExecuteAfterUnixSeconds: payload.ExecuteAfterUnixSeconds}
	case ActionRecoverAgent:
		var payload RecoverAgentPayload
		if err := DecodePayload(action, &payload); err != nil {
			return RegistryState{}, err
		}
		pending := previous.PendingRecovery
		if pendingRecoveryIsZero(pending) || pending.InitiationActionDigest != payload.InitiationActionDigest || pending.NewPolicyDigest != payload.NewPolicyDigest || pending.ExecuteAfterUnixSeconds != payload.ExecuteAfterUnixSeconds {
			return RegistryState{}, fail(CodeCrossDomainReplay, "recovery.pending_state")
		}
		if observedUnixSeconds == 0 || observedUnixSeconds < pending.ExecuteAfterUnixSeconds {
			return RegistryState{}, fail(CodeTimelockPending, "recovery.execute_after_unix_seconds")
		}
		state.CurrentPolicyDigest = pending.NewPolicyDigest
		state.CurrentPolicyCBORBase64 = pending.NewPolicyCBORBase64
		state.PendingRecovery = PendingRecovery{}
		state.DelegationActionDigests = []string{}
	case ActionRevokeAgent:
		var payload RevocationPayload
		if err := DecodePayload(action, &payload); err != nil {
			return RegistryState{}, err
		}
		if payload.Scope != "agent" {
			return RegistryState{}, fail(CodeCanonicalEncoding, "payload.revocation.scope")
		}
		state.Tombstoned = true
		state.PendingRecovery = PendingRecovery{}
		state.DelegationActionDigests = []string{}
	case ActionUpdateCapability:
		var payload CapabilityVersionPayload
		if err := DecodePayload(action, &payload); err != nil {
			return RegistryState{}, err
		}
		if payload.OwnerAgentID != previous.OwnerAgentID || hasCapabilityVersion(state.CapabilityVersions, action.CapabilityVersion) {
			return RegistryState{}, fail(CodeSequenceConflict, "capability_version")
		}
		if len(state.CapabilityVersions) >= MaxCapabilityVersionsPerLineage {
			return RegistryState{}, fail(CodeCanonicalEncoding, "registry_state.capability_versions.limit")
		}
		state.CapabilityVersions = insertCapabilityVersion(state.CapabilityVersions, CapabilityVersionState{Version: action.CapabilityVersion, PayloadDigest: action.PayloadDigest})
	case ActionTransferCapability:
		var payload TransferCapabilityPayload
		if err := DecodePayload(action, &payload); err != nil {
			return RegistryState{}, err
		}
		if payload.CurrentOwnerAgentID != previous.OwnerAgentID {
			return RegistryState{}, fail(CodeCrossDomainReplay, "payload.current_owner_agent_id")
		}
		state.OwnerAgentID = payload.NewOwnerAgentID
	case ActionRevokeCapability:
		var payload RevocationPayload
		if err := DecodePayload(action, &payload); err != nil {
			return RegistryState{}, err
		}
		switch payload.Scope {
		case "lineage":
			if action.CapabilityVersion != "" {
				return RegistryState{}, fail(CodeCanonicalEncoding, "payload.revocation.scope")
			}
			state.Tombstoned = true
		case "version":
			if action.CapabilityVersion == "" || !markCapabilityVersionRevoked(state.CapabilityVersions, action.CapabilityVersion) {
				return RegistryState{}, fail(CodeSequenceConflict, "capability_version")
			}
		default:
			return RegistryState{}, fail(CodeCanonicalEncoding, "payload.revocation.scope")
		}
	default:
		return RegistryState{}, fail(CodeSequenceConflict, "registry_action.kind")
	}
	if err := state.Validate(); err != nil {
		return RegistryState{}, err
	}
	return CanonicalState(state)
}

func ValidateTransition(previous *RegistryState, action RegistryAction, expectedAuthorityPolicyDigest string, observedUnixSeconds uint64) error {
	_, err := DeriveNextState(previous, action, expectedAuthorityPolicyDigest, observedUnixSeconds)
	return err
}

// ValidateEventTransition derives state rather than accepting caller-supplied
// state, then requires the finalized event to commit exactly that result.
func ValidateEventTransition(previous *RegistryState, action RegistryAction, expectedAuthorityPolicyDigest string, observedUnixSeconds uint64, event RegistryEvent) (RegistryState, error) {
	state, err := DeriveNextState(previous, action, expectedAuthorityPolicyDigest, observedUnixSeconds)
	if err != nil {
		return RegistryState{}, err
	}
	if err := validateEventForActionAndState(action, state, event); err != nil {
		return RegistryState{}, err
	}
	return state, nil
}

// ValidateRecoveryTransition binds recovery to the immediately preceding
// finalized initiation state. Policy bytes and timelock come from that state,
// never from caller-selected authority.
func ValidateRecoveryTransition(preInitiation RegistryState, previous RegistryState, action RegistryAction, initiation RegistryAction, initiationEvent RegistryEvent, observation EventObservation, executionBlockUnixSeconds uint64) error {
	if preInitiation.ObjectKind != "agent" || previous.ObjectKind != "agent" || initiation.Kind != ActionInitiateRecovery || initiation.AgentID != action.AgentID || initiation.Network != action.Network || observation.Network != action.Network {
		return fail(CodeCrossDomainReplay, "recovery.initiation")
	}
	derivedInitiation, err := ValidateEventTransition(&preInitiation, initiation, preInitiation.CurrentPolicyDigest, 0, initiationEvent)
	if err != nil {
		return err
	}
	derivedDigest, err := StateDigest(derivedInitiation)
	if err != nil {
		return err
	}
	previousDigest, err := StateDigest(previous)
	if err != nil || derivedDigest != previousDigest {
		return fail(CodeCrossDomainReplay, "recovery.immediate_predecessor")
	}
	initDigest, err := ActionDigest(initiation)
	if err != nil {
		return err
	}
	if previous.LastActionDigest != initDigest || previous.PendingRecovery.InitiationActionDigest != initDigest {
		return fail(CodeCrossDomainReplay, "recovery.immediate_predecessor")
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
	initEventDigest, err := EventDigest(initiationEvent)
	if err != nil || observation.EventDigest != initEventDigest {
		return fail(CodeCrossDomainReplay, "recovery.initiation_observation")
	}
	if recoverPayload.InitiationActionDigest != initDigest || recoverPayload.InitiationReference != observation.Reference || recoverPayload.NewPolicyDigest != initiatePayload.NewPolicyDigest || previous.PendingRecovery.NewPolicyDigest != initiatePayload.NewPolicyDigest {
		return fail(CodeCrossDomainReplay, "recovery.initiation_tuple")
	}
	oldPolicy, err := DecodeControllerPolicy(previous.CurrentPolicyCBORBase64, previous.CurrentPolicyDigest)
	if err != nil {
		return err
	}
	minimumExecuteAfter := observation.BlockUnixSeconds + oldPolicy.RecoveryTimelock
	if minimumExecuteAfter < observation.BlockUnixSeconds ||
		recoverPayload.ExecuteAfterUnixSeconds != initiatePayload.ExecuteAfterUnixSeconds ||
		previous.PendingRecovery.ExecuteAfterUnixSeconds != initiatePayload.ExecuteAfterUnixSeconds ||
		initiatePayload.ExecuteAfterUnixSeconds < minimumExecuteAfter {
		return fail(CodeTimelockPending, "recovery.execute_after_unix_seconds")
	}
	_, err = DeriveNextState(&previous, action, previous.CurrentPolicyDigest, executionBlockUnixSeconds)
	return err
}

func cloneState(value RegistryState) RegistryState {
	value.CapabilityVersions = append([]CapabilityVersionState(nil), value.CapabilityVersions...)
	value.DelegationActionDigests = append([]string(nil), value.DelegationActionDigests...)
	return value
}

func insertSortedDigest(values []string, digest string) []string {
	index := sort.SearchStrings(values, digest)
	if index < len(values) && values[index] == digest {
		return values
	}
	values = append(values, "")
	copy(values[index+1:], values[index:])
	values[index] = digest
	return values
}

func hasCapabilityVersion(values []CapabilityVersionState, version string) bool {
	index := sort.Search(len(values), func(i int) bool { return values[i].Version >= version })
	return index < len(values) && values[index].Version == version
}

func insertCapabilityVersion(values []CapabilityVersionState, value CapabilityVersionState) []CapabilityVersionState {
	index := sort.Search(len(values), func(i int) bool { return values[i].Version >= value.Version })
	values = append(values, CapabilityVersionState{})
	copy(values[index+1:], values[index:])
	values[index] = value
	return values
}

func markCapabilityVersionRevoked(values []CapabilityVersionState, version string) bool {
	index := sort.Search(len(values), func(i int) bool { return values[i].Version >= version })
	if index == len(values) || values[index].Version != version || values[index].Revoked {
		return false
	}
	values[index].Revoked = true
	return true
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
