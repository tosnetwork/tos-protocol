package trustedcapability

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

type OwnerPolicyBodyV1 struct {
	OwnerID                         []byte  `cbor:"1,keyasint" json:"owner_id"`
	PolicyID                        []byte  `cbor:"2,keyasint" json:"policy_id"`
	Revision                        uint64  `cbor:"3,keyasint" json:"revision"`
	PredecessorPolicyDigest         *[]byte `cbor:"4,keyasint" json:"predecessor_policy_digest"`
	AuthorityEpoch                  uint64  `cbor:"5,keyasint" json:"authority_epoch"`
	AuthorityProfileSetDigest       []byte  `cbor:"6,keyasint" json:"authority_profile_set_digest"`
	CommandProfileSetDigest         []byte  `cbor:"7,keyasint" json:"command_profile_set_digest"`
	CapabilityPolicyDigest          []byte  `cbor:"8,keyasint" json:"capability_policy_digest"`
	PromotionSeparationPolicyDigest []byte  `cbor:"9,keyasint" json:"promotion_separation_policy_digest"`
	RecoveryQuorumDigest            []byte  `cbor:"10,keyasint" json:"recovery_quorum_digest"`
	ValidTimeProfileDigest          []byte  `cbor:"11,keyasint" json:"valid_time_profile_digest"`
	NotBeforeUnix                   uint64  `cbor:"12,keyasint" json:"not_before_unix"`
	ExpiresAtUnix                   uint64  `cbor:"13,keyasint" json:"expires_at_unix"`
}

type OwnerCommandEffectV1 struct {
	SchemaVersion               uint16   `cbor:"1,keyasint" json:"schema_version"`
	DomainKind                  uint8    `cbor:"2,keyasint" json:"domain_kind"`
	DomainID                    []byte   `cbor:"3,keyasint" json:"domain_id"`
	OwnerID                     []byte   `cbor:"4,keyasint" json:"owner_id"`
	AgentID                     *[]byte  `cbor:"5,keyasint" json:"agent_id"`
	CommandKind                 string   `cbor:"6,keyasint" json:"command_kind"`
	CommandInstanceID           []byte   `cbor:"7,keyasint" json:"command_instance_id"`
	TargetObjectKind            string   `cbor:"8,keyasint" json:"target_object_kind"`
	TargetObjectID              []byte   `cbor:"9,keyasint" json:"target_object_id"`
	SinkAuthorityID             []byte   `cbor:"10,keyasint" json:"sink_authority_id"`
	SinkClusterEpoch            uint64   `cbor:"11,keyasint" json:"sink_cluster_epoch"`
	ResolutionNamespace         []byte   `cbor:"12,keyasint" json:"resolution_namespace"`
	ControlScopeGeneration      uint64   `cbor:"13,keyasint" json:"control_scope_generation"`
	ExpectedTargetRevision      uint64   `cbor:"14,keyasint" json:"expected_target_revision"`
	ExactParameterDigest        []byte   `cbor:"15,keyasint" json:"exact_parameter_digest"`
	PolicyRevision              uint64   `cbor:"16,keyasint" json:"policy_revision"`
	PolicyDigest                []byte   `cbor:"17,keyasint" json:"policy_digest"`
	SemanticConfirmationDigest  []byte   `cbor:"18,keyasint" json:"semantic_confirmation_digest"`
	AuthorityPredicateSetDigest []byte   `cbor:"19,keyasint" json:"authority_predicate_set_digest"`
	CreatedAtUnix               uint64   `cbor:"20,keyasint" json:"created_at_unix"`
	ExpiresAtUnix               uint64   `cbor:"21,keyasint" json:"expires_at_unix"`
	Extensions                  [][]byte `cbor:"22,keyasint" json:"extensions"`
}

type OwnerCommandAuthorizationAttemptV1 struct {
	CommandEffectDigest         []byte                           `cbor:"1,keyasint" json:"command_effect_digest"`
	ActionID                    []byte                           `cbor:"2,keyasint" json:"action_id"`
	ExactRequestDigest          []byte                           `cbor:"3,keyasint" json:"exact_request_digest"`
	DeviceSessionDigest         []byte                           `cbor:"4,keyasint" json:"device_session_digest"`
	SessionGeneration           uint64                           `cbor:"5,keyasint" json:"session_generation"`
	SessionRevocationGeneration uint64                           `cbor:"6,keyasint" json:"session_revocation_generation"`
	AuthorityEpoch              uint64                           `cbor:"7,keyasint" json:"authority_epoch"`
	CommandLeaseDigest          []byte                           `cbor:"8,keyasint" json:"command_lease_digest"`
	AuthorizationEnvelopes      []ProfileAuthorizationEnvelopeV1 `cbor:"9,keyasint" json:"authorization_envelopes"`
	AttemptedAtUnix             uint64                           `cbor:"10,keyasint" json:"attempted_at_unix"`
	ExpiresAtUnix               uint64                           `cbor:"11,keyasint" json:"expires_at_unix"`
}

type OwnerCommandLeaseV1 struct {
	SchemaVersion               uint16 `cbor:"1,keyasint" json:"schema_version"`
	LeaseID                     []byte `cbor:"2,keyasint" json:"lease_id"`
	DomainKind                  uint8  `cbor:"3,keyasint" json:"domain_kind"`
	DomainID                    []byte `cbor:"4,keyasint" json:"domain_id"`
	OwnerID                     []byte `cbor:"5,keyasint" json:"owner_id"`
	DeviceSessionDigest         []byte `cbor:"6,keyasint" json:"device_session_digest"`
	AllowedCommandClassesDigest []byte `cbor:"7,keyasint" json:"allowed_command_classes_digest"`
	Audience                    string `cbor:"8,keyasint" json:"audience"`
	SinkAuthorityID             []byte `cbor:"9,keyasint" json:"sink_authority_id"`
	SinkClusterEpoch            uint64 `cbor:"10,keyasint" json:"sink_cluster_epoch"`
	ControlScopeGeneration      uint64 `cbor:"11,keyasint" json:"control_scope_generation"`
	PolicyRevision              uint64 `cbor:"12,keyasint" json:"policy_revision"`
	PolicyDigest                []byte `cbor:"13,keyasint" json:"policy_digest"`
	AuthorityEpoch              uint64 `cbor:"14,keyasint" json:"authority_epoch"`
	NotBeforeUnix               uint64 `cbor:"15,keyasint" json:"not_before_unix"`
	ExpiresAtUnix               uint64 `cbor:"16,keyasint" json:"expires_at_unix"`
}

var OwnerCommandKindsV1 = []string{
	"agreement.amendment.propose", "agreement.approve", "agreement.reject", "capability.admit", "capability.promotion.activate",
	"capability.promotion.revoke", "capability.remove", "capability.resume", "capability.revoke", "capability.suspend", "credential.revoke", "delegation.revoke",
	"device-session.revoke", "evidence.export", "intent.publish", "intent.revise", "intent.withdraw", "owner.exit", "owner.pause", "owner.policy.propose",
	"owner.resume", "reconcile.apply", "reconcile.dry-run", "session.revoke", "steering.bounded",
}

// OwnerCommandProfileV1 freezes the semantic target and intentional-repeat
// policy for one released command kind.  It is a code registry, rather than a
// caller supplied field, so two implementations cannot choose different
// Action identities or confirmation targets for the same command.
type OwnerCommandProfileV1 struct {
	CommandKind             string `json:"command_kind"`
	TargetObjectKind        string `json:"target_object_kind"`
	RequireAgentScope       bool   `json:"require_agent_scope"`
	CommandInstanceIDPolicy string `json:"command_instance_id_policy"` // "required" or "forbidden"
}

var ownerCommandProfilesV1 = map[string]OwnerCommandProfileV1{
	"agreement.amendment.propose":   {"agreement.amendment.propose", "agreement", true, "required"},
	"agreement.approve":             {"agreement.approve", "agreement", true, "required"},
	"agreement.reject":              {"agreement.reject", "agreement", true, "required"},
	"capability.admit":              {"capability.admit", "capability", true, "required"},
	"capability.promotion.activate": {"capability.promotion.activate", "capability", true, "required"},
	"capability.promotion.revoke":   {"capability.promotion.revoke", "capability", true, "required"},
	"capability.remove":             {"capability.remove", "capability", true, "required"},
	"capability.resume":             {"capability.resume", "capability", true, "required"},
	"capability.revoke":             {"capability.revoke", "capability", true, "required"},
	"capability.suspend":            {"capability.suspend", "capability", true, "required"},
	"credential.revoke":             {"credential.revoke", "credential", true, "required"},
	"delegation.revoke":             {"delegation.revoke", "delegation", true, "required"},
	"device-session.revoke":         {"device-session.revoke", "device-session", true, "required"},
	"evidence.export":               {"evidence.export", "evidence-export", true, "required"},
	"intent.publish":                {"intent.publish", "intent", true, "required"},
	"intent.revise":                 {"intent.revise", "intent", true, "required"},
	"intent.withdraw":               {"intent.withdraw", "intent", true, "required"},
	"owner.exit":                    {"owner.exit", "owner", true, "required"},
	"owner.pause":                   {"owner.pause", "agent", true, "required"},
	"owner.policy.propose":          {"owner.policy.propose", "owner-policy", true, "required"},
	"owner.resume":                  {"owner.resume", "agent", true, "required"},
	"reconcile.apply":               {"reconcile.apply", "portfolio", true, "required"},
	"reconcile.dry-run":             {"reconcile.dry-run", "portfolio", true, "required"},
	"session.revoke":                {"session.revoke", "device-session", true, "required"},
	"steering.bounded":              {"steering.bounded", "owner-policy", true, "required"},
}

func OwnerCommandProfile(commandKind string) (OwnerCommandProfileV1, error) {
	profile, ok := ownerCommandProfilesV1[commandKind]
	if !ok {
		return OwnerCommandProfileV1{}, errors.New("owner command kind is not released")
	}
	return profile, nil
}

func OwnerCommandProfilesV1() []OwnerCommandProfileV1 {
	profiles := make([]OwnerCommandProfileV1, 0, len(OwnerCommandKindsV1))
	for _, kind := range OwnerCommandKindsV1 {
		profiles = append(profiles, ownerCommandProfilesV1[kind])
	}
	return profiles
}

func ValidateOwnerCommandEffect(body OwnerCommandEffectV1) error {
	if body.SchemaVersion != SchemaVersion || body.DomainKind == 0 || len(body.DomainID) == 0 || len(body.OwnerID) == 0 || body.CommandKind == "" ||
		body.TargetObjectKind == "" || len(body.TargetObjectID) == 0 || len(body.SinkAuthorityID) == 0 ||
		body.SinkClusterEpoch == 0 || len(body.ResolutionNamespace) != 32 || body.ControlScopeGeneration == 0 || len(body.ExactParameterDigest) != 32 ||
		body.PolicyRevision == 0 || len(body.PolicyDigest) != 32 || len(body.SemanticConfirmationDigest) != 32 || len(body.AuthorityPredicateSetDigest) != 32 ||
		body.CreatedAtUnix == 0 || body.CreatedAtUnix >= body.ExpiresAtUnix {
		return errors.New("owner command effect is incomplete")
	}
	profile, err := OwnerCommandProfile(body.CommandKind)
	if err != nil || body.TargetObjectKind != profile.TargetObjectKind || profile.RequireAgentScope && (body.AgentID == nil || len(*body.AgentID) == 0) {
		return errors.New("owner command target or Agent scope differs from its released profile")
	}
	if body.TargetObjectKind == "agent" && (body.AgentID == nil || !bytes.Equal(body.TargetObjectID, *body.AgentID)) ||
		body.TargetObjectKind == "owner" && !bytes.Equal(body.TargetObjectID, body.OwnerID) {
		return errors.New("owner command target identity differs from its released profile")
	}
	switch profile.CommandInstanceIDPolicy {
	case "required":
		if len(body.CommandInstanceID) != 16 {
			return errors.New("owner command requires a 128-bit intentional-repeat identity")
		}
	case "forbidden":
		if len(body.CommandInstanceID) != 0 {
			return errors.New("owner command forbids an intentional-repeat identity")
		}
	default:
		return errors.New("owner command profile has an invalid repeat policy")
	}
	return nil
}

type OwnerCommandResolutionV1 struct {
	State                   string                       `cbor:"1,keyasint" json:"state"`
	EffectDigest            []byte                       `cbor:"2,keyasint" json:"effect_digest"`
	AcceptedAttemptDigest   *[]byte                      `cbor:"3,keyasint" json:"accepted_attempt_digest"`
	ActionID                []byte                       `cbor:"4,keyasint" json:"action_id"`
	ExactRequestDigest      []byte                       `cbor:"5,keyasint" json:"exact_request_digest"`
	TargetPriorRevision     uint64                       `cbor:"6,keyasint" json:"target_prior_revision"`
	TargetResultRevision    *uint64                      `cbor:"7,keyasint" json:"target_result_revision"`
	AuthorityEvidenceDigest *[]byte                      `cbor:"8,keyasint" json:"authority_evidence_digest"`
	SinkIdentity            []byte                       `cbor:"9,keyasint" json:"sink_identity"`
	EffectReferences        []ImmutableObjectReferenceV1 `cbor:"10,keyasint" json:"effect_references"`
	ErrorCode               *string                      `cbor:"11,keyasint" json:"error_code"`
	ObservedAtUnix          uint64                       `cbor:"12,keyasint" json:"observed_at_unix"`
}

func ValidateOwnerCommandResolution(body OwnerCommandResolutionV1) error {
	validState := body.State == "prepared" || body.State == "admitted" || body.State == "submitted" || body.State == "ambiguous" ||
		body.State == "applied" || body.State == "rejected" || body.State == "conflict" || body.State == "expired" || body.State == "terminal"
	if !validState || len(body.EffectDigest) != sha256.Size || len(body.ActionID) != sha256.Size || len(body.ExactRequestDigest) != sha256.Size ||
		len(body.SinkIdentity) == 0 || body.ObservedAtUnix == 0 || body.AcceptedAttemptDigest != nil && len(*body.AcceptedAttemptDigest) != sha256.Size ||
		body.AuthorityEvidenceDigest != nil && len(*body.AuthorityEvidenceDigest) != sha256.Size {
		return errors.New("owner command resolution is incomplete")
	}
	for _, reference := range body.EffectReferences {
		if ValidateReference(reference) != nil {
			return errors.New("owner command resolution evidence reference is invalid")
		}
	}
	if body.State == "prepared" && (body.AcceptedAttemptDigest != nil || body.TargetResultRevision != nil || body.ErrorCode != nil) {
		return errors.New("prepared owner command resolution contains terminal evidence")
	}
	if body.State == "applied" && (body.AcceptedAttemptDigest == nil || body.TargetResultRevision == nil || body.ErrorCode != nil) {
		return errors.New("applied owner command resolution lacks accepted attempt or result revision")
	}
	return nil
}

var resolutionTransitions = map[string]map[string]bool{
	"unknown":   {"prepared": true, "rejected": true, "expired": true},
	"prepared":  {"admitted": true, "rejected": true, "conflict": true, "expired": true, "ambiguous": true},
	"admitted":  {"submitted": true, "applied": true, "rejected": true, "conflict": true, "ambiguous": true},
	"submitted": {"applied": true, "rejected": true, "conflict": true, "ambiguous": true},
	"ambiguous": {"submitted": true, "applied": true, "rejected": true, "conflict": true},
	"applied":   {"terminal": true}, "rejected": {"terminal": true}, "conflict": {"terminal": true}, "expired": {"terminal": true},
}

func ValidateResolutionTransition(from, to string) error {
	if !resolutionTransitions[from][to] {
		return errors.New("invalid owner command resolution transition")
	}
	return nil
}

type SemanticConfirmationV1 struct {
	DisplayProfileURI           string   `cbor:"1,keyasint" json:"display_profile_uri"`
	DisplayProfileVersion       uint16   `cbor:"2,keyasint" json:"display_profile_version"`
	RiskClass                   string   `cbor:"3,keyasint" json:"risk_class"`
	DomainID                    []byte   `cbor:"4,keyasint" json:"domain_id"`
	OwnerID                     []byte   `cbor:"5,keyasint" json:"owner_id"`
	ActionID                    []byte   `cbor:"6,keyasint" json:"action_id"`
	CommandKind                 string   `cbor:"7,keyasint" json:"command_kind"`
	Target                      string   `cbor:"8,keyasint" json:"target"`
	RecipientOrDestination      *string  `cbor:"9,keyasint" json:"recipient_or_destination"`
	PermissionDelta             []byte   `cbor:"10,keyasint" json:"permission_delta"`
	AmountAndAssetOrCostCeiling *string  `cbor:"11,keyasint" json:"amount_and_asset_or_cost_ceiling"`
	PolicyDelta                 []byte   `cbor:"12,keyasint" json:"policy_delta"`
	CriticalParameters          [][]byte `cbor:"13,keyasint" json:"critical_parameters"`
	ExpiresAtUnix               uint64   `cbor:"14,keyasint" json:"expires_at_unix"`
}

const OwnerCommandConfirmationProfileV1 = "tos.owner-command-confirmation.v1"

// OwnerCommandAuthorizationPredicateSetV1 is the released, deterministic
// authorization profile selected by command semantics.  A client cannot
// choose a weaker quorum after the command body has been created.
type OwnerCommandAuthorizationPredicateSetV1 struct {
	SchemaVersion              uint16   `cbor:"1,keyasint" json:"schema_version"`
	ProfileURI                 string   `cbor:"2,keyasint" json:"profile_uri"`
	ProfileVersion             uint16   `cbor:"3,keyasint" json:"profile_version"`
	CommandKind                string   `cbor:"4,keyasint" json:"command_kind"`
	TargetObjectKind           string   `cbor:"5,keyasint" json:"target_object_kind"`
	ExactParameterDigest       []byte   `cbor:"6,keyasint" json:"exact_parameter_digest"`
	GoverningPolicyDigest      []byte   `cbor:"7,keyasint" json:"governing_policy_digest"`
	RequiredAuthorityKinds     []string `cbor:"8,keyasint" json:"required_authority_kinds"`
	MinimumDistinctPrincipals  uint16   `cbor:"9,keyasint" json:"minimum_distinct_principals"`
	RequireAuthenticatedDevice bool     `cbor:"10,keyasint" json:"require_authenticated_device"`
	RequireIndependentApprover bool     `cbor:"11,keyasint" json:"require_independent_approver"`
	ForbidSelfAuthorization    bool     `cbor:"12,keyasint" json:"forbid_self_authorization"`
}

// OwnerCommandAuthorizationPredicateSet returns the sole released V1 profile.
// Commands that change trust, authority, executable capabilities, credentials,
// external publication, agreements, or accounting require two disjoint
// principals. Bounded pause/resume, rejection, dry-run and evidence export are
// device-confirmed but remain exact-body signed operations.
func OwnerCommandAuthorizationPredicateSet(effect OwnerCommandEffectV1) (OwnerCommandAuthorizationPredicateSetV1, error) {
	if err := ValidateOwnerCommandEffect(effect); err != nil {
		return OwnerCommandAuthorizationPredicateSetV1{}, err
	}
	highRisk := effect.CommandKind != "owner.pause" && effect.CommandKind != "owner.resume" && effect.CommandKind != "agreement.reject" &&
		effect.CommandKind != "reconcile.dry-run" && effect.CommandKind != "evidence.export"
	minimum := uint16(1)
	kinds := []string{"authenticated-device"}
	if highRisk {
		minimum = 2
		kinds = append(kinds, "independent-owner-authority")
	}
	return OwnerCommandAuthorizationPredicateSetV1{SchemaVersion: SchemaVersion,
		ProfileURI: "tos.owner-command-authorization-predicate-set.v1", ProfileVersion: 1,
		CommandKind: effect.CommandKind, TargetObjectKind: effect.TargetObjectKind,
		ExactParameterDigest: append([]byte(nil), effect.ExactParameterDigest...), GoverningPolicyDigest: append([]byte(nil), effect.PolicyDigest...),
		RequiredAuthorityKinds: kinds, MinimumDistinctPrincipals: minimum, RequireAuthenticatedDevice: true,
		RequireIndependentApprover: highRisk, ForbidSelfAuthorization: highRisk}, nil
}

func OwnerCommandAuthorizationPredicateSetDigest(effect OwnerCommandEffectV1) ([]byte, error) {
	profile, err := OwnerCommandAuthorizationPredicateSet(effect)
	if err != nil {
		return nil, err
	}
	wire, err := MarshalBody(profile)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("tos.owner-command-authorization-predicate-set.v1\x00"), wire...))
	return digest[:], nil
}

func SemanticConfirmationDigest(confirmation SemanticConfirmationV1) ([]byte, error) {
	wire, err := MarshalBody(confirmation)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("tos.semantic-confirmation.v1\x00"), wire...))
	return digest[:], nil
}

// ValidateSemanticConfirmation rejects model prose and partial UI projection:
// the released profile always commits the exact parameter, policy and target
// bytes in this order.
func ValidateSemanticConfirmation(confirmation SemanticConfirmationV1, effect OwnerCommandEffectV1, actionID []byte, now uint64) error {
	profile, err := OwnerCommandAuthorizationPredicateSet(effect)
	if err != nil {
		return err
	}
	risk := "bounded"
	if profile.RequireIndependentApprover {
		risk = "high"
	}
	target := effect.TargetObjectKind + ":" + fmtHex(effect.TargetObjectID)
	if confirmation.DisplayProfileURI != OwnerCommandConfirmationProfileV1 || confirmation.DisplayProfileVersion != 1 || confirmation.RiskClass != risk ||
		len(actionID) != sha256.Size || confirmation.PermissionDelta == nil || confirmation.PolicyDelta == nil || confirmation.CriticalParameters == nil ||
		!bytes.Equal(confirmation.DomainID, effect.DomainID) || !bytes.Equal(confirmation.OwnerID, effect.OwnerID) || !bytes.Equal(confirmation.ActionID, actionID) ||
		confirmation.CommandKind != effect.CommandKind || confirmation.Target != target || confirmation.ExpiresAtUnix == 0 || confirmation.ExpiresAtUnix > effect.ExpiresAtUnix || now >= confirmation.ExpiresAtUnix ||
		len(confirmation.CriticalParameters) != 3 || !bytes.Equal(confirmation.CriticalParameters[0], effect.ExactParameterDigest) ||
		!bytes.Equal(confirmation.CriticalParameters[1], effect.PolicyDigest) || !bytes.Equal(confirmation.CriticalParameters[2], effect.TargetObjectID) {
		return errors.New("semantic confirmation is incomplete or does not bind the exact owner command")
	}
	return nil
}

func fmtHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2], out[i*2+1] = alphabet[b>>4], alphabet[b&15]
	}
	return string(out)
}
