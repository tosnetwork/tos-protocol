package agentcommerce

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type WriterFenceBody struct {
	SchemaVersion    uint16   `json:"schema_version"`
	OwnerID          string   `json:"owner_id"`
	AgentID          string   `json:"agent_id"`
	InstanceID       string   `json:"instance_id"`
	LeaseID          string   `json:"lease_id"`
	WriterGeneration uint64   `json:"writer_generation"`
	IssuedAtUnix     uint64   `json:"issued_at_unix"`
	ExpiresAtUnix    uint64   `json:"expires_at_unix"`
	AuthorityID      string   `json:"authority_id"`
	Scope            []string `json:"scope"`
}

type WriterFence struct {
	Body      WriterFenceBody `json:"body"`
	PublicKey string          `json:"public_key"`
	Proof     string          `json:"fence_proof"`
}

type FenceAuthorityResolver interface {
	AuthorizeFenceKey(authorityID string, publicKey ed25519.PublicKey, at time.Time) error
}

type AuthorizedAction struct {
	SchemaVersion      uint16 `json:"schema_version"`
	OwnerID            string `json:"owner_id"`
	AgentID            string `json:"agent_id"`
	ActionKind         string `json:"action_kind"`
	StableActionID     string `json:"stable_action_id"`
	ExactRequestDigest string `json:"exact_request_digest"`
	WriterGeneration   uint64 `json:"writer_generation"`
	WriterFenceDigest  string `json:"writer_fence_digest"`
	PolicyRevision     uint64 `json:"policy_revision"`
	MandateDigest      string `json:"mandate_digest"`
	ApprovalDigest     string `json:"approval_digest,omitempty"`
	ExpectedPriorState string `json:"expected_prior_state"`
	ExpiresAtUnix      uint64 `json:"expires_at_unix"`
	AuthorityID        string `json:"authority_id"`
	AuthorityPublicKey string `json:"authority_public_key"`
	AuthorizationProof string `json:"authorization_proof"`
}

type ActionResolutionState string

const (
	ActionUnknown   ActionResolutionState = "unknown"
	ActionPrepared  ActionResolutionState = "prepared"
	ActionSubmitted ActionResolutionState = "submitted"
	ActionAccepted  ActionResolutionState = "accepted"
	ActionRejected  ActionResolutionState = "rejected"
	ActionConflict  ActionResolutionState = "conflict"
	ActionTerminal  ActionResolutionState = "terminal"
)

type ActionResolution struct {
	StableActionID     string                `json:"stable_action_id"`
	ExactRequestDigest string                `json:"exact_request_digest"`
	State              ActionResolutionState `json:"state"`
	SinkReference      string                `json:"sink_reference,omitempty"`
	EvidenceRefs       []string              `json:"evidence_refs,omitempty"`
	StateRevision      uint64                `json:"state_revision"`
}

type AuthorityInstanceAllocationRequest struct {
	OwnerID                          string `json:"owner_id"`
	AgentID                          string `json:"agent_id"`
	PurposeKind                      string `json:"purpose_kind"`
	MandateDigest                    string `json:"mandate_digest"`
	ApprovalDigestOrZero             string `json:"approval_digest_or_zero"`
	DownstreamEffectDescriptorDigest string `json:"downstream_effect_descriptor_digest"`
	PredecessorAuthorityInstanceID   string `json:"predecessor_authority_instance_id"`
}

type AuthorityInstanceRecord struct {
	RequestDigest       string `json:"allocation_request_digest"`
	AllocationSequence  uint64 `json:"authority_allocation_sequence"`
	AuthorityInstanceID string `json:"authority_instance_id"`
	PolicyRevision      uint64 `json:"policy_revision"`
	Terminal            bool   `json:"terminal"`
}

func SignWriterFence(body WriterFenceBody, privateKey ed25519.PrivateKey) (WriterFence, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return WriterFence{}, errors.New("writer fence signing key is invalid")
	}
	if err := validateWriterFenceBody(body); err != nil {
		return WriterFence{}, err
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		return WriterFence{}, err
	}
	message := framedSHA256("tos.writer-fence.v1\x00", canonical)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return WriterFence{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(publicKey),
		Proof: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

func VerifyWriterFence(fence WriterFence, resolver FenceAuthorityResolver, now time.Time, actionKind string) error {
	if err := validateWriterFenceBody(fence.Body); err != nil {
		return err
	}
	if resolver == nil || !now.UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) ||
		now.UTC().Before(time.Unix(int64(fence.Body.IssuedAtUnix), 0).UTC().Add(-MaxIntentClockSkew)) ||
		!containsSorted(fence.Body.Scope, actionKind) {
		return errors.New("writer fence is expired, premature, or out of scope")
	}
	publicKey, err := parseEd25519PublicKey(fence.PublicKey)
	if err != nil {
		return err
	}
	if err := resolver.AuthorizeFenceKey(fence.Body.AuthorityID, publicKey, now); err != nil {
		return err
	}
	proof, err := parseEd25519Signature(fence.Proof)
	if err != nil {
		return err
	}
	canonical, err := codec.Marshal(fence.Body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, framedSHA256("tos.writer-fence.v1\x00", canonical), proof) {
		return errors.New("writer fence proof is invalid")
	}
	return nil
}

func WriterFenceDigest(fence WriterFence) (string, error) {
	return codec.Digest("tos.writer-fence-envelope.v1", fence)
}

func BuildAuthorizedAction(ownerID, agentID, actionKind string, semanticFields map[string]SemanticValue,
	canonicalRequest []byte, fence WriterFence, policyRevision uint64, mandateDigest, approvalDigest,
	expectedPriorState string, expiresAt uint64) (AuthorizedAction, error) {
	stableID, _, err := DeriveStableActionID(actionKind, semanticFields)
	if err != nil {
		return AuthorizedAction{}, err
	}
	requestDigest, err := ExactRequestDigest(canonicalRequest)
	if err != nil {
		return AuthorizedAction{}, err
	}
	fenceDigest, err := WriterFenceDigest(fence)
	if err != nil {
		return AuthorizedAction{}, err
	}
	action := AuthorizedAction{SchemaVersion: 1, OwnerID: ownerID, AgentID: agentID, ActionKind: actionKind,
		StableActionID: stableID, ExactRequestDigest: requestDigest, WriterGeneration: fence.Body.WriterGeneration,
		WriterFenceDigest: fenceDigest, PolicyRevision: policyRevision, MandateDigest: mandateDigest,
		ApprovalDigest: approvalDigest, ExpectedPriorState: expectedPriorState, ExpiresAtUnix: expiresAt,
		AuthorityID: fence.Body.AuthorityID}
	if err := validateAuthorizedActionShape(action); err != nil {
		return AuthorizedAction{}, err
	}
	return action, nil
}

func SignAuthorizedAction(action AuthorizedAction, privateKey ed25519.PrivateKey) (AuthorizedAction, error) {
	if len(privateKey) != ed25519.PrivateKeySize || action.AuthorityPublicKey != "" || action.AuthorizationProof != "" {
		return AuthorizedAction{}, errors.New("authorized action signing request is invalid")
	}
	if err := validateAuthorizedActionShape(action); err != nil {
		return AuthorizedAction{}, err
	}
	public := privateKey.Public().(ed25519.PublicKey)
	action.AuthorityPublicKey = "ed25519:" + hex.EncodeToString(public)
	message, err := authorizedActionSignatureMessage(action)
	if err != nil {
		return AuthorizedAction{}, err
	}
	action.AuthorizationProof = "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	return action, nil
}

func VerifyAuthorizedAction(action AuthorizedAction, semanticFields map[string]SemanticValue, canonicalRequest []byte,
	fence WriterFence, resolver FenceAuthorityResolver, now time.Time) error {
	if err := validateAuthorizedActionShape(action); err != nil {
		return err
	}
	if action.OwnerID != fence.Body.OwnerID || action.AgentID != fence.Body.AgentID || action.WriterGeneration != fence.Body.WriterGeneration ||
		action.ExpiresAtUnix > fence.Body.ExpiresAtUnix || !now.UTC().Before(time.Unix(int64(action.ExpiresAtUnix), 0).UTC()) {
		return errors.New("authorized action does not match the current writer fence")
	}
	if err := VerifyWriterFence(fence, resolver, now, action.ActionKind); err != nil {
		return err
	}
	if action.AuthorityID != fence.Body.AuthorityID || action.AuthorityPublicKey != fence.PublicKey {
		return errors.New("authorized action authority differs from the writer fence")
	}
	authorityKey, err := parseEd25519PublicKey(action.AuthorityPublicKey)
	if err != nil || resolver.AuthorizeFenceKey(action.AuthorityID, authorityKey, now.UTC()) != nil {
		return errors.New("authorized action authority key is not authorized")
	}
	authorizationProof, err := parseEd25519Signature(action.AuthorizationProof)
	message, messageErr := authorizedActionSignatureMessage(action)
	if err != nil || messageErr != nil || !ed25519.Verify(authorityKey, message, authorizationProof) {
		return errors.New("authorized action proof is invalid")
	}
	fenceDigest, err := WriterFenceDigest(fence)
	if err != nil || fenceDigest != action.WriterFenceDigest {
		return errors.New("authorized action fence digest mismatch")
	}
	stableID, _, err := DeriveStableActionID(action.ActionKind, semanticFields)
	if err != nil || stableID != action.StableActionID {
		return errors.New("authorized action semantic identity mismatch")
	}
	requestDigest, err := ExactRequestDigest(canonicalRequest)
	if err != nil || requestDigest != action.ExactRequestDigest {
		return errors.New("authorized action request digest mismatch")
	}
	return nil
}

func ValidateActionResolution(resolution ActionResolution) error {
	if !canonicalDigestPattern.MatchString(resolution.StableActionID) || !canonicalDigestPattern.MatchString(resolution.ExactRequestDigest) ||
		resolution.StateRevision == 0 || validateSortedDigests(resolution.EvidenceRefs, 256) != nil || len(resolution.SinkReference) > 1024 {
		return errors.New("action resolution is invalid")
	}
	switch resolution.State {
	case ActionUnknown:
		if resolution.StateRevision != 1 || resolution.SinkReference != "" || len(resolution.EvidenceRefs) != 0 {
			return errors.New("unknown action carries sink state")
		}
	case ActionPrepared, ActionSubmitted, ActionAccepted, ActionRejected, ActionConflict, ActionTerminal:
	default:
		return errors.New("action resolution state is unknown")
	}
	return nil
}

func DownstreamEffectDescriptorDigest(canonicalEffectBody []byte) (string, error) {
	if len(canonicalEffectBody) == 0 || len(canonicalEffectBody) > MaxActionRequestBytes {
		return "", errors.New("canonical effect body has invalid size")
	}
	return "sha256:" + hex.EncodeToString(framedSHA256("tos.authority-instance-effect.v1\x00", canonicalEffectBody)), nil
}

func AuthorityInstanceAllocationRequestDigest(request AuthorityInstanceAllocationRequest) (string, error) {
	if !boundedIdentifier(request.OwnerID, 256) || !boundedIdentifier(request.AgentID, 256) || !canonicalLowerToken(request.PurposeKind) ||
		!canonicalDigestPattern.MatchString(request.MandateDigest) || !canonicalDigestOrZero(request.ApprovalDigestOrZero) ||
		!canonicalDigestPattern.MatchString(request.DownstreamEffectDescriptorDigest) || !canonicalDigestOrZero(request.PredecessorAuthorityInstanceID) {
		return "", errors.New("authority instance allocation request is invalid")
	}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(framedSHA256("tos.authority-instance-allocation.v1\x00", canonical)), nil
}

func DeriveAuthorityInstanceID(request AuthorityInstanceAllocationRequest, sequence uint64) (string, error) {
	requestDigest, err := AuthorityInstanceAllocationRequestDigest(request)
	if err != nil || sequence == 0 {
		return "", errors.New("authority instance allocation sequence is invalid")
	}
	identifier, _, err := DeriveStableActionID("authority.instance", map[string]SemanticValue{
		"owner_id": ID(request.OwnerID), "agent_id": ID(request.AgentID), "purpose_kind": Kind(request.PurposeKind),
		"mandate_digest": Digest32(request.MandateDigest), "allocation_request_digest": Digest32(requestDigest),
		"authority_allocation_sequence": U64(sequence),
	})
	return identifier, err
}

func validateWriterFenceBody(body WriterFenceBody) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.OwnerID, 256) || !boundedIdentifier(body.AgentID, 256) ||
		!boundedIdentifier(body.InstanceID, 256) || !boundedIdentifier(body.LeaseID, 256) || body.WriterGeneration == 0 ||
		body.IssuedAtUnix == 0 || body.ExpiresAtUnix <= body.IssuedAtUnix || body.ExpiresAtUnix-body.IssuedAtUnix > 24*60*60 ||
		!boundedIdentifier(body.AuthorityID, 256) || len(body.Scope) == 0 || validateSortedStrings(body.Scope, 64, 128) != nil {
		return errors.New("writer fence body is invalid")
	}
	for _, kind := range body.Scope {
		if _, known := semanticActionRegistry[kind]; !known {
			return fmt.Errorf("writer fence contains unknown action scope %q", kind)
		}
	}
	return nil
}

func validateAuthorizedActionShape(action AuthorizedAction) error {
	if action.SchemaVersion != 1 || !boundedIdentifier(action.OwnerID, 256) || !boundedIdentifier(action.AgentID, 256) ||
		semanticActionRegistry[action.ActionKind].ActionKind == "" || !canonicalDigestPattern.MatchString(action.StableActionID) ||
		!canonicalDigestPattern.MatchString(action.ExactRequestDigest) || action.WriterGeneration == 0 ||
		!canonicalDigestPattern.MatchString(action.WriterFenceDigest) || action.PolicyRevision == 0 ||
		!canonicalDigestPattern.MatchString(action.MandateDigest) || action.ApprovalDigest != "" && !canonicalDigestPattern.MatchString(action.ApprovalDigest) ||
		!boundedIdentifier(action.ExpectedPriorState, 128) || action.ExpiresAtUnix == 0 || !boundedIdentifier(action.AuthorityID, 256) ||
		(action.AuthorityPublicKey == "") != (action.AuthorizationProof == "") {
		return errors.New("authorized action is invalid")
	}
	if action.AuthorityPublicKey != "" {
		if _, err := parseEd25519PublicKey(action.AuthorityPublicKey); err != nil {
			return errors.New("authorized action authority key is invalid")
		}
		if _, err := parseEd25519Signature(action.AuthorizationProof); err != nil {
			return errors.New("authorized action proof encoding is invalid")
		}
	}
	return nil
}

func authorizedActionSignatureMessage(action AuthorizedAction) ([]byte, error) {
	action.AuthorizationProof = ""
	canonical, err := codec.Marshal(action)
	if err != nil {
		return nil, err
	}
	return framedSHA256("tos.authorized-action-proof.v1\x00", canonical), nil
}

func canonicalDigestOrZero(value string) bool {
	return value == "sha256:"+stringsOfZero(64) || canonicalDigestPattern.MatchString(value)
}

func stringsOfZero(length int) string {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = '0'
	}
	return string(buffer)
}
