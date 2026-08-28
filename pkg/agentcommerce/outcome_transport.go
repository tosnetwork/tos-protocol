package agentcommerce

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type OperationCarrierRequestV1 struct {
	SchemaVersion           uint16                           `json:"schema_version"`
	CarrierID               string                           `json:"carrier_id"`
	CarrierProfile          ProfileRefV1                     `json:"carrier_profile"`
	AudiencePolicyDigest    string                           `json:"audience_policy_digest"`
	OperationID             string                           `json:"operation_id"`
	OperationEnvelopeDigest string                           `json:"operation_envelope_digest"`
	OperationEnvelope       []byte                           `json:"operation_envelope"`
	EventPayload            []byte                           `json:"event_payload"`
	Artifacts               OperationOutcomeArtifactBundleV1 `json:"artifacts"`
}

type OperationPrivateRequestV1 struct {
	SchemaVersion           uint16                           `json:"schema_version"`
	RecipientSetDigest      string                           `json:"recipient_set_digest"`
	RecipientAgentIDs       []string                         `json:"recipient_agent_ids"`
	MembershipEpoch         uint64                           `json:"membership_epoch"`
	AudiencePolicyDigest    string                           `json:"audience_policy_digest"`
	OperationID             string                           `json:"operation_id"`
	OperationEnvelopeDigest string                           `json:"operation_envelope_digest"`
	ConversationScopeDigest string                           `json:"conversation_scope_digest"`
	TransportProfile        ProfileRefV1                     `json:"transport_profile"`
	OperationEnvelope       []byte                           `json:"operation_envelope"`
	EventPayload            []byte                           `json:"event_payload"`
	Artifacts               OperationOutcomeArtifactBundleV1 `json:"artifacts"`
}

type OperationJournalAppendAdmissionRequestV1 struct {
	OrderingDomain          string `json:"ordering_domain"`
	Epoch                   uint64 `json:"epoch"`
	Sequence                uint64 `json:"sequence"`
	EventContentID          string `json:"event_content_id"`
	OperationEnvelopeDigest string `json:"operation_envelope_digest"`
	GapSetDigest            string `json:"gap_set_digest"`
}

type OperationCarrierSubmissionV1 struct {
	Request          OperationCarrierRequestV1 `json:"request"`
	AuthorizedAction AuthorizedAction          `json:"authorized_action"`
	WriterFence      WriterFence               `json:"writer_fence"`
}

type OperationPrivateSubmissionV1 struct {
	Request          OperationPrivateRequestV1 `json:"request"`
	AuthorizedAction AuthorizedAction          `json:"authorized_action"`
	WriterFence      WriterFence               `json:"writer_fence"`
}

type OperationSubmissionReceiptV1 struct {
	SchemaVersion      uint16                `json:"schema_version"`
	StableActionID     string                `json:"stable_action_id"`
	ExactRequestDigest string                `json:"exact_request_digest"`
	State              ActionResolutionState `json:"state"`
	SinkID             string                `json:"sink_id"`
	SinkReference      string                `json:"sink_reference"`
	AuthorityTimeUnix  uint64                `json:"authority_time_unix"`
	StateRevision      uint64                `json:"state_revision"`
	EvidenceDigest     string                `json:"evidence_digest"`
	SinkProof          []byte                `json:"sink_proof"`
}

func MarshalAgentOperationEnvelopeV1(envelope AgentOperationEnvelopeV1) ([]byte, string, error) {
	digest, err := AgentOperationEnvelopeDigestV1(envelope)
	if err != nil {
		return nil, "", err
	}
	canonical, err := codec.Marshal(envelope)
	return canonical, digest, err
}

func OperationPublishSemanticFieldsV1(ownerID, agentID string, request OperationCarrierRequestV1) (map[string]SemanticValue, error) {
	if err := ValidateOperationCarrierRequestV1(request); err != nil {
		return nil, err
	}
	if err := validateOperationRequestActorV1(agentID, request.OperationEnvelope); err != nil {
		return nil, err
	}
	profileDigest, err := ProfileRefDigestV1(request.CarrierProfile)
	if err != nil {
		return nil, err
	}
	return map[string]SemanticValue{
		"owner_id": ID(ownerID), "agent_id": ID(agentID), "carrier_id": ID(request.CarrierID),
		"operation_id": Digest32(request.OperationID), "operation_envelope_digest": Digest32(request.OperationEnvelopeDigest),
		"audience_policy_digest": Digest32(request.AudiencePolicyDigest), "carrier_profile_digest": Digest32(profileDigest),
	}, nil
}

func OperationJournalAppendSemanticFieldsV1(ownerID, agentID, orderingDomain string, epoch, sequence uint64,
	eventContentID string) (map[string]SemanticValue, error) {
	fields := map[string]SemanticValue{"owner_id": ID(ownerID), "agent_id": ID(agentID),
		"ordering_domain": Digest32(orderingDomain), "epoch": U64(epoch), "sequence": U64(sequence),
		"event_content_id": Digest32(eventContentID)}
	if _, _, err := DeriveStableActionID("operation.journal.append", fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func ValidateOperationJournalAppendAdmissionRequestV1(request OperationJournalAppendAdmissionRequestV1) error {
	if !digest32(request.OrderingDomain) || request.Epoch == 0 || request.Sequence == 0 || !digest32(request.EventContentID) ||
		!digest32(request.OperationEnvelopeDigest) || !digest32(request.GapSetDigest) {
		return errors.New("operation journal append admission request is invalid")
	}
	return nil
}

func OperationPrivateSendSemanticFieldsV1(ownerID, agentID string, request OperationPrivateRequestV1) (map[string]SemanticValue, error) {
	if err := ValidateOperationPrivateRequestV1(request); err != nil {
		return nil, err
	}
	if err := validateOperationRequestActorV1(agentID, request.OperationEnvelope); err != nil {
		return nil, err
	}
	profileDigest, err := ProfileRefDigestV1(request.TransportProfile)
	if err != nil {
		return nil, err
	}
	return map[string]SemanticValue{
		"owner_id": ID(ownerID), "agent_id": ID(agentID), "recipient_set_digest": Digest32(request.RecipientSetDigest),
		"membership_epoch": U64(request.MembershipEpoch), "audience_policy_digest": Digest32(request.AudiencePolicyDigest),
		"operation_id": Digest32(request.OperationID), "operation_envelope_digest": Digest32(request.OperationEnvelopeDigest),
		"conversation_scope_digest": Digest32(request.ConversationScopeDigest), "transport_profile_digest": Digest32(profileDigest),
	}, nil
}

func validateOperationRequestActorV1(agentID string, canonicalEnvelope []byte) error {
	var envelope AgentOperationEnvelopeV1
	if !outcomeToken(agentID, 256) || codec.Unmarshal(canonicalEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != agentID {
		return errors.New("operation request actor does not match the authorized Agent")
	}
	return nil
}

func ValidateOperationCarrierRequestV1(request OperationCarrierRequestV1) error {
	if request.SchemaVersion != 1 || !outcomeToken(request.CarrierID, 256) || ValidateProfileRefV1(request.CarrierProfile) != nil ||
		!digest32(request.AudiencePolicyDigest) || !digest32(request.OperationID) || !digest32(request.OperationEnvelopeDigest) ||
		len(request.OperationEnvelope) == 0 || len(request.OperationEnvelope) > MaxAgentOperationEnvelopeBytes {
		return errors.New("operation Carrier request is invalid")
	}
	return validateOperationEnvelopeBytes(request.OperationID, request.OperationEnvelopeDigest, request.OperationEnvelope, request.EventPayload, request.Artifacts)
}

func ValidateOperationPrivateRequestV1(request OperationPrivateRequestV1) error {
	if request.SchemaVersion != 1 || !digest32(request.RecipientSetDigest) || request.MembershipEpoch == 0 ||
		!digest32(request.AudiencePolicyDigest) || !digest32(request.OperationID) || !digest32(request.OperationEnvelopeDigest) ||
		!digest32(request.ConversationScopeDigest) || ValidateProfileRefV1(request.TransportProfile) != nil ||
		len(request.OperationEnvelope) == 0 || len(request.OperationEnvelope) > MaxAgentOperationEnvelopeBytes {
		return errors.New("operation private request is invalid")
	}
	if len(request.RecipientAgentIDs) != 1 || !sortedUniqueStrings(request.RecipientAgentIDs, 1, func(value string) bool { return outcomeToken(value, 256) }) {
		return errors.New("operation private recipients are invalid")
	}
	recipientDigest, err := codec.Digest("tos.messenger-recipient-set.v1", request.RecipientAgentIDs)
	if err != nil || recipientDigest != request.RecipientSetDigest {
		return errors.New("operation private recipient set digest mismatch")
	}
	return validateOperationEnvelopeBytes(request.OperationID, request.OperationEnvelopeDigest, request.OperationEnvelope, request.EventPayload, request.Artifacts)
}

func ValidateOperationSubmissionReceiptV1(receipt OperationSubmissionReceiptV1) error {
	if receipt.SchemaVersion != 1 || !digest32(receipt.StableActionID) || !digest32(receipt.ExactRequestDigest) ||
		!validActionResolutionState(receipt.State) || !outcomeToken(receipt.SinkID, 256) || !outcomeToken(receipt.SinkReference, 4096) ||
		receipt.AuthorityTimeUnix == 0 || receipt.StateRevision == 0 || !digest32(receipt.EvidenceDigest) || len(receipt.SinkProof) == 0 || len(receipt.SinkProof) > 64<<10 {
		return errors.New("operation submission receipt is invalid")
	}
	return nil
}

func SignOperationSubmissionReceiptV1(receipt OperationSubmissionReceiptV1, key ed25519.PrivateKey) (OperationSubmissionReceiptV1, error) {
	if len(key) != ed25519.PrivateKeySize || len(receipt.SinkProof) != 0 {
		return OperationSubmissionReceiptV1{}, errors.New("operation receipt signing request is invalid")
	}
	message, err := operationSubmissionReceiptMessageV1(receipt)
	if err != nil {
		return OperationSubmissionReceiptV1{}, err
	}
	receipt.SinkProof = ed25519.Sign(key, message)
	if err := ValidateOperationSubmissionReceiptV1(receipt); err != nil {
		return OperationSubmissionReceiptV1{}, err
	}
	return receipt, nil
}

func VerifyOperationSubmissionReceiptV1(receipt OperationSubmissionReceiptV1, expectedKey ed25519.PublicKey) error {
	if len(expectedKey) != ed25519.PublicKeySize || ValidateOperationSubmissionReceiptV1(receipt) != nil || len(receipt.SinkProof) != ed25519.SignatureSize {
		return errors.New("operation submission receipt is invalid")
	}
	message, err := operationSubmissionReceiptMessageV1(receipt)
	if err != nil || !ed25519.Verify(expectedKey, message, receipt.SinkProof) {
		return errors.New("operation submission receipt signature is invalid")
	}
	return nil
}

func operationSubmissionReceiptMessageV1(receipt OperationSubmissionReceiptV1) ([]byte, error) {
	proof := append([]byte(nil), receipt.SinkProof...)
	receipt.SinkProof = nil
	if receipt.SchemaVersion != 1 || !digest32(receipt.StableActionID) || !digest32(receipt.ExactRequestDigest) ||
		!validActionResolutionState(receipt.State) || !outcomeToken(receipt.SinkID, 256) || !outcomeToken(receipt.SinkReference, 4096) ||
		receipt.AuthorityTimeUnix == 0 || receipt.StateRevision == 0 || !digest32(receipt.EvidenceDigest) {
		return nil, errors.New("operation submission receipt body is invalid")
	}
	if len(proof) != 0 && len(proof) != ed25519.SignatureSize {
		return nil, errors.New("operation submission receipt proof length is invalid")
	}
	canonical, err := codec.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte("tos.operation-submission-receipt.v1\x00"), canonical...), nil
}

func VerifyOperationCarrierSubmissionV1(submission OperationCarrierSubmissionV1, resolver FenceAuthorityResolver, now time.Time) error {
	if err := ValidateOperationCarrierRequestV1(submission.Request); err != nil {
		return err
	}
	request, err := codec.Marshal(submission.Request)
	if err != nil {
		return err
	}
	fields, err := OperationPublishSemanticFieldsV1(submission.AuthorizedAction.OwnerID, submission.AuthorizedAction.AgentID, submission.Request)
	if err != nil {
		return err
	}
	if submission.AuthorizedAction.ActionKind != "operation.publish" {
		return errors.New("operation Carrier submission has wrong Action kind")
	}
	return VerifyAuthorizedAction(submission.AuthorizedAction, fields, request, submission.WriterFence, resolver, now)
}

func VerifyOperationPrivateSubmissionV1(submission OperationPrivateSubmissionV1, resolver FenceAuthorityResolver, now time.Time) error {
	if err := ValidateOperationPrivateRequestV1(submission.Request); err != nil {
		return err
	}
	privateRequest, err := codec.Marshal(submission.Request)
	if err != nil {
		return err
	}
	request, err := CanonicalMessengerEffectRequest(MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: append([]string(nil), submission.Request.RecipientAgentIDs...), EventKind: "operation.outcome",
		ContentType: "application/vnd.tos.operation-outcome-private+cbor", Payload: privateRequest})
	if err != nil {
		return err
	}
	fields, err := OperationPrivateSendSemanticFieldsV1(submission.AuthorizedAction.OwnerID, submission.AuthorizedAction.AgentID, submission.Request)
	if err != nil {
		return err
	}
	if submission.AuthorizedAction.ActionKind != "operation.private-send" {
		return errors.New("operation private submission has wrong Action kind")
	}
	return VerifyAuthorizedAction(submission.AuthorizedAction, fields, request, submission.WriterFence, resolver, now)
}

func validateOperationEnvelopeBytes(operationID, envelopeDigest string, canonical, eventPayload []byte,
	artifacts OperationOutcomeArtifactBundleV1) error {
	var envelope AgentOperationEnvelopeV1
	if err := codec.Unmarshal(canonical, &envelope); err != nil {
		return errors.New("operation envelope bytes are not canonical")
	}
	digest, err := AgentOperationEnvelopeDigestV1(envelope)
	if err != nil || digest != envelopeDigest || envelope.Body.OperationID != operationID {
		return errors.New("operation request envelope binding is invalid")
	}
	payloadDigest, err := AgentOperationPayloadDigest(envelope.Body.PayloadProfile, eventPayload)
	if err != nil || payloadDigest != envelope.Body.PayloadDigest || uint64(len(eventPayload)) != envelope.Body.PayloadSize {
		return errors.New("operation request event payload binding is invalid")
	}
	var body OperationOutcomeEventBodyV1
	if codec.Unmarshal(eventPayload, &body) != nil {
		return errors.New("operation request event body is invalid")
	}
	return VerifyOperationOutcomeArtifactBundleV1(body, artifacts)
}

func validActionResolutionState(state ActionResolutionState) bool {
	switch state {
	case ActionUnknown, ActionPrepared, ActionSubmitted, ActionAccepted, ActionRejected, ActionConflict, ActionTerminal:
		return true
	default:
		return false
	}
}
