package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type outcomeAuthorityVerifier struct{ calls int }

func (verifier *outcomeAuthorityVerifier) VerifyOutcomeAuthorityTime(AuthorityTimeProofV1,
	OutcomeEvidenceItemV1, time.Time) error {
	verifier.calls++
	return nil
}

func TestOperationSubmissionReceiptSignatureBindsActionAndEvidence(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	receipt := OperationSubmissionReceiptV1{SchemaVersion: 1, StableActionID: outcomeDigest("1"), ExactRequestDigest: outcomeDigest("2"),
		State: ActionTerminal, SinkID: "carrier:one", SinkReference: outcomeDigest("3"), AuthorityTimeUnix: 10,
		StateRevision: 2, EvidenceDigest: outcomeDigest("4")}
	signed, err := SignOperationSubmissionReceiptV1(receipt, key)
	if err != nil || VerifyOperationSubmissionReceiptV1(signed, key.Public().(ed25519.PublicKey)) != nil {
		t.Fatal(err)
	}
	signed.EvidenceDigest = outcomeDigest("5")
	if VerifyOperationSubmissionReceiptV1(signed, key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("receipt evidence substitution accepted")
	}
}

func (verifier *outcomeAuthorityVerifier) VerifyOutcomeIssuerQualification(IssuerQualificationProofV1,
	OutcomeEvidenceItemV1, AuthorityTimeProofV1, time.Time) error {
	verifier.calls++
	return nil
}

type rejectingOutcomeAuthorityVerifier struct{}

func (rejectingOutcomeAuthorityVerifier) VerifyOutcomeAuthorityTime(AuthorityTimeProofV1,
	OutcomeEvidenceItemV1, time.Time) error {
	return errors.New("untrusted checkpoint")
}
func (rejectingOutcomeAuthorityVerifier) VerifyOutcomeIssuerQualification(IssuerQualificationProofV1,
	OutcomeEvidenceItemV1, AuthorityTimeProofV1, time.Time) error {
	return nil
}

func outcomeDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

func buildOutcomeEnvelope(t *testing.T) (AgentOperationEnvelopeV1, []byte, OperationOutcomeArtifactBundleV1, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	assertionPayload, err := codec.Marshal(ActionResolutionReferencePayloadV1{StableActionID: outcomeDigest("1"),
		ExactRequestDigest: outcomeDigest("2"), AuthorizedActionDigest: outcomeDigest("3"),
		ActionResolutionDigest: outcomeDigest("4"), ResolutionState: ActionTerminal, ResolutionStateRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	body, err := BuildOperationOutcomeEventV1(OutcomeObservation,
		OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: outcomeDigest("1")}, nil,
		OutcomeProfileActionResolutionReference, assertionPayload,
		EmptyOutcomeEvidenceManifestV1("local_projection"), EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, payload, err := OperationOutcomeEventContentIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	op := AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION",
		OpcodeName: "OUTCOME", OpcodeVersion: 1, ActorAgentID: "agent:publisher",
		AuthorizationRef:   ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1, ProfileDigest: outcomeDigest("b")},
		AudienceDescriptor: "local-private", ObjectID: contentID, OrderingDomain: "outcome:journal:1", Epoch: 1, Sequence: 1,
		CreatedAtUnix: uint64(now.Unix()), PayloadProfile: OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(payload))}
	op.OperationID, err = DeriveAgentOperationIDV1(op)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignAgentOperationV1(op, op.ActorAgentID, private, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	artifacts := OperationOutcomeArtifactBundleV1{AssertionPayload: assertionPayload,
		EvidenceManifest: EmptyOutcomeEvidenceManifestV1("local_projection"), ExtensionSet: EmptyOutcomeExtensionSetV1(),
		AuthorityProofs: []OutcomeAuthorityProofMaterialV1{}}
	return envelope, payload, artifacts, public, private
}

func TestOperationOutcomeRoundTripAndOuterBinding(t *testing.T) {
	envelope, payload, _, public, _ := buildOutcomeEnvelope(t)
	now := time.Unix(1_900_000_000, 0).UTC()
	if _, err := VerifyOperationOutcomeEnvelopeV1(envelope, payload, operationTestResolver{key: public}, now); err != nil {
		t.Fatal(err)
	}

	tampered := envelope
	tampered.Body.OperationID = outcomeDigest("c")
	if _, err := VerifyOperationOutcomeEnvelopeV1(tampered, payload, operationTestResolver{key: public}, now); err == nil {
		t.Fatal("caller-selected operation ID was accepted")
	}
	tampered = envelope
	tampered.Body.ObjectID = outcomeDigest("d")
	if _, err := VerifyOperationOutcomeEnvelopeV1(tampered, payload, operationTestResolver{key: public}, now); err == nil {
		t.Fatal("mismatched event content ID was accepted")
	}
}

func TestOutcomeManifestAndCausalityAreCanonical(t *testing.T) {
	assertionPayload, err := codec.Marshal(ActionResolutionReferencePayloadV1{StableActionID: outcomeDigest("1"),
		ExactRequestDigest: outcomeDigest("2"), AuthorizedActionDigest: outcomeDigest("3"),
		ActionResolutionDigest: outcomeDigest("4"), ResolutionState: ActionTerminal, ResolutionStateRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	event, err := BuildOperationOutcomeEventV1(OutcomeObservation,
		OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: outcomeDigest("1")}, nil,
		OutcomeProfileActionResolutionReference, assertionPayload,
		EmptyOutcomeEvidenceManifestV1("local_projection"), EmptyOutcomeExtensionSetV1())
	if err != nil || event.CausalPredecessorAssertionRefs == nil {
		t.Fatalf("builder did not normalize the typed empty predecessor set: %#v err=%v", event.CausalPredecessorAssertionRefs, err)
	}
	event.CausalPredecessorAssertionRefs = nil
	if ValidateOperationOutcomeEventBodyV1(event) == nil {
		t.Fatal("null predecessor set was accepted as canonical")
	}

	manifest := EmptyOutcomeEvidenceManifestV1("qualified_assertion")
	manifest.AuthorityProofRefs = []OutcomeAuthorityProofRefV1{
		{ProofProfileURI: "tos.proof.z.v1", ObjectDigest: outcomeDigest("2"), CanonicalSize: 10},
		{ProofProfileURI: "tos.proof.a.v1", ObjectDigest: outcomeDigest("1"), CanonicalSize: 10},
	}
	if ValidateOutcomeEvidenceManifestV1(manifest) == nil {
		t.Fatal("unsorted authority proofs were accepted")
	}
	if err := SortOutcomeAuthorityProofRefsV1(manifest.AuthorityProofRefs); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOutcomeEvidenceManifestV1(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.AuthorityProofRefs = append(manifest.AuthorityProofRefs, manifest.AuthorityProofRefs[1])
	if err := SortOutcomeAuthorityProofRefsV1(manifest.AuthorityProofRefs); err == nil {
		t.Fatal("duplicate authority proof was accepted")
	}
}

func TestOperationPublishAndPrivateSendSemanticIdentity(t *testing.T) {
	envelope, eventPayload, artifacts, _, authorityKey := buildOutcomeEnvelope(t)
	canonicalEnvelope, envelopeDigest, err := MarshalAgentOperationEnvelopeV1(envelope)
	if err != nil {
		t.Fatal(err)
	}
	carrierProfile := ProfileRefV1{ProfileURI: "tos.carrier.outcome.v1", ProfileVersion: 1, ProfileDigest: outcomeDigest("4")}
	request := OperationCarrierRequestV1{SchemaVersion: 1, CarrierID: "carrier:one", CarrierProfile: carrierProfile,
		AudiencePolicyDigest: outcomeDigest("5"), OperationID: envelope.Body.OperationID,
		OperationEnvelopeDigest: envelopeDigest, OperationEnvelope: canonicalEnvelope, EventPayload: eventPayload, Artifacts: artifacts}
	fields, err := OperationPublishSemanticFieldsV1("owner:test", "agent:publisher", request)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := DeriveStableActionID("operation.publish", fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OperationPublishSemanticFieldsV1("owner:test", "agent:impersonator", request); err == nil {
		t.Fatal("publication Action accepted an Operation issued by another Agent")
	}
	request.CarrierID = "carrier:two"
	secondFields, _ := OperationPublishSemanticFieldsV1("owner:test", "agent:publisher", request)
	second, _, _ := DeriveStableActionID("operation.publish", secondFields)
	if first == second {
		t.Fatal("different Carrier reused publication identity")
	}

	recipientSet := []string{"agent:buyer"}
	recipientDigest, _ := codec.Digest("tos.messenger-recipient-set.v1", recipientSet)
	private := OperationPrivateRequestV1{SchemaVersion: 1, RecipientSetDigest: recipientDigest, RecipientAgentIDs: recipientSet, MembershipEpoch: 7,
		AudiencePolicyDigest: outcomeDigest("7"), OperationID: envelope.Body.OperationID, OperationEnvelopeDigest: envelopeDigest,
		ConversationScopeDigest: outcomeDigest("8"), TransportProfile: ProfileRefV1{ProfileURI: "tos.messenger.outcome.v1", ProfileVersion: 1, ProfileDigest: outcomeDigest("9")},
		OperationEnvelope: canonicalEnvelope, EventPayload: eventPayload, Artifacts: artifacts}
	privateFields, err := OperationPrivateSendSemanticFieldsV1("owner:test", "agent:publisher", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OperationPrivateSendSemanticFieldsV1("owner:test", "agent:impersonator", private); err == nil {
		t.Fatal("private-send Action accepted an Operation issued by another Agent")
	}
	privateID, _, err := DeriveStableActionID("operation.private-send", privateFields)
	if err != nil || privateID == first {
		t.Fatalf("private identity invalid: %s %v", privateID, err)
	}
	_ = authorityKey
}

func TestOutcomeAuthorityVerificationRequiresCompleteBoundProofs(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	timeProof := AuthorityTimeProofV1{ProfileURI: "tos.authority.clock.v1", AuthorityOrCheckpointID: "clock:one",
		IntervalStartUnix: uint64(now.Add(-2 * time.Minute).Unix()), IntervalEndUnix: uint64(now.Add(-time.Minute).Unix()),
		FinalizedHighWater: 19, FinalizedRootDigest: outcomeDigest("1"), ProofDigest: outcomeDigest("2")}
	timeBytes, err := codec.Marshal(timeProof)
	if err != nil {
		t.Fatal(err)
	}
	timeMaterial := OutcomeAuthorityProofMaterialV1{ProofProfileURI: OutcomeAuthorityTimeProofProfileV1, CanonicalObject: timeBytes}
	timeDigest, err := OutcomeAuthorityProofObjectDigestV1(timeMaterial)
	if err != nil {
		t.Fatal(err)
	}
	qualification := IssuerQualificationProofV1{RootAuthorityID: "authority:root", IssuerAgentID: "agent:executor",
		IssuerKeyDigest: outcomeDigest("3"), OrderedDelegationChainDigest: outcomeDigest("4"), ScopeProfileURI: "tos.execution.resolution.v1",
		SubjectScopeDigest: outcomeDigest("5"), ValidFromUnix: uint64(now.Add(-time.Hour).Unix()), ValidUntilUnix: uint64(now.Add(time.Hour).Unix()),
		RevocationHandleSetDigest: outcomeDigest("6"), AuthorityTimeProofDigest: timeDigest, RevocationHighWater: 8,
		RevocationRootDigest: outcomeDigest("7")}
	qualificationBytes, err := codec.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	qualificationMaterial := OutcomeAuthorityProofMaterialV1{ProofProfileURI: OutcomeIssuerQualificationProofProfileV1, CanonicalObject: qualificationBytes}
	qualificationDigest, err := OutcomeAuthorityProofObjectDigestV1(qualificationMaterial)
	if err != nil {
		t.Fatal(err)
	}
	manifest := OutcomeEvidenceManifestV1{SchemaVersion: 1, ManifestPurpose: "qualified_assertion",
		AuthorityProofRefs: []OutcomeAuthorityProofRefV1{
			{ProofProfileURI: timeMaterial.ProofProfileURI, ObjectDigest: timeDigest, CanonicalSize: uint64(len(timeBytes))},
			{ProofProfileURI: qualificationMaterial.ProofProfileURI, ObjectDigest: qualificationDigest, CanonicalSize: uint64(len(qualificationBytes))}},
		EvidenceItems: []OutcomeEvidenceItemV1{{EvidenceRole: "authoritative_resolution", EvidenceProfileURI: "tos.execution.resolution.v1",
			SourceObjectProfileURI: "tos.execution.result.v1", SourceObjectDigest: outcomeDigest("8"), ObjectDigest: outcomeDigest("9"),
			CanonicalSize: 128, MediaType: "application/cbor", IssuerDescriptor: "issuer:pseudonym", SubjectDescriptor: "execution:pseudonym",
			ClaimedObservationTimeUnix: timeProof.IntervalEndUnix, AuthorityTimeProofDigest: timeDigest,
			IssuerQualificationProofDigest: qualificationDigest, Visibility: "local_private", AudienceDigest: outcomeDigest("a"),
			RetentionPolicyDigest: outcomeDigest("b"), RetrievalPolicyDigest: outcomeDigest("c")}}}
	if err := SortOutcomeAuthorityProofRefsV1(manifest.AuthorityProofRefs); err != nil {
		t.Fatal(err)
	}
	if err := SortOutcomeEvidenceItemsV1(manifest.EvidenceItems); err != nil {
		t.Fatal(err)
	}
	body := OperationOutcomeEventBodyV1{SchemaVersion: 1, EventKind: OutcomeTerminalObservation,
		PrimarySubjectRef:   OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.execution.v1", SubjectID: "execution:one"},
		AssertionProfileURI: OutcomeProfileTerminal, AssertionPayloadDigest: outcomeDigest("d"), AssertionPayloadSize: 1,
		EvidenceManifestDigest: outcomeDigest("e"), ExtensionSetDigest: outcomeDigest("f")}
	verifier := &outcomeAuthorityVerifier{}
	assessment, err := VerifyOperationOutcomeAuthorityV1(body, manifest,
		[]OutcomeAuthorityProofMaterialV1{qualificationMaterial, timeMaterial}, verifier, now)
	if err != nil || !assessment.AuthorityQualified || assessment.AuthorityTimeHighWater != 19 || verifier.calls != 2 {
		t.Fatalf("qualified authority evidence rejected: %+v calls=%d err=%v", assessment, verifier.calls, err)
	}
	if _, err := VerifyOperationOutcomeAuthorityV1(body, manifest, []OutcomeAuthorityProofMaterialV1{timeMaterial}, verifier, now); err == nil {
		t.Fatal("partial authority proof union was accepted")
	}
	if _, err := VerifyOperationOutcomeAuthorityV1(body, manifest,
		[]OutcomeAuthorityProofMaterialV1{qualificationMaterial, timeMaterial}, rejectingOutcomeAuthorityVerifier{}, now); err == nil {
		t.Fatal("cryptographically rejected authority was accepted")
	}
}
