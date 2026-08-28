package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type objectVector struct {
	Name                string `json:"name"`
	Domain              string `json:"digest_domain"`
	JSONModel           any    `json:"json_model"`
	CanonicalCBORBase64 string `json:"canonical_cbor_base64"`
	Digest              string `json:"digest"`
}
type actionVector struct {
	ActionKind     string                        `json:"action_kind"`
	Fields         []commerce.SemanticFieldValue `json:"fields"`
	StableActionID string                        `json:"stable_action_id"`
	PreimageHex    string                        `json:"preimage_hex"`
}
type document struct {
	Schema            string         `json:"schema"`
	Objects           []objectVector `json:"objects"`
	Actions           []actionVector `json:"semantic_actions"`
	NegativeMutations []string       `json:"negative_mutations"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: operation-outcome-fixtures OUTPUT")
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	digest := func(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
	authorityTime := commerce.AuthorityTimeProofV1{ProfileURI: "tos.authority.clock.v1", AuthorityOrCheckpointID: "checkpoint:19",
		IntervalStartUnix: uint64(now.Add(-time.Minute).Unix()), IntervalEndUnix: uint64(now.Unix()), FinalizedHighWater: 19,
		FinalizedRootDigest: digest("1"), ProofDigest: digest("2")}
	authorityTimeBytes, err := codec.Marshal(authorityTime)
	must(err)
	authorityTimeMaterial := commerce.OutcomeAuthorityProofMaterialV1{ProofProfileURI: commerce.OutcomeAuthorityTimeProofProfileV1,
		CanonicalObject: authorityTimeBytes}
	authorityTimeDigest, err := commerce.OutcomeAuthorityProofObjectDigestV1(authorityTimeMaterial)
	must(err)
	qualification := commerce.IssuerQualificationProofV1{RootAuthorityID: "authority:executor", IssuerAgentID: "agent:executor",
		IssuerKeyDigest: digest("3"), OrderedDelegationChainDigest: digest("4"), ScopeProfileURI: "tos.execution.resolution.v1",
		SubjectScopeDigest: digest("5"), ValidFromUnix: uint64(now.Add(-time.Hour).Unix()), ValidUntilUnix: uint64(now.Add(time.Hour).Unix()),
		RevocationHandleSetDigest: digest("6"), AuthorityTimeProofDigest: authorityTimeDigest, RevocationHighWater: 8,
		RevocationRootDigest: digest("7")}
	qualificationBytes, err := codec.Marshal(qualification)
	must(err)
	qualificationMaterial := commerce.OutcomeAuthorityProofMaterialV1{ProofProfileURI: commerce.OutcomeIssuerQualificationProofProfileV1,
		CanonicalObject: qualificationBytes}
	qualificationDigest, err := commerce.OutcomeAuthorityProofObjectDigestV1(qualificationMaterial)
	must(err)
	authorityMaterials := []commerce.OutcomeAuthorityProofMaterialV1{authorityTimeMaterial, qualificationMaterial}
	must(commerce.SortOutcomeAuthorityProofMaterialsV1(authorityMaterials))
	proofs := []commerce.OutcomeAuthorityProofRefV1{
		{ProofProfileURI: authorityTimeMaterial.ProofProfileURI, ObjectDigest: authorityTimeDigest, CanonicalSize: uint64(len(authorityTimeBytes))},
		{ProofProfileURI: qualificationMaterial.ProofProfileURI, ObjectDigest: qualificationDigest, CanonicalSize: uint64(len(qualificationBytes))}}
	must(commerce.SortOutcomeAuthorityProofRefsV1(proofs))
	items := []commerce.OutcomeEvidenceItemV1{{EvidenceRole: "authoritative_resolution", EvidenceProfileURI: "tos.execution.resolution.v1",
		SourceObjectProfileURI: "tos.execution.state.v1", SourceObjectDigest: digest("3"), ObjectDigest: digest("4"), CanonicalSize: 384,
		MediaType: "application/cbor", IssuerDescriptor: "issuer:pseudonym:1", SubjectDescriptor: "execution:pseudonym:1",
		ClaimedObservationTimeUnix: uint64(now.Unix()), AuthorityTimeProofDigest: authorityTimeDigest, IssuerQualificationProofDigest: qualificationDigest,
		Visibility: "named_participants", AudienceDigest: digest("5"), RetentionPolicyDigest: digest("6"), RetrievalPolicyDigest: digest("7")}}
	manifest := commerce.OutcomeEvidenceManifestV1{SchemaVersion: 1, ManifestPurpose: "qualified_assertion", AuthorityProofRefs: proofs, EvidenceItems: items}
	terminal := commerce.TerminalDispositionV1{TerminalScope: "execution", TerminalSubjectID: digest("8"), OwningStateProfileURI: "tos.execution.state.v1",
		AuthoritativeResolutionDigest: digest("3"), TerminalStateRevision: 4, SuccessorPolicyDigest: digest("9"), Disposition: "failed",
		FailureStage: "execution", FailureCode: "execution.tool_failed", RetryDisposition: "successor_after_terminal", ResolvedAtUnix: uint64(now.Unix())}
	assertion, err := codec.Marshal(terminal)
	must(err)
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeTerminalObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.execution.v1", SubjectID: digest("8")}, nil,
		commerce.OutcomeProfileTerminal, assertion, manifest, commerce.EmptyOutcomeExtensionSetV1())
	must(err)
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	must(err)
	artifactBundle := commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertion, EvidenceManifest: manifest,
		ExtensionSet: commerce.EmptyOutcomeExtensionSetV1(), AuthorityProofs: authorityMaterials}
	must(commerce.VerifyOperationOutcomeArtifactBundleV1(event, artifactBundle))
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	trustConfigurationDigest, err := codec.Digest("tos.fixture.trust-configuration.v1", struct {
		Name string `json:"name"`
	}{"operation-outcome-fixture"})
	must(err)
	operationAuthority, err := commerce.NewPinnedAgentOperationAuthorityV1("agent:"+strings.Repeat("a", 64), key.Public().(ed25519.PublicKey),
		time.Unix(1, 0).UTC(), time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC), trustConfigurationDigest)
	must(err)
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:testnet", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: "agent:" + strings.Repeat("a", 64), AuthorizationRef: operationAuthority.Profile,
		AudienceDescriptor: "participants:agreement", ObjectID: contentID, OrderingDomain: digest("b"), Epoch: 7, Sequence: 11,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	must(err)
	envelope, err := commerce.SignAgentOperationV1(body, body.ActorAgentID, key, operationAuthority.Proof)
	must(err)
	envelopeBytes, envelopeDigest, err := commerce.MarshalAgentOperationEnvelopeV1(envelope)
	must(err)
	carrier := commerce.OperationCarrierRequestV1{SchemaVersion: 1, CarrierID: "carrier:one", CarrierProfile: commerce.ProfileRefV1{ProfileURI: "tos.carrier.operation.v1", ProfileVersion: 1, ProfileDigest: digest("c")},
		AudiencePolicyDigest: digest("5"), OperationID: body.OperationID, OperationEnvelopeDigest: envelopeDigest, OperationEnvelope: envelopeBytes, EventPayload: eventPayload, Artifacts: artifactBundle}
	recipients := []string{"agent:" + strings.Repeat("d", 64)}
	recipientDigest, _ := codec.Digest("tos.messenger-recipient-set.v1", recipients)
	private := commerce.OperationPrivateRequestV1{SchemaVersion: 1, RecipientSetDigest: recipientDigest, RecipientAgentIDs: recipients, MembershipEpoch: 3,
		AudiencePolicyDigest: digest("5"), OperationID: body.OperationID, OperationEnvelopeDigest: envelopeDigest, ConversationScopeDigest: digest("e"),
		TransportProfile: commerce.ProfileRefV1{ProfileURI: "tos.messenger.operation-outcome.v1", ProfileVersion: 1, ProfileDigest: digest("f")}, OperationEnvelope: envelopeBytes, EventPayload: eventPayload, Artifacts: artifactBundle}
	journalAppend := commerce.OperationJournalAppendAdmissionRequestV1{OrderingDomain: body.OrderingDomain, Epoch: body.Epoch,
		Sequence: body.Sequence, EventContentID: contentID, OperationEnvelopeDigest: envelopeDigest, GapSetDigest: digest("9")}
	must(commerce.ValidateOperationJournalAppendAdmissionRequestV1(journalAppend))
	artifactDigest, err := codec.Digest("tos.operation-outcome.artifact-bundle.v1", artifactBundle)
	must(err)
	receipt, err := commerce.SignOperationSubmissionReceiptV1(commerce.OperationSubmissionReceiptV1{SchemaVersion: 1,
		StableActionID: digest("1"), ExactRequestDigest: digest("2"), State: commerce.ActionTerminal, SinkID: "carrier:one",
		SinkReference: envelopeDigest, AuthorityTimeUnix: uint64(now.Unix()), StateRevision: 2, EvidenceDigest: artifactDigest}, key)
	must(err)
	perimeter := commerce.EconomicPerimeterV1{PerimeterID: digest("1"), ControllerSetDigest: digest("2"), BeneficialOwnerSetDigest: digest("3"),
		RelatedPartySetDigest: digest("4"), FundingOriginSetDigest: digest("5"), ClassificationPolicyDigest: digest("6"),
		ValidFromUnix: uint64(now.Add(-time.Hour).Unix()), ValidUntilUnix: uint64(now.Add(time.Hour).Unix())}
	revenue := commerce.RevenueRecognitionV1{AgreementBodyDigest: digest("1"), ObligationInstanceID: digest("2"), PaymentAssertionDigest: digest("3"),
		SellerPerimeterDigest: digest("4"), BuyerPerimeterDigest: digest("5"), RelationshipClass: "external", ConsiderationAssetDigest: digest("6"),
		GrossAmountAtomic: "50", RecognizedAmountAtomic: "50", RecognitionPolicyDigest: digest("7"), AuthorityEvidenceSetRoot: digest("8")}
	conversion := commerce.AssetConversionEvidenceV1{SourceAssetDigest: digest("1"), TargetAssetDigest: digest("2"), SourceAmountAtomic: "10",
		RateNumerator: "3", RateDenominator: "2", RateType: "executed", PriceSourceProfileURI: "tos.price.source.v1", PriceEvidenceDigest: digest("3"),
		QuotedAtUnix: uint64(now.Unix()), ValidUntilUnix: uint64(now.Add(time.Minute).Unix()), FeeAmountAtomic: "1", RoundingRule: "floor",
		TargetAmountAtomic: "14", ConversionPolicyDigest: digest("4")}
	forecast := commerce.OutcomeForecastV1{ForecastID: digest("1"), IssuedAtAuthorityUnix: uint64(now.Unix()), ModelArtifactDigest: digest("2"),
		FeatureCutDigest: digest("3"), CohortPolicyDigest: digest("4"), TargetProfileURI: commerce.OutcomeProfileTerminal,
		TargetSubjectDigest: digest("5"), HorizonEndUnix: uint64(now.Add(time.Hour).Unix()), ProbabilityPPM: 700000, ForecastAuthorityDigest: digest("6")}
	calibration := commerce.CalibrationReportV1{ReportID: digest("1"), ForecastSetRoot: digest("2"), OutcomeSetRoot: digest("3"),
		CensoringPolicyDigest: digest("4"), ClusterPolicyDigest: digest("5"), ScoringRule: "brier", ScoreNumerator: "21", ScoreDenominator: "100",
		BinSpecificationDigest: digest("6"), UniqueClusterCount: 8, VarianceMethodDigest: digest("7"), CorrelationIdentifierRoot: digest("8"), OutputDigest: digest("9")}
	financial := commerce.FinancialReportV1{ReportID: digest("1"), EventSetRoot: digest("2"), CohortCheckpointDigest: digest("3"), AuthorityCutDigest: digest("4"),
		FinalityCutDigest: digest("5"), AccountingBookID: "book:one", AccountingPolicyDigest: digest("6"), EconomicPerimeterDigest: digest("7"),
		ReportingAssetDigest: digest("8"), ConversionEvidenceRoot: digest("9"), WindowStartUnix: uint64(now.Add(-time.Hour).Unix()), WindowEndUnix: uint64(now.Unix()),
		Timezone: "utc", SoftwareBuildDigest: digest("a"), RegistryDigest: digest("b"), ArithmeticProfileURI: "tos.arithmetic.integer.v1", LedgerRoot: digest("c"),
		UnknownSetRoot: digest("d"), ConflictSetRoot: digest("e"), ExclusionSetRoot: digest("f"), PriorReportDigest: digest("0"), RestatementReason: "original", OutputDigest: digest("1")}
	censoring := commerce.OutcomeCensoringV1{AttemptAssertionRef: commerce.OutcomeAssertionRefV1{NetworkID: body.NetworkID, ActorAgentID: body.ActorAgentID,
		OperationID: body.OperationID, OperationEnvelopeDigest: envelopeDigest}, AdmissionTimeUnix: uint64(now.Add(-time.Hour).Unix()), ObservationEndUnix: uint64(now.Unix()),
		CensorKind: "right_censored", CensorReason: "window_closed", LastStateProfileURI: "tos.execution.state.v1", LastState: "running", LastStateRevision: 3}
	availability := commerce.EvidenceAvailabilityObservationV1{EvidenceObjectDigest: digest("1"), EvidenceProfileURI: "tos.evidence.object.v1", PriorState: "available",
		TargetState: "redacted", StateRevision: 2, CustodianID: "custodian:one", RetentionUntilUnix: uint64(now.Unix()), AvailabilityProof: digest("2"), ObservedAtUnix: uint64(now.Unix())}
	gateObservation := commerce.GateExecutionObservationV1{ExecutionID: digest("1"), AgreementBodyDigest: digest("2"), ObligationID: "work", PlanDigest: digest("3"),
		GatePolicyDigest: digest("4"), InputSetDigest: digest("5"), ResourceSetDigest: digest("6"), CredentialSetDigest: digest("7"), EffectSetDigest: digest("8"),
		State: "failed", StateRevision: 4, StartActionID: digest("9"), StartRequestDigest: digest("a"), AuthoritativeRecord: digest("b"), ObservedAtUnix: uint64(now.Unix())}
	carrierObservation := commerce.CarrierReceiptObservationV1{CarrierID: "carrier:one", OperationEnvelopeDigest: envelopeDigest, CarrierReceiptDigest: digest("1"),
		CarrierSequence: 19, AcceptedAtUnix: uint64(now.Unix()), RetentionCommitment: digest("2")}
	giftObservation := commerce.TransferObservationV1{TransferClass: "gift", NetworkID: body.NetworkID, TransactionDigest: digest("1"), FinalityEvidenceDigest: digest("2"),
		PayerID: "agent:payer", PayeeID: "agent:payee", AssetIdentityDigest: digest("3"), AmountAtomic: "7", DestinationDigest: digest("4"), GiftObjectDigest: digest("5"),
		AdapterProfileURI: "tos.transfer.tos.v1", ResolutionState: "validator_finalized", ObservedAtUnix: uint64(now.Unix())}
	paymentObservation := commerce.TransferObservationV1{TransferClass: "agreement_bound", NetworkID: body.NetworkID, TransactionDigest: digest("1"), FinalityEvidenceDigest: digest("2"),
		PayerID: "agent:payer", PayeeID: "agent:payee", AssetIdentityDigest: digest("3"), AmountAtomic: "7", DestinationDigest: digest("4"), AgreementBodyDigest: digest("5"),
		ObligationInstanceID: digest("6"), PaymentRequestDigest: digest("7"), StableActionID: digest("8"), ExactRequestDigest: digest("9"),
		AdapterProfileURI: "tos.transfer.tos.v1", ResolutionState: "validator_finalized", ObservedAtUnix: uint64(now.Unix())}
	escrowObservation := commerce.TOSEscrowObservationV1{Stage: "release_finalized", TransferClass: "agreement_bound", NetworkID: body.NetworkID,
		AcceptedQuoteDigest: digest("1"), AgreementBodyDigest: digest("2"), ObligationInstanceID: digest("3"), EscrowAccountDigest: digest("4"),
		ContractCodeDigest: digest("5"), ContractConfigurationHash: digest("6"), StableActionID: digest("7"), ExactRequestDigest: digest("8"),
		TransactionBytesDigest: digest("9"), TransactionDigest: digest("a"), FinalizedCheckpointDigest: digest("b"), AssetIdentityDigest: digest("c"),
		AmountAtomic: "50", AuthorityEvidenceSetRoot: digest("d"), ObservedAtUnix: uint64(now.Unix())}
	audiencePolicy := commerce.AudiencePolicyV1{SchemaVersion: 1, NetworkID: body.NetworkID, AudienceKind: "named_recipients",
		RecipientPrincipalKeySetDigest: digest("1"), PermittedPurposeSetDigest: digest("2"), OnwardDisclosureRule: "forbidden",
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), PolicyRevision: 1}
	privateEvidence := []byte("fixture private evidence")
	encryptedMetadata := commerce.OutcomeEncryptedEvidenceMetadataV1{ObjectDigest: digest("3"), AudiencePolicyDigest: digest("4"),
		RetentionPolicyDigest: digest("5"), EvidenceRole: "authoritative_resolution", CanonicalSize: uint64(len(privateEvidence))}
	keyReferenceDigest := digest("6")
	authenticatedContext := struct {
		SchemaVersion      uint16                                      `json:"schema_version"`
		CipherSuite        string                                      `json:"cipher_suite"`
		KeyReferenceDigest string                                      `json:"key_reference_digest"`
		Metadata           commerce.OutcomeEncryptedEvidenceMetadataV1 `json:"metadata"`
	}{1, commerce.OutcomeEvidenceCipherSuiteV1, keyReferenceDigest, encryptedMetadata}
	metadataBytes, err := codec.Marshal(authenticatedContext)
	must(err)
	metadataDigest, err := codec.Digest("tos.outcome.encrypted-evidence-associated-data.v1", authenticatedContext)
	must(err)
	block, err := aes.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	must(err)
	aead, err := cipher.NewGCM(block)
	must(err)
	nonce := []byte("fixtureNONCE")
	encryptedEvidence := commerce.OutcomeEncryptedEvidenceV1{SchemaVersion: 1, CipherSuite: commerce.OutcomeEvidenceCipherSuiteV1,
		KeyReferenceDigest: keyReferenceDigest, Nonce: nonce, AssociatedData: encryptedMetadata, AssociatedDataDigest: metadataDigest,
		Ciphertext: aead.Seal(nil, nonce, privateEvidence, metadataBytes)}
	must(commerce.ValidateOutcomeEncryptedEvidenceV1(encryptedEvidence))
	disclosure := commerce.OutcomeDisclosureProjectionV1{SchemaVersion: 1,
		SourceAssertionRefs: []commerce.OutcomeAssertionRefV1{{NetworkID: body.NetworkID, ActorAgentID: body.ActorAgentID,
			OperationID: body.OperationID, OperationEnvelopeDigest: envelopeDigest}}, SourceDisclosurePolicyRoot: digest("1"),
		SourceAudienceEpochRoot: digest("2"), ProjectionProfileURI: "tos.outcome.projection.summary.v1",
		Fields:               []commerce.OutcomeDisclosureFieldV1{{FieldPath: "disposition", Treatment: "disclosed", ValueDigest: digest("3")}},
		DerivationProfileURI: "tos.outcome.derivation.identity.v1", CompositionBudgetID: "budget:fixture", AudiencePolicyDigest: digest("4"),
		PurposeDigest: digest("5"), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), RetentionPolicyDigest: digest("6"), ProjectionIssuerID: body.ActorAgentID}
	must(commerce.ValidateOutcomeDisclosureProjectionV1(disclosure))
	membership, membershipRoot, err := commerce.BuildOutcomeCohortMembershipProofV1([]commerce.OutcomeAssertionRefV1{
		disclosure.SourceAssertionRefs[0], {NetworkID: body.NetworkID, ActorAgentID: "agent:" + strings.Repeat("b", 64),
			OperationID: digest("7"), OperationEnvelopeDigest: digest("8")}}, disclosure.SourceAssertionRefs[0])
	must(err)
	must(commerce.VerifyOutcomeCohortMembershipProofV1(membership, membershipRoot))
	learning := commerce.LearningDatasetManifestV1{ManifestID: digest("1"), IncludedAssertionSetRoot: digest("2"), IncludedCount: 8,
		ExcludedAssertionSetRoot: digest("3"), ExcludedCount: 2, ConflictAssertionSetRoot: digest("4"), ConflictCount: 1,
		CensoredAssertionSetRoot: digest("5"), CensoredCount: 3, CohortCheckpointRoot: digest("6"), ClusterPolicyDigest: digest("7"),
		SamplingPolicyDigest: digest("8"), WeightPolicyDigest: digest("9"), ProducerConcentrationDigest: digest("a"),
		SoftwareBuildDigest: digest("b"), EvaluationHoldoutSetRoot: digest("c"), AuthorityCutDigest: digest("d")}
	promotion := commerce.SkillPromotionDecisionV1{DecisionID: digest("1"), PriorSkillDigest: digest("2"), CandidateSkillDigest: digest("3"),
		DatasetManifestDigest: digest("4"), EvaluationReportDigest: digest("5"), RegressionThresholdDigest: digest("6"), SafetyThresholdDigest: digest("7"),
		ApproverAuthorityDigest: digest("8"), RollbackTargetDigest: digest("2"), StableActionID: digest("9"), ExactRequestDigest: digest("a"),
		Decision: "approved", DecidedAtUnix: uint64(now.Unix())}
	for _, validation := range []error{commerce.ValidateEconomicPerimeterV1(perimeter), commerce.ValidateRevenueRecognitionV1(revenue),
		commerce.ValidateAssetConversionEvidenceV1(conversion), commerce.ValidateOutcomeForecastV1(forecast),
		commerce.ValidateCalibrationReportV1(calibration), commerce.ValidateFinancialReportV1(financial), commerce.ValidateOutcomeCensoringV1(censoring),
		commerce.ValidateEvidenceAvailabilityObservationV1(availability), commerce.ValidateGateExecutionObservationV1(gateObservation),
		commerce.ValidateCarrierReceiptObservationV1(carrierObservation), commerce.ValidateTransferObservationV1(giftObservation),
		commerce.ValidateTransferObservationV1(paymentObservation), commerce.ValidateTOSEscrowObservationV1(escrowObservation),
		commerce.ValidateAudiencePolicyV1(audiencePolicy), commerce.ValidateLearningDatasetManifestV1(learning),
		commerce.ValidateSkillPromotionDecisionV1(promotion)} {
		must(validation)
	}
	doc := document{Schema: "tos.operation-outcome-conformance.v1", NegativeMutations: []string{"caller-selected-operation-id", "event-payload-substitution", "envelope-signature-substitution", "unsorted-evidence", "cross-issuer-content-deduplication", "publication-action-reused-across-carriers", "private-send-reused-after-membership-epoch-change"}}
	add := func(name, domain string, value any) {
		canonical, err := codec.Marshal(value)
		must(err)
		valueDigest, err := codec.Digest(domain, value)
		must(err)
		doc.Objects = append(doc.Objects, objectVector{name, domain, value, base64.StdEncoding.EncodeToString(canonical), valueDigest})
	}
	add("evidence_manifest", commerce.OperationOutcomeEvidenceManifestDomain, manifest)
	add("authority_time_material", commerce.OutcomeAuthorityProofObjectDomain, authorityTimeMaterial)
	add("issuer_qualification_material", commerce.OutcomeAuthorityProofObjectDomain, qualificationMaterial)
	add("artifact_bundle", "tos.operation-outcome.artifact-bundle.v1", artifactBundle)
	add("pinned_operation_authority", commerce.PinnedAgentOperationAuthorityDomain, operationAuthority.Body)
	add("terminal_disposition", "tos.operation-outcome.terminal-disposition.v1", terminal)
	add("event_body", commerce.OperationOutcomeEventDomain, event)
	add("operation_body", commerce.AgentOperationBodyDomain, body)
	add("operation_envelope", commerce.AgentOperationEnvelopeDomain, envelope)
	add("carrier_request", "tos.operation-carrier-request.v1", carrier)
	add("private_request", "tos.operation-private-request.v1", private)
	add("journal_append_request", "tos.operation-journal-append-admission-request.v1", journalAppend)
	add("submission_receipt", "tos.operation-submission-receipt.v1", receipt)
	add("economic_perimeter", "tos.operation-outcome.economic-perimeter.v1", perimeter)
	add("revenue_recognition", "tos.operation-outcome.revenue-recognition.v1", revenue)
	add("asset_conversion", "tos.operation-outcome.asset-conversion.v1", conversion)
	add("forecast", "tos.operation-outcome.forecast.v1", forecast)
	add("calibration_report", "tos.operation-outcome.calibration-report.v1", calibration)
	add("financial_report", "tos.operation-outcome.financial-report.v1", financial)
	add("censoring", "tos.operation-outcome.censoring.v1", censoring)
	add("evidence_availability", "tos.operation-outcome.evidence-availability.v1", availability)
	add("gate_execution", "tos.operation-outcome.gate-execution.v1", gateObservation)
	add("carrier_receipt", "tos.operation-outcome.carrier-receipt.v1", carrierObservation)
	add("gift_transfer", "tos.operation-outcome.transfer.gift.v1", giftObservation)
	add("agreement_payment", "tos.operation-outcome.transfer.agreement-payment.v1", paymentObservation)
	add("tos_escrow_transfer", "tos.operation-outcome.transfer.tos-escrow.v1", escrowObservation)
	add("audience_policy", "tos.operation-outcome.audience-policy.v1", audiencePolicy)
	add("encrypted_evidence", "tos.operation-outcome.encrypted-evidence.v1", encryptedEvidence)
	add("disclosure_projection", "tos.operation-outcome.disclosure-projection.v1", disclosure)
	add("cohort_membership_proof", "tos.operation-outcome.cohort-membership-proof.v1", membership)
	add("learning_dataset", "tos.operation-outcome.learning-dataset.v1", learning)
	add("skill_promotion", "tos.operation-outcome.skill-promotion.v1", promotion)
	addAction := func(kind string, fields map[string]commerce.SemanticValue) {
		wire, err := commerce.ExportSemanticFields(kind, fields)
		must(err)
		id, preimage, err := commerce.DeriveStableActionID(kind, fields)
		must(err)
		doc.Actions = append(doc.Actions, actionVector{kind, wire, id, hex.EncodeToString(preimage)})
	}
	fields, err := commerce.OperationPublishSemanticFieldsV1("owner:test", body.ActorAgentID, carrier)
	must(err)
	addAction("operation.publish", fields)
	fields, err = commerce.OperationPrivateSendSemanticFieldsV1("owner:test", body.ActorAgentID, private)
	must(err)
	addAction("operation.private-send", fields)
	addAction("operation.journal.append", map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:test"), "agent_id": commerce.ID(body.ActorAgentID), "ordering_domain": commerce.Digest32(body.OrderingDomain), "epoch": commerce.U64(body.Epoch), "sequence": commerce.U64(body.Sequence), "event_content_id": commerce.Digest32(contentID)})
	raw, err := json.MarshalIndent(doc, "", "  ")
	must(err)
	must(os.WriteFile(os.Args[1], append(raw, '\n'), 0o644))
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("operation outcome fixture: %v", err))
	}
}
