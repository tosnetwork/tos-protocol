package agentguarantor

type ClaimDecisionApplicationActionBodyV1 struct {
	SchemaVersion                                       uint16                     `json:"schema_version"`
	AuthorizedClaimDecisionDigest                       string                     `json:"authorized_claim_decision_digest"`
	AuthorizedClaimAdmissionReceiptDigest               string                     `json:"authorized_claim_admission_receipt_digest"`
	AuthorizedClaimDecisionAdmissionReceiptDigest       string                     `json:"authorized_claim_decision_admission_receipt_digest"`
	AuthorizedTerminalClaimStateTransitionReceiptDigest string                     `json:"authorized_terminal_claim_state_transition_receipt_digest"`
	DecisionApplicationToken                            DecisionApplicationTokenV1 `json:"decision_application_token"`
	ExpectedCoverageEndCommitmentDigest                 string                     `json:"expected_coverage_end_commitment_digest"`
	PayoutTemplateDigest                                string                     `json:"payout_template_digest"`
	ExpectedCurrentCoverageRevision                     uint64                     `json:"expected_current_coverage_revision"`
	TargetCoverageRevision                              uint64                     `json:"target_coverage_revision"`
	ExpectedAggregatePendingDecisionReserve             AtomicAmountV1             `json:"expected_aggregate_pending_decision_reserve"`
	TargetAggregatePendingDecisionReserve               AtomicAmountV1             `json:"target_aggregate_pending_decision_reserve"`
	ExpectedApplicationTokenRevision                    uint64                     `json:"expected_application_token_revision"`
	ExpectedClaimStateRevision                          uint64                     `json:"expected_claim_state_revision"`
	TargetClaimState                                    string                     `json:"target_claim_state"`
	ExpectedNextPayoutSequence                          uint64                     `json:"expected_next_payout_sequence"`
	ExpectedMaterializedPayoutLineDigest                string                     `json:"expected_materialized_payout_line_digest,omitempty"`
}

type ClaimDecisionApplicationReceiptBodyV1 struct {
	SchemaVersion                             uint16         `json:"schema_version"`
	AuthorityID                               string         `json:"authority_id"`
	CoverageAgreementBodyDigest               string         `json:"coverage_agreement_body_digest"`
	CoverageObligationID                      string         `json:"coverage_obligation_id"`
	ClaimID                                   string         `json:"claim_id"`
	AuthorizedClaimDecisionDigest             string         `json:"authorized_claim_decision_digest"`
	ClaimDecisionAdmissionReceiptDigest       string         `json:"claim_decision_admission_receipt_digest"`
	TerminalClaimStateTransitionReceiptDigest string         `json:"terminal_claim_state_transition_receipt_digest"`
	DecisionApplicationTokenID                string         `json:"decision_application_token_id"`
	DecisionApplicationTokenDigest            string         `json:"decision_application_token_digest"`
	PriorApplicationTokenRevision             uint64         `json:"prior_application_token_revision"`
	ResultingApplicationTokenRevision         uint64         `json:"resulting_application_token_revision"`
	ResultingApplicationTokenState            string         `json:"resulting_application_token_state"`
	MaterializedPayoutObligationSetDigest     string         `json:"materialized_payout_obligation_set_digest"`
	AuthorizedActionDigest                    string         `json:"authorized_action_digest"`
	StableActionID                            string         `json:"stable_action_id"`
	ExactRequestDigest                        string         `json:"exact_request_digest"`
	WriterGeneration                          uint64         `json:"writer_generation"`
	WriterFenceDigest                         string         `json:"writer_fence_digest"`
	PriorCoverageRevision                     uint64         `json:"prior_coverage_revision"`
	AppliedCoverageRevision                   uint64         `json:"applied_coverage_revision"`
	PriorCoverageEndCommitmentDigest          string         `json:"prior_coverage_end_commitment_digest"`
	ResultingCoverageEndCommitmentDigest      string         `json:"resulting_coverage_end_commitment_digest"`
	PriorClaimStateRevision                   uint64         `json:"prior_claim_state_revision"`
	AppliedClaimStateRevision                 uint64         `json:"applied_claim_state_revision"`
	PriorNextPayoutSequence                   uint64         `json:"prior_next_payout_sequence"`
	ResultingNextPayoutSequence               uint64         `json:"resulting_next_payout_sequence"`
	PriorMaterializedPayoutLineDigest         string         `json:"prior_materialized_payout_line_digest,omitempty"`
	ResultingMaterializedPayoutLineDigest     string         `json:"resulting_materialized_payout_line_digest,omitempty"`
	CumulativeApprovedBefore                  AtomicAmountV1 `json:"cumulative_approved_before"`
	CumulativeApprovedAfter                   AtomicAmountV1 `json:"cumulative_approved_after"`
	AggregatePendingDecisionReserveBefore     AtomicAmountV1 `json:"aggregate_pending_decision_reserve_before"`
	AggregatePendingDecisionReserveAfter      AtomicAmountV1 `json:"aggregate_pending_decision_reserve_after"`
	AppliedAtUnix                             uint64         `json:"applied_at_unix"`
}

type AuthorizedClaimDecisionApplicationReceiptV1 struct {
	Body                                          ClaimDecisionApplicationReceiptBodyV1   `json:"body"`
	StageActionAdmissionEvidence                  PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	CoverageEndCommitment                         CoverageEndCommitmentV1                 `json:"coverage_end_commitment"`
	AuthorizedTerminalClaimStateTransitionReceipt AuthorizedClaimStateTransitionReceiptV1 `json:"authorized_terminal_claim_state_transition_receipt"`
	DecisionApplicationToken                      DecisionApplicationTokenV1              `json:"decision_application_token"`
	MaterializedPayoutObligationSet               MaterializedPayoutObligationSetV1       `json:"materialized_payout_obligation_set"`
	Authorizations                                []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type ClaimStateTransitionActionBodyV1 struct {
	SchemaVersion                                 uint16                          `json:"schema_version"`
	CoverageAgreementBodyDigest                   string                          `json:"coverage_agreement_body_digest"`
	CoverageObligationID                          string                          `json:"coverage_obligation_id"`
	ClaimID                                       string                          `json:"claim_id"`
	TransitionKind                                string                          `json:"transition_kind"`
	ExpectedClaimStateRevision                    uint64                          `json:"expected_claim_state_revision"`
	TargetState                                   string                          `json:"target_state"`
	ExpectedChallengeRoundsUsed                   uint64                          `json:"expected_challenge_rounds_used"`
	TargetChallengeRoundsUsed                     uint64                          `json:"target_challenge_rounds_used"`
	ExpectedNonterminalRoundsUsed                 uint64                          `json:"expected_nonterminal_rounds_used"`
	TargetNonterminalRoundsUsed                   uint64                          `json:"target_nonterminal_rounds_used"`
	SuccessorDecisionDueAtUnix                    uint64                          `json:"successor_decision_due_at_unix,omitempty"`
	AuthorizedClaimDecisionAdmissionReceiptDigest string                          `json:"authorized_claim_decision_admission_receipt_digest"`
	TransitionEvidenceProjection                  TransitionEvidenceProjectionV1  `json:"transition_evidence_projection"`
	TransitionEvidenceSet                         CanonicalGuarantorEvidenceSetV1 `json:"transition_evidence_set"`
}

type ClaimStateTransitionReceiptBodyV1 struct {
	SchemaVersion                               uint16 `json:"schema_version"`
	AuthorityID                                 string `json:"authority_id"`
	CoverageAgreementBodyDigest                 string `json:"coverage_agreement_body_digest"`
	CoverageObligationID                        string `json:"coverage_obligation_id"`
	ClaimID                                     string `json:"claim_id"`
	TransitionKind                              string `json:"transition_kind"`
	TransitionEvidenceProjectionDigest          string `json:"transition_evidence_projection_digest"`
	AuthorizedActionDigest                      string `json:"authorized_action_digest"`
	StableActionID                              string `json:"stable_action_id"`
	ExactRequestDigest                          string `json:"exact_request_digest"`
	WriterGeneration                            uint64 `json:"writer_generation"`
	WriterFenceDigest                           string `json:"writer_fence_digest"`
	PriorClaimState                             string `json:"prior_claim_state"`
	ResultingClaimState                         string `json:"resulting_claim_state"`
	PriorClaimStateRevision                     uint64 `json:"prior_claim_state_revision"`
	ResultingClaimStateRevision                 uint64 `json:"resulting_claim_state_revision"`
	ChallengeRoundsUsedBefore                   uint64 `json:"challenge_rounds_used_before"`
	ChallengeRoundsUsedAfter                    uint64 `json:"challenge_rounds_used_after"`
	NonterminalRoundsUsedBefore                 uint64 `json:"nonterminal_rounds_used_before"`
	NonterminalRoundsUsedAfter                  uint64 `json:"nonterminal_rounds_used_after"`
	SuccessorDecisionDueAtUnix                  uint64 `json:"successor_decision_due_at_unix,omitempty"`
	TransitionedAtUnix                          uint64 `json:"transitioned_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedClaimStateTransitionReceiptV1 struct {
	Body                                  ClaimStateTransitionReceiptBodyV1       `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	DecisionAdmissionProof                ClaimDecisionAdmissionReceiptProofV1    `json:"decision_admission_proof"`
	TransitionEvidenceProjection          TransitionEvidenceProjectionV1          `json:"transition_evidence_projection"`
	TransitionEvidenceSet                 CanonicalGuarantorEvidenceSetV1         `json:"transition_evidence_set"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1 `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type ClaimDecisionAdmissionReceiptSealBodyV1 struct {
	SchemaVersion                 uint16 `json:"schema_version"`
	ReceiptEnvelopeDigest         string `json:"receipt_envelope_digest"`
	ReceiptBodyDigest             string `json:"receipt_body_digest"`
	AuthorizedActionDigest        string `json:"authorized_action_digest"`
	AuthorizedClaimDecisionDigest string `json:"authorized_claim_decision_digest"`
	AuthorizedClaimEnvelopeDigest string `json:"authorized_claim_envelope_digest"`
	CoverageEndCommitmentDigest   string `json:"coverage_end_commitment_digest"`
	CoverageTermsDigest           string `json:"coverage_terms_digest"`
	SealedAtUnix                  uint64 `json:"sealed_at_unix"`
}

type ClaimDecisionAdmissionReceiptProofV1 struct {
	SchemaVersion           uint16                                  `json:"schema_version"`
	ReceiptEnvelopeDigest   string                                  `json:"receipt_envelope_digest"`
	ReceiptDescriptor       ImmutableEvidenceDescriptorV1           `json:"receipt_descriptor"`
	ReceiptBody             ClaimDecisionAdmissionReceiptBodyV1     `json:"receipt_body"`
	CoverageEndCommitment   CoverageEndCommitmentV1                 `json:"coverage_end_commitment"`
	AuthorizedClaimDecision AuthorizedClaimDecisionV1               `json:"authorized_claim_decision"`
	AuthorizedClaim         AuthorizedCoverageClaimV1               `json:"authorized_claim"`
	ReceiptAuthorizations   []ProfileQualifiedObjectAuthorizationV1 `json:"receipt_authorizations"`
	SealBody                ClaimDecisionAdmissionReceiptSealBodyV1 `json:"seal_body"`
	SealAuthorization       ProfileQualifiedObjectAuthorizationV1   `json:"seal_authorization"`
}
