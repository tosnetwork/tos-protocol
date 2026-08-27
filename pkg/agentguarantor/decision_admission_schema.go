package agentguarantor

type DecisionApplicationTokenV1 struct {
	SchemaVersion                 uint16         `json:"schema_version"`
	TokenID                       string         `json:"token_id"`
	CoverageAgreementBodyDigest   string         `json:"coverage_agreement_body_digest"`
	CoverageObligationID          string         `json:"coverage_obligation_id"`
	ClaimID                       string         `json:"claim_id"`
	AuthorizedClaimDecisionDigest string         `json:"authorized_claim_decision_digest"`
	DecisionSequence              uint64         `json:"decision_sequence"`
	DecisionRevision              uint64         `json:"decision_revision"`
	ReservedApprovedAmount        AtomicAmountV1 `json:"reserved_approved_amount"`
	TokenRevision                 uint64         `json:"token_revision"`
	State                         string         `json:"state"`
}

type ClaimRevisionEpochExpectationV1 struct {
	SchemaVersion               uint16 `json:"schema_version"`
	CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
	CoverageObligationID        string `json:"coverage_obligation_id"`
	ClaimID                     string `json:"claim_id"`
	RevisionEpoch               uint64 `json:"revision_epoch"`
	RevisionIngressLogID        string `json:"revision_ingress_log_id"`
	ExpectedEpochState          string `json:"expected_epoch_state"`
	ExpectedEpochStateRevision  uint64 `json:"expected_epoch_state_revision"`
	ExpectedClaimRevision       uint64 `json:"expected_claim_revision"`
}

type AuthorizedDecisionAdmissionVariantV1 struct {
	AuthorizedClaimDecisionDigest                string                          `json:"authorized_claim_decision_digest"`
	AuthorizedClaimAdmissionReceiptDigest        string                          `json:"authorized_claim_admission_receipt_digest"`
	ClaimRevisionEpochExpectation                ClaimRevisionEpochExpectationV1 `json:"claim_revision_epoch_expectation"`
	PredecessorDecisionAdmissionReceiptDigest    string                          `json:"predecessor_decision_admission_receipt_digest,omitempty"`
	PredecessorClaimStateTransitionReceiptDigest string                          `json:"predecessor_claim_state_transition_receipt_digest,omitempty"`
	ExpectedClaimStateRevision                   uint64                          `json:"expected_claim_state_revision"`
	ExpectedChallengeRoundsUsed                  uint64                          `json:"expected_challenge_rounds_used"`
	ExpectedNonterminalRoundsUsed                uint64                          `json:"expected_nonterminal_rounds_used"`
}

type DeterministicFallbackAdmissionVariantV1 struct {
	CoverageAgreementBodyDigest        string                                     `json:"coverage_agreement_body_digest"`
	CoverageObligationID               string                                     `json:"coverage_obligation_id"`
	ClaimID                            string                                     `json:"claim_id"`
	AuthorizedClaimAdmissionReceipt    AuthorizedClaimAdmissionReceiptV1          `json:"authorized_claim_admission_receipt"`
	ClaimRevisionEpochExpectation      ClaimRevisionEpochExpectationV1            `json:"claim_revision_epoch_expectation"`
	CurrentDecisionAdmissionReceipt    *AuthorizedClaimDecisionAdmissionReceiptV1 `json:"current_decision_admission_receipt,omitempty"`
	CurrentClaimStateTransitionReceipt *AuthorizedClaimStateTransitionReceiptV1   `json:"current_claim_state_transition_receipt,omitempty"`
	LateFilingCloseReceipt             *AuthorizedClaimFilingCloseReceiptV1       `json:"late_filing_close_receipt,omitempty"`
	FallbackProfileDigest              string                                     `json:"fallback_profile_digest"`
	SourceClaimRevision                uint64                                     `json:"source_claim_revision"`
	SourceClaimStateRevision           uint64                                     `json:"source_claim_state_revision"`
	SourceClaimState                   string                                     `json:"source_claim_state"`
	ExpectedChallengeRoundsUsed        uint64                                     `json:"expected_challenge_rounds_used"`
	ExpectedNonterminalRoundsUsed      uint64                                     `json:"expected_nonterminal_rounds_used"`
	TriggerCutoffUnix                  uint64                                     `json:"trigger_cutoff_unix"`
	DecisionSequence                   uint64                                     `json:"decision_sequence"`
}

type ClaimDecisionSourceHeadV1 struct {
	SchemaVersion                            uint16 `json:"schema_version"`
	AuthorizedClaimAdmissionReceiptDigest    string `json:"authorized_claim_admission_receipt_digest"`
	CurrentDecisionAdmissionReceiptDigest    string `json:"current_decision_admission_receipt_digest,omitempty"`
	CurrentClaimStateTransitionReceiptDigest string `json:"current_claim_state_transition_receipt_digest,omitempty"`
	LateFilingCloseReceiptDigest             string `json:"late_filing_close_receipt_digest,omitempty"`
	ClaimRevisionEpochExpectationDigest      string `json:"claim_revision_epoch_expectation_digest"`
}

type AuthorizedDecisionAdmissionIdentityV1 struct {
	SchemaVersion           uint16 `json:"schema_version"`
	ClaimDecisionBodyDigest string `json:"claim_decision_body_digest"`
	DecisionRevision        uint64 `json:"decision_revision"`
	DerivedTargetState      string `json:"derived_target_state"`
}

type DeterministicFallbackAdmissionIdentityV1 struct {
	SchemaVersion                       uint16 `json:"schema_version"`
	FallbackProfileDigest               string `json:"fallback_profile_digest"`
	TriggerCutoffUnix                   uint64 `json:"trigger_cutoff_unix"`
	ClaimRevisionEpochExpectationDigest string `json:"claim_revision_epoch_expectation_digest"`
}

type ClaimDecisionAdmissionActionBodyV1 struct {
	SchemaVersion                uint16                                   `json:"schema_version"`
	AdmissionMode                string                                   `json:"admission_mode"`
	AuthorizedDecisionVariant    *AuthorizedDecisionAdmissionVariantV1    `json:"authorized_decision_variant,omitempty"`
	DeterministicFallbackVariant *DeterministicFallbackAdmissionVariantV1 `json:"deterministic_fallback_variant,omitempty"`
}

type ClaimDecisionAdmissionReceiptBodyV1 struct {
	SchemaVersion                                uint16                      `json:"schema_version"`
	AuthorityID                                  string                      `json:"authority_id"`
	CoverageAgreementBodyDigest                  string                      `json:"coverage_agreement_body_digest"`
	CoverageObligationID                         string                      `json:"coverage_obligation_id"`
	ClaimID                                      string                      `json:"claim_id"`
	AuthorizedClaimDecisionDigest                string                      `json:"authorized_claim_decision_digest"`
	AdmissionMode                                string                      `json:"admission_mode"`
	FallbackTriggerCutoffUnix                    uint64                      `json:"fallback_trigger_cutoff_unix,omitempty"`
	AuthorizedClaimAdmissionReceiptDigest        string                      `json:"authorized_claim_admission_receipt_digest"`
	ClaimRevisionIngressCutProofDigest           string                      `json:"claim_revision_ingress_cut_proof_digest"`
	LateFilingCloseReceiptDigest                 string                      `json:"late_filing_close_receipt_digest,omitempty"`
	FrozenRevisionEpoch                          uint64                      `json:"frozen_revision_epoch"`
	PriorRevisionEpochStateRevision              uint64                      `json:"prior_revision_epoch_state_revision"`
	FrozenRevisionEpochStateRevision             uint64                      `json:"frozen_revision_epoch_state_revision"`
	FrozenClaimRevisionIngressHighWater          uint64                      `json:"frozen_claim_revision_ingress_high_water"`
	FrozenClaimRevisionIngressLogRoot            string                      `json:"frozen_claim_revision_ingress_log_root"`
	PredecessorDecisionAdmissionReceiptDigest    string                      `json:"predecessor_decision_admission_receipt_digest,omitempty"`
	PredecessorClaimStateTransitionReceiptDigest string                      `json:"predecessor_claim_state_transition_receipt_digest,omitempty"`
	DecisionSequence                             uint64                      `json:"decision_sequence"`
	DecisionRevision                             uint64                      `json:"decision_revision"`
	DecisionPath                                 string                      `json:"decision_path"`
	PriorCoverageRevision                        uint64                      `json:"prior_coverage_revision"`
	AdmittedCoverageRevision                     uint64                      `json:"admitted_coverage_revision"`
	PriorCoverageEndCommitmentDigest             string                      `json:"prior_coverage_end_commitment_digest"`
	ResultingCoverageEndCommitmentDigest         string                      `json:"resulting_coverage_end_commitment_digest"`
	PriorClaimState                              string                      `json:"prior_claim_state"`
	AdmittedClaimState                           string                      `json:"admitted_claim_state"`
	PriorClaimStateRevision                      uint64                      `json:"prior_claim_state_revision"`
	AdmittedClaimStateRevision                   uint64                      `json:"admitted_claim_state_revision"`
	ChallengeRoundsUsedBefore                    uint64                      `json:"challenge_rounds_used_before"`
	ChallengeRoundsUsedAfter                     uint64                      `json:"challenge_rounds_used_after"`
	NonterminalRoundsUsedBefore                  uint64                      `json:"nonterminal_rounds_used_before"`
	NonterminalRoundsUsedAfter                   uint64                      `json:"nonterminal_rounds_used_after"`
	ChallengeStartsAtUnix                        uint64                      `json:"challenge_starts_at_unix,omitempty"`
	ChallengeEndsAtUnix                          uint64                      `json:"challenge_ends_at_unix,omitempty"`
	ResolutionStartsAtUnix                       uint64                      `json:"resolution_starts_at_unix,omitempty"`
	ResolutionDueAtUnix                          uint64                      `json:"resolution_due_at_unix,omitempty"`
	PriorApplicationTokenDigest                  string                      `json:"prior_application_token_digest,omitempty"`
	PriorApplicationTokenTerminalState           string                      `json:"prior_application_token_terminal_state,omitempty"`
	ResultingApplicationToken                    *DecisionApplicationTokenV1 `json:"resulting_application_token,omitempty"`
	AggregatePendingDecisionReserveBefore        AtomicAmountV1              `json:"aggregate_pending_decision_reserve_before"`
	AggregatePendingDecisionReserveAfter         AtomicAmountV1              `json:"aggregate_pending_decision_reserve_after"`
	AuthorizedActionDigest                       string                      `json:"authorized_action_digest"`
	StableActionID                               string                      `json:"stable_action_id"`
	ExactRequestDigest                           string                      `json:"exact_request_digest"`
	WriterGeneration                             uint64                      `json:"writer_generation"`
	WriterFenceDigest                            string                      `json:"writer_fence_digest"`
	AdmittedAtUnix                               uint64                      `json:"admitted_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest  string                      `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedClaimDecisionAdmissionReceiptV1 struct {
	Body                                   ClaimDecisionAdmissionReceiptBodyV1      `json:"body"`
	StageActionAdmissionEvidence           PortableStageActionAdmissionEvidenceV1   `json:"stage_action_admission_evidence"`
	AuthorizedClaimDecision                AuthorizedClaimDecisionV1                `json:"authorized_claim_decision"`
	AuthorizedClaimAdmissionReceipt        AuthorizedClaimAdmissionReceiptV1        `json:"authorized_claim_admission_receipt"`
	ClaimRevisionIngressCutProof           ClaimIngressAdmissionCutProofV1          `json:"claim_revision_ingress_cut_proof"`
	LateFilingCloseReceipt                 *AuthorizedClaimFilingCloseReceiptV1     `json:"late_filing_close_receipt,omitempty"`
	CoverageEndCommitment                  CoverageEndCommitmentV1                  `json:"coverage_end_commitment"`
	PriorPendingApplicationToken           *DecisionApplicationTokenV1              `json:"prior_pending_application_token,omitempty"`
	PredecessorClaimStateTransitionReceipt *AuthorizedClaimStateTransitionReceiptV1 `json:"predecessor_claim_state_transition_receipt,omitempty"`
	AuthorityAdmissionEligibilityProofSet  AuthorityAdmissionEligibilityProofSetV1  `json:"authority_admission_eligibility_proof_set"`
	Authorizations                         []ProfileQualifiedObjectAuthorizationV1  `json:"authorizations"`
}
