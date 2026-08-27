package agentguarantor

import "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"

type CoverageAcceptanceAdmissionActionBodyV1 struct {
	SchemaVersion                    uint16                                `json:"schema_version"`
	AuthorizedAcceptanceRequest      AuthorizedCoverageAcceptanceRequestV1 `json:"authorized_acceptance_request"`
	TransitionEvidenceProjection     TransitionEvidenceProjectionV1        `json:"transition_evidence_projection"`
	ExpectedReservationRevision      uint64                                `json:"expected_reservation_revision"`
	ExpectedOfferStateRevision       uint64                                `json:"expected_offer_state_revision"`
	TargetOfferStateRevision         uint64                                `json:"target_offer_state_revision"`
	ExpectedCoverageRevision         uint64                                `json:"expected_coverage_revision"`
	TargetCoverageRevision           uint64                                `json:"target_coverage_revision"`
	ExpectedClaimFilingState         string                                `json:"expected_claim_filing_state"`
	TargetClaimFilingState           string                                `json:"target_claim_filing_state"`
	ExpectedClaimFilingStateRevision uint64                                `json:"expected_claim_filing_state_revision"`
	TargetClaimFilingStateRevision   uint64                                `json:"target_claim_filing_state_revision"`
}

type CoverageNonActivationActionBodyV1 struct {
	SchemaVersion                      uint16                                `json:"schema_version"`
	AuthorizedAcceptanceReceipt        AuthorizedCoverageAcceptanceReceiptV1 `json:"authorized_acceptance_receipt"`
	ActivationAdmissionCutProof        ActivationAdmissionCutProofV1         `json:"activation_admission_cut_proof"`
	NonActivationReasonEvidence        CoverageNonActivationReasonEvidenceV1 `json:"non_activation_reason_evidence"`
	FeeResolutionEvidenceSet           *CanonicalGuarantorEvidenceSetV1      `json:"fee_resolution_evidence_set,omitempty"`
	CollateralNonActivationEvidenceSet *CanonicalGuarantorEvidenceSetV1      `json:"collateral_non_activation_evidence_set,omitempty"`
	TransitionEvidenceProjection       TransitionEvidenceProjectionV1        `json:"transition_evidence_projection"`
	ExpectedCoverageRevision           uint64                                `json:"expected_coverage_revision"`
	TargetCoverageRevision             uint64                                `json:"target_coverage_revision"`
	TargetCoverageState                string                                `json:"target_coverage_state"`
	ExpectedClaimFilingState           string                                `json:"expected_claim_filing_state"`
	TargetClaimFilingState             string                                `json:"target_claim_filing_state"`
	ExpectedClaimFilingStateRevision   uint64                                `json:"expected_claim_filing_state_revision"`
	TargetClaimFilingStateRevision     uint64                                `json:"target_claim_filing_state_revision"`
}

type CoverageCancellationActionBodyV1 struct {
	SchemaVersion                 uint16                                  `json:"schema_version"`
	AuthorizedCancellationRequest AuthorizedCoverageCancellationRequestV1 `json:"authorized_cancellation_request"`
	ExpectedCoverageEndCommitment CoverageEndCommitmentV1                 `json:"expected_coverage_end_commitment"`
	TransitionEvidenceProjection  TransitionEvidenceProjectionV1          `json:"transition_evidence_projection"`
	ExpectedCoverageRevision      uint64                                  `json:"expected_coverage_revision"`
	TargetCoverageRevision        uint64                                  `json:"target_coverage_revision"`
	TargetCoverageState           string                                  `json:"target_coverage_state"`
}

type CollateralTransitionActionBodyV1 struct {
	SchemaVersion               uint16                          `json:"schema_version"`
	CoverageAgreementBodyDigest string                          `json:"coverage_agreement_body_digest"`
	ObligationID                string                          `json:"obligation_id"`
	CollateralPositionID        string                          `json:"collateral_position_id"`
	TransitionBinding           CollateralTransitionBindingV1   `json:"transition_binding"`
	TransitionKind              string                          `json:"transition_kind"`
	ExpectedStateRevision       uint64                          `json:"expected_state_revision"`
	ExpectedStateDigest         string                          `json:"expected_state_digest"`
	Asset                       AssetIdentityV1                 `json:"asset"`
	Amount                      AtomicAmountV1                  `json:"amount"`
	PayoutDestinationDigest     string                          `json:"payout_destination_digest,omitempty"`
	PrerequisiteEvidenceSet     CanonicalGuarantorEvidenceSetV1 `json:"prerequisite_evidence_set"`
	AdapterRequest              CollateralAdapterRequestV1      `json:"adapter_request"`
}

type GuarantorAgreementPaymentActionBodyV1 struct {
	SchemaVersion                   uint16                                `json:"schema_version"`
	PaymentRequest                  agentcommerce.AgreementPaymentRequest `json:"payment_request"`
	SettlementObligation            agentcommerce.SettlementObligation    `json:"settlement_obligation"`
	MaterializedPayoutObligationSet MaterializedPayoutObligationSetV1     `json:"materialized_payout_obligation_set"`
}

type CollateralBackedAgreementPaymentActionBodyV1 struct {
	SchemaVersion                   uint16                                `json:"schema_version"`
	AgreementPaymentRequest         agentcommerce.AgreementPaymentRequest `json:"agreement_payment_request"`
	SettlementObligation            agentcommerce.SettlementObligation    `json:"settlement_obligation"`
	MaterializedPayoutObligationSet MaterializedPayoutObligationSetV1     `json:"materialized_payout_obligation_set"`
	CollateralTransitionAction      CollateralTransitionActionBodyV1      `json:"collateral_transition_action"`
}
