package agentguarantor

import (
	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type CollateralTermsV1 struct {
	PositionID                            string                          `json:"position_id"`
	SelectedCollateralProfileDigest       string                          `json:"selected_collateral_profile_digest"`
	AssuranceLevel                        AssuranceLevel                  `json:"assurance_level"`
	Asset                                 AssetIdentityV1                 `json:"asset"`
	Amount                                AtomicAmountV1                  `json:"amount"`
	CollateralPrincipalSubject            string                          `json:"collateral_principal_subject"`
	CustodyAdapterProfile                 ProfileRefV1                    `json:"custody_adapter_profile"`
	CollateralControlDisclosure           CollateralControlDisclosureV1   `json:"collateral_control_disclosure"`
	PositionIdentityProfile               ProfileRefV1                    `json:"position_identity_profile"`
	TransitionBindings                    []CollateralTransitionBindingV1 `json:"transition_bindings"`
	IndependentExecutionProfile           *ProfileRefV1                   `json:"independent_execution_profile,omitempty"`
	IndependentExecutionAuthoritySubjects []string                        `json:"independent_execution_authority_subjects"`
	IndependentExecutionQuorumRule        string                          `json:"independent_execution_quorum_rule,omitempty"`
	NetworkDomainDigest                   string                          `json:"network_domain_digest,omitempty"`
	ContractOrAccountDigest               string                          `json:"contract_or_account_digest"`
	AdapterCodeDigest                     string                          `json:"adapter_code_digest,omitempty"`
	ExclusiveAllocationRequired           bool                            `json:"exclusive_allocation_required"`
	LockByUnix                            uint64                          `json:"lock_by_unix"`
	LockUntilUnix                         uint64                          `json:"lock_until_unix"`
	ReleaseNotBeforeUnix                  uint64                          `json:"release_not_before_unix"`
	FinalityProfile                       ProfileRefV1                    `json:"finality_profile"`
	MaximumEvidenceAgeSeconds             uint64                          `json:"maximum_evidence_age_seconds"`
	ReorgWindowSeconds                    uint64                          `json:"reorg_window_seconds"`
}

type CollateralAdapterRequestV1 struct {
	SchemaVersion                         uint16                    `json:"schema_version"`
	AdapterProfile                        ProfileRefV1              `json:"adapter_profile"`
	AdapterRequestProfile                 ProfileRefV1              `json:"adapter_request_profile"`
	CoverageAgreementBodyDigest           string                    `json:"coverage_agreement_body_digest"`
	CollateralObligationID                string                    `json:"collateral_obligation_id"`
	CollateralPositionID                  string                    `json:"collateral_position_id"`
	TransitionBindingDigest               string                    `json:"transition_binding_digest"`
	TransitionKind                        string                    `json:"transition_kind"`
	ExpectedPositionState                 CollateralPositionStateV1 `json:"expected_position_state"`
	ExpectedStateDigest                   string                    `json:"expected_state_digest"`
	Asset                                 AssetIdentityV1           `json:"asset"`
	Amount                                AtomicAmountV1            `json:"amount"`
	PayoutDestinationDigest               string                    `json:"payout_destination_digest,omitempty"`
	AgreementPaymentRequestDigest         string                    `json:"agreement_payment_request_digest,omitempty"`
	ObligationInstanceID                  string                    `json:"obligation_instance_id,omitempty"`
	AuthorizedClaimDecisionEnvelopeDigest string                    `json:"authorized_claim_decision_envelope_digest,omitempty"`
	PrerequisiteEvidenceSetDigest         string                    `json:"prerequisite_evidence_set_digest"`
	AdapterOperationParameters            []byte                    `json:"adapter_operation_parameters"`
}

type CollateralEvidenceBodyV1 struct {
	SchemaVersion                               uint16         `json:"schema_version"`
	CoverageAgreementBodyDigest                 string         `json:"coverage_agreement_body_digest"`
	CollateralObligationID                      string         `json:"collateral_obligation_id"`
	PositionID                                  string         `json:"position_id"`
	PositionDigest                              string         `json:"position_digest"`
	TransitionBindingDigest                     string         `json:"transition_binding_digest"`
	CollateralTransitionActionBodyDigest        string         `json:"collateral_transition_action_body_digest"`
	AdapterProfile                              ProfileRefV1   `json:"adapter_profile"`
	EvidenceProfile                             ProfileRefV1   `json:"evidence_profile"`
	EvidenceContentType                         string         `json:"evidence_content_type"`
	TransitionKind                              string         `json:"transition_kind"`
	Amount                                      AtomicAmountV1 `json:"amount"`
	CumulativeConsumed                          AtomicAmountV1 `json:"cumulative_consumed"`
	PriorStateRevision                          uint64         `json:"prior_state_revision"`
	ResultingStateRevision                      uint64         `json:"resulting_state_revision"`
	ExpectedStateDigest                         string         `json:"expected_state_digest"`
	ResultingStateDigest                        string         `json:"resulting_state_digest"`
	CoverageBindingDigest                       string         `json:"coverage_binding_digest"`
	AuthorizedClaimDecisionEnvelopeDigest       string         `json:"authorized_claim_decision_envelope_digest,omitempty"`
	AgreementPaymentRequestDigest               string         `json:"agreement_payment_request_digest,omitempty"`
	ObligationInstanceID                        string         `json:"obligation_instance_id,omitempty"`
	FinalityReference                           string         `json:"finality_reference"`
	FinalizedAtUnix                             uint64         `json:"finalized_at_unix"`
	AdapterRequestDigest                        string         `json:"adapter_request_digest"`
	AdapterEvidenceDigest                       string         `json:"adapter_evidence_digest"`
	AuthorizedActionDigest                      string         `json:"authorized_action_digest"`
	StableActionID                              string         `json:"stable_action_id"`
	ExactRequestDigest                          string         `json:"exact_request_digest"`
	WriterGeneration                            uint64         `json:"writer_generation"`
	WriterFenceDigest                           string         `json:"writer_fence_digest"`
	AuthorityAdmissionEligibilityProofSetDigest string         `json:"authority_admission_eligibility_proof_set_digest"`
}

type CollateralAdapterEvidenceV1 struct {
	ContentType             string                         `json:"content_type"`
	EvidenceProfile         ProfileRefV1                   `json:"evidence_profile"`
	TransitionBindingDigest string                         `json:"transition_binding_digest"`
	AdapterProfileDigest    string                         `json:"adapter_profile_digest"`
	TransitionKind          string                         `json:"transition_kind"`
	AdapterRequestDigest    string                         `json:"adapter_request_digest"`
	PriorStateRevision      uint64                         `json:"prior_state_revision"`
	ResultingStateRevision  uint64                         `json:"resulting_state_revision"`
	ExpectedStateDigest     string                         `json:"expected_state_digest"`
	ResultingStateDigest    string                         `json:"resulting_state_digest"`
	Representation          string                         `json:"representation"`
	CanonicalEvidenceBytes  []byte                         `json:"canonical_evidence_bytes,omitempty"`
	ImmutableDescriptor     *ImmutableEvidenceDescriptorV1 `json:"immutable_descriptor,omitempty"`
}

type AuthorizedCollateralEvidenceV1 struct {
	Body                                  CollateralEvidenceBodyV1                `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	CollateralTransitionActionBody        CollateralTransitionActionBodyV1        `json:"collateral_transition_action_body"`
	AdapterEvidence                       CollateralAdapterEvidenceV1             `json:"adapter_evidence"`
	ResultingPositionState                CollateralPositionStateV1               `json:"resulting_position_state"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1 `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type CollateralPayoutPaymentEvidenceProjectionV1 struct {
	SchemaVersion                        uint16          `json:"schema_version"`
	CoverageAgreementBodyDigest          string          `json:"coverage_agreement_body_digest"`
	PayoutTemplateObligationID           string          `json:"payout_template_obligation_id"`
	ObligationInstanceID                 string          `json:"obligation_instance_id"`
	AgreementPaymentRequestDigest        string          `json:"agreement_payment_request_digest"`
	CollateralObligationID               string          `json:"collateral_obligation_id"`
	CollateralPositionID                 string          `json:"collateral_position_id"`
	CollateralTransitionActionBodyDigest string          `json:"collateral_transition_action_body_digest"`
	AuthorizedCollateralEvidenceDigest   string          `json:"authorized_collateral_evidence_digest"`
	Asset                                AssetIdentityV1 `json:"asset"`
	Amount                               AtomicAmountV1  `json:"amount"`
	PayoutDestinationDigest              string          `json:"payout_destination_digest"`
	ExactTransferReference               string          `json:"exact_transfer_reference"`
	FinalityReference                    string          `json:"finality_reference"`
	StableActionID                       string          `json:"stable_action_id"`
	ExactRequestDigest                   string          `json:"exact_request_digest"`
}

type ProfileQualifiedSettlementParametersV1 = agentcommerce.ProfileQualifiedSettlementParametersV1
type ConditionalSettlementTemplateV1 = agentcommerce.ConditionalSettlementTemplateV1
