package agentguarantor

import "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"

type ClaimSubmissionIngressActionBodyV1 struct {
	SchemaVersion      uint16                    `json:"schema_version"`
	AuthorizedClaim    AuthorizedCoverageClaimV1 `json:"authorized_claim"`
	TargetIngressState string                    `json:"target_ingress_state"`
}

type ClaimSubmissionIngressReceiptBodyV1 struct {
	SchemaVersion                               uint16 `json:"schema_version"`
	AuthorityID                                 string `json:"authority_id"`
	CoverageAgreementBodyDigest                 string `json:"coverage_agreement_body_digest"`
	CoverageObligationID                        string `json:"coverage_obligation_id"`
	ClaimID                                     string `json:"claim_id"`
	ClaimRevision                               uint64 `json:"claim_revision"`
	IngressKind                                 string `json:"ingress_kind"`
	ClaimBodyDigest                             string `json:"claim_body_digest"`
	AuthorizedClaimEnvelopeDigest               string `json:"authorized_claim_envelope_digest"`
	IngressStateDomainDigest                    string `json:"ingress_state_domain_digest"`
	ClaimIngressLogID                           string `json:"claim_ingress_log_id"`
	ClaimIngressSequence                        uint64 `json:"claim_ingress_sequence"`
	PriorClaimIngressLogRoot                    string `json:"prior_claim_ingress_log_root"`
	AdmittedClaimIngressLogRoot                 string `json:"admitted_claim_ingress_log_root"`
	IngressSlotRevision                         uint64 `json:"ingress_slot_revision"`
	State                                       string `json:"state"`
	AuthorizedActionDigest                      string `json:"authorized_action_digest"`
	StableActionID                              string `json:"stable_action_id"`
	ExactRequestDigest                          string `json:"exact_request_digest"`
	WriterGeneration                            uint64 `json:"writer_generation"`
	WriterFenceDigest                           string `json:"writer_fence_digest"`
	ReceivedAtUnix                              uint64 `json:"received_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedClaimSubmissionIngressReceiptV1 struct {
	Body                                  ClaimSubmissionIngressReceiptBodyV1     `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	AuthorizedClaim                       AuthorizedCoverageClaimV1               `json:"authorized_claim"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1 `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type ClaimIngressResolutionEntryV1 struct {
	ClaimIngressSequence           uint64                          `json:"claim_ingress_sequence"`
	ReceivedAtUnix                 uint64                          `json:"received_at_unix"`
	IngressActionResolution        agentcommerce.ActionResolution  `json:"ingress_action_resolution"`
	ClaimIngressReceiptDigest      string                          `json:"claim_ingress_receipt_digest,omitempty"`
	ResolutionKind                 string                          `json:"resolution_kind"`
	ClaimAdmissionActionResolution *agentcommerce.ActionResolution `json:"claim_admission_action_resolution,omitempty"`
	ClaimAdmissionReceiptDigest    string                          `json:"claim_admission_receipt_digest,omitempty"`
}

type ClaimIngressAdmissionCutProofV1 struct {
	SchemaVersion               uint16                          `json:"schema_version"`
	CoverageAgreementBodyDigest string                          `json:"coverage_agreement_body_digest"`
	CoverageObligationID        string                          `json:"coverage_obligation_id"`
	CutKind                     string                          `json:"cut_kind"`
	ClaimID                     string                          `json:"claim_id,omitempty"`
	RevisionEpoch               uint64                          `json:"revision_epoch,omitempty"`
	PriorEpochStateRevision     uint64                          `json:"prior_epoch_state_revision,omitempty"`
	FrozenEpochStateRevision    uint64                          `json:"frozen_epoch_state_revision,omitempty"`
	ClaimIngressLogID           string                          `json:"claim_ingress_log_id"`
	IngressCutoffUnix           uint64                          `json:"ingress_cutoff_unix"`
	AdmissionHighWater          uint64                          `json:"admission_high_water"`
	AdmissionLogRoot            string                          `json:"admission_log_root"`
	Entries                     []ClaimIngressResolutionEntryV1 `json:"entries"`
	AdmittedClaimCount          uint64                          `json:"admitted_claim_count"`
	RejectedIngressOrClaimCount uint64                          `json:"rejected_ingress_or_claim_count"`
	PendingOrAmbiguousCount     uint64                          `json:"pending_or_ambiguous_count"`
}

type ClaimSubmissionAuthorityInstanceEffectV1 struct {
	SchemaVersion                         uint16                                    `json:"schema_version"`
	AuthorizedClaimIngressReceipt         AuthorizedClaimSubmissionIngressReceiptV1 `json:"authorized_claim_ingress_receipt"`
	AuthorizedCoverageActivationEvidence  AuthorizedCoverageActivationEvidenceV1    `json:"authorized_coverage_activation_evidence"`
	AuthorizedCoverageCancellationReceipt *AuthorizedCoverageCancellationReceiptV1  `json:"authorized_coverage_cancellation_receipt,omitempty"`
	ExpectedCoverageEndCommitment         CoverageEndCommitmentV1                   `json:"expected_coverage_end_commitment"`
	ExpectedCoverageRevision              uint64                                    `json:"expected_coverage_revision"`
}

type ClaimSubmissionActionBodyV1 struct {
	SchemaVersion           uint16                                   `json:"schema_version"`
	AuthorityInstanceID     string                                   `json:"authority_instance_id"`
	AuthorityInstanceRecord agentcommerce.AuthorityInstanceRecord    `json:"authority_instance_record"`
	AuthorityInstanceEffect ClaimSubmissionAuthorityInstanceEffectV1 `json:"authority_instance_effect"`
}

type ClaimAdmissionReceiptBodyV1 struct {
	SchemaVersion                               uint16 `json:"schema_version"`
	AuthorityID                                 string `json:"authority_id"`
	CoverageAgreementBodyDigest                 string `json:"coverage_agreement_body_digest"`
	CoverageObligationID                        string `json:"coverage_obligation_id"`
	ClaimID                                     string `json:"claim_id"`
	AuthorizedClaimEnvelopeDigest               string `json:"authorized_claim_envelope_digest"`
	ClaimSubmissionIngressReceiptDigest         string `json:"claim_submission_ingress_receipt_digest"`
	AuthorityInstanceID                         string `json:"authority_instance_id"`
	AuthorityInstanceAllocationRequestDigest    string `json:"authority_instance_allocation_request_digest"`
	AuthorizedActionDigest                      string `json:"authorized_action_digest"`
	StableActionID                              string `json:"stable_action_id"`
	ExactRequestDigest                          string `json:"exact_request_digest"`
	PriorCoverageRevision                       uint64 `json:"prior_coverage_revision"`
	AdmittedCoverageRevision                    uint64 `json:"admitted_coverage_revision"`
	PriorCoverageEndCommitmentDigest            string `json:"prior_coverage_end_commitment_digest"`
	ResultingCoverageEndCommitmentDigest        string `json:"resulting_coverage_end_commitment_digest"`
	PriorClaimRevision                          uint64 `json:"prior_claim_revision"`
	AdmittedClaimRevision                       uint64 `json:"admitted_claim_revision"`
	AdmissionKind                               string `json:"admission_kind"`
	ClaimAdmissionLogID                         string `json:"claim_admission_log_id"`
	ClaimAdmissionSequence                      uint64 `json:"claim_admission_sequence"`
	InitialClaimAdmissionReceiptDigest          string `json:"initial_claim_admission_receipt_digest,omitempty"`
	ClaimRevisionLogID                          string `json:"claim_revision_log_id"`
	ClaimRevisionAdmissionSequence              uint64 `json:"claim_revision_admission_sequence"`
	PredecessorRevisionAdmissionReceiptDigest   string `json:"predecessor_revision_admission_receipt_digest,omitempty"`
	PriorClaimAdmissionLogRoot                  string `json:"prior_claim_admission_log_root"`
	AdmittedClaimAdmissionLogRoot               string `json:"admitted_claim_admission_log_root"`
	PriorClaimRevisionLogRoot                   string `json:"prior_claim_revision_log_root"`
	AdmittedClaimRevisionLogRoot                string `json:"admitted_claim_revision_log_root"`
	WriterGeneration                            uint64 `json:"writer_generation"`
	WriterFenceDigest                           string `json:"writer_fence_digest"`
	AdmittedAtUnix                              uint64 `json:"admitted_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string `json:"authority_admission_eligibility_proof_set_digest"`
}

type ClaimRevisionAdmissionLeafV1 struct {
	ClaimID                                   string `json:"claim_id"`
	ClaimRevisionAdmissionSequence            uint64 `json:"claim_revision_admission_sequence"`
	AuthorizedClaimEnvelopeDigest             string `json:"authorized_claim_envelope_digest"`
	PredecessorRevisionAdmissionReceiptDigest string `json:"predecessor_revision_admission_receipt_digest,omitempty"`
}

type AuthorizedClaimAdmissionReceiptV1 struct {
	Body                                  ClaimAdmissionReceiptBodyV1               `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1    `json:"stage_action_admission_evidence"`
	AuthorizedClaimIngressReceipt         AuthorizedClaimSubmissionIngressReceiptV1 `json:"authorized_claim_ingress_receipt"`
	CoverageEndCommitment                 CoverageEndCommitmentV1                   `json:"coverage_end_commitment"`
	AuthorityInstanceRecord               agentcommerce.AuthorityInstanceRecord     `json:"authority_instance_record"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1   `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1   `json:"authorizations"`
}
