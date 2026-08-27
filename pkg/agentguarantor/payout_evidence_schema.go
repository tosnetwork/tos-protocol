package agentguarantor

import (
	"bytes"
	"errors"
	"math/big"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	GuarantorPayoutExecutionEvidenceDomainV1 = "tos.service.agent-guarantor-payout-execution-evidence.v1"
	TerminalPayoutEvidenceSetDomainV1        = "tos.service.agent-guarantor-terminal-payout-evidence-set.v1"
)

// PayoutDefaultEvidenceVerifier is implemented by the Agreement-selected
// settlement Adapter (or its independently authenticated verifier).  A local
// timeout, ledger flag, or Guarantor signature is intentionally insufficient.
type PayoutDefaultEvidenceVerifier interface {
	VerifyGuarantorPayoutDefaultEvidence(agentcommerce.AgreementPaymentRequest,
		agentcommerce.AgreementPaymentEvidence, agentcommerce.SettlementObligation,
		CoverageTermsV1, time.Time) error
}

type TerminalPayoutEvidenceSetV1 struct {
	SchemaVersion                         uint16                                         `json:"schema_version"`
	CoverageAgreementBodyDigest           string                                         `json:"coverage_agreement_body_digest"`
	ClaimID                               string                                         `json:"claim_id"`
	AuthorizedClaimDecisionDigest         string                                         `json:"authorized_claim_decision_digest"`
	MaterializedPayoutObligationSetDigest string                                         `json:"materialized_payout_obligation_set_digest"`
	Disposition                           string                                         `json:"disposition"`
	ApprovedAmount                        AtomicAmountV1                                 `json:"approved_amount"`
	PaidAmount                            AtomicAmountV1                                 `json:"paid_amount"`
	DefaultedAmount                       AtomicAmountV1                                 `json:"defaulted_amount"`
	OutstandingAmount                     AtomicAmountV1                                 `json:"outstanding_amount"`
	PayoutExecutionEvidence               []AuthorizedGuarantorPayoutExecutionEvidenceV1 `json:"payout_execution_evidence"`
	TerminalSettlementEvidenceSet         CanonicalGuarantorEvidenceSetV1                `json:"terminal_settlement_evidence_set"`
}

type GuarantorNoPayoutMarkerV1 struct {
	SchemaVersion                         uint16 `json:"schema_version"`
	CoverageAgreementBodyDigest           string `json:"coverage_agreement_body_digest"`
	ClaimID                               string `json:"claim_id"`
	AuthorizedClaimDecisionDigest         string `json:"authorized_claim_decision_digest"`
	MaterializedPayoutObligationSetDigest string `json:"materialized_payout_obligation_set_digest"`
}

type AuthorizedGuarantorPayoutExecutionEvidenceV1 struct {
	SchemaVersion                uint16                                 `json:"schema_version"`
	ObligationInstanceID         string                                 `json:"obligation_instance_id"`
	StageActionAdmissionEvidence PortableStageActionAdmissionEvidenceV1 `json:"stage_action_admission_evidence"`
	AgreementPaymentEvidence     agentcommerce.AgreementPaymentEvidence `json:"agreement_payment_evidence"`
	CollateralEvidence           *AuthorizedCollateralEvidenceV1        `json:"collateral_evidence,omitempty"`
}

type CoverageTerminalPayoutEvidenceEntryV1 struct {
	ClaimAdmissionSequence          uint64 `json:"claim_admission_sequence"`
	TerminalPayoutEvidenceSetDigest string `json:"terminal_payout_evidence_set_digest"`
}

type CoverageTerminalPayoutEvidenceSetV1 struct {
	SchemaVersion                            uint16                                  `json:"schema_version"`
	CoverageAgreementBodyDigest              string                                  `json:"coverage_agreement_body_digest"`
	AuthorizedTerminalClaimSetEvidenceDigest string                                  `json:"authorized_terminal_claim_set_evidence_digest"`
	Entries                                  []CoverageTerminalPayoutEvidenceEntryV1 `json:"entries"`
}

func GuarantorPayoutExecutionEvidenceDigestV1(value AuthorizedGuarantorPayoutExecutionEvidenceV1) (string, error) {
	if value.SchemaVersion != 1 || !validDigest(value.ObligationInstanceID) {
		return "", errors.New("Guarantor payout execution evidence is invalid")
	}
	return codec.Digest(GuarantorPayoutExecutionEvidenceDomainV1, value)
}

func TerminalPayoutEvidenceSetDigestV1(value TerminalPayoutEvidenceSetV1) (string, error) {
	if value.SchemaVersion != 1 || !validDigest(value.CoverageAgreementBodyDigest) || !validDigest(value.ClaimID) ||
		!validDigest(value.AuthorizedClaimDecisionDigest) || !validDigest(value.MaterializedPayoutObligationSetDigest) ||
		(value.Disposition != "resolved" && value.Disposition != "defaulted" && value.Disposition != "not_applicable") {
		return "", errors.New("terminal payout evidence set is invalid")
	}
	approved, aOK := new(big.Int).SetString(value.ApprovedAmount.AmountAtomic, 10)
	paid, pOK := new(big.Int).SetString(value.PaidAmount.AmountAtomic, 10)
	defaulted, dOK := new(big.Int).SetString(value.DefaultedAmount.AmountAtomic, 10)
	outstanding, oOK := new(big.Int).SetString(value.OutstandingAmount.AmountAtomic, 10)
	if !aOK || !pOK || !dOK || !oOK || approved.Sign() < 0 || paid.Sign() < 0 || defaulted.Sign() < 0 || outstanding.Sign() != 0 ||
		value.ApprovedAmount.Asset != value.PaidAmount.Asset || value.ApprovedAmount.Asset != value.DefaultedAmount.Asset ||
		value.ApprovedAmount.Asset != value.OutstandingAmount.Asset ||
		new(big.Int).Add(new(big.Int).Set(paid), defaulted).Cmp(approved) != 0 ||
		(value.Disposition == "resolved" && defaulted.Sign() != 0) ||
		(value.Disposition == "defaulted" && defaulted.Sign() == 0) ||
		(value.Disposition == "not_applicable" && (approved.Sign() != 0 || len(value.PayoutExecutionEvidence) != 0)) ||
		ValidateCanonicalGuarantorEvidenceSetV1(value.TerminalSettlementEvidenceSet) != nil ||
		value.TerminalSettlementEvidenceSet.Purpose != "terminal-payout" ||
		value.TerminalSettlementEvidenceSet.ContextDigest != value.AuthorizedClaimDecisionDigest {
		return "", errors.New("terminal payout arithmetic or evidence set is invalid")
	}
	seen := make(map[string]struct{}, len(value.PayoutExecutionEvidence))
	for _, execution := range value.PayoutExecutionEvidence {
		if _, err := GuarantorPayoutExecutionEvidenceDigestV1(execution); err != nil {
			return "", errors.New("terminal payout execution is invalid")
		}
		if _, duplicate := seen[execution.ObligationInstanceID]; duplicate {
			return "", errors.New("terminal payout execution is duplicated")
		}
		seen[execution.ObligationInstanceID] = struct{}{}
	}
	return codec.Digest(TerminalPayoutEvidenceSetDomainV1, value)
}

func VerifyGuarantorPayoutExecutionEvidenceV1(value AuthorizedGuarantorPayoutExecutionEvidenceV1,
	request agentcommerce.AgreementPaymentRequest, obligation agentcommerce.SettlementObligation,
	materialized MaterializedPayoutObligationSetV1, terms CoverageTermsV1,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver,
	paymentVerifier agentcommerce.PaymentEvidenceVerifier, now time.Time) error {
	if paymentVerifier == nil || value.SchemaVersion != 1 || value.ObligationInstanceID != obligation.ObligationInstanceID ||
		request.ObligationInstanceID != obligation.ObligationInstanceID {
		return errors.New("Guarantor payout execution context is invalid")
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "payout_execution")
	if err != nil {
		return err
	}
	operation, err := StageOperationBindingForAuthorityV1(bound)
	if err != nil || agentcommerce.PaymentActionKind(request) != operation.ActionKind {
		return errors.New("Guarantor payout uses a settlement route not selected by the Agreement")
	}
	lineIndex := -1
	for index := range materialized.Obligations {
		if materialized.Obligations[index].ObligationInstanceID == obligation.ObligationInstanceID {
			lineIndex = index
			break
		}
	}
	if lineIndex < 0 || lineIndex >= len(materialized.MaterializedLines) || !equalCanonical(materialized.Obligations[lineIndex], obligation) ||
		verifyTerminalPaymentRequestBindingV1(request, obligation, materialized.MaterializedLines[lineIndex], terms) != nil {
		return errors.New("Guarantor payout differs from its materialized obligation")
	}
	actionBody := GuarantorAgreementPaymentActionBodyV1{SchemaVersion: 1, PaymentRequest: request,
		SettlementObligation: obligation, MaterializedPayoutObligationSet: materialized}
	canonical, err := codec.Marshal(actionBody)
	if err != nil || !bytes.Equal(canonical, value.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("Guarantor payout stage request is substituted")
	}
	_, fields, err := agentcommerce.PaymentAuthorizationMaterial(request)
	if err != nil || VerifyPortableStageActionAdmissionEvidenceV1(value.StageActionAdmissionEvidence, bound,
		canonical, fields, authorityResolver, fenceResolver, now) != nil {
		return errors.New("Guarantor payout lacks its Agreement-bound portable stage admission")
	}
	resolvedAt := time.Unix(int64(value.AgreementPaymentEvidence.ResolvedAtUnix), 0).UTC()
	switch value.AgreementPaymentEvidence.ResolvedState {
	case "finalized":
		if agentcommerce.VerifyAgreementPaymentEvidence(request, value.AgreementPaymentEvidence,
			paymentVerifier, resolvedAt) != nil {
			return errors.New("Guarantor payout has invalid terminal payment evidence")
		}
	case "defaulted":
		defaultVerifier, ok := paymentVerifier.(PayoutDefaultEvidenceVerifier)
		if !ok || defaultVerifier.VerifyGuarantorPayoutDefaultEvidence(request,
			value.AgreementPaymentEvidence, obligation, terms, resolvedAt) != nil {
			return errors.New("Guarantor payout default is not proven by the selected Adapter")
		}
	default:
		return errors.New("Guarantor payout is not terminal")
	}
	if value.CollateralEvidence != nil {
		return errors.New("ordinary Guarantor payout carries collateral evidence")
	}
	return nil
}

func VerifyTerminalPayoutEvidenceSetV1(value TerminalPayoutEvidenceSetV1,
	materialized MaterializedPayoutObligationSetV1, terms CoverageTermsV1,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver,
	paymentVerifier agentcommerce.PaymentEvidenceVerifier, now time.Time) error {
	if _, err := TerminalPayoutEvidenceSetDigestV1(value); err != nil {
		return err
	}
	materializedDigest, err := codec.Digest(PayoutSetDomain, materialized)
	if err != nil || value.MaterializedPayoutObligationSetDigest != materializedDigest ||
		value.CoverageAgreementBodyDigest != materialized.CoverageAgreementBodyDigest ||
		value.AuthorizedClaimDecisionDigest != materialized.AuthorizedClaimDecisionDigest {
		return errors.New("terminal payout set differs from its materialized obligations")
	}
	if value.Disposition == "not_applicable" {
		if len(materialized.Obligations) != 0 || len(value.TerminalSettlementEvidenceSet.Items) != 1 {
			return errors.New("no-payout terminal set has invalid cardinality")
		}
		marker := GuarantorNoPayoutMarkerV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: value.CoverageAgreementBodyDigest, ClaimID: value.ClaimID,
			AuthorizedClaimDecisionDigest:         value.AuthorizedClaimDecisionDigest,
			MaterializedPayoutObligationSetDigest: value.MaterializedPayoutObligationSetDigest}
		markerBytes, _ := codec.Marshal(marker)
		markerDigest, _ := codec.Digest("tos.service.agent-guarantor-no-payout-marker.v1", marker)
		item := value.TerminalSettlementEvidenceSet.Items[0]
		if item.ContentType != "application/vnd.tos.service.agent-guarantor-no-payout.v1+cbor" ||
			item.EvidenceProfileDigest != terms.SelectedPayoutAdapterProfile.ProfileDigest ||
			item.EvidenceEnvelopeDigest != markerDigest || item.Representation != "inline" ||
			!bytes.Equal(item.CanonicalEnvelopeBytes, markerBytes) || item.ImmutableDescriptor != nil {
			return errors.New("no-payout terminal marker is substituted")
		}
		return nil
	}
	if len(value.PayoutExecutionEvidence) != len(materialized.Obligations) ||
		len(value.TerminalSettlementEvidenceSet.Items) != len(value.PayoutExecutionEvidence) {
		return errors.New("terminal payout evidence cardinality differs")
	}
	for index, execution := range value.PayoutExecutionEvidence {
		obligation := materialized.Obligations[index]
		var actionBody GuarantorAgreementPaymentActionBodyV1
		if codec.Unmarshal(execution.StageActionAdmissionEvidence.CanonicalRequest, &actionBody) != nil ||
			!equalCanonical(actionBody.SettlementObligation, obligation) ||
			!equalCanonical(actionBody.MaterializedPayoutObligationSet, materialized) ||
			VerifyGuarantorPayoutExecutionEvidenceV1(execution, actionBody.PaymentRequest, obligation,
				materialized, terms, authorityResolver, fenceResolver, paymentVerifier, now) != nil {
			return errors.New("terminal payout execution is invalid")
		}
		executionBytes, _ := codec.Marshal(execution)
		executionDigest, _ := GuarantorPayoutExecutionEvidenceDigestV1(execution)
		found := false
		for _, item := range value.TerminalSettlementEvidenceSet.Items {
			if item.EvidenceEnvelopeDigest != executionDigest {
				continue
			}
			found = item.ContentType == "application/vnd.tos.service.agent-guarantor-payout-execution-evidence.v1+cbor" &&
				item.EvidenceProfileDigest == terms.SelectedPayoutAdapterProfile.ProfileDigest &&
				item.Representation == "inline" && bytes.Equal(item.CanonicalEnvelopeBytes, executionBytes) && item.ImmutableDescriptor == nil
		}
		if !found {
			return errors.New("terminal settlement evidence omits an exact payout execution")
		}
	}
	return nil
}
