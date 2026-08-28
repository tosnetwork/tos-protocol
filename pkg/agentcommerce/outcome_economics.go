package agentcommerce

import (
	"errors"
	"math/big"
)

// EconomicPerimeterV1 prevents campaign-funded, related-party, or circular
// transfers from being reported as external revenue.
type EconomicPerimeterV1 struct {
	PerimeterID                string `json:"perimeter_id"`
	ControllerSetDigest        string `json:"controller_set_digest"`
	BeneficialOwnerSetDigest   string `json:"beneficial_owner_set_digest"`
	RelatedPartySetDigest      string `json:"related_party_set_digest"`
	FundingOriginSetDigest     string `json:"funding_origin_set_digest"`
	ClassificationPolicyDigest string `json:"classification_policy_digest"`
	ValidFromUnix              uint64 `json:"valid_from_unix"`
	ValidUntilUnix             uint64 `json:"valid_until_unix"`
}

type RevenueRecognitionV1 struct {
	AgreementBodyDigest      string `json:"agreement_body_digest"`
	ObligationInstanceID     string `json:"obligation_instance_id"`
	PaymentAssertionDigest   string `json:"payment_assertion_digest"`
	SellerPerimeterDigest    string `json:"seller_perimeter_digest"`
	BuyerPerimeterDigest     string `json:"buyer_perimeter_digest"`
	RelationshipClass        string `json:"relationship_class"`
	ConsiderationAssetDigest string `json:"consideration_asset_digest"`
	GrossAmountAtomic        string `json:"gross_amount_atomic"`
	RecognizedAmountAtomic   string `json:"recognized_amount_atomic"`
	RecognitionPolicyDigest  string `json:"recognition_policy_digest"`
	AuthorityEvidenceSetRoot string `json:"authority_evidence_set_root"`
}

type AssetConversionEvidenceV1 struct {
	SourceAssetDigest      string `json:"source_asset_digest"`
	TargetAssetDigest      string `json:"target_asset_digest"`
	SourceAmountAtomic     string `json:"source_amount_atomic"`
	RateNumerator          string `json:"rate_numerator"`
	RateDenominator        string `json:"rate_denominator"`
	RateType               string `json:"rate_type"`
	PriceSourceProfileURI  string `json:"price_source_profile_uri"`
	PriceEvidenceDigest    string `json:"price_evidence_digest"`
	QuotedAtUnix           uint64 `json:"quoted_at_unix"`
	ValidUntilUnix         uint64 `json:"valid_until_unix"`
	FeeAmountAtomic        string `json:"fee_amount_atomic"`
	RoundingRule           string `json:"rounding_rule"`
	TargetAmountAtomic     string `json:"target_amount_atomic"`
	ConversionPolicyDigest string `json:"conversion_policy_digest"`
}

type OutcomeForecastV1 struct {
	ForecastID              string `json:"forecast_id"`
	IssuedAtAuthorityUnix   uint64 `json:"issued_at_authority_unix"`
	ModelArtifactDigest     string `json:"model_artifact_digest"`
	FeatureCutDigest        string `json:"feature_cut_digest"`
	CohortPolicyDigest      string `json:"cohort_policy_digest"`
	TargetProfileURI        string `json:"target_profile_uri"`
	TargetSubjectDigest     string `json:"target_subject_digest"`
	HorizonEndUnix          uint64 `json:"horizon_end_unix"`
	ProbabilityPPM          uint32 `json:"probability_ppm"`
	ForecastAuthorityDigest string `json:"forecast_authority_digest"`
}

type CalibrationReportV1 struct {
	ReportID                  string `json:"report_id"`
	ForecastSetRoot           string `json:"forecast_set_root"`
	OutcomeSetRoot            string `json:"outcome_set_root"`
	CensoringPolicyDigest     string `json:"censoring_policy_digest"`
	ClusterPolicyDigest       string `json:"cluster_policy_digest"`
	ScoringRule               string `json:"scoring_rule"`
	ScoreNumerator            string `json:"score_numerator"`
	ScoreDenominator          string `json:"score_denominator"`
	BinSpecificationDigest    string `json:"bin_specification_digest"`
	UniqueClusterCount        uint64 `json:"unique_cluster_count"`
	VarianceMethodDigest      string `json:"variance_method_digest"`
	CorrelationIdentifierRoot string `json:"correlation_identifier_root"`
	OutputDigest              string `json:"output_digest"`
}

type FinancialReportV1 struct {
	ReportID                string `json:"report_id"`
	EventSetRoot            string `json:"event_set_root"`
	CohortCheckpointDigest  string `json:"cohort_checkpoint_digest"`
	AuthorityCutDigest      string `json:"authority_cut_digest"`
	FinalityCutDigest       string `json:"finality_cut_digest"`
	AccountingBookID        string `json:"accounting_book_id"`
	AccountingPolicyDigest  string `json:"accounting_policy_digest"`
	EconomicPerimeterDigest string `json:"economic_perimeter_digest"`
	ReportingAssetDigest    string `json:"reporting_asset_digest"`
	ConversionEvidenceRoot  string `json:"conversion_evidence_root"`
	WindowStartUnix         uint64 `json:"window_start_unix"`
	WindowEndUnix           uint64 `json:"window_end_unix"`
	Timezone                string `json:"timezone"`
	SoftwareBuildDigest     string `json:"software_build_digest"`
	RegistryDigest          string `json:"registry_digest"`
	ArithmeticProfileURI    string `json:"arithmetic_profile_uri"`
	LedgerRoot              string `json:"ledger_root"`
	UnknownSetRoot          string `json:"unknown_set_root"`
	ConflictSetRoot         string `json:"conflict_set_root"`
	ExclusionSetRoot        string `json:"exclusion_set_root"`
	PriorReportDigest       string `json:"prior_report_digest"`
	RestatementReason       string `json:"restatement_reason"`
	OutputDigest            string `json:"output_digest"`
}

type OutcomeCensoringV1 struct {
	AttemptAssertionRef OutcomeAssertionRefV1 `json:"attempt_assertion_ref"`
	AdmissionTimeUnix   uint64                `json:"admission_time_unix"`
	ObservationEndUnix  uint64                `json:"observation_end_unix"`
	CensorKind          string                `json:"censor_kind"`
	CensorReason        string                `json:"censor_reason"`
	LastStateProfileURI string                `json:"last_state_profile_uri"`
	LastState           string                `json:"last_state"`
	LastStateRevision   uint64                `json:"last_state_revision"`
}

type EvidenceAvailabilityObservationV1 struct {
	EvidenceObjectDigest string `json:"evidence_object_digest"`
	EvidenceProfileURI   string `json:"evidence_profile_uri"`
	PriorState           string `json:"prior_state"`
	TargetState          string `json:"target_state"`
	StateRevision        uint64 `json:"state_revision"`
	CustodianID          string `json:"custodian_id"`
	RetentionUntilUnix   uint64 `json:"retention_until_unix"`
	AvailabilityProof    string `json:"availability_proof_digest"`
	ObservedAtUnix       uint64 `json:"observed_at_unix"`
}

type GateExecutionObservationV1 struct {
	ExecutionID         string `json:"execution_id"`
	AgreementBodyDigest string `json:"agreement_body_digest"`
	ObligationID        string `json:"obligation_id"`
	PlanDigest          string `json:"plan_digest"`
	GatePolicyDigest    string `json:"gate_policy_digest"`
	InputSetDigest      string `json:"input_set_digest"`
	ResourceSetDigest   string `json:"resource_set_digest"`
	CredentialSetDigest string `json:"credential_set_digest"`
	EffectSetDigest     string `json:"effect_set_digest"`
	State               string `json:"state"`
	StateRevision       uint64 `json:"state_revision"`
	StartActionID       string `json:"start_action_id"`
	StartRequestDigest  string `json:"start_request_digest"`
	AuthoritativeRecord string `json:"authoritative_record_digest"`
	ObservedAtUnix      uint64 `json:"observed_at_unix"`
}

type CarrierReceiptObservationV1 struct {
	CarrierID               string `json:"carrier_id"`
	OperationEnvelopeDigest string `json:"operation_envelope_digest"`
	CarrierReceiptDigest    string `json:"carrier_receipt_digest"`
	CarrierSequence         uint64 `json:"carrier_sequence"`
	AcceptedAtUnix          uint64 `json:"accepted_at_unix"`
	RetentionCommitment     string `json:"retention_commitment_digest"`
}

type TransferObservationV1 struct {
	TransferClass          string `json:"transfer_class"`
	NetworkID              string `json:"network_id"`
	TransactionDigest      string `json:"transaction_digest"`
	FinalityEvidenceDigest string `json:"finality_evidence_digest"`
	PayerID                string `json:"payer_id"`
	PayeeID                string `json:"payee_id"`
	AssetIdentityDigest    string `json:"asset_identity_digest"`
	AmountAtomic           string `json:"amount_atomic"`
	DestinationDigest      string `json:"destination_digest"`
	AgreementBodyDigest    string `json:"agreement_body_digest,omitempty"`
	ObligationInstanceID   string `json:"obligation_instance_id,omitempty"`
	PaymentRequestDigest   string `json:"payment_request_digest,omitempty"`
	GiftObjectDigest       string `json:"gift_object_digest,omitempty"`
	StableActionID         string `json:"stable_action_id,omitempty"`
	ExactRequestDigest     string `json:"exact_request_digest,omitempty"`
	AdapterProfileURI      string `json:"adapter_profile_uri"`
	ResolutionState        string `json:"resolution_state"`
	ObservedAtUnix         uint64 `json:"observed_at_unix"`
}

// TOSEscrowObservationV1 is an evidence projection of the existing escrow
// state machine. It does not authorize a transition and it does not replace
// Accepted Quote, custody, contract, or validator-finality verification.
type TOSEscrowObservationV1 struct {
	Stage                     string `json:"stage"`
	TransferClass             string `json:"transfer_class"`
	NetworkID                 string `json:"network_id"`
	AcceptedQuoteDigest       string `json:"accepted_quote_digest"`
	AgreementBodyDigest       string `json:"agreement_body_digest"`
	ObligationInstanceID      string `json:"obligation_instance_id"`
	EscrowAccountDigest       string `json:"escrow_account_digest"`
	ContractCodeDigest        string `json:"contract_code_digest"`
	ContractConfigurationHash string `json:"contract_configuration_digest"`
	StableActionID            string `json:"stable_action_id"`
	ExactRequestDigest        string `json:"exact_request_digest"`
	TransactionBytesDigest    string `json:"transaction_bytes_digest"`
	TransactionDigest         string `json:"transaction_digest"`
	FinalizedCheckpointDigest string `json:"finalized_checkpoint_digest"`
	AssetIdentityDigest       string `json:"asset_identity_digest"`
	AmountAtomic              string `json:"amount_atomic"`
	AuthorityEvidenceSetRoot  string `json:"authority_evidence_set_root"`
	ObservedAtUnix            uint64 `json:"observed_at_unix"`
}

func ValidateEconomicPerimeterV1(value EconomicPerimeterV1) error {
	if !digest32(value.PerimeterID) || !digest32(value.ControllerSetDigest) || !digest32(value.BeneficialOwnerSetDigest) ||
		!digest32(value.RelatedPartySetDigest) || !digest32(value.FundingOriginSetDigest) || !digest32(value.ClassificationPolicyDigest) ||
		value.ValidFromUnix == 0 || value.ValidUntilUnix <= value.ValidFromUnix {
		return errors.New("economic perimeter is invalid")
	}
	return nil
}

func ValidateRevenueRecognitionV1(value RevenueRecognitionV1) error {
	if !digest32(value.AgreementBodyDigest) || !digest32(value.ObligationInstanceID) || !digest32(value.PaymentAssertionDigest) ||
		!digest32(value.SellerPerimeterDigest) || !digest32(value.BuyerPerimeterDigest) ||
		!oneOf(value.RelationshipClass, "external", "related_party", "intra_perimeter", "campaign_funded", "circular", "unknown") ||
		!digest32(value.ConsiderationAssetDigest) || !canonicalUnsignedDecimal(value.GrossAmountAtomic) ||
		!canonicalUnsignedDecimal(value.RecognizedAmountAtomic) || !digest32(value.RecognitionPolicyDigest) ||
		!digest32(value.AuthorityEvidenceSetRoot) || compareUnsigned(value.RecognizedAmountAtomic, value.GrossAmountAtomic) > 0 {
		return errors.New("revenue recognition is invalid")
	}
	if value.RelationshipClass != "external" && value.RecognizedAmountAtomic != "0" {
		return errors.New("non-external value cannot be recognized as external revenue")
	}
	return nil
}

func ValidateAssetConversionEvidenceV1(value AssetConversionEvidenceV1) error {
	if !digest32(value.SourceAssetDigest) || !digest32(value.TargetAssetDigest) || value.SourceAssetDigest == value.TargetAssetDigest ||
		!canonicalUnsignedDecimal(value.SourceAmountAtomic) || !positiveUnsigned(value.RateNumerator) || !positiveUnsigned(value.RateDenominator) ||
		!oneOf(value.RateType, "spot", "executed", "period_average") || !outcomeToken(value.PriceSourceProfileURI, MaxProfileURIBytes) ||
		!digest32(value.PriceEvidenceDigest) || value.QuotedAtUnix == 0 || value.ValidUntilUnix < value.QuotedAtUnix ||
		!canonicalUnsignedDecimal(value.FeeAmountAtomic) || !oneOf(value.RoundingRule, "floor", "ceiling", "half_even") ||
		!canonicalUnsignedDecimal(value.TargetAmountAtomic) || !digest32(value.ConversionPolicyDigest) {
		return errors.New("asset conversion evidence is invalid")
	}
	source, _ := new(big.Int).SetString(value.SourceAmountAtomic, 10)
	numerator, _ := new(big.Int).SetString(value.RateNumerator, 10)
	denominator, _ := new(big.Int).SetString(value.RateDenominator, 10)
	fee, _ := new(big.Int).SetString(value.FeeAmountAtomic, 10)
	target, _ := new(big.Int).SetString(value.TargetAmountAtomic, 10)
	product := new(big.Int).Mul(source, numerator)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, denominator, remainder)
	switch value.RoundingRule {
	case "ceiling":
		if remainder.Sign() != 0 {
			quotient.Add(quotient, big.NewInt(1))
		}
	case "half_even":
		twice := new(big.Int).Lsh(remainder, 1)
		comparison := twice.Cmp(denominator)
		if comparison > 0 || comparison == 0 && quotient.Bit(0) == 1 {
			quotient.Add(quotient, big.NewInt(1))
		}
	}
	if quotient.Cmp(fee) < 0 || quotient.Sub(quotient, fee).Cmp(target) != 0 {
		return errors.New("asset conversion arithmetic is invalid")
	}
	return nil
}

func ValidateOutcomeForecastV1(value OutcomeForecastV1) error {
	if !digest32(value.ForecastID) || value.IssuedAtAuthorityUnix == 0 || !digest32(value.ModelArtifactDigest) || !digest32(value.FeatureCutDigest) ||
		!digest32(value.CohortPolicyDigest) || !outcomeToken(value.TargetProfileURI, MaxProfileURIBytes) || !digest32(value.TargetSubjectDigest) ||
		value.HorizonEndUnix <= value.IssuedAtAuthorityUnix || value.ProbabilityPPM > 1_000_000 || !digest32(value.ForecastAuthorityDigest) {
		return errors.New("outcome forecast is invalid")
	}
	return nil
}

func ValidateCalibrationReportV1(value CalibrationReportV1) error {
	if !digest32(value.ReportID) || !digest32(value.ForecastSetRoot) || !digest32(value.OutcomeSetRoot) ||
		!digest32(value.CensoringPolicyDigest) || !digest32(value.ClusterPolicyDigest) ||
		!oneOf(value.ScoringRule, "brier", "log") || !canonicalUnsignedDecimal(value.ScoreNumerator) ||
		!positiveUnsigned(value.ScoreDenominator) || !digest32(value.BinSpecificationDigest) || value.UniqueClusterCount == 0 ||
		!digest32(value.VarianceMethodDigest) || !digest32(value.CorrelationIdentifierRoot) || !digest32(value.OutputDigest) {
		return errors.New("calibration report is invalid")
	}
	return nil
}

func ValidateFinancialReportV1(value FinancialReportV1) error {
	if !digest32(value.ReportID) || !digest32(value.EventSetRoot) || !digest32(value.CohortCheckpointDigest) ||
		!digest32(value.AuthorityCutDigest) || !digest32(value.FinalityCutDigest) || !outcomeToken(value.AccountingBookID, 256) ||
		!digest32(value.AccountingPolicyDigest) || !digest32(value.EconomicPerimeterDigest) || !digest32(value.ReportingAssetDigest) ||
		!digest32(value.ConversionEvidenceRoot) || value.WindowStartUnix == 0 || value.WindowEndUnix <= value.WindowStartUnix ||
		!outcomeToken(value.Timezone, 128) || !digest32(value.SoftwareBuildDigest) || !digest32(value.RegistryDigest) ||
		!outcomeToken(value.ArithmeticProfileURI, MaxProfileURIBytes) || !digest32(value.LedgerRoot) || !digest32(value.UnknownSetRoot) ||
		!digest32(value.ConflictSetRoot) || !digest32(value.ExclusionSetRoot) || !digest32(value.PriorReportDigest) ||
		!canonicalLowerToken(value.RestatementReason) || !digest32(value.OutputDigest) {
		return errors.New("financial report is invalid")
	}
	return nil
}

func ValidateOutcomeCensoringV1(value OutcomeCensoringV1) error {
	ref := value.AttemptAssertionRef
	if !outcomeToken(ref.NetworkID, 256) || !outcomeToken(ref.ActorAgentID, 256) || !outcomeToken(ref.OperationID, 256) || !digest32(ref.OperationEnvelopeDigest) ||
		value.AdmissionTimeUnix == 0 || value.ObservationEndUnix < value.AdmissionTimeUnix || !oneOf(value.CensorKind, "right_censored", "lost_to_followup") ||
		!canonicalLowerToken(value.CensorReason) || !outcomeToken(value.LastStateProfileURI, MaxProfileURIBytes) || !canonicalLowerToken(value.LastState) || value.LastStateRevision == 0 {
		return errors.New("outcome censoring record is invalid")
	}
	return nil
}

func ValidateEvidenceAvailabilityObservationV1(value EvidenceAvailabilityObservationV1) error {
	if !digest32(value.EvidenceObjectDigest) || !outcomeToken(value.EvidenceProfileURI, MaxProfileURIBytes) ||
		!oneOf(value.PriorState, "unknown", "available", "unavailable", "redacted", "key_destroyed") ||
		!oneOf(value.TargetState, "available", "unavailable", "redacted", "key_destroyed") || value.PriorState == value.TargetState ||
		value.StateRevision == 0 || !outcomeToken(value.CustodianID, 256) || !digest32(value.AvailabilityProof) || value.ObservedAtUnix == 0 {
		return errors.New("evidence availability observation is invalid")
	}
	return nil
}

func ValidateGateExecutionObservationV1(value GateExecutionObservationV1) error {
	if !digest32(value.ExecutionID) || !digest32(value.AgreementBodyDigest) || !outcomeToken(value.ObligationID, 256) ||
		!digest32(value.PlanDigest) || !digest32(value.GatePolicyDigest) || !digest32(value.InputSetDigest) || !digest32(value.ResourceSetDigest) ||
		!digest32(value.CredentialSetDigest) || !digest32(value.EffectSetDigest) || !canonicalLowerToken(value.State) || value.StateRevision == 0 ||
		!digest32(value.AuthoritativeRecord) || value.ObservedAtUnix == 0 {
		return errors.New("Gate execution observation is invalid")
	}
	if (value.StartActionID == "") != (value.StartRequestDigest == "") || value.StartActionID != "" && (!digest32(value.StartActionID) || !digest32(value.StartRequestDigest)) {
		return errors.New("Gate start identity is incomplete")
	}
	return nil
}

func ValidateCarrierReceiptObservationV1(value CarrierReceiptObservationV1) error {
	if !outcomeToken(value.CarrierID, 256) || !digest32(value.OperationEnvelopeDigest) || !digest32(value.CarrierReceiptDigest) ||
		value.CarrierSequence == 0 || value.AcceptedAtUnix == 0 || !digest32(value.RetentionCommitment) {
		return errors.New("Carrier receipt observation is invalid")
	}
	return nil
}

func ValidateTransferObservationV1(value TransferObservationV1) error {
	if !oneOf(value.TransferClass, "agreement_bound", "gift", "refund", "fee", "collateral", "unrelated", "unknown") ||
		!outcomeToken(value.NetworkID, 256) || !digest32(value.TransactionDigest) || !digest32(value.FinalityEvidenceDigest) ||
		!outcomeToken(value.PayerID, 256) || !outcomeToken(value.PayeeID, 256) || value.PayerID == value.PayeeID ||
		!digest32(value.AssetIdentityDigest) || !positiveUnsigned(value.AmountAtomic) || !digest32(value.DestinationDigest) ||
		!outcomeToken(value.AdapterProfileURI, MaxProfileURIBytes) ||
		!oneOf(value.ResolutionState, "observed_unproven", "corroborated_terminal", "validator_finalized", "reversed", "finality_indeterminate") || value.ObservedAtUnix == 0 {
		return errors.New("transfer observation is invalid")
	}
	agreementFields := value.AgreementBodyDigest != "" || value.ObligationInstanceID != "" || value.PaymentRequestDigest != ""
	actionFields := value.StableActionID != "" || value.ExactRequestDigest != ""
	switch value.TransferClass {
	case "gift":
		if agreementFields || actionFields || !digest32(value.GiftObjectDigest) {
			return errors.New("Gift observation carries commercial settlement fields")
		}
	case "agreement_bound", "refund", "collateral":
		if !digest32(value.AgreementBodyDigest) || !digest32(value.ObligationInstanceID) || !digest32(value.PaymentRequestDigest) ||
			!digest32(value.StableActionID) || !digest32(value.ExactRequestDigest) || value.GiftObjectDigest != "" {
			return errors.New("Agreement transfer binding is incomplete")
		}
	default:
		if agreementFields || value.GiftObjectDigest != "" {
			return errors.New("unbound transfer carries an Agreement or Gift binding")
		}
		if actionFields && (!digest32(value.StableActionID) || !digest32(value.ExactRequestDigest)) {
			return errors.New("transfer Action identity is incomplete")
		}
	}
	return nil
}

func ValidateTOSEscrowObservationV1(value TOSEscrowObservationV1) error {
	if !oneOf(value.Stage, "funding_observed", "principal_locked", "release_submitted", "release_finalized",
		"refund_submitted", "refund_finalized", "bounce_recovery", "fee_finalized", "finality_indeterminate") ||
		!oneOf(value.TransferClass, "collateral", "agreement_bound", "refund", "fee") || !outcomeToken(value.NetworkID, 256) ||
		!digest32(value.AcceptedQuoteDigest) || !digest32(value.AgreementBodyDigest) || !digest32(value.ObligationInstanceID) ||
		!digest32(value.EscrowAccountDigest) || !digest32(value.ContractCodeDigest) || !digest32(value.ContractConfigurationHash) ||
		!digest32(value.StableActionID) || !digest32(value.ExactRequestDigest) || !digest32(value.TransactionBytesDigest) ||
		!digest32(value.TransactionDigest) || !digest32(value.FinalizedCheckpointDigest) || !digest32(value.AssetIdentityDigest) ||
		!positiveUnsigned(value.AmountAtomic) || !digest32(value.AuthorityEvidenceSetRoot) || value.ObservedAtUnix == 0 {
		return errors.New("TOS escrow observation is invalid")
	}
	switch value.Stage {
	case "funding_observed", "principal_locked", "release_submitted", "refund_submitted", "bounce_recovery", "finality_indeterminate":
		if value.TransferClass != "collateral" {
			return errors.New("non-final TOS escrow principal is collateral")
		}
	case "release_finalized":
		if value.TransferClass != "agreement_bound" {
			return errors.New("finalized TOS escrow release must be Agreement-bound")
		}
	case "refund_finalized":
		if value.TransferClass != "refund" {
			return errors.New("finalized TOS escrow refund has the wrong transfer class")
		}
	case "fee_finalized":
		if value.TransferClass != "fee" {
			return errors.New("finalized TOS escrow fee has the wrong transfer class")
		}
	}
	return nil
}

func positiveUnsigned(value string) bool { return canonicalUnsignedDecimal(value) && value != "0" }

func compareUnsigned(left, right string) int {
	a, okA := new(big.Int).SetString(left, 10)
	b, okB := new(big.Int).SetString(right, 10)
	if !okA || !okB {
		return 1
	}
	return a.Cmp(b)
}
