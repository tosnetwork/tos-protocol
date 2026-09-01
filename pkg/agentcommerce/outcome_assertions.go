package agentcommerce

import (
	"bytes"
	"errors"
	"math/big"
	"sort"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxOutcomeEvidenceRefs       = 64
	MaxOutcomeLedgerEntries      = 256
	MaxOutcomeCheckpointGaps     = 1024
	MaxOutcomeCheckpointExcluded = 1024
)

type StateTransitionPayloadV1 struct {
	SubjectKind          string `json:"subject_kind"`
	SubjectID            string `json:"subject_id"`
	PriorState           string `json:"prior_state"`
	TargetState          string `json:"target_state"`
	PriorStateRevision   uint64 `json:"prior_state_revision"`
	TargetStateRevision  uint64 `json:"target_state_revision"`
	TransitionReasonCode string `json:"transition_reason_code"`
}

type TerminalDispositionV1 struct {
	TerminalScope                 string `json:"terminal_scope"`
	TerminalSubjectID             string `json:"terminal_subject_id"`
	OwningStateProfileURI         string `json:"owning_state_profile_uri"`
	AuthoritativeResolutionDigest string `json:"authoritative_resolution_digest"`
	TerminalStateRevision         uint64 `json:"terminal_state_revision"`
	SuccessorPolicyDigest         string `json:"successor_policy_digest"`
	Disposition                   string `json:"disposition"`
	FailureStage                  string `json:"failure_stage"`
	FailureCode                   string `json:"failure_code"`
	RetryDisposition              string `json:"retry_disposition"`
	ResolvedAtUnix                uint64 `json:"resolved_at_unix"`
}

type CostObservationPayloadV1 struct {
	SubjectKind                  string                `json:"subject_kind"`
	SubjectID                    string                `json:"subject_id"`
	CostItemID                   string                `json:"cost_item_id"`
	CostClass                    string                `json:"cost_class"`
	Category                     string                `json:"category"`
	AssetIdentityDigest          string                `json:"asset_identity_digest"`
	AmountAtomic                 string                `json:"amount_atomic"`
	EconomicDirection            string                `json:"economic_direction"`
	QuantityDigest               string                `json:"quantity_digest"`
	MeterIntervalDigest          string                `json:"meter_interval_digest"`
	MeterUnit                    string                `json:"meter_unit"`
	InvoiceIdentityDigest        string                `json:"invoice_identity_digest"`
	PaymentRequestDigest         string                `json:"payment_request_digest"`
	MeterOrInvoiceEvidenceDigest string                `json:"meter_or_invoice_evidence_digest"`
	AccountingPolicyDigest       string                `json:"accounting_policy_digest"`
	IncurredAtUnix               uint64                `json:"incurred_at_unix"`
	OriginalCostAssertionRef     OutcomeAssertionRefV1 `json:"original_cost_assertion_ref"`
}

type EconomicLedgerLineV1 struct {
	AccountCode     string `json:"account_code"`
	DebitOrCredit   string `json:"debit_or_credit"`
	AssetProfileURI string `json:"asset_profile_uri"`
	AssetInstanceID string `json:"asset_instance_id"`
	AmountAtomic    string `json:"amount_atomic"`
}

type EconomicLedgerEntryV1 struct {
	EntryID                string                 `json:"entry_id"`
	BookID                 string                 `json:"book_id"`
	AccountingEntityID     string                 `json:"accounting_entity_id"`
	AccountingPolicyDigest string                 `json:"accounting_policy_digest"`
	RecognitionBasis       string                 `json:"recognition_basis"`
	EffectiveAtUnix        uint64                 `json:"effective_at_unix"`
	PostingAtUnix          uint64                 `json:"posting_at_unix"`
	SourceAssertionRef     OutcomeAssertionRefV1  `json:"source_assertion_ref"`
	TransactionGroupID     string                 `json:"transaction_group_id"`
	Lines                  []EconomicLedgerLineV1 `json:"lines"`
	ReversesEntryID        string                 `json:"reverses_entry_id"`
}

type CohortCheckpointPayloadV1 struct {
	SchemaVersion                  uint16 `json:"schema_version"`
	AdmissionAuthorityID           string `json:"admission_authority_id"`
	OrderingDomain                 string `json:"ordering_domain"`
	AuthorityEpoch                 uint64 `json:"authority_epoch"`
	PreviousCheckpointDigest       string `json:"previous_checkpoint_digest"`
	FirstSequence                  uint64 `json:"first_sequence"`
	LastSequence                   uint64 `json:"last_sequence"`
	AdmittedAttemptSetRoot         string `json:"admitted_attempt_set_root"`
	AdmittedAttemptCount           uint64 `json:"admitted_attempt_count"`
	EligibleAttemptSetRoot         string `json:"eligible_attempt_set_root"`
	EligibleCount                  uint64 `json:"eligible_count"`
	ExcludedAttemptSetRoot         string `json:"excluded_attempt_set_root"`
	ExcludedCount                  uint64 `json:"excluded_count"`
	ExclusionReasonHistogramDigest string `json:"exclusion_reason_histogram_digest"`
	IncludedAttemptSetRoot         string `json:"included_attempt_set_root"`
	OutcomeCutoffUnix              uint64 `json:"outcome_cutoff_unix"`
	FollowupPolicyDigest           string `json:"followup_policy_digest"`
	CensoringSetRoot               string `json:"censoring_set_root"`
	CensoredCount                  uint64 `json:"censored_count"`
	ExplicitGapSetDigest           string `json:"explicit_gap_set_digest"`
	ForkInventoryDigest            string `json:"fork_inventory_digest"`
	InclusionPolicyDigest          string `json:"inclusion_policy_digest"`
	AdmissionClosureState          string `json:"admission_closure_state"`
	OutcomeClosureState            string `json:"outcome_closure_state"`
	CutoffUnix                     uint64 `json:"cutoff_unix"`
}

type AgreementObligationStateObservationV1 struct {
	AgreementBodyDigest      string `json:"agreement_body_digest"`
	AgreementObligationID    string `json:"agreement_obligation_id"`
	ObligationInstanceID     string `json:"obligation_instance_id"`
	ObligationDigest         string `json:"obligation_digest"`
	PaymentRequestDigest     string `json:"payment_request_digest"`
	PriorRevision            uint64 `json:"prior_revision"`
	TargetRevision           uint64 `json:"target_revision"`
	PriorPaidAmountAtomic    string `json:"prior_paid_amount_atomic"`
	AppliedAmountAtomic      string `json:"applied_amount_atomic"`
	TargetPaidAmountAtomic   string `json:"target_paid_amount_atomic"`
	TargetOutstandingAtomic  string `json:"target_outstanding_amount_atomic"`
	AppliedEvidenceSetDigest string `json:"applied_payment_evidence_set_digest"`
	OwningBillingProfileURI  string `json:"owning_billing_profile_uri"`
}

type AudiencePolicyV1 struct {
	SchemaVersion                  uint16 `json:"schema_version"`
	NetworkID                      string `json:"network_id"`
	AudienceKind                   string `json:"audience_kind"`
	RecipientPrincipalKeySetDigest string `json:"recipient_principal_key_set_digest"`
	GroupID                        string `json:"group_id"`
	MembershipEpoch                uint64 `json:"membership_epoch"`
	MembershipRootDigest           string `json:"membership_root_digest"`
	PermittedPurposeSetDigest      string `json:"permitted_purpose_set_digest"`
	OnwardDisclosureRule           string `json:"onward_disclosure_rule"`
	ExpiresAtUnix                  uint64 `json:"expires_at_unix"`
	PolicyRevision                 uint64 `json:"policy_revision"`
}

func ValidateStateTransitionPayloadV1(value StateTransitionPayloadV1) error {
	if !outcomeToken(value.SubjectKind, 128) || !outcomeToken(value.SubjectID, 4096) ||
		!canonicalLowerToken(value.PriorState) || !canonicalLowerToken(value.TargetState) ||
		value.TargetStateRevision != value.PriorStateRevision+1 || !canonicalLowerToken(value.TransitionReasonCode) {
		return errors.New("outcome state transition is invalid")
	}
	return nil
}

func ValidateTerminalDispositionV1(value TerminalDispositionV1) error {
	if !oneOf(value.TerminalScope, "agreement_attempt", "authorized_action", "execution", "delivery", "obligation", "transfer_attempt", "engagement") ||
		!outcomeToken(value.TerminalSubjectID, 4096) || !outcomeToken(value.OwningStateProfileURI, MaxProfileURIBytes) ||
		!digest32(value.AuthoritativeResolutionDigest) || !digest32(value.SuccessorPolicyDigest) || value.TerminalStateRevision == 0 ||
		!oneOf(value.Disposition, "succeeded", "refused", "withdrawn", "expired", "superseded", "cancelled", "failed", "timed_out", "conflict", "disputed", "refunded", "written_off", "indeterminate") ||
		!validOutcomeFailureStage(value.FailureStage) || !canonicalLowerToken(value.FailureCode) ||
		!oneOf(value.RetryDisposition, "forbidden", "exact_retry", "successor_after_terminal", "owner_review", "counterparty_action", "none") ||
		value.ResolvedAtUnix == 0 {
		return errors.New("outcome terminal disposition is invalid")
	}
	if value.Disposition == "succeeded" && value.FailureStage != "not_applicable" {
		return errors.New("successful outcome must not claim a failure stage")
	}
	return nil
}

func ValidateCostObservationPayloadV1(value CostObservationPayloadV1) error {
	if !outcomeToken(value.SubjectKind, 128) || !outcomeToken(value.SubjectID, 4096) || !outcomeToken(value.CostItemID, 256) ||
		!oneOf(value.CostClass, "declared_ceiling", "estimate", "usage_measured", "payable_invoiced", "cash_finalized", "allocated", "contra", "penalty", "write_off") ||
		!oneOf(value.Category, "compute", "model", "api", "tool", "storage", "network", "labor", "capital", "chain_fee", "collateral", "dispute", "other") ||
		!digest32(value.AssetIdentityDigest) || !canonicalUnsignedDecimal(value.AmountAtomic) ||
		!oneOf(value.EconomicDirection, "debit", "credit") || !digest32(value.QuantityDigest) || !digest32(value.MeterIntervalDigest) ||
		!outcomeToken(value.MeterUnit, 64) || !digest32(value.InvoiceIdentityDigest) || !digest32(value.PaymentRequestDigest) ||
		!digest32(value.MeterOrInvoiceEvidenceDigest) || !digest32(value.AccountingPolicyDigest) || value.IncurredAtUnix == 0 {
		return errors.New("outcome cost observation is invalid")
	}
	ref := value.OriginalCostAssertionRef
	emptyRef := ref.NetworkID == "" && ref.ActorAgentID == "" && ref.OperationID == "" && ref.OperationEnvelopeDigest == ""
	if value.CostClass == "contra" {
		if !outcomeToken(ref.NetworkID, 256) || !outcomeToken(ref.ActorAgentID, 256) ||
			!digest32(ref.OperationID) || !digest32(ref.OperationEnvelopeDigest) {
			return errors.New("contra cost lacks its exact original assertion")
		}
	} else if !emptyRef {
		return errors.New("non-contra cost claims an original assertion")
	}
	return nil
}

func ValidateEconomicLedgerEntriesV1(entries []EconomicLedgerEntryV1) error {
	if len(entries) > MaxOutcomeLedgerEntries {
		return errors.New("too many economic ledger entries")
	}
	return validateCanonicalOutcomeSlice(entries, func(entry EconomicLedgerEntryV1) error {
		if !digest32(entry.EntryID) || !outcomeToken(entry.BookID, 256) || !outcomeToken(entry.AccountingEntityID, 256) ||
			!digest32(entry.AccountingPolicyDigest) || !canonicalLowerToken(entry.RecognitionBasis) || entry.EffectiveAtUnix == 0 ||
			entry.PostingAtUnix < entry.EffectiveAtUnix || !digest32(entry.TransactionGroupID) || !digest32(entry.ReversesEntryID) ||
			len(entry.Lines) < 2 || len(entry.Lines) > 64 {
			return errors.New("economic ledger entry is invalid")
		}
		ref := entry.SourceAssertionRef
		if !outcomeToken(ref.NetworkID, 256) || !outcomeToken(ref.ActorAgentID, 256) || !outcomeToken(ref.OperationID, 256) || !digest32(ref.OperationEnvelopeDigest) {
			return errors.New("ledger source assertion is invalid")
		}
		balances := map[string][2]string{}
		for _, line := range entry.Lines {
			if !canonicalLowerToken(line.AccountCode) || !oneOf(line.DebitOrCredit, "debit", "credit") || !outcomeToken(line.AssetProfileURI, MaxProfileURIBytes) || !outcomeToken(line.AssetInstanceID, 256) || !canonicalUnsignedDecimal(line.AmountAtomic) || line.AmountAtomic == "0" {
				return errors.New("ledger line is invalid")
			}
			key := line.AssetProfileURI + "\x00" + line.AssetInstanceID
			pair := balances[key]
			if line.DebitOrCredit == "debit" {
				pair[0] = addCanonicalUnsigned(pair[0], line.AmountAtomic)
			} else {
				pair[1] = addCanonicalUnsigned(pair[1], line.AmountAtomic)
			}
			balances[key] = pair
		}
		for _, pair := range balances {
			if pair[0] != pair[1] {
				return errors.New("ledger entry does not balance per asset")
			}
		}
		return nil
	})
}

func ValidateCohortCheckpointPayloadV1(value CohortCheckpointPayloadV1) error {
	if value.SchemaVersion != 1 || !outcomeToken(value.AdmissionAuthorityID, 256) || !outcomeToken(value.OrderingDomain, 256) || value.AuthorityEpoch == 0 ||
		!digest32(value.PreviousCheckpointDigest) || !digest32(value.AdmittedAttemptSetRoot) || !digest32(value.EligibleAttemptSetRoot) ||
		!digest32(value.ExcludedAttemptSetRoot) || !digest32(value.ExclusionReasonHistogramDigest) || !digest32(value.IncludedAttemptSetRoot) ||
		value.OutcomeCutoffUnix == 0 || !digest32(value.FollowupPolicyDigest) || !digest32(value.CensoringSetRoot) ||
		!digest32(value.ExplicitGapSetDigest) || !digest32(value.ForkInventoryDigest) || !digest32(value.InclusionPolicyDigest) ||
		!oneOf(value.AdmissionClosureState, "open", "closed", "incomplete") || !oneOf(value.OutcomeClosureState, "open", "closed", "incomplete") ||
		value.CutoffUnix == 0 || value.AdmittedAttemptCount != value.EligibleCount+value.ExcludedCount || value.CensoredCount > value.AdmittedAttemptCount {
		return errors.New("outcome cohort checkpoint is invalid")
	}
	if value.AdmittedAttemptCount == 0 {
		if value.FirstSequence != 0 || value.LastSequence != 0 {
			return errors.New("empty checkpoint range is invalid")
		}
	} else if value.FirstSequence == 0 || value.LastSequence < value.FirstSequence {
		return errors.New("checkpoint range is invalid")
	}
	return nil
}

func ValidateAgreementObligationStateObservationV1(value AgreementObligationStateObservationV1) error {
	if !digest32(value.AgreementBodyDigest) || !outcomeToken(value.AgreementObligationID, 256) ||
		!digest32(value.ObligationInstanceID) || !digest32(value.ObligationDigest) || !digest32(value.PaymentRequestDigest) ||
		value.TargetRevision != value.PriorRevision+1 || !canonicalUnsignedDecimal(value.PriorPaidAmountAtomic) ||
		!canonicalUnsignedDecimal(value.AppliedAmountAtomic) || !canonicalUnsignedDecimal(value.TargetPaidAmountAtomic) ||
		!canonicalUnsignedDecimal(value.TargetOutstandingAtomic) || !digest32(value.AppliedEvidenceSetDigest) ||
		!outcomeToken(value.OwningBillingProfileURI, MaxProfileURIBytes) {
		return errors.New("obligation state observation is invalid")
	}
	if addCanonicalUnsigned(value.PriorPaidAmountAtomic, value.AppliedAmountAtomic) != value.TargetPaidAmountAtomic {
		return errors.New("obligation paid amount arithmetic is invalid")
	}
	return nil
}

func ValidateAudiencePolicyV1(value AudiencePolicyV1) error {
	if value.SchemaVersion != 1 || !outcomeToken(value.NetworkID, 256) || !oneOf(value.AudienceKind, "local_private", "named_participants", "named_recipients", "public") ||
		!digest32(value.PermittedPurposeSetDigest) || !canonicalLowerToken(value.OnwardDisclosureRule) || value.ExpiresAtUnix == 0 || value.PolicyRevision == 0 {
		return errors.New("outcome audience policy is invalid")
	}
	switch value.AudienceKind {
	case "local_private", "public":
		if value.RecipientPrincipalKeySetDigest != "" || value.GroupID != "" || value.MembershipEpoch != 0 || value.MembershipRootDigest != "" {
			return errors.New("non-member audience carries membership fields")
		}
	case "named_recipients":
		if !digest32(value.RecipientPrincipalKeySetDigest) || value.GroupID != "" || value.MembershipEpoch != 0 || value.MembershipRootDigest != "" {
			return errors.New("named-recipient audience is invalid")
		}
	case "named_participants":
		if !digest32(value.RecipientPrincipalKeySetDigest) || !outcomeToken(value.GroupID, 256) || value.MembershipEpoch == 0 || !digest32(value.MembershipRootDigest) {
			return errors.New("participant audience membership is invalid")
		}
	}
	return nil
}

func EconomicLedgerCutDigestV1(entries []EconomicLedgerEntryV1) (string, error) {
	if err := ValidateEconomicLedgerEntriesV1(entries); err != nil {
		return "", err
	}
	return codec.Digest("tos.operation-outcome.economic-ledger-cut.v1", entries)
}

func SortEconomicLedgerEntriesV1(entries []EconomicLedgerEntryV1) error {
	sort.Slice(entries, func(i, j int) bool {
		left, _ := codec.Marshal(entries[i])
		right, _ := codec.Marshal(entries[j])
		return bytes.Compare(left, right) < 0
	})
	return ValidateEconomicLedgerEntriesV1(entries)
}

func validOutcomeFailureStage(value string) bool {
	return oneOf(value, "discovery", "retrieval", "policy", "contact", "agreement", "reservation", "funding", "input", "gate", "execution", "delivery", "acceptance", "billing", "settlement", "finality", "reconciliation", "not_applicable", "unknown")
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func addCanonicalUnsigned(left, right string) string {
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}
	a, okA := new(big.Int).SetString(left, 10)
	b, okB := new(big.Int).SetString(right, 10)
	if !okA || !okB {
		return ""
	}
	return new(big.Int).Add(a, b).String()
}
