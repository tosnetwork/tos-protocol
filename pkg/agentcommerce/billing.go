package agentcommerce

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type SettlementObligation struct {
	AgreementBodyDigest        string          `json:"agreement_body_digest"`
	AgreementObligationID      string          `json:"agreement_obligation_id"`
	ObligationInstanceID       string          `json:"obligation_instance_id"`
	Sequence                   uint64          `json:"sequence"`
	PredecessorInstanceID      string          `json:"predecessor_instance_id,omitempty"`
	PayerAgentID               string          `json:"payer_agent_id"`
	PayeeAgentID               string          `json:"payee_agent_id"`
	Amount                     AgreementAmount `json:"amount"`
	NotBeforeUnix              uint64          `json:"not_before_unix,omitempty"`
	DueAtUnix                  uint64          `json:"due_at_unix,omitempty"`
	ExpiresAtUnix              uint64          `json:"expires_at_unix,omitempty"`
	MaximumAggregateAmount     AgreementAmount `json:"maximum_aggregate_amount"`
	SettlementAdapterURI       string          `json:"settlement_adapter_uri"`
	SettlementParametersDigest string          `json:"settlement_parameters_digest"`
	MandateDigest              string          `json:"mandate_digest,omitempty"`
	StableActionID             string          `json:"stable_action_id"`
}

type SettlementState string

const (
	SettlementPending       SettlementState = "pending"
	SettlementPartiallyPaid SettlementState = "partially_paid"
	SettlementPaid          SettlementState = "paid"
	SettlementOverdue       SettlementState = "overdue"
	SettlementCancelled     SettlementState = "cancelled"
	SettlementDisputed      SettlementState = "disputed"
	SettlementWrittenOff    SettlementState = "written_off"
)

type SettlementObligationState struct {
	ObligationDigest       string          `json:"obligation_digest"`
	State                  SettlementState `json:"state"`
	AppliedPaymentEvidence []string        `json:"applied_payment_evidence,omitempty"`
	PaidToDate             AgreementAmount `json:"paid_to_date"`
	OutstandingAmount      AgreementAmount `json:"outstanding_amount"`
	StateRevision          uint64          `json:"state_revision"`
	EvidenceRefs           []string        `json:"evidence_refs,omitempty"`
}

func MaterializeSettlementObligations(ownerID, agentID, agreementDigest, obligationID, mandateDigest string,
	obligation AgreementObligation) ([]SettlementObligation, error) {
	if !boundedIdentifier(ownerID, 256) || !boundedIdentifier(agentID, 256) || !canonicalDigestPattern.MatchString(agreementDigest) ||
		!boundedIdentifier(obligationID, 128) || obligation.ObligationID != obligationID || obligation.Amount == nil ||
		!canonicalDigestPattern.MatchString(mandateDigest) || validateAgreementAmount(*obligation.Amount) != nil ||
		!boundedIdentifier(obligation.BeneficiaryAgentID, 256) || !boundedIdentifier(obligation.SettlementAdapterURI, 256) ||
		len(obligation.SettlementParameters) == 0 {
		return nil, errors.New("settlement materialization input is invalid")
	}
	count := uint64(1)
	firstSequence := uint64(1)
	maximum := *obligation.Amount
	if obligation.BillingTerms != nil {
		if err := validateBillingTerms(*obligation.BillingTerms, *obligation.Amount); err != nil {
			return nil, err
		}
		firstSequence = obligation.BillingTerms.FirstSequence
		maximum = obligation.BillingTerms.MaximumAggregateAmount
		if obligation.BillingTerms.BillingKind == "periodic" {
			count = obligation.BillingTerms.RecurrenceCount
		}
	}
	if exceedsAggregate(*obligation.Amount, count, maximum) {
		return nil, errors.New("billing instances exceed the maximum aggregate amount")
	}
	parameterDigest, err := codec.Digest("tos.settlement-adapter-parameters.v1", obligation.SettlementParameters)
	if err != nil {
		return nil, err
	}
	result := make([]SettlementObligation, 0, count)
	predecessor := ""
	for offset := uint64(0); offset < count; offset++ {
		sequence := firstSequence + offset
		notBefore, due, expires := obligation.NotBeforeUnix, obligation.DueAtUnix, obligation.ExpiresAtUnix
		if obligation.BillingTerms != nil && obligation.BillingTerms.BillingKind == "periodic" {
			increment := offset * obligation.BillingTerms.RecurrenceIntervalSecs
			notBefore = obligation.BillingTerms.RecurrenceStartUnix + increment
			if due == 0 || due < notBefore {
				due = notBefore
			}
			if expires == 0 || expires > obligation.BillingTerms.RecurrenceEndUnix {
				expires = obligation.BillingTerms.RecurrenceEndUnix
			}
			if notBefore >= expires {
				return nil, errors.New("periodic billing instance falls outside recurrence bounds")
			}
		}
		identityProjection := struct {
			AgreementBodyDigest   string `json:"agreement_body_digest"`
			AgreementObligationID string `json:"agreement_obligation_id"`
			Sequence              uint64 `json:"sequence"`
			PredecessorInstanceID string `json:"predecessor_instance_id,omitempty"`
		}{agreementDigest, obligationID, sequence, predecessor}
		instanceID, err := codec.Digest("tos.settlement-obligation-instance.v1", identityProjection)
		if err != nil {
			return nil, err
		}
		actionID, _, err := DeriveStableActionID("billing.materialize", map[string]SemanticValue{
			"owner_id": ID(ownerID), "agent_id": ID(agentID), "agreement_body_digest": Digest32(agreementDigest),
			"agreement_obligation_id": ID(obligationID), "sequence": U64(sequence),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, SettlementObligation{AgreementBodyDigest: agreementDigest, AgreementObligationID: obligationID,
			ObligationInstanceID: instanceID, Sequence: sequence, PredecessorInstanceID: predecessor,
			PayerAgentID: obligation.ObligorAgentID, PayeeAgentID: obligation.BeneficiaryAgentID, Amount: *obligation.Amount,
			NotBeforeUnix: notBefore, DueAtUnix: due, ExpiresAtUnix: expires, MaximumAggregateAmount: maximum,
			SettlementAdapterURI: obligation.SettlementAdapterURI, SettlementParametersDigest: parameterDigest,
			MandateDigest: mandateDigest, StableActionID: actionID})
		predecessor = instanceID
	}
	return result, nil
}

func ValidateSettlementObligation(obligation SettlementObligation) error {
	if !canonicalDigestPattern.MatchString(obligation.AgreementBodyDigest) || !boundedIdentifier(obligation.AgreementObligationID, 128) ||
		!canonicalDigestPattern.MatchString(obligation.ObligationInstanceID) || obligation.Sequence == 0 ||
		obligation.PredecessorInstanceID != "" && !canonicalDigestPattern.MatchString(obligation.PredecessorInstanceID) ||
		!boundedIdentifier(obligation.PayerAgentID, 256) || !boundedIdentifier(obligation.PayeeAgentID, 256) ||
		validateAgreementAmount(obligation.Amount) != nil || validateAgreementAmount(obligation.MaximumAggregateAmount) != nil ||
		!boundedIdentifier(obligation.SettlementAdapterURI, 256) || !canonicalDigestPattern.MatchString(obligation.SettlementParametersDigest) ||
		obligation.MandateDigest != "" && !canonicalDigestPattern.MatchString(obligation.MandateDigest) ||
		!canonicalDigestPattern.MatchString(obligation.StableActionID) {
		return errors.New("settlement obligation is invalid")
	}
	if obligation.NotBeforeUnix != 0 && obligation.ExpiresAtUnix != 0 && obligation.NotBeforeUnix >= obligation.ExpiresAtUnix ||
		obligation.DueAtUnix != 0 && obligation.ExpiresAtUnix != 0 && obligation.DueAtUnix > obligation.ExpiresAtUnix {
		return errors.New("settlement obligation time bounds are invalid")
	}
	return nil
}

func NewSettlementState(obligation SettlementObligation) (SettlementObligationState, error) {
	if err := ValidateSettlementObligation(obligation); err != nil {
		return SettlementObligationState{}, err
	}
	digest, err := codec.Digest("tos.settlement-obligation.v1", obligation)
	if err != nil {
		return SettlementObligationState{}, err
	}
	zero := obligation.Amount
	zero.AmountAtomic = ""
	zero.AmountDecimal = ""
	if obligation.Amount.AmountAtomic != "" {
		zero.AmountAtomic = "0"
	} else {
		zero.AmountDecimal = "0"
	}
	return SettlementObligationState{ObligationDigest: digest, State: SettlementPending, PaidToDate: zero,
		OutstandingAmount: obligation.Amount, StateRevision: 1}, nil
}

func ApplyPayment(state SettlementObligationState, obligation SettlementObligation, evidenceDigest string,
	paid AgreementAmount, at time.Time) (SettlementObligationState, error) {
	if err := ValidateSettlementObligation(obligation); err != nil || !canonicalDigestPattern.MatchString(evidenceDigest) ||
		validateAgreementAmount(paid) != nil || paid.AssetNamespace != obligation.Amount.AssetNamespace ||
		paid.AssetIdentifier != obligation.Amount.AssetIdentifier || paid.Unit != obligation.Amount.Unit {
		return SettlementObligationState{}, errors.New("payment evidence is invalid")
	}
	wantDigest, err := codec.Digest("tos.settlement-obligation.v1", obligation)
	if err != nil || state.ObligationDigest != wantDigest || state.StateRevision == 0 {
		return SettlementObligationState{}, errors.New("settlement state does not match obligation")
	}
	for _, existing := range state.AppliedPaymentEvidence {
		if existing == evidenceDigest {
			return state, nil
		}
	}
	if state.State == SettlementPaid || state.State == SettlementCancelled || state.State == SettlementWrittenOff {
		return SettlementObligationState{}, errors.New("terminal settlement state cannot accept payment")
	}
	if obligation.ExpiresAtUnix != 0 && !at.UTC().Before(time.Unix(int64(obligation.ExpiresAtUnix), 0).UTC()) {
		return SettlementObligationState{}, errors.New("payment evidence arrived after obligation expiry")
	}
	total, err := addAmounts(state.PaidToDate, paid)
	if err != nil || compareAmounts(total, obligation.Amount) > 0 {
		return SettlementObligationState{}, errors.New("payment exceeds obligation amount")
	}
	outstanding, err := subtractAmounts(obligation.Amount, total)
	if err != nil {
		return SettlementObligationState{}, err
	}
	updated := state
	updated.AppliedPaymentEvidence = append(append([]string(nil), state.AppliedPaymentEvidence...), evidenceDigest)
	updated.EvidenceRefs = append(append([]string(nil), state.EvidenceRefs...), evidenceDigest)
	sort.Strings(updated.AppliedPaymentEvidence)
	sort.Strings(updated.EvidenceRefs)
	updated.PaidToDate = total
	updated.OutstandingAmount = outstanding
	updated.StateRevision++
	if amountIsZero(outstanding) {
		updated.State = SettlementPaid
	} else {
		updated.State = SettlementPartiallyPaid
	}
	return updated, nil
}

// ResolveSettlementState applies a non-payment terminal or risk transition.
// The caller must separately authorize the exact billing.resolve action; this
// function only defines deterministic ledger semantics.
func ResolveSettlementState(state SettlementObligationState, obligation SettlementObligation, target SettlementState,
	evidenceDigest string, at time.Time) (SettlementObligationState, error) {
	if err := ValidateSettlementObligation(obligation); err != nil || !canonicalDigestPattern.MatchString(evidenceDigest) || state.StateRevision == 0 {
		return SettlementObligationState{}, errors.New("settlement state transition evidence is invalid")
	}
	wantDigest, err := codec.Digest("tos.settlement-obligation.v1", obligation)
	if err != nil || state.ObligationDigest != wantDigest {
		return SettlementObligationState{}, errors.New("settlement state does not match obligation")
	}
	for _, prior := range state.EvidenceRefs {
		if prior == evidenceDigest && state.State == target {
			return state, nil
		}
	}
	allowed := false
	switch target {
	case SettlementOverdue:
		allowed = (state.State == SettlementPending || state.State == SettlementPartiallyPaid) && obligation.DueAtUnix != 0 &&
			!at.UTC().Before(time.Unix(int64(obligation.DueAtUnix), 0).UTC())
	case SettlementCancelled:
		allowed = state.State == SettlementPending || state.State == SettlementPartiallyPaid || state.State == SettlementOverdue || state.State == SettlementDisputed
	case SettlementDisputed:
		allowed = state.State == SettlementPending || state.State == SettlementPartiallyPaid || state.State == SettlementOverdue
	case SettlementWrittenOff:
		allowed = state.State == SettlementOverdue || state.State == SettlementDisputed
	default:
		return SettlementObligationState{}, errors.New("settlement target requires another evidence profile")
	}
	if !allowed {
		return SettlementObligationState{}, errors.New("settlement state transition is not permitted")
	}
	updated := state
	updated.State = target
	updated.StateRevision++
	updated.EvidenceRefs = append(append([]string(nil), state.EvidenceRefs...), evidenceDigest)
	sort.Strings(updated.EvidenceRefs)
	for index := 1; index < len(updated.EvidenceRefs); index++ {
		if updated.EvidenceRefs[index-1] == updated.EvidenceRefs[index] {
			return SettlementObligationState{}, errors.New("settlement evidence conflicts with prior transition")
		}
	}
	return updated, nil
}

func exceedsAggregate(amount AgreementAmount, count uint64, maximum AgreementAmount) bool {
	if amount.AssetNamespace != maximum.AssetNamespace || amount.AssetIdentifier != maximum.AssetIdentifier || amount.Unit != maximum.Unit ||
		(amount.AmountAtomic == "") != (maximum.AmountAtomic == "") {
		return true
	}
	per, perScale, ok := amountCoefficient(amount)
	if !ok {
		return true
	}
	capValue, capScale, ok := amountCoefficient(maximum)
	if !ok {
		return true
	}
	per, capValue, _ = alignDecimals(per, perScale, capValue, capScale)
	total := new(big.Int).Mul(per, new(big.Int).SetUint64(count))
	return total.Cmp(capValue) > 0
}

func amountCoefficient(amount AgreementAmount) (*big.Int, int, bool) {
	if amount.AmountAtomic != "" {
		value, ok := new(big.Int).SetString(amount.AmountAtomic, 10)
		return value, 0, ok
	}
	return decimalCoefficient(amount.AmountDecimal)
}

func addAmounts(first, second AgreementAmount) (AgreementAmount, error) {
	if first.AssetNamespace != second.AssetNamespace || first.AssetIdentifier != second.AssetIdentifier || first.Unit != second.Unit ||
		(first.AmountAtomic == "") != (second.AmountAtomic == "") {
		return AgreementAmount{}, errors.New("payment arithmetic requires matching amount profiles")
	}
	result := first
	if first.AmountAtomic != "" {
		a, _ := new(big.Int).SetString(first.AmountAtomic, 10)
		b, _ := new(big.Int).SetString(second.AmountAtomic, 10)
		result.AmountAtomic = new(big.Int).Add(a, b).String()
		return result, nil
	}
	a, scaleA, okA := decimalCoefficient(first.AmountDecimal)
	b, scaleB, okB := decimalCoefficient(second.AmountDecimal)
	if !okA || !okB {
		return AgreementAmount{}, errors.New("decimal amount is invalid")
	}
	a, b, scale := alignDecimals(a, scaleA, b, scaleB)
	result.AmountDecimal = formatDecimal(new(big.Int).Add(a, b), scale)
	return result, nil
}

func subtractAmounts(first, second AgreementAmount) (AgreementAmount, error) {
	if compareAmounts(first, second) < 0 || (first.AmountAtomic == "") != (second.AmountAtomic == "") {
		return AgreementAmount{}, errors.New("invalid amount subtraction")
	}
	result := first
	if first.AmountAtomic != "" {
		a, _ := new(big.Int).SetString(first.AmountAtomic, 10)
		b, _ := new(big.Int).SetString(second.AmountAtomic, 10)
		result.AmountAtomic = new(big.Int).Sub(a, b).String()
		return result, nil
	}
	a, scaleA, okA := decimalCoefficient(first.AmountDecimal)
	b, scaleB, okB := decimalCoefficient(second.AmountDecimal)
	if !okA || !okB {
		return AgreementAmount{}, errors.New("decimal amount is invalid")
	}
	a, b, scale := alignDecimals(a, scaleA, b, scaleB)
	result.AmountDecimal = formatDecimal(new(big.Int).Sub(a, b), scale)
	return result, nil
}

func compareAmounts(first, second AgreementAmount) int {
	if (first.AmountAtomic == "") != (second.AmountAtomic == "") || first.AssetNamespace != second.AssetNamespace ||
		first.AssetIdentifier != second.AssetIdentifier || first.Unit != second.Unit {
		return 2
	}
	if first.AmountAtomic != "" {
		a, okA := new(big.Int).SetString(first.AmountAtomic, 10)
		b, okB := new(big.Int).SetString(second.AmountAtomic, 10)
		if !okA || !okB {
			return 2
		}
		return a.Cmp(b)
	}
	a, scaleA, okA := decimalCoefficient(first.AmountDecimal)
	b, scaleB, okB := decimalCoefficient(second.AmountDecimal)
	if !okA || !okB {
		return 2
	}
	a, b, _ = alignDecimals(a, scaleA, b, scaleB)
	return a.Cmp(b)
}

func decimalCoefficient(value string) (*big.Int, int, bool) {
	if !canonicalDecimal(value) {
		return nil, 0, false
	}
	parts := strings.Split(value, ".")
	scale := 0
	digits := parts[0]
	if len(parts) == 2 {
		scale = len(parts[1])
		digits += parts[1]
	}
	coefficient, ok := new(big.Int).SetString(digits, 10)
	return coefficient, scale, ok
}

func alignDecimals(a *big.Int, scaleA int, b *big.Int, scaleB int) (*big.Int, *big.Int, int) {
	a = new(big.Int).Set(a)
	b = new(big.Int).Set(b)
	scale := scaleA
	if scaleA < scaleB {
		a.Mul(a, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scaleB-scaleA)), nil))
		scale = scaleB
	} else if scaleB < scaleA {
		b.Mul(b, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scaleA-scaleB)), nil))
	}
	return a, b, scale
}

func formatDecimal(coefficient *big.Int, scale int) string {
	if coefficient.Sign() == 0 {
		return "0"
	}
	digits := coefficient.String()
	if scale == 0 {
		return digits
	}
	if len(digits) <= scale {
		digits = strings.Repeat("0", scale-len(digits)+1) + digits
	}
	cut := len(digits) - scale
	formatted := digits[:cut] + "." + digits[cut:]
	formatted = strings.TrimRight(formatted, "0")
	return strings.TrimSuffix(formatted, ".")
}

func amountIsZero(amount AgreementAmount) bool {
	return amount.AmountAtomic == "0" || amount.AmountDecimal == "0"
}

func ValidateSettlementState(state SettlementObligationState) error {
	if !canonicalDigestPattern.MatchString(state.ObligationDigest) || state.StateRevision == 0 ||
		validateSortedDigests(state.AppliedPaymentEvidence, 10_000) != nil || validateSortedDigests(state.EvidenceRefs, 10_000) != nil ||
		validateAgreementAmount(state.PaidToDate) != nil || validateAgreementAmount(state.OutstandingAmount) != nil {
		return errors.New("settlement obligation state is invalid")
	}
	switch state.State {
	case SettlementPending, SettlementPartiallyPaid, SettlementPaid, SettlementOverdue, SettlementCancelled, SettlementDisputed, SettlementWrittenOff:
	default:
		return fmt.Errorf("unknown settlement state %q", state.State)
	}
	return nil
}
