package payment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/nilcheck"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
)

type ReconciliationStatus string

const (
	ReconciliationApplied     ReconciliationStatus = "applied"
	ReconciliationReorganized ReconciliationStatus = "reorganized"
)

// ReconciliationBinding is the immutable payment material recovered from the
// durable request journal. It is not authority by itself; Reconcile always
// queries the authoritative chain resolver and requires an exact response.
type ReconciliationBinding struct {
	Network               string
	ServiceID             string
	SessionID             string
	Operation             string
	RequestID             string
	IntentDigest          string
	AuthorizationID       string
	QuoteID               string
	Reference             string
	Payer                 string
	Payee                 string
	AmountNanoTOS         uint64
	QuoteEnvelopeDigest   string
	PaymentEnvelopeDigest string
}

// VerifiedReconciliation is opaque output from an exact post-application
// chain recheck. Its zero value cannot mutate durable payment state.
type VerifiedReconciliation struct {
	valid                 bool
	binding               ReconciliationBinding
	status                ReconciliationStatus
	observedMasterSeqno   uint64
	observedAt            time.Time
	reconciliationExpires time.Time
	verifiedAt            time.Time
}

type ReconciliationMaterial struct {
	Binding             ReconciliationBinding
	Status              ReconciliationStatus
	ObservedMasterSeqno uint64
	ObservedAt          time.Time
}

// Reconcile rechecks an already applied durable payment. Unlike Observe, it
// can run after the signed quote has expired because the journal already
// contains the authenticated immutable binding. A reorganized response is
// accepted only when the resolver echoes the complete tuple, parties, amount,
// a monotonic masterchain position, and the configured finality state.
func (o *Observer) Reconcile(
	ctx context.Context,
	binding ReconciliationBinding,
	minimumMasterSeqno uint64,
	now time.Time,
) (VerifiedReconciliation, error) {
	if o == nil || nilcheck.IsNil(o.resolver) {
		return VerifiedReconciliation{}, errors.New("invalid payment observer")
	}
	if ctx == nil {
		return VerifiedReconciliation{}, errors.New("nil payment reconciliation context")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedReconciliation{}, err
	}
	if err := binding.validate(); err != nil {
		return VerifiedReconciliation{}, err
	}
	if minimumMasterSeqno == 0 {
		return VerifiedReconciliation{}, errors.New("payment reconciliation high-water mark is required")
	}
	if now.IsZero() {
		return VerifiedReconciliation{}, errors.New("payment reconciliation time is required")
	}
	now = now.UTC()
	reference := chain.PaymentReference{
		Network: binding.Network, AuthorizationID: binding.AuthorizationID,
		QuoteID: binding.QuoteID, RequestID: binding.RequestID,
		Reference: binding.Reference, Payer: binding.Payer, Payee: binding.Payee,
		AmountNanoTOS:      binding.AmountNanoTOS,
		MinimumMasterSeqno: minimumMasterSeqno,
	}
	queryContext, cancel := context.WithTimeout(ctx, o.policy.QueryTimeout)
	defer cancel()
	state, err := safeObservePayment(o.resolver, queryContext, reference)
	if err != nil {
		return VerifiedReconciliation{}, fmt.Errorf("reconcile payment: %w", err)
	}
	if err := queryContext.Err(); err != nil {
		return VerifiedReconciliation{}, err
	}
	if state.Network != reference.Network ||
		state.AuthorizationID != reference.AuthorizationID ||
		state.QuoteID != reference.QuoteID ||
		state.RequestID != reference.RequestID ||
		state.Reference != reference.Reference {
		return VerifiedReconciliation{}, errors.New(
			"payment reconciliation does not match query reference",
		)
	}
	if state.Payer != binding.Payer || state.Payee != binding.Payee ||
		state.AmountNanoTOS != binding.AmountNanoTOS {
		return VerifiedReconciliation{}, errors.New(
			"payment reconciliation changed parties or amount",
		)
	}
	if state.ObservedMasterSeqno < minimumMasterSeqno {
		return VerifiedReconciliation{}, errors.New(
			"payment reconciliation is older than its high-water mark",
		)
	}
	observedAt := state.ObservedAt.UTC()
	if state.ObservedMasterSeqno == 0 || state.ObservedAt.IsZero() ||
		observedAt.After(now.Add(identity.MaxClockSkew)) ||
		!observedAt.Add(o.policy.MaxObservationAge).After(now) {
		return VerifiedReconciliation{}, errors.New(
			"payment reconciliation is stale or from the future",
		)
	}
	if o.policy.RequireFinalized && !state.Finalized {
		return VerifiedReconciliation{}, errors.New(
			"payment reconciliation is not finalized",
		)
	}
	status := ReconciliationApplied
	if state.Reorganized {
		if state.Confirmed {
			return VerifiedReconciliation{}, errors.New(
				"reorganized payment cannot remain confirmed",
			)
		}
		status = ReconciliationReorganized
	} else if !state.Confirmed {
		return VerifiedReconciliation{}, errors.New(
			"reconciled payment is not confirmed",
		)
	}
	return VerifiedReconciliation{
		valid: true, binding: binding, status: status,
		observedMasterSeqno: state.ObservedMasterSeqno,
		observedAt:          observedAt,
		reconciliationExpires: observedAt.Add(
			o.policy.MaxObservationAge,
		),
		verifiedAt: now,
	}, nil
}

// ApplicationMaterial rechecks the current durable binding and high-water
// mark immediately before journal mutation.
func (v VerifiedReconciliation) ApplicationMaterial(
	binding ReconciliationBinding,
	minimumMasterSeqno uint64,
	now time.Time,
) (ReconciliationMaterial, error) {
	if !v.valid {
		return ReconciliationMaterial{}, errors.New(
			"invalid verified payment reconciliation",
		)
	}
	if err := binding.validate(); err != nil {
		return ReconciliationMaterial{}, err
	}
	if now.IsZero() {
		return ReconciliationMaterial{}, errors.New(
			"payment reconciliation application time is required",
		)
	}
	now = now.UTC()
	if binding != v.binding ||
		minimumMasterSeqno == 0 ||
		v.observedMasterSeqno < minimumMasterSeqno {
		return ReconciliationMaterial{}, errors.New(
			"payment reconciliation application binding mismatch",
		)
	}
	if now.Before(v.verifiedAt.Add(-identity.MaxClockSkew)) ||
		!v.reconciliationExpires.After(now) {
		return ReconciliationMaterial{}, errors.New(
			"payment reconciliation is no longer current",
		)
	}
	return ReconciliationMaterial{
		Binding: v.binding, Status: v.status,
		ObservedMasterSeqno: v.observedMasterSeqno,
		ObservedAt:          v.observedAt,
	}, nil
}

func (b ReconciliationBinding) validate() error {
	for name, value := range map[string]string{
		"network": b.Network, "service ID": b.ServiceID,
		"session ID": b.SessionID, "operation": b.Operation,
		"request ID": b.RequestID, "payment authorization ID": b.AuthorizationID,
		"quote ID": b.QuoteID, "payment reference": b.Reference,
		"payer": b.Payer, "payee": b.Payee,
	} {
		if value == "" || len(value) > 512 || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s has invalid length or content", name)
		}
	}
	for name, value := range map[string]string{
		"intent":           b.IntentDigest,
		"quote envelope":   b.QuoteEnvelopeDigest,
		"payment envelope": b.PaymentEnvelopeDigest,
	} {
		if !validSHA256Digest(value) {
			return fmt.Errorf("%s digest is invalid", name)
		}
	}
	return nil
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 ||
		!strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
