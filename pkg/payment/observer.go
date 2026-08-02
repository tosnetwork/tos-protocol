// Package payment verifies chain payment observations against already
// authenticated quote and client authorization values. It does not execute
// work or settle/refund funds.
package payment

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/nilcheck"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
)

const (
	DefaultQueryTimeout      = 3 * time.Second
	DefaultMaxObservationAge = 5 * time.Minute

	maxQueryTimeout   = time.Minute
	maxObservationAge = time.Hour
)

type Resolver interface {
	ObservePayment(context.Context, chain.PaymentReference) (chain.PaymentState, error)
}

type Policy struct {
	QueryTimeout      time.Duration
	MaxObservationAge time.Duration
	RequireFinalized  bool
	AllowOverpayment  bool
}

func DefaultPolicy() Policy {
	return Policy{
		QueryTimeout:      DefaultQueryTimeout,
		MaxObservationAge: DefaultMaxObservationAge,
		RequireFinalized:  true,
	}
}

type Observer struct {
	resolver Resolver
	policy   Policy
}

// VerifiedObservation is an opaque, fresh, exact payment observation.
type VerifiedObservation struct {
	valid               bool
	material            authorization.PaymentObservationMaterial
	amountNanoTOS       uint64
	observedMasterSeqno uint64
	observedAt          time.Time
	validUntil          time.Time
	verifiedAt          time.Time
}

type ApplicationMaterial struct {
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
	ObservedMasterSeqno   uint64
	ObservedAt            time.Time
}

func NewObserver(resolver Resolver, policy Policy) (*Observer, error) {
	if nilcheck.IsNil(resolver) {
		return nil, errors.New("nil payment resolver")
	}
	if policy.QueryTimeout <= 0 || policy.QueryTimeout > maxQueryTimeout ||
		policy.MaxObservationAge <= 0 ||
		policy.MaxObservationAge > maxObservationAge {
		return nil, errors.New("invalid payment observation policy")
	}
	return &Observer{resolver: resolver, policy: policy}, nil
}

// Observe queries one exact authorization/quote/request/reference tuple and
// rejects stale, rolled-back, ambiguous, underfunded, over-authorized, or
// non-final results according to local policy.
func (o *Observer) Observe(
	ctx context.Context,
	authorized authorization.AuthorizedPayment,
	minimumMasterSeqno uint64,
	now time.Time,
) (VerifiedObservation, error) {
	if o == nil || nilcheck.IsNil(o.resolver) {
		return VerifiedObservation{}, errors.New("invalid payment observer")
	}
	if ctx == nil {
		return VerifiedObservation{}, errors.New("nil payment observation context")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedObservation{}, err
	}
	if now.IsZero() {
		return VerifiedObservation{}, errors.New("payment observation time is required")
	}
	now = now.UTC()
	material, err := authorized.ObservationMaterial(now)
	if err != nil {
		return VerifiedObservation{}, err
	}
	reference := chain.PaymentReference{
		Network:            material.Network,
		AuthorizationID:    material.AuthorizationID,
		QuoteID:            material.QuoteID,
		RequestID:          material.RequestID,
		Reference:          material.Reference,
		Payer:              material.Payer,
		Payee:              material.Payee,
		AmountNanoTOS:      material.PriceNanoTOS,
		MinimumMasterSeqno: minimumMasterSeqno,
	}
	queryContext, cancel := context.WithTimeout(ctx, o.policy.QueryTimeout)
	defer cancel()
	state, err := safeObservePayment(o.resolver, queryContext, reference)
	if err != nil {
		return VerifiedObservation{}, fmt.Errorf("observe payment: %w", err)
	}
	if err := queryContext.Err(); err != nil {
		return VerifiedObservation{}, err
	}
	if state.Network != reference.Network ||
		state.AuthorizationID != reference.AuthorizationID ||
		state.QuoteID != reference.QuoteID ||
		state.RequestID != reference.RequestID ||
		state.Reference != reference.Reference {
		return VerifiedObservation{}, errors.New("payment observation does not match query reference")
	}
	if state.Reorganized {
		return VerifiedObservation{}, errors.New("payment observation was reorganized")
	}
	if !state.Confirmed {
		return VerifiedObservation{}, errors.New("payment is not confirmed")
	}
	if o.policy.RequireFinalized && !state.Finalized {
		return VerifiedObservation{}, errors.New("payment is not finalized")
	}
	if state.Payer != material.Payer || state.Payee != material.Payee {
		return VerifiedObservation{}, errors.New("payment party binding mismatch")
	}
	if state.AmountNanoTOS < material.PriceNanoTOS {
		return VerifiedObservation{}, errors.New("payment amount is below quoted price")
	}
	if !o.policy.AllowOverpayment &&
		state.AmountNanoTOS != material.PriceNanoTOS {
		return VerifiedObservation{}, errors.New("payment amount does not equal quoted price")
	}
	if state.AmountNanoTOS > material.MaxNanoTOS {
		return VerifiedObservation{}, errors.New("payment amount exceeds client authorization")
	}
	if state.ObservedMasterSeqno == 0 ||
		state.ObservedMasterSeqno < minimumMasterSeqno {
		return VerifiedObservation{}, errors.New("payment observation is older than caller high-water mark")
	}
	observedAt := state.ObservedAt.UTC()
	if state.ObservedAt.IsZero() ||
		observedAt.After(now.Add(identity.MaxClockSkew)) ||
		!observedAt.Add(o.policy.MaxObservationAge).After(now) {
		return VerifiedObservation{}, errors.New("payment observation is stale or from the future")
	}
	return VerifiedObservation{
		valid: true, material: material,
		amountNanoTOS:       state.AmountNanoTOS,
		observedMasterSeqno: state.ObservedMasterSeqno,
		observedAt:          observedAt,
		validUntil: earliestTime(
			observedAt.Add(o.policy.MaxObservationAge),
			material.ValidUntil,
		),
		verifiedAt: now,
	}, nil
}

func earliestTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

func (v VerifiedObservation) ApplicationMaterial(
	network, serviceID, sessionID, operation, requestID, intentDigest string,
	authorizationID, quoteID, reference string,
	minimumMasterSeqno uint64,
	now time.Time,
) (ApplicationMaterial, error) {
	if !v.valid {
		return ApplicationMaterial{}, errors.New("invalid verified payment observation")
	}
	if now.IsZero() {
		return ApplicationMaterial{}, errors.New("payment application time is required")
	}
	now = now.UTC()
	if now.Before(v.verifiedAt.Add(-identity.MaxClockSkew)) ||
		!v.validUntil.After(now) {
		return ApplicationMaterial{}, errors.New("payment observation is no longer current")
	}
	if network != v.material.Network ||
		serviceID != v.material.ServiceID ||
		sessionID != v.material.SessionID ||
		operation != v.material.Operation ||
		requestID != v.material.RequestID ||
		intentDigest != v.material.IntentDigest ||
		authorizationID != v.material.AuthorizationID ||
		quoteID != v.material.QuoteID ||
		reference != v.material.Reference ||
		v.observedMasterSeqno < minimumMasterSeqno {
		return ApplicationMaterial{}, errors.New("payment application binding mismatch")
	}
	return ApplicationMaterial{
		Network: v.material.Network, ServiceID: v.material.ServiceID,
		SessionID: v.material.SessionID, Operation: v.material.Operation,
		RequestID: v.material.RequestID, IntentDigest: v.material.IntentDigest,
		AuthorizationID: v.material.AuthorizationID,
		QuoteID:         v.material.QuoteID, Reference: v.material.Reference,
		Payer: v.material.Payer, Payee: v.material.Payee,
		AmountNanoTOS:         v.amountNanoTOS,
		QuoteEnvelopeDigest:   v.material.QuoteEnvelopeDigest,
		PaymentEnvelopeDigest: v.material.PaymentEnvelopeDigest,
		ObservedMasterSeqno:   v.observedMasterSeqno,
		ObservedAt:            v.observedAt,
	}, nil
}
