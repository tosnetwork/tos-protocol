package authorization

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

// VerifiedQuote is a canonical quote signed by a current manifest runtime key
// with the quote role. Its fields remain private so discovery data cannot be
// substituted for runtime authority.
type VerifiedQuote struct {
	valid          bool
	quote          protocol.Quote
	envelope       identity.Envelope
	envelopeDigest string
	network        string
	serviceID      string
	validUntil     time.Time
}

// AuthorizedPayment is a client-signed payment authorization bound to a
// VerifiedQuote and a runtime-issued session. It is still not evidence that a
// payment exists on chain.
type AuthorizedPayment struct {
	valid                 bool
	quote                 protocol.Quote
	authorization         protocol.PaymentAuthorization
	quoteEnvelopeDigest   string
	paymentEnvelopeDigest string
	network               string
	serviceID             string
	profileVersion        string
	profileExtensions     []string
	requestAuthorization  AuthorizedSessionEnvelope
	validUntil            time.Time
	verifiedAt            time.Time
}

// PaymentObservationMaterial is returned only from a non-expired
// AuthorizedPayment. Payment observers use it to construct an exact chain
// query and validate every echoed field.
type PaymentObservationMaterial struct {
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
	PriceNanoTOS          uint64
	MaxNanoTOS            uint64
	QuoteEnvelopeDigest   string
	PaymentEnvelopeDigest string
	ValidUntil            time.Time
}

// VerifyQuote establishes runtime authority and the quote's exact current
// manifest/profile bindings.
func (m *VerifiedManifest) VerifyQuote(
	envelope identity.Envelope,
	now time.Time,
) (*VerifiedQuote, error) {
	verified, err := m.verifyRuntimeEnvelope(
		envelope,
		protocol.QuoteDomain,
		protocol.RuntimeRoleQuote,
		now,
	)
	if err != nil {
		return nil, err
	}
	var quote protocol.Quote
	if err := codec.Unmarshal(verified.envelope.Payload, &quote); err != nil {
		return nil, fmt.Errorf("decode canonical quote: %w", err)
	}
	if err := quote.Validate(verified.verifiedAt); err != nil {
		return nil, fmt.Errorf("validate quote: %w", err)
	}
	if quote.Network != m.manifest.Network ||
		quote.ServiceID != m.manifest.ServiceID ||
		quote.ServiceRevision != m.manifest.Revision ||
		!manifestHasProfileID(m.manifest, quote.ProfileID) {
		return nil, errors.New("quote does not match current manifest authority")
	}
	envelopeIssuedAt := time.UnixMilli(verified.envelope.IssuedAt)
	envelopeExpiresAt := time.UnixMilli(verified.envelope.ExpiresAt)
	if envelopeIssuedAt.After(envelopeTime(quote.IssuedAt)) ||
		envelopeExpiresAt.Before(envelopeTime(quote.ExpiresAt)) {
		return nil, errors.New("quote exceeds its authenticated runtime envelope")
	}
	digest, err := verified.envelope.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("fingerprint quote: %w", err)
	}
	return &VerifiedQuote{
		valid: true, quote: quote, envelope: cloneEnvelope(verified.envelope),
		envelopeDigest: digest,
		network:        m.manifest.Network, serviceID: m.manifest.ServiceID,
		validUntil: earliest(verified.validUntil, quote.ExpiresAt),
	}, nil
}

// SignedEnvelope returns a defensive copy of the current runtime-signed quote
// for delivery to the authenticated client. It does not expose mutable quote
// authority after the verified lifetime expires.
func (q *VerifiedQuote) SignedEnvelope(now time.Time) (
	identity.Envelope,
	error,
) {
	if q == nil || !q.valid || q.envelopeDigest == "" {
		return identity.Envelope{}, errors.New("invalid verified quote")
	}
	now, err := validateNow(now)
	if err != nil {
		return identity.Envelope{}, err
	}
	if !q.validUntil.After(now) {
		return identity.Envelope{}, errors.New("verified quote is no longer current")
	}
	return cloneEnvelope(q.envelope), nil
}

// AuthorizePayment verifies a direct client or complete delegation chain over
// a canonical PaymentAuthorization. requiredScope applies to every delegation.
func (q *VerifiedQuote) AuthorizePayment(
	ctx context.Context,
	session *VerifiedSessionGrant,
	resolver ClientKeyResolver,
	minimumMasterSeqno uint64,
	delegations []identity.Envelope,
	envelope identity.Envelope,
	requiredScope string,
	now time.Time,
) (AuthorizedPayment, error) {
	if q == nil || !q.valid {
		return AuthorizedPayment{}, errors.New("invalid verified quote")
	}
	if session == nil || session.grantDigest == "" {
		return AuthorizedPayment{}, errors.New("invalid verified session grant")
	}
	now, err := validateNow(now)
	if err != nil {
		return AuthorizedPayment{}, err
	}
	if !q.validUntil.After(now) {
		return AuthorizedPayment{}, errors.New("verified quote is no longer current")
	}
	if q.network != session.network ||
		q.quote.ServiceID != session.grant.ServiceID ||
		q.quote.SessionID != session.grant.SessionID ||
		q.quote.ProfileID != session.grant.ProfileID ||
		q.quote.IssuedAt.Before(session.grant.IssuedAt) ||
		q.quote.ExpiresAt.After(session.grant.ExpiresAt) {
		return AuthorizedPayment{}, errors.New("quote does not match the verified session")
	}
	binding := AdmissionBinding{
		SessionID:    q.quote.SessionID,
		Operation:    q.quote.Operation,
		RequestID:    q.quote.RequestID,
		IntentDigest: q.quote.IntentDigest,
	}
	var paymentAuthorization protocol.PaymentAuthorization
	authorized, err := session.AuthorizeClientEnvelope(
		ctx, resolver, minimumMasterSeqno, delegations, envelope,
		protocol.PaymentAuthorizationDomain, requiredScope, now,
		binding, q.quote.PriceNanoTOS,
		func(
			canonicalCBOR []byte,
			actualBinding AdmissionBinding,
			chargeNanoTOS uint64,
		) error {
			if actualBinding != binding || chargeNanoTOS != q.quote.PriceNanoTOS {
				return errors.New("payment authorization admission binding mismatch")
			}
			if err := codec.Unmarshal(canonicalCBOR, &paymentAuthorization); err != nil {
				return err
			}
			return paymentAuthorization.Validate(q.quote, now)
		},
	)
	if err != nil {
		return AuthorizedPayment{}, err
	}
	if paymentAuthorization.Payer != authorized.clientPrincipal {
		return AuthorizedPayment{}, errors.New(
			"payment payer does not match the session client principal",
		)
	}
	for _, budget := range authorized.budgets {
		if paymentAuthorization.MaxNanoTOS > budget.MaxNanoTOS {
			return AuthorizedPayment{}, errors.New(
				"payment authorization expands a session or delegation budget",
			)
		}
	}
	paymentDigest, err := authorized.envelope.Fingerprint()
	if err != nil {
		return AuthorizedPayment{}, fmt.Errorf("fingerprint payment authorization: %w", err)
	}
	return AuthorizedPayment{
		valid: true, quote: q.quote, authorization: paymentAuthorization,
		quoteEnvelopeDigest: q.envelopeDigest, paymentEnvelopeDigest: paymentDigest,
		network: q.network, serviceID: q.serviceID,
		profileVersion:       session.grant.ProfileVersion,
		profileExtensions:    append([]string(nil), session.grant.ProfileExtensions...),
		requestAuthorization: authorized,
		validUntil: earliest(
			q.validUntil, authorized.validUntil,
			paymentAuthorization.ExpiresAt,
		),
		verifiedAt: now,
	}, nil
}

// RequestAuthorization returns the same opaque client authorization and exact
// quote price that must be atomically admitted by Edge Core. The returned
// authorization retains all original request and charge bindings.
func (a AuthorizedPayment) RequestAuthorization() (
	AuthorizedSessionEnvelope,
	uint64,
	error,
) {
	if !a.valid {
		return AuthorizedSessionEnvelope{}, 0, errors.New("invalid authorized payment")
	}
	return a.requestAuthorization, a.quote.PriceNanoTOS, nil
}

func (a AuthorizedPayment) ObservationMaterial(
	now time.Time,
) (PaymentObservationMaterial, error) {
	if !a.valid {
		return PaymentObservationMaterial{}, errors.New("invalid authorized payment")
	}
	now, err := validateNow(now)
	if err != nil {
		return PaymentObservationMaterial{}, err
	}
	if now.Before(a.verifiedAt.Add(-identity.MaxClockSkew)) ||
		!a.validUntil.After(now) {
		return PaymentObservationMaterial{}, errors.New("authorized payment is no longer observable")
	}
	return PaymentObservationMaterial{
		Network: a.network, ServiceID: a.serviceID,
		SessionID: a.quote.SessionID, Operation: a.quote.Operation,
		RequestID: a.quote.RequestID, IntentDigest: a.quote.IntentDigest,
		AuthorizationID: a.authorization.AuthorizationID,
		QuoteID:         a.quote.QuoteID, Reference: a.authorization.Reference,
		Payer: a.authorization.Payer, Payee: a.authorization.Payee,
		PriceNanoTOS:          a.quote.PriceNanoTOS,
		MaxNanoTOS:            a.authorization.MaxNanoTOS,
		QuoteEnvelopeDigest:   a.quoteEnvelopeDigest,
		PaymentEnvelopeDigest: a.paymentEnvelopeDigest,
		ValidUntil:            a.validUntil,
	}, nil
}

func manifestHasProfileID(
	manifest protocol.ServiceManifest,
	profileID string,
) bool {
	for _, profile := range manifest.Profiles {
		if profile.ID == profileID {
			return true
		}
	}
	return false
}
