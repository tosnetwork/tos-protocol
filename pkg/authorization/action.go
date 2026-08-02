package authorization

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/nilcheck"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

// PaidActionCredentials are the signed public credentials required for one
// paid action. Intent remains separate because it is committed by the quote
// and mapped only after payment is durably applied.
type PaidActionCredentials struct {
	SessionGrant         identity.Envelope
	Quote                identity.Envelope
	Delegations          []identity.Envelope
	PaymentAuthorization identity.Envelope
}

// PaidActionAuthorizerConfig binds one service deployment to current chain
// authority and client-key sources. The manifest envelope is operator-loaded;
// discovery data or request input cannot replace it.
type PaidActionAuthorizerConfig struct {
	Verifier           *Verifier
	AuthorityResolver  Resolver
	ClientKeyResolver  ClientKeyResolver
	Reference          Reference
	ManifestEnvelope   identity.Envelope
	RequiredScope      string
	InitialMasterSeqno uint64
}

// PaidActionAuthorizer is safe for concurrent use. Its only mutable state is
// a monotonic chain high-water mark; request-derived data is never cached.
type PaidActionAuthorizer struct {
	verifier          *Verifier
	authorityResolver Resolver
	clientKeys        ClientKeyResolver
	reference         Reference
	manifestEnvelope  identity.Envelope
	requiredScope     string
	highWater         atomic.Uint64
}

// AuthorizedPaidAction is opaque proof that the current controller manifest,
// runtime session, quote, full delegation chain, client payment signature,
// and exact profile intent commitment were verified together.
type AuthorizedPaidAction struct {
	valid              bool
	manifest           *VerifiedManifest
	payment            AuthorizedPayment
	intent             []byte
	authority          string
	minimumMasterSeqno uint64
	verifiedAt         time.Time
}

// PaidActionMaterial is the defensive, exact scope consumed by Edge Core.
type PaidActionMaterial struct {
	Network              string
	Authority            string
	ServiceID            string
	SessionID            string
	Operation            string
	RequestID            string
	IntentDigest         string
	Intent               []byte
	MinimumMasterSeqno   uint64
	Manifest             *VerifiedManifest
	PaymentAuthorization AuthorizedPayment
}

func NewPaidActionAuthorizer(
	config PaidActionAuthorizerConfig,
) (*PaidActionAuthorizer, error) {
	if config.Verifier == nil || nilcheck.IsNil(config.AuthorityResolver) ||
		nilcheck.IsNil(config.ClientKeyResolver) {
		return nil, errors.New("incomplete paid-action authority dependencies")
	}
	if err := config.Reference.validate(); err != nil {
		return nil, err
	}
	if config.ManifestEnvelope.Domain != protocol.ServiceManifestDomain ||
		len(config.ManifestEnvelope.Payload) == 0 {
		return nil, errors.New("invalid paid-action manifest envelope")
	}
	if config.RequiredScope != "" &&
		!serviceIDPattern.MatchString(config.RequiredScope) {
		return nil, errors.New("invalid paid-action delegation scope")
	}
	authorizer := &PaidActionAuthorizer{
		verifier:          config.Verifier,
		authorityResolver: config.AuthorityResolver,
		clientKeys:        config.ClientKeyResolver,
		reference:         config.Reference,
		manifestEnvelope:  cloneEnvelope(config.ManifestEnvelope),
		requiredScope:     config.RequiredScope,
	}
	authorizer.highWater.Store(config.InitialMasterSeqno)
	return authorizer, nil
}

// Authorize resolves current service authority, advances the chain high-water
// mark, verifies every signed credential, and binds the exact intent bytes to
// the quote. It performs no payment observation, journal mutation, or work.
func (a *PaidActionAuthorizer) Authorize(
	ctx context.Context,
	credentials PaidActionCredentials,
	intent []byte,
	now time.Time,
) (AuthorizedPaidAction, error) {
	if a == nil || a.verifier == nil || nilcheck.IsNil(a.authorityResolver) ||
		nilcheck.IsNil(a.clientKeys) {
		return AuthorizedPaidAction{}, errors.New("invalid paid-action authorizer")
	}
	if ctx == nil {
		return AuthorizedPaidAction{}, errors.New("nil paid-action context")
	}
	if err := ctx.Err(); err != nil {
		return AuthorizedPaidAction{}, err
	}
	now, err := validateNow(now)
	if err != nil {
		return AuthorizedPaidAction{}, err
	}
	now = now.UTC()
	reference := a.reference
	reference.MinimumMasterSeqno = max(
		reference.MinimumMasterSeqno, a.highWater.Load(),
	)
	snapshot, err := safeResolveAuthority(a.authorityResolver, ctx, reference)
	if err != nil {
		return AuthorizedPaidAction{}, fmt.Errorf(
			"resolve paid-action authority: %w", err,
		)
	}
	if err := ctx.Err(); err != nil {
		return AuthorizedPaidAction{}, err
	}
	if snapshot.Network != reference.Network ||
		snapshot.ServiceID != reference.ServiceID ||
		snapshot.ObservedMasterSeqno < reference.MinimumMasterSeqno {
		return AuthorizedPaidAction{}, errors.New(
			"paid-action authority rolled back or changed scope",
		)
	}
	if err := snapshot.validate(a.verifier.policy, now); err != nil {
		return AuthorizedPaidAction{}, fmt.Errorf(
			"validate paid-action authority snapshot: %w", err,
		)
	}
	advanceHighWater(&a.highWater, snapshot.ObservedMasterSeqno)
	reference.MinimumMasterSeqno = snapshot.ObservedMasterSeqno
	manifest, err := a.verifier.VerifyManifest(
		snapshot, cloneEnvelope(a.manifestEnvelope), now,
	)
	if err != nil {
		return AuthorizedPaidAction{}, fmt.Errorf(
			"verify paid-action manifest: %w", err,
		)
	}
	session, err := manifest.VerifySessionGrant(
		cloneEnvelope(credentials.SessionGrant), now,
	)
	if err != nil {
		return AuthorizedPaidAction{}, fmt.Errorf(
			"verify paid-action session: %w", err,
		)
	}
	quote, err := manifest.VerifyQuote(cloneEnvelope(credentials.Quote), now)
	if err != nil {
		return AuthorizedPaidAction{}, fmt.Errorf(
			"verify paid-action quote: %w", err,
		)
	}
	intentDigest, err := protocol.RequestIntentDigest(
		quote.quote.ProfileID,
		session.grant.ProfileVersion,
		session.grant.ProfileExtensions,
		quote.quote.Operation,
		intent,
	)
	if err != nil {
		return AuthorizedPaidAction{}, fmt.Errorf(
			"commit paid-action intent: %w", err,
		)
	}
	if intentDigest != quote.quote.IntentDigest {
		return AuthorizedPaidAction{}, errors.New(
			"paid-action intent does not match signed quote",
		)
	}
	if len(credentials.Delegations) > protocol.MaxDelegationDepth+1 {
		return AuthorizedPaidAction{}, errors.New(
			"paid-action delegation chain exceeds protocol maximum",
		)
	}
	delegations := cloneEnvelopes(credentials.Delegations)
	payment, err := quote.AuthorizePayment(
		ctx,
		session,
		a.clientKeys,
		reference.MinimumMasterSeqno,
		delegations,
		cloneEnvelope(credentials.PaymentAuthorization),
		a.requiredScope,
		now,
	)
	if err != nil {
		return AuthorizedPaidAction{}, fmt.Errorf(
			"verify paid-action payment authorization: %w", err,
		)
	}
	// The resolver call started with the high-water value observed before it
	// went to the chain. Another concurrent authorization may have completed
	// against a newer controller snapshot while this request was verifying its
	// credential chain. Treat this final check as the authorization
	// linearization point: an older snapshot may complete first, but it cannot
	// be accepted after a newer snapshot has advanced the process high-water.
	if snapshot.ObservedMasterSeqno < a.highWater.Load() {
		return AuthorizedPaidAction{}, errors.New(
			"paid-action authority became stale during authorization",
		)
	}
	return AuthorizedPaidAction{
		valid: true, manifest: manifest, payment: payment,
		intent:             append([]byte(nil), intent...),
		authority:          payment.requestAuthorization.authority,
		minimumMasterSeqno: reference.MinimumMasterSeqno,
		verifiedAt:         now,
	}, nil
}

// Material returns defensive execution scope only while the payment
// authorization remains current. Restart recovery after expiry must use the
// exact durable context in Edge Core and a separately authenticated read.
func (a AuthorizedPaidAction) Material(now time.Time) (
	PaidActionMaterial,
	error,
) {
	if !a.valid || a.manifest == nil || a.authority == "" {
		return PaidActionMaterial{}, errors.New("invalid authorized paid action")
	}
	now, err := validateNow(now)
	if err != nil {
		return PaidActionMaterial{}, err
	}
	binding, err := a.payment.ObservationMaterial(now)
	if err != nil {
		return PaidActionMaterial{}, err
	}
	if now.Before(a.verifiedAt.Add(-identity.MaxClockSkew)) {
		return PaidActionMaterial{}, errors.New(
			"authorized paid action is not current",
		)
	}
	return PaidActionMaterial{
		Network: binding.Network, Authority: a.authority,
		ServiceID: binding.ServiceID, SessionID: binding.SessionID,
		Operation: binding.Operation, RequestID: binding.RequestID,
		IntentDigest:         binding.IntentDigest,
		Intent:               append([]byte(nil), a.intent...),
		MinimumMasterSeqno:   a.minimumMasterSeqno,
		Manifest:             a.manifest,
		PaymentAuthorization: a.payment,
	}, nil
}

func advanceHighWater(highWater *atomic.Uint64, observed uint64) {
	for {
		current := highWater.Load()
		if observed <= current || highWater.CompareAndSwap(current, observed) {
			return
		}
	}
}

func cloneEnvelopes(values []identity.Envelope) []identity.Envelope {
	if values == nil {
		return nil
	}
	cloned := make([]identity.Envelope, len(values))
	for index, value := range values {
		cloned[index] = cloneEnvelope(value)
	}
	return cloned
}
