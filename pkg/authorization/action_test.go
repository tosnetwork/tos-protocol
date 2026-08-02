package authorization

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type orderedAuthorityResolver struct {
	calls        atomic.Uint32
	lowerStarted chan struct{}
	releaseLower chan struct{}
	lower        AuthoritySnapshot
	higher       AuthoritySnapshot
}

func (r *orderedAuthorityResolver) ResolveAuthority(
	ctx context.Context,
	_ Reference,
) (AuthoritySnapshot, error) {
	if r.calls.Add(1) == 1 {
		close(r.lowerStarted)
		select {
		case <-ctx.Done():
			return AuthoritySnapshot{}, ctx.Err()
		case <-r.releaseLower:
			return r.lower, nil
		}
	}
	return r.higher, nil
}

type recordingAuthorityResolver struct {
	mu       sync.Mutex
	snapshot AuthoritySnapshot
	refs     []Reference
	panicNow bool
	cancel   context.CancelFunc
}

func TestPaidActionAuthorizerRejectsTypedNilAuthorityDependency(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	var resolver *recordingAuthorityResolver
	authorizer, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{
		Verifier: newTestVerifier(t), AuthorityResolver: resolver,
		ClientKeyResolver: fixture.resolver,
		Reference: Reference{
			Network: fixture.manifest.Network, Address: "tos:test:service-contract",
			ServiceID: fixture.manifest.ServiceID,
		},
		ManifestEnvelope: fixture.manifestEnvelope,
	})
	if err == nil || authorizer != nil {
		t.Fatal("typed-nil authority dependency accepted")
	}
}

func (r *recordingAuthorityResolver) ResolveAuthority(
	_ context.Context,
	reference Reference,
) (AuthoritySnapshot, error) {
	if r.panicNow {
		panic("mock paid-action authority secret")
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refs = append(r.refs, reference)
	return r.snapshot, nil
}

func TestPaidActionAuthorizerRejectsCancellationLateAuthoritySuccess(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	intent := []byte("paid action intent")
	ctx, cancel := context.WithCancel(context.Background())
	authorizer, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{
		Verifier: newTestVerifier(t),
		AuthorityResolver: &recordingAuthorityResolver{
			snapshot: fixture.snapshot, cancel: cancel,
		},
		ClientKeyResolver: fixture.resolver,
		Reference: Reference{
			Network: fixture.manifest.Network, Address: "tos:test:service-contract",
			ServiceID: fixture.manifest.ServiceID,
		},
		ManifestEnvelope: fixture.manifestEnvelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authorize(
		ctx, paidActionCredentials(t, fixture, intent), intent, fixture.now,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation-late authority success accepted: %v", err)
	}
}

func TestPaidActionAuthorizerContainsAuthorityResolverPanic(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	intent := []byte("paid action intent")
	authorizer, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{
		Verifier: newTestVerifier(t),
		AuthorityResolver: &recordingAuthorityResolver{
			panicNow: true,
		},
		ClientKeyResolver: fixture.resolver,
		Reference: Reference{
			Network: fixture.manifest.Network, Address: "tos:test:service-contract",
			ServiceID: fixture.manifest.ServiceID,
		},
		ManifestEnvelope: fixture.manifestEnvelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authorizer.Authorize(
		context.Background(), paidActionCredentials(t, fixture, intent),
		intent, fixture.now,
	)
	if err == nil || !strings.Contains(err.Error(), "authority resolver panicked") ||
		strings.Contains(err.Error(), "mock paid-action authority secret") {
		t.Fatalf("authority resolver panic was not safely converted: %v", err)
	}
}

func TestPaidActionAuthorizerBindsEntireCredentialChain(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	intent := []byte("paid action intent")
	credentials := paidActionCredentials(t, fixture, intent)
	resolver := &recordingAuthorityResolver{snapshot: fixture.snapshot}
	authorizer, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{
		Verifier: newTestVerifier(t), AuthorityResolver: resolver,
		ClientKeyResolver: fixture.resolver,
		Reference: Reference{
			Network:   fixture.manifest.Network,
			Address:   "tos:test:service-contract",
			ServiceID: fixture.manifest.ServiceID,
		},
		ManifestEnvelope:   fixture.manifestEnvelope,
		InitialMasterSeqno: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := authorizer.Authorize(
		context.Background(), credentials, intent, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := authorized.Material(fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if material.Network != fixture.manifest.Network ||
		material.ServiceID != fixture.manifest.ServiceID ||
		material.SessionID != fixture.session.SessionID ||
		material.Operation != fixture.payload.Operation ||
		material.RequestID != fixture.payload.RequestID ||
		material.Authority != fixture.session.Client ||
		material.MinimumMasterSeqno != fixture.snapshot.ObservedMasterSeqno ||
		string(material.Intent) != string(intent) || material.Manifest == nil {
		t.Fatalf("unexpected paid-action material: %#v", material)
	}
	material.Intent[0] ^= 0xff
	again, err := authorized.Material(fixture.now)
	if err != nil || string(again.Intent) != string(intent) {
		t.Fatal("paid-action material aliases caller intent")
	}
	resolver.mu.Lock()
	resolver.snapshot.ObservedMasterSeqno++
	resolver.snapshot.ObservedAt = fixture.now
	resolver.mu.Unlock()
	root := fixture.resolver.keys[fixture.session.Client]
	root.ObservedMasterSeqno++
	fixture.resolver.keys[fixture.session.Client] = root
	if _, err := authorizer.Authorize(
		context.Background(), credentials, intent, fixture.now,
	); err != nil {
		t.Fatal(err)
	}
	resolver.mu.Lock()
	refs := append([]Reference(nil), resolver.refs...)
	resolver.mu.Unlock()
	if len(refs) != 2 || refs[1].MinimumMasterSeqno != 100 {
		t.Fatalf("chain high-water references=%#v", refs)
	}
}

func TestPaidActionAuthorizerRejectsIntentAndAuthorityDrift(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	intent := []byte("paid action intent")
	credentials := paidActionCredentials(t, fixture, intent)
	resolver := &recordingAuthorityResolver{snapshot: fixture.snapshot}
	authorizer, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{
		Verifier: newTestVerifier(t), AuthorityResolver: resolver,
		ClientKeyResolver: fixture.resolver,
		Reference: Reference{
			Network:   fixture.manifest.Network,
			Address:   "tos:test:service-contract",
			ServiceID: fixture.manifest.ServiceID,
		},
		ManifestEnvelope: fixture.manifestEnvelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authorize(
		context.Background(), credentials, []byte("changed"), fixture.now,
	); err == nil {
		t.Fatal("changed paid-action intent was accepted")
	}
	resolver.mu.Lock()
	resolver.snapshot.ObservedMasterSeqno = 99
	resolver.mu.Unlock()
	if _, err := authorizer.Authorize(
		context.Background(), credentials, intent, fixture.now,
	); err == nil {
		t.Fatal("rolled-back authority snapshot was accepted")
	}
	badPayment := credentials
	badPayment.PaymentAuthorization.Payload = append(
		[]byte(nil), badPayment.PaymentAuthorization.Payload...,
	)
	badPayment.PaymentAuthorization.Payload[0] ^= 0xff
	resolver.mu.Lock()
	resolver.snapshot = fixture.snapshot
	resolver.mu.Unlock()
	if _, err := authorizer.Authorize(
		context.Background(), badPayment, intent, fixture.now,
	); err == nil {
		t.Fatal("altered payment authorization was accepted")
	}
	var zero AuthorizedPaidAction
	if _, err := zero.Material(fixture.now); err == nil {
		t.Fatal("zero paid-action authorization returned material")
	}
	if _, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{}); err == nil {
		t.Fatal("incomplete paid-action authorizer was accepted")
	}
}

func TestPaidActionAuthorizerDoesNotPoisonHighWaterWithInvalidSnapshot(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	intent := []byte("paid action intent")
	credentials := paidActionCredentials(t, fixture, intent)
	invalid := fixture.snapshot
	invalid.ObservedMasterSeqno = 1 << 60
	invalid.ControllerPublicKey = nil
	resolver := &recordingAuthorityResolver{snapshot: invalid}
	authorizer, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{
		Verifier: newTestVerifier(t), AuthorityResolver: resolver,
		ClientKeyResolver: fixture.resolver,
		Reference: Reference{
			Network: fixture.manifest.Network, Address: "tos:test:service-contract",
			ServiceID: fixture.manifest.ServiceID,
		},
		ManifestEnvelope: fixture.manifestEnvelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authorize(
		context.Background(), credentials, intent, fixture.now,
	); err == nil {
		t.Fatal("invalid authority snapshot was accepted")
	}
	resolver.mu.Lock()
	resolver.snapshot = fixture.snapshot
	resolver.mu.Unlock()
	if _, err := authorizer.Authorize(
		context.Background(), credentials, intent, fixture.now,
	); err != nil {
		t.Fatalf("invalid snapshot poisoned authority high-water: %v", err)
	}
}

func TestPaidActionAuthorizerRejectsSnapshotOvertakenConcurrently(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	intent := []byte("paid action intent")
	credentials := paidActionCredentials(t, fixture, intent)
	lower := fixture.snapshot
	higher := fixture.snapshot
	higher.ObservedMasterSeqno++
	resolver := &orderedAuthorityResolver{
		lowerStarted: make(chan struct{}), releaseLower: make(chan struct{}),
		lower: lower, higher: higher,
	}
	root := fixture.resolver.keys[fixture.session.Client]
	root.ObservedMasterSeqno = higher.ObservedMasterSeqno
	fixture.resolver.keys[fixture.session.Client] = root
	authorizer, err := NewPaidActionAuthorizer(PaidActionAuthorizerConfig{
		Verifier: newTestVerifier(t), AuthorityResolver: resolver,
		ClientKeyResolver: fixture.resolver,
		Reference: Reference{
			Network: fixture.manifest.Network, Address: "tos:test:service-contract",
			ServiceID: fixture.manifest.ServiceID,
		},
		ManifestEnvelope: fixture.manifestEnvelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	lowerResult := make(chan error, 1)
	go func() {
		_, authorizeErr := authorizer.Authorize(
			context.Background(), credentials, intent, fixture.now,
		)
		lowerResult <- authorizeErr
	}()
	<-resolver.lowerStarted
	if _, err := authorizer.Authorize(
		context.Background(), credentials, intent, fixture.now,
	); err != nil {
		t.Fatal(err)
	}
	close(resolver.releaseLower)
	if err := <-lowerResult; err == nil {
		t.Fatal("authority snapshot overtaken by a concurrent request was accepted")
	}
}

func paidActionCredentials(
	t *testing.T,
	fixture sessionAuthFixture,
	intent []byte,
) PaidActionCredentials {
	t.Helper()
	digest, err := protocol.RequestIntentDigest(
		fixture.session.ProfileID,
		fixture.session.ProfileVersion,
		fixture.session.ProfileExtensions,
		fixture.payload.Operation,
		intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	quote := sessionQuote(fixture)
	quote.IntentDigest = digest
	quoteEnvelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.QuoteDomain,
		fixture.manifest.RuntimeKeys[0].KeyID,
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	payment := protocol.PaymentAuthorization{
		Version:         protocol.BaseEnvelopeVersion,
		AuthorizationID: "paid-action-authorization-0001",
		QuoteID:         quote.QuoteID, RequestID: quote.RequestID,
		Network: quote.Network, Payer: fixture.session.Client,
		Payee: quote.Payee, MaxNanoTOS: quote.PriceNanoTOS,
		Reference: quote.Settlement, ExpiresAt: quote.ExpiresAt,
	}
	paymentEnvelope, err := identity.SignCanonical(
		fixture.rootPrivate, protocol.PaymentAuthorizationDomain,
		fixture.session.Client, payment, fixture.now, payment.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the exact grant envelope used by newSessionAuthFixture; the
	// original opaque verified grant deliberately does not expose it.
	sessionEnvelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.SessionGrantDomain,
		fixture.manifest.RuntimeKeys[0].KeyID, fixture.session,
		fixture.session.IssuedAt, fixture.session.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return PaidActionCredentials{
		SessionGrant: sessionEnvelope, Quote: quoteEnvelope,
		PaymentAuthorization: paymentEnvelope,
	}
}
