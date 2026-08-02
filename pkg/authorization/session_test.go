package authorization

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type testClientKeyResolver struct {
	keys     map[string]ClientKeySnapshot
	refs     []ClientKeyReference
	err      error
	panicNow bool
}

func (r *testClientKeyResolver) ResolveClientKey(
	_ context.Context,
	reference ClientKeyReference,
) (ClientKeySnapshot, error) {
	if r.panicNow {
		panic("mock client-key resolver secret")
	}
	r.refs = append(r.refs, reference)
	if r.err != nil {
		return ClientKeySnapshot{}, r.err
	}
	snapshot, ok := r.keys[reference.KeyID]
	if !ok {
		return ClientKeySnapshot{}, errors.New("key not found")
	}
	snapshot.PublicKey = append(ed25519.PublicKey(nil), snapshot.PublicKey...)
	snapshot.RevokedDelegationIDs = append(
		[]string(nil), snapshot.RevokedDelegationIDs...,
	)
	return snapshot, nil
}

func TestSessionContainsClientKeyResolverPanic(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	fixture.resolver.panicNow = true
	_, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 100, nil,
		fixture.clientEnvelope, runtimeDomain, "",
		fixture.now, fixture.admissionBinding, 4,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 4),
	)
	if err == nil || !strings.Contains(err.Error(), "client-key resolver panicked") ||
		strings.Contains(err.Error(), "mock client-key resolver secret") {
		t.Fatalf("client-key resolver panic was not safely converted: %v", err)
	}
}

type sessionAuthFixture struct {
	authFixture
	session          protocol.SessionGrant
	verified         *VerifiedSessionGrant
	rootPublic       ed25519.PublicKey
	rootPrivate      ed25519.PrivateKey
	resolver         *testClientKeyResolver
	payload          testPayload
	clientEnvelope   identity.Envelope
	admissionBinding AdmissionBinding
}

func newSessionAuthFixture(t *testing.T) sessionAuthFixture {
	t.Helper()
	fixture := newAuthFixture(t)
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := protocol.SessionGrant{
		Version: protocol.BaseEnvelopeVersion, SessionID: "session-0001",
		ServiceID:      fixture.manifest.ServiceID,
		ProfileID:      fixture.manifest.Profiles[0].ID,
		ProfileVersion: fixture.manifest.Profiles[0].Version,
		Client:         "client-key-root", RuntimeKeyID: fixture.manifest.RuntimeKeys[0].KeyID,
		ManifestRevision: fixture.manifest.Revision,
		Operations:       []string{"invoke", "cancel"},
		MaxRequests:      2, MaxNanoTOS: 10,
		IssuedAt:  fixture.now.Add(-time.Second),
		ExpiresAt: fixture.now.Add(10 * time.Minute),
	}
	sessionEnvelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.SessionGrantDomain,
		fixture.manifest.RuntimeKeys[0].KeyID, session,
		session.IssuedAt, session.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := manifest.VerifySessionGrant(sessionEnvelope, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload{
		RequestID: "request-0001", SessionID: session.SessionID,
		Operation: "invoke",
	}
	clientEnvelope, err := identity.SignCanonical(
		rootPrivate, runtimeDomain, session.Client, payload,
		fixture.now, fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &testClientKeyResolver{keys: map[string]ClientKeySnapshot{
		session.Client: clientKeySnapshot(
			fixture, session.Client, rootPublic,
		),
	}}
	return sessionAuthFixture{
		authFixture: fixture, session: session, verified: verified,
		rootPublic: rootPublic, rootPrivate: rootPrivate,
		resolver: resolver, payload: payload,
		clientEnvelope:   clientEnvelope,
		admissionBinding: testAdmissionBinding(payload),
	}
}

func clientKeySnapshot(
	fixture authFixture,
	keyID string,
	publicKey ed25519.PublicKey,
) ClientKeySnapshot {
	return ClientKeySnapshot{
		Network: fixture.manifest.Network, ServiceID: fixture.manifest.ServiceID,
		KeyID: keyID, Principal: keyID, PublicKey: publicKey,
		NotBefore:           fixture.now.Add(-time.Hour),
		NotAfter:            fixture.now.Add(time.Hour),
		ObservedMasterSeqno: 100, ObservedAt: fixture.now.Add(-time.Second),
	}
}

func TestSessionAuthorizesDirectClientAndReturnsOpaqueBudgets(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	authorized, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 100, nil,
		fixture.clientEnvelope, runtimeDomain, "",
		fixture.now, fixture.admissionBinding, 4,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 4),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clientEnvelope.Payload[0] ^= 1
	material, err := authorized.AdmissionMaterial(
		fixture.manifest.Network, fixture.manifest.ServiceID,
		fixture.session.Client, fixture.admissionBinding, 4, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if material.ClientID != fixture.session.Client ||
		material.ChargeNanoTOS != 4 ||
		len(material.Budgets) != 1 ||
		material.Budgets[0].Kind != "session" ||
		material.Budgets[0].MaxActions != fixture.session.MaxRequests {
		t.Fatalf("unexpected admission material: %#v", material)
	}
	material.Budgets[0].MaxActions = 100
	second, err := authorized.AdmissionMaterial(
		fixture.manifest.Network, fixture.manifest.ServiceID,
		fixture.session.Client, fixture.admissionBinding, 4, fixture.now,
	)
	if err != nil || second.Budgets[0].MaxActions != fixture.session.MaxRequests {
		t.Fatal("admission material was not defensively copied")
	}
	if _, err := authorized.AdmissionMaterial(
		fixture.manifest.Network, fixture.manifest.ServiceID,
		fixture.session.Client, fixture.admissionBinding, 5, fixture.now,
	); err == nil {
		t.Fatal("mismatched admission charge accepted")
	}
}

func TestSessionVerifiesCompleteDelegationChain(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	firstPublic, firstPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.resolver.keys["delegate-key-1"] = clientKeySnapshot(
		fixture.authFixture, "delegate-key-1", firstPublic,
	)
	fixture.resolver.keys["delegate-key-leaf"] = clientKeySnapshot(
		fixture.authFixture, "delegate-key-leaf", leafPublic,
	)
	root := protocol.Delegation{
		Version: protocol.BaseEnvelopeVersion, DelegationID: "delegation-root",
		SessionID: fixture.session.SessionID,
		Issuer:    fixture.session.Client, Subject: "delegate-key-1",
		Audience: fixture.manifest.ServiceID, Scopes: []string{"tos.ai.invoke"},
		MaxNanoTOS: 8, MaxActions: 2, NotBefore: fixture.session.IssuedAt,
		ExpiresAt: fixture.now.Add(8 * time.Minute),
	}
	child := protocol.Delegation{
		Version: protocol.BaseEnvelopeVersion, DelegationID: "delegation-child",
		SessionID: root.SessionID,
		Issuer:    root.Subject, Subject: "delegate-key-leaf",
		Audience: root.Audience, Scopes: []string{"tos.ai.invoke"},
		ParentID: root.DelegationID, Depth: 1,
		MaxNanoTOS: 5, MaxActions: 1, NotBefore: fixture.now,
		ExpiresAt: fixture.now.Add(5 * time.Minute),
	}
	rootEnvelope := signDelegation(t, fixture.rootPrivate, root)
	childEnvelope := signDelegation(t, firstPrivate, child)
	leafEnvelope, err := identity.SignCanonical(
		leafPrivate, runtimeDomain, child.Subject, fixture.payload,
		fixture.now, fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 100,
		[]identity.Envelope{rootEnvelope, childEnvelope},
		leafEnvelope, runtimeDomain, "tos.ai.invoke",
		fixture.now, fixture.admissionBinding, 5,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 5),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := authorized.AdmissionMaterial(
		fixture.manifest.Network, fixture.manifest.ServiceID,
		child.Subject, fixture.admissionBinding, 5, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(material.Budgets) != 3 ||
		material.Budgets[1].ID != root.DelegationID ||
		material.Budgets[2].ID != child.DelegationID ||
		material.Budgets[2].MaxActions != 1 {
		t.Fatalf("unexpected delegation budgets: %#v", material.Budgets)
	}
	for _, reference := range fixture.resolver.refs {
		if reference.MinimumMasterSeqno != 100 {
			t.Fatalf("resolver lost high-water mark: %#v", reference)
		}
	}
}

func TestSessionRejectsRevocationExpansionAndStaleKeys(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	delegatePublic, delegatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.resolver.keys["delegate-key-1"] = clientKeySnapshot(
		fixture.authFixture, "delegate-key-1", delegatePublic,
	)
	delegation := protocol.Delegation{
		Version: protocol.BaseEnvelopeVersion, DelegationID: "delegation-root",
		SessionID: fixture.session.SessionID,
		Issuer:    fixture.session.Client, Subject: "delegate-key-1",
		Audience: fixture.manifest.ServiceID, Scopes: []string{"tos.ai.invoke"},
		MaxNanoTOS: 5, MaxActions: 1, NotBefore: fixture.session.IssuedAt,
		ExpiresAt: fixture.now.Add(5 * time.Minute),
	}
	delegationEnvelope := signDelegation(t, fixture.rootPrivate, delegation)
	delegateEnvelope, err := identity.SignCanonical(
		delegatePrivate, runtimeDomain, delegation.Subject, fixture.payload,
		fixture.now, fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	root := fixture.resolver.keys[fixture.session.Client]
	root.RevokedDelegationIDs = []string{delegation.DelegationID}
	fixture.resolver.keys[fixture.session.Client] = root
	if _, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 100,
		[]identity.Envelope{delegationEnvelope}, delegateEnvelope,
		runtimeDomain, "tos.ai.invoke", fixture.now,
		fixture.admissionBinding, 1,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 1),
	); err == nil || !containsError(err, "revoked") {
		t.Fatalf("revoked delegation accepted: %v", err)
	}

	root.RevokedDelegationIDs = nil
	root.ObservedAt = fixture.now.Add(-DefaultMaxAuthorityAge)
	fixture.resolver.keys[fixture.session.Client] = root
	if _, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 100,
		[]identity.Envelope{delegationEnvelope}, delegateEnvelope,
		runtimeDomain, "tos.ai.invoke", fixture.now,
		fixture.admissionBinding, 1,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 1),
	); err == nil || !containsError(err, "stale") {
		t.Fatalf("stale root key accepted: %v", err)
	}

	root.ObservedAt = fixture.now
	fixture.resolver.keys[fixture.session.Client] = root
	expanded := delegation
	expanded.MaxNanoTOS = fixture.session.MaxNanoTOS + 1
	expandedEnvelope := signDelegation(t, fixture.rootPrivate, expanded)
	if _, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 100,
		[]identity.Envelope{expandedEnvelope}, delegateEnvelope,
		runtimeDomain, "tos.ai.invoke", fixture.now,
		fixture.admissionBinding, 1,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 1),
	); err == nil {
		t.Fatal("delegation expanding session payment budget accepted")
	}

	crossSession := delegation
	crossSession.SessionID = "session-0002"
	crossSessionEnvelope := signDelegation(t, fixture.rootPrivate, crossSession)
	if _, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 100,
		[]identity.Envelope{crossSessionEnvelope}, delegateEnvelope,
		runtimeDomain, "tos.ai.invoke", fixture.now,
		fixture.admissionBinding, 1,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 1),
	); err == nil {
		t.Fatal("delegation from another session accepted")
	}
}

func TestSessionGrantBindsManifestProfileAndRuntimeEnvelope(t *testing.T) {
	fixture := newAuthFixture(t)
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant := protocol.SessionGrant{
		Version: protocol.BaseEnvelopeVersion, SessionID: "session-0001",
		ServiceID:      fixture.manifest.ServiceID,
		ProfileID:      fixture.manifest.Profiles[0].ID,
		ProfileVersion: "9.9.9", Client: "client-key-root",
		RuntimeKeyID:     fixture.manifest.RuntimeKeys[0].KeyID,
		ManifestRevision: fixture.manifest.Revision,
		Operations:       []string{"invoke"}, MaxRequests: 1,
		IssuedAt: fixture.now, ExpiresAt: fixture.now.Add(time.Minute),
	}
	envelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.SessionGrantDomain,
		grant.RuntimeKeyID, grant, grant.IssuedAt, grant.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.VerifySessionGrant(envelope, fixture.now); err == nil {
		t.Fatal("session with absent profile version accepted")
	}

	grant.ProfileVersion = fixture.manifest.Profiles[0].Version
	grant.ProfileExtensions = []string{"urn:tos:extension:undeclared"}
	envelope, err = identity.SignCanonical(
		fixture.runtimePrivate, protocol.SessionGrantDomain,
		grant.RuntimeKeyID, grant, grant.IssuedAt, grant.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.VerifySessionGrant(envelope, fixture.now); err == nil {
		t.Fatal("session with undeclared profile extension accepted")
	}
}

func TestSessionPropagatesCancellationAndMasterchainHighWater(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.verified.AuthorizeClientEnvelope(
		canceled, fixture.resolver, 100, nil,
		fixture.clientEnvelope, runtimeDomain, "",
		fixture.now, fixture.admissionBinding, 0,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 0),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authorization error = %v", err)
	}
	if _, err := fixture.verified.AuthorizeClientEnvelope(
		context.Background(), fixture.resolver, 101, nil,
		fixture.clientEnvelope, runtimeDomain, "",
		fixture.now, fixture.admissionBinding, 0,
		validateSessionPayload(fixture.payload, fixture.admissionBinding, 0),
	); err == nil {
		t.Fatal("client key below masterchain high-water mark accepted")
	}
}

func signDelegation(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	delegation protocol.Delegation,
) identity.Envelope {
	t.Helper()
	envelope, err := identity.SignCanonical(
		privateKey, protocol.DelegationDomain, delegation.Issuer,
		delegation, delegation.NotBefore, delegation.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func containsError(err error, text string) bool {
	return err != nil && strings.Contains(err.Error(), text)
}

func validateSessionPayload(
	expected testPayload,
	expectedBinding AdmissionBinding,
	expectedCharge uint64,
) SessionPayloadValidator {
	return func(
		encoded []byte,
		binding AdmissionBinding,
		charge uint64,
	) error {
		if binding != expectedBinding || charge != expectedCharge {
			return errors.New("session admission binding mismatch")
		}
		return validateTestPayload(expected)(encoded)
	}
}
