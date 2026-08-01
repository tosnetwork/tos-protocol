package authorization

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type sessionSignerFunc func(
	context.Context,
	[]byte,
	time.Time,
	time.Time,
) (identity.Envelope, error)

func (f sessionSignerFunc) SignSession(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	return f(ctx, payload, issuedAt, expiresAt)
}

func TestIssueSessionGrantDerivesAuthorityAndContainsSignerFailures(t *testing.T) {
	fixture := newAuthFixture(t)
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	draft := SessionDraft{
		SessionID: "issued-session-0001", ProfileID: "tos.ai.inference",
		ProfileVersion: "0.1.0", Client: "client-key-0001",
		RuntimeKeyID: fixture.manifest.RuntimeKeys[0].KeyID,
		Operations:   []string{"invoke"}, MaxRequests: 10, MaxNanoTOS: 100,
		ExpiresAt: fixture.now.Add(10 * time.Minute),
	}
	validSigner := sessionSignerFunc(func(
		_ context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		return identity.Sign(
			fixture.runtimePrivate, protocol.SessionGrantDomain,
			fixture.manifest.RuntimeKeys[0].KeyID,
			payload, issuedAt, expiresAt,
		)
	})
	verified, envelope, err := manifest.IssueSessionGrant(
		context.Background(), draft, validSigner, fixture.now,
	)
	if err != nil || verified == nil ||
		envelope.KeyID != fixture.manifest.RuntimeKeys[0].KeyID {
		t.Fatalf("verified=%v envelope=%#v err=%v", verified, envelope, err)
	}
	if verified.grant.ServiceID != fixture.manifest.ServiceID ||
		verified.grant.ManifestRevision != fixture.manifest.Revision ||
		verified.grant.SessionID != draft.SessionID ||
		verified.grant.RuntimeKeyID != draft.RuntimeKeyID {
		t.Fatalf("issued grant changed authority: %#v", verified.grant)
	}
	draft.Operations[0] = "changed"
	if verified.grant.Operations[0] != "invoke" {
		t.Fatal("issued grant aliases caller operations")
	}

	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]SessionSigner{
		"payload substitution": sessionSignerFunc(func(
			_ context.Context, payload []byte, issuedAt, expiresAt time.Time,
		) (identity.Envelope, error) {
			changed := append([]byte(nil), payload...)
			changed[0] ^= 1
			return identity.Sign(
				fixture.runtimePrivate, protocol.SessionGrantDomain,
				fixture.manifest.RuntimeKeys[0].KeyID,
				changed, issuedAt, expiresAt,
			)
		}),
		"wrong custody key": sessionSignerFunc(func(
			_ context.Context, payload []byte, issuedAt, expiresAt time.Time,
		) (identity.Envelope, error) {
			return identity.Sign(
				wrongPrivate, protocol.SessionGrantDomain,
				fixture.manifest.RuntimeKeys[0].KeyID,
				payload, issuedAt, expiresAt,
			)
		}),
		"custody error": sessionSignerFunc(func(
			context.Context, []byte, time.Time, time.Time,
		) (identity.Envelope, error) {
			return identity.Envelope{}, errors.New("custody unavailable")
		}),
		"custody panic": sessionSignerFunc(func(
			context.Context, []byte, time.Time, time.Time,
		) (identity.Envelope, error) {
			panic("custody failure")
		}),
	}
	for name, signer := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := draft
			candidate.Operations = []string{"invoke"}
			if _, _, issueErr := manifest.IssueSessionGrant(
				context.Background(), candidate, signer, fixture.now,
			); issueErr == nil {
				t.Fatal("unsafe signer result was accepted")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	draft.Operations = []string{"invoke"}
	if _, _, err := manifest.IssueSessionGrant(
		canceled, draft, validSigner, fixture.now,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled issuance error=%v", err)
	}
}

func TestIssueSessionGrantRejectsRevokedAuthenticateKey(t *testing.T) {
	fixture := newAuthFixture(t)
	fixture.snapshot.RevokedRuntimeKeyIDs = []string{
		fixture.manifest.RuntimeKeys[0].KeyID,
	}
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	draft := SessionDraft{
		SessionID: "revoked-session-0001", ProfileID: "tos.ai.inference",
		ProfileVersion: "0.1.0", Client: "client-key-0001",
		RuntimeKeyID: fixture.manifest.RuntimeKeys[0].KeyID,
		Operations:   []string{"invoke"}, MaxRequests: 1, MaxNanoTOS: 1,
		ExpiresAt: fixture.now.Add(time.Minute),
	}
	signer := sessionSignerFunc(func(
		_ context.Context, payload []byte, issuedAt, expiresAt time.Time,
	) (identity.Envelope, error) {
		return identity.Sign(
			fixture.runtimePrivate, protocol.SessionGrantDomain,
			fixture.manifest.RuntimeKeys[0].KeyID,
			payload, issuedAt, expiresAt,
		)
	})
	if _, _, err := manifest.IssueSessionGrant(
		context.Background(), draft, signer, fixture.now,
	); err == nil {
		t.Fatal("revoked authenticate key issued a session")
	}
}
