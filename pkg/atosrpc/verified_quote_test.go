package atosrpc

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	bolt "go.etcd.io/bbolt"
)

func verifiedQuoteFixture(t *testing.T) (*Server, *atostosv1.QuoteCommitmentInput) {
	t.Helper()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	s, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "state.db"), BearerToken: "test", Authority: new(verifiedTestAuthority), EconomicDriver: new(verifiedTestEconomy), Now: func() time.Time { return now }, TrustDomain: "atos.im"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, id := range []string{"agent-requester", "provider-1"} {
		if err := s.SeedIdentity(&atostosv1.AgentIdentity{AgentId: id, CanonicalUri: "atos://" + id, Controllers: []string{testCanonicalController(byte(len(id)))}, IdentityRef: &NetworkReference{Network: "tos-test", Reference: "identity:" + id, Finalized: true}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.bindPrincipal("principal-requester", "agent-requester"); err != nil {
		t.Fatal(err)
	}
	if err := s.bindPrincipal("provider-1", "provider-1"); err != nil {
		t.Fatal(err)
	}
	manifest := digestMessage([]byte("manifest"))
	capResp, err := s.CommitCapabilityManifest(context.Background(), connect.NewRequest(&atostosv1.CommitCapabilityManifestRequest{Context: mutationContext("manifest-1"), CapabilityId: "cap-1", ProviderId: "provider-1", Version: "1.0.0", ManifestDigest: manifest, RequestedTrustModes: []atostosv1.TrustMode{atostosv1.TrustMode_TRUST_MODE_VERIFIED}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(capResp.Msg.Capability.ActiveTrustModes) == 0 {
		capResp.Msg.Capability.ActiveTrustModes = []atostosv1.TrustMode{atostosv1.TrustMode_TRUST_MODE_VERIFIED}
		if err := s.store.update(func(tx *bolt.Tx) error {
			return s.store.putProto(tx, bucketCapabilities, capabilityKey("cap-1", "1.0.0"), capResp.Msg.Capability)
		}); err != nil {
			t.Fatal(err)
		}
	}
	authResp, err := s.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(&atostosv1.AuthorizeExecutionSignerRequest{Context: mutationContext("auth-1"), Authorization: &atostosv1.ExecutionSignerAuthorizationInput{AuthorizationId: "auth-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", ExecutionSignerId: "signer-1", SignerPublicKey: make([]byte, 32), SignatureAlgorithm: "ed25519", ValidFromUnixMillis: now.Add(-time.Hour).UnixMilli(), ValidUntilUnixMillis: now.Add(time.Hour).UnixMilli()}}))
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(10 * time.Minute).UnixMilli()
	q := &atostosv1.QuoteCommitmentInput{QuoteId: "quote-1", PrincipalId: "principal-requester", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, TotalMax: &atostosv1.Money{Amount: "1.05", Currency: "USD"}, TermsDigest: digestMessage([]byte("terms")), ExpiresUnixMillis: expires, Version: verifiedQuoteVersion, NetworkId: "tos-test", Domain: "atos.im", RequesterAgentId: "agent-requester", ManifestDigest: manifest, OwnershipRef: capResp.Msg.Capability.OwnershipRef, Subtotal: &atostosv1.Money{Amount: "1.00", Currency: "USD"}, Fees: &atostosv1.Money{Amount: "0.05", Currency: "USD"}, AssetDecimals: 2, AcceptanceDeadlineUnixMillis: expires, ExecutionDeadlineUnixMillis: now.Add(20 * time.Minute).UnixMilli(), SignerAuthorizationId: "auth-1", SignerAuthorizationRef: authResp.Msg.Authorization.AuthorizationRef, SettlementBackend: "tos", SettlementAsset: "TOS"}
	return s, q
}

func TestVerifiedQuoteCommitmentReplayConflictAndRecovery(t *testing.T) {
	s, q := verifiedQuoteFixture(t)
	ctx := context.Background()
	request := func(value *atostosv1.QuoteCommitmentInput) *connect.Request[atostosv1.CommitQuoteRequest] {
		return connect.NewRequest(&atostosv1.CommitQuoteRequest{Context: mutationContext(value.QuoteId), Quote: value})
	}
	first, err := s.CommitQuote(ctx, request(q))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Msg.Created || !first.Msg.Quote.CommitmentRef.Finalized {
		t.Fatalf("first=%+v", first.Msg)
	}
	if got := fmt.Sprintf("sha256:%x", first.Msg.Quote.CommitmentDigest.Value); got != "sha256:fe88505b6e6404e97b02973e189ae008e896a46449806706ec2259f621998043" {
		t.Fatalf("commitment vector digest=%s", got)
	}
	replay, err := s.CommitQuote(ctx, request(q))
	if err != nil {
		t.Fatal(err)
	}
	if replay.Msg.Quote.CommitmentRef.Reference != first.Msg.Quote.CommitmentRef.Reference {
		t.Fatal("exact replay diverged")
	}
	got, err := s.GetQuoteCommitment(ctx, connect.NewRequest(&atostosv1.GetQuoteCommitmentRequest{Context: readContext("get-quote"), QuoteId: q.QuoteId}))
	if err != nil || !got.Msg.Found || got.Msg.Quote.CommitmentDigest == nil {
		t.Fatalf("get=%+v err=%v", got, err)
	}
	changed := cloneMessage(q)
	changed.TotalMax.Amount = "2.05"
	if _, err := s.CommitQuote(ctx, request(changed)); err == nil {
		t.Fatal("changed semantics replay succeeded")
	}
}

func TestVerifiedQuoteRejectsNetworkManifestAndRevokedSignerSubstitution(t *testing.T) {
	s, q := verifiedQuoteFixture(t)
	ctx := context.Background()
	request := func(value *atostosv1.QuoteCommitmentInput) *connect.Request[atostosv1.CommitQuoteRequest] {
		return connect.NewRequest(&atostosv1.CommitQuoteRequest{Context: mutationContext(value.QuoteId), Quote: value})
	}
	cross := cloneMessage(q)
	cross.NetworkId = "tos-other"
	if _, err := s.CommitQuote(ctx, request(cross)); err == nil {
		t.Fatal("cross-network quote succeeded")
	}
	manifest := cloneMessage(q)
	manifest.QuoteId = "quote-manifest"
	manifest.ManifestDigest = digestMessage([]byte("other"))
	if _, err := s.CommitQuote(ctx, request(manifest)); err == nil {
		t.Fatal("manifest substitution succeeded")
	}
	if _, err := s.RevokeExecutionSigner(ctx, connect.NewRequest(&atostosv1.RevokeExecutionSignerRequest{Context: mutationContext("revoke-auth"), AuthorizationId: "auth-1", ReasonCode: "rotated"})); err != nil {
		t.Fatal(err)
	}
	revoked := cloneMessage(q)
	revoked.QuoteId = "quote-revoked"
	if _, err := s.CommitQuote(ctx, request(revoked)); err == nil {
		t.Fatal("revoked signer quote succeeded")
	}
}
