package atosrpc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
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
		if err := s.SeedIdentity(&atostosv1.AgentIdentity{AgentId: id, CanonicalUri: "atos://" + id, Controllers: []string{testCanonicalController(byte(len(id)))}, Assurance: "tos_attested", IdentityRef: &NetworkReference{Network: "tos-test", Reference: "identity:" + id, Finalized: true}}); err != nil {
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
	q := &atostosv1.QuoteCommitmentInput{QuoteId: "quote-1", PrincipalId: "principal-requester", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, TotalMax: &atostosv1.Money{Amount: "1.00", Currency: "USD"}, TermsDigest: digestMessage([]byte("terms")), DisputePolicyDigest: digestMessage([]byte("dispute-policy")), ExpiresUnixMillis: expires, Version: quotecommitment.Version, Canonicalization: quotecommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", RequesterAgentId: "agent-requester", ManifestDigest: manifest, OwnershipRef: capResp.Msg.Capability.OwnershipRef, Subtotal: &atostosv1.Money{Amount: "1.00", Currency: "USD"}, Fees: &atostosv1.Money{Amount: "0.00", Currency: "USD"}, AssetDecimals: 2, AcceptanceDeadlineUnixMillis: expires, ExecutionDeadlineUnixMillis: now.Add(20 * time.Minute).UnixMilli(), SignerAuthorizationId: "auth-1", SignerAuthorizationRef: authResp.Msg.Authorization.AuthorizationRef, SettlementBackend: "tos", SettlementAsset: "TOS", UnderlyingServiceQuoteRef: "service-quote-1"}
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
	if got := fmt.Sprintf("sha256:%x", first.Msg.Quote.CommitmentDigest.Value); got != "sha256:0e2349b842a815f0a1953d1015f0e7179ec8c868202661ccd490950636c70501" {
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

func TestVerifiedQuoteRejectsUnknownFieldsRecursively(t *testing.T) {
	s, q := verifiedQuoteFixture(t)
	q.TotalMax.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	_, err := s.CommitQuote(context.Background(), connect.NewRequest(&atostosv1.CommitQuoteRequest{Context: mutationContext(q.QuoteId), Quote: q}))
	if err == nil {
		t.Fatal("recursive protobuf unknown field was accepted")
	}
}

func TestVerifiedQuoteCanonicalLookupWorksOnIndependentReplicaAndFailsOnReorg(t *testing.T) {
	s, q := verifiedQuoteFixture(t)
	ctx := context.Background()
	committed, err := s.CommitQuote(ctx, connect.NewRequest(&atostosv1.CommitQuoteRequest{Context: mutationContext(q.QuoteId), Quote: q}))
	if err != nil {
		t.Fatal(err)
	}
	authority := s.authority.(*verifiedTestAuthority)
	other, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "other.db"), BearerToken: "test", Authority: authority, EconomicDriver: new(verifiedTestEconomy), Now: s.now, TrustDomain: "atos.im"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// Deliberately omit ExpectedCommitmentRef: this is the exact successful
	// CommitQuote/lost-response recovery shape on a replica with an empty
	// local bbolt cache.
	request := connect.NewRequest(&atostosv1.GetQuoteCommitmentRequest{Context: readContext("cross-replica"), QuoteId: q.QuoteId, ExpectedQuote: q})
	got, err := other.GetQuoteCommitment(ctx, request)
	if err != nil || !got.Msg.Found || got.Msg.Quote.CommitmentRef.Reference != committed.Msg.Quote.CommitmentRef.Reference {
		t.Fatalf("cross-replica lookup=%+v err=%v", got, err)
	}
	authority.resolveErr = errors.New("reorganized")
	if _, err := other.GetQuoteCommitment(ctx, request); err == nil {
		t.Fatal("reorganized commitment remained usable")
	}
	if _, err := s.CommitQuote(ctx, connect.NewRequest(&atostosv1.CommitQuoteRequest{Context: mutationContext(q.QuoteId), Quote: q})); err == nil {
		t.Fatal("cached CommitQuote replay bypassed live finality")
	}
}

func TestVerifiedQuoteRejectsMissingCommercialTerms(t *testing.T) {
	for name, mutate := range map[string]func(*atostosv1.QuoteCommitmentInput){
		"settlement backend": func(q *atostosv1.QuoteCommitmentInput) { q.SettlementBackend = "" },
		"settlement asset":   func(q *atostosv1.QuoteCommitmentInput) { q.SettlementAsset = "" },
		"service quote":      func(q *atostosv1.QuoteCommitmentInput) { q.UnderlyingServiceQuoteRef = "" },
		"dispute digest":     func(q *atostosv1.QuoteCommitmentInput) { q.DisputePolicyDigest = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s, q := verifiedQuoteFixture(t)
			mutate(q)
			_, err := s.CommitQuote(context.Background(), connect.NewRequest(&atostosv1.CommitQuoteRequest{Context: mutationContext(q.QuoteId), Quote: q}))
			if err == nil {
				t.Fatal("missing required commercial term was accepted")
			}
		})
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
