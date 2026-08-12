package verifiedproof

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/receiptcommitment"
	"testing"
)

type testObserver struct{ signer SignerObservation }

func (o testObserver) Observe(_ context.Context, r EvidenceRequest) (EvidenceObservation, error) {
	return EvidenceObservation{Found: true, Network: r.Reference.Network, Kind: r.Kind, ObjectID: r.ObjectID, Digest: r.Digest, Reference: r.Reference.Reference, Finalized: true, FinalizedCheckpoint: r.Reference.FinalizedCheckpoint}, nil
}
func (o testObserver) ResolveSigner(_ context.Context, _ Package) (SignerObservation, error) {
	return o.signer, nil
}
func d(c byte) string {
	const h = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = h[int(c)%16]
	}
	return "sha256:" + string(b)
}
func ref(n, s string, c uint64) Reference { return Reference{n, s, c} }
func pd(s string) *atostosv1.Digest {
	b, _ := hex.DecodeString(s[7:])
	return &atostosv1.Digest{Algorithm: "sha256", Value: b}
}
func fixture(t *testing.T) Package {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := Package{Version: Version, Canonicalization: Canonicalization, NetworkID: "tos-test", GatewayDomain: "atos.im", PrincipalID: "principal-1", RequesterAgentID: "agent-1", RequesterIdentityRef: ref("tos-test", "id-requester", 10), ProviderID: "provider-1", ProviderIdentityRef: ref("tos-test", "id-provider", 10), Capability: Capability{"cap-1", "1.0.0", d(1), ref("tos-test", "ownership", 11)}, Quote: Quote{"quote-1", d(2), ref("tos-test", "quote", 12), d(3), "verified", "tos_verified_v1", "tos", "TOS", 9, "1000", "0", "1000", 1, 2, 3, "service-quote", d(4), nil}, Escrow: Escrow{"esc-1", "job-1", ref("tos-test", "contract", 13), d(5), d(6), ref("tos-test", "reserve", 13), "1000", 4, "gateway_sponsored", nil}, SignerAuthorization: &SignerAuthorization{"auth-1", "signer-1", ref("tos-test", "auth", 11), "ed25519", pub, 0, 100000000}, Receipt: &Receipt{"receipt-1", "", ref("tos-test", "receipt", 14), "success", d(8), d(9), d(10), 10000000, 20000000, "700", "ed25519", nil, nil}, Outcome: Outcome{Kind: "provider_settlement", OutcomeRef: ref("tos-test", "settle", 15), ChargedAtomic: "700", RefundedAtomic: "300"}, ProofOfService: &ProofOfService{"pos-1", d(11), ref("tos-test", "pos", 16), d(12), ""}}
	qi := &atostosv1.QuoteCommitmentInput{Version: quotecommitment.Version, Canonicalization: quotecommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", QuoteId: "quote-1", PrincipalId: "principal-1", RequesterAgentId: "agent-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", ManifestDigest: pd(d(1)), TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Subtotal: &atostosv1.Money{Amount: "1000", Currency: "TOS"}, Fees: &atostosv1.Money{Amount: "0", Currency: "TOS"}, TotalMax: &atostosv1.Money{Amount: "1000", Currency: "TOS"}, AssetDecimals: 9, TermsDigest: pd(d(3)), DisputePolicyDigest: pd(d(4)), AcceptanceDeadlineUnixMillis: 0, ExpiresUnixMillis: 0, ExecutionDeadlineUnixMillis: 0, SettlementBackend: "tos", SettlementAsset: "TOS", UnderlyingServiceQuoteRef: "service-quote"}
	p.Quote.CanonicalCBOR, _ = quotecommitment.Bytes(qi)
	p.Quote.CommitmentDigest, _ = quotecommitment.Digest(qi)
	ei := &atostosv1.VerifiedEscrowTerms{Version: escrowcommitment.Version, Canonicalization: escrowcommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", EscrowId: "esc-1", JobId: "job-1", QuoteId: "quote-1", QuoteCommitmentDigest: p.Quote.CommitmentDigest, PrincipalId: "principal-1", RequesterAgentId: "agent-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", ManifestDigest: pd(d(1)), TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Reserve: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, AssetDecimals: 9, SettlementBackend: "tos", SettlementAsset: "TOS", FundingModel: "gateway_sponsored", DisputePolicyDigest: pd(d(4)), TermsDigest: pd(d(3))}
	p.Escrow.CanonicalCBOR, _ = escrowcommitment.Bytes(ei)
	p.Escrow.ReservationDigest, _ = escrowcommitment.Digest(ei)
	env := &atostosv1.ExecutionReceiptEnvelope{ReceiptId: "receipt-1", QuoteId: "quote-1", EscrowId: "esc-1", JobId: "job-1", PrincipalId: "principal-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Result: atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS, InputCommitment: pd(d(8)), OutputCommitment: pd(d(9)), UsageCommitment: pd(d(10)), NetworkCharge: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "700"}, ExecutionSignerId: "signer-1", SignerAuthorizationId: "auth-1", SignatureAlgorithm: "ed25519", CompletedUnixMillis: 20}
	p.Receipt.CanonicalCBOR, _ = receiptcommitment.Bytes(env)
	raw, receiptDigest, err := ReceiptSigningDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Receipt.ReceiptDigest = receiptDigest
	p.Receipt.Signature = ed25519.Sign(priv, raw)
	return p
}
func TestCanonicalRoundTripAndIndependentVerification(t *testing.T) {
	p := fixture(t)
	o := testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidFromUnixNanos: 0, ValidUntilUnixNanos: 100000000, FinalizedCheckpoint: 11}}
	b, e := Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	r := (Verifier{Observer: o, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), parsed)
	if !r.Valid {
		t.Fatalf("failures=%+v", r.Failures)
	}
}
func TestRejectsNetworkSignerOutcomeAndNonCanonicalCBOR(t *testing.T) {
	p := fixture(t)
	o := testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100000000}}
	p.NetworkID = "tos-other"
	p.Outcome.RefundedAtomic = "301"
	r := (Verifier{Observer: o, Network: "tos-test"}).Verify(context.Background(), p)
	if r.Valid || len(r.Failures) < 2 {
		t.Fatalf("result=%+v", r)
	}
	b, _ := Marshal(fixture(t))
	b = append(b, 0)
	if _, e := Parse(b); e == nil {
		t.Fatal("accepted trailing CBOR")
	}
}

func TestRequesterReleaseOmitsExecutionEvidenceAndStillVerifies(t *testing.T) {
	p := fixture(t)
	p.SignerAuthorization = nil
	p.Receipt = nil
	p.ProofOfService = nil
	p.Outcome = Outcome{Kind: "requester_release", OutcomeRef: ref("tos-test", "release", 15), ChargedAtomic: "0", RefundedAtomic: "1000", ReleaseDigest: d(13), ReasonCode: "canceled"}
	o := testObserver{}
	r := (Verifier{Observer: o, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p)
	if !r.Valid {
		t.Fatalf("failures=%+v", r.Failures)
	}
}
