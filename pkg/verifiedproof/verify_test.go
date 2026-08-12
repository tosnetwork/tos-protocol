package verifiedproof

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
func fixture(t *testing.T) Package {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := Package{Version: Version, Canonicalization: Canonicalization, NetworkID: "tos-test", GatewayDomain: "atos.im", PrincipalID: "principal-1", RequesterAgentID: "agent-1", RequesterIdentityRef: ref("tos-test", "id-requester", 10), ProviderID: "provider-1", ProviderIdentityRef: ref("tos-test", "id-provider", 10), Capability: Capability{"cap-1", "1.0.0", d(1), ref("tos-test", "ownership", 11)}, Quote: Quote{"quote-1", d(2), ref("tos-test", "quote", 12), d(3), "verified", "tos_verified_v1", "tos", "TOS", 9, "1000", "0", "1000", 1, 2, 3, "service-quote", d(4)}, Escrow: Escrow{"esc-1", "job-1", ref("tos-test", "contract", 13), d(5), d(6), ref("tos-test", "reserve", 13), "1000", 4, "task_escrow_v1"}, SignerAuthorization: SignerAuthorization{"auth-1", "signer-1", ref("tos-test", "auth", 11), "ed25519", pub, 0, 100}, Receipt: Receipt{"receipt-1", "", ref("tos-test", "receipt", 14), "success", d(8), d(9), d(10), 10, 20, "700", "ed25519", nil}, Outcome: Outcome{Kind: "provider_settlement", OutcomeRef: ref("tos-test", "settle", 15), ChargedAtomic: "700", RefundedAtomic: "300"}, ProofOfService: ProofOfService{"pos-1", d(11), ref("tos-test", "pos", 16), d(12), ""}}
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
	o := testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidFromUnixNanos: 0, ValidUntilUnixNanos: 100, FinalizedCheckpoint: 11}}
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
	o := testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100}}
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
