package verifiedproof

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/disputecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/poscommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/receiptcommitment"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testObserver struct{ signer SignerObservation }

func (o testObserver) Observe(_ context.Context, r EvidenceRequest) (EvidenceObservation, error) {
	return EvidenceObservation{Found: true, Network: r.Reference.Network, Kind: r.Kind, ObjectID: r.ObjectID, Digest: r.Digest, Reference: r.Reference.Reference, Finalized: true, FinalizedCheckpoint: r.Reference.FinalizedCheckpoint}, nil
}
func (o testObserver) ResolveSigner(_ context.Context, _ Package) (SignerObservation, error) {
	return o.signer, nil
}

type fixedIdentityObserver struct{ testObserver }

func (o fixedIdentityObserver) Observe(ctx context.Context, r EvidenceRequest) (EvidenceObservation, error) {
	if r.Kind == "identity" {
		if r.ObjectID == "agent-1" && (r.Package.RequesterIdentity.CanonicalURI != "tos://agent/agent-1" || r.Package.RequesterIdentity.Controllers[0] != "0:"+strings.Repeat("1", 64)) {
			return EvidenceObservation{}, errors.New("requester identity tuple mismatch")
		}
		if r.ObjectID == "provider-1" && r.Package.ProviderIdentity.CanonicalURI != "tos://agent/provider-1" {
			return EvidenceObservation{}, errors.New("provider identity tuple mismatch")
		}
	}
	return o.testObserver.Observe(ctx, r)
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
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	p := Package{Version: Version, Canonicalization: Canonicalization, NetworkID: "tos-test", GatewayDomain: "atos.im", PrincipalID: "principal-1", RequesterAgentID: "agent-1", RequesterIdentityRef: ref("tos-test", "id-requester", 10), ProviderID: "provider-1", ProviderIdentityRef: ref("tos-test", "id-provider", 10), Capability: Capability{"cap-1", "1.0.0", d(1), ref("tos-test", "ownership", 11)}, Quote: Quote{QuoteID: "quote-1", CommitmentDigest: d(2), CommitmentRef: ref("tos-test", "quote", 12), TermsDigest: d(3), TrustMode: "verified", ProofProfile: "tos_verified_v1", SettlementBackend: "tos", SettlementAsset: "TOS", AssetDecimals: 9, SubtotalAtomic: "1000", FeesAtomic: "0", TotalMaxAtomic: "1000", AcceptanceDeadlineUnixNanos: 1_000_000, QuoteExpiryUnixNanos: 2_000_000, ExecutionDeadlineUnixNanos: 3_000_000, UnderlyingServiceQuoteRef: "service-quote", DisputePolicyDigest: d(4)}, Escrow: Escrow{EscrowID: "esc-1", JobID: "job-1", ContractRef: ref("tos-test", "contract", 13), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("5", 64), ReservationDigest: d(6), ReservationRef: ref("tos-test", "reserve", 13), ReservedAtomic: "1000", EscrowDeadlineUnixNanos: 4_000_000, FundingModel: "gateway_sponsored"}, SignerAuthorization: &SignerAuthorization{"auth-1", "signer-1", ref("tos-test", "auth", 11), "ed25519", pub, 0, 100000000}, Receipt: &Receipt{"receipt-1", "", ref("tos-test", "receipt", 14), "success", d(8), d(9), d(10), 10000000, 20000000, "700", "ed25519", nil, nil}, Outcome: Outcome{Kind: "provider_settlement", OutcomeRef: ref("tos-test", "settle", 15), ChargedAtomic: "700", RefundedAtomic: "300"}, ProofOfService: &ProofOfService{EvidenceID: "pos-1", EvidenceRef: ref("tos-test", "pos", 16), ContentDigest: d(12)}}
	qi := &atostosv1.QuoteCommitmentInput{Version: quotecommitment.Version, Canonicalization: quotecommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", QuoteId: "quote-1", PrincipalId: "principal-1", RequesterAgentId: "agent-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", ManifestDigest: pd(d(1)), TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Subtotal: &atostosv1.Money{Amount: "0.000001000", Currency: "TOS"}, Fees: &atostosv1.Money{Amount: "0.000000000", Currency: "TOS"}, TotalMax: &atostosv1.Money{Amount: "0.000001000", Currency: "TOS"}, AssetDecimals: 9, TermsDigest: pd(d(3)), DisputePolicyDigest: pd(d(4)), AcceptanceDeadlineUnixMillis: 1, ExpiresUnixMillis: 2, ExecutionDeadlineUnixMillis: 3, SettlementBackend: "tos", SettlementAsset: "TOS", UnderlyingServiceQuoteRef: "service-quote", SignerAuthorizationId: "auth-1", SignerAuthorizationRef: &atostosv1.NetworkReference{Network: "tos-test", Reference: "auth"}}
	p.RequesterIdentity = Identity{AgentID: "agent-1", CanonicalURI: "tos://agent/agent-1", Controllers: []string{"0:" + strings.Repeat("1", 64)}, Assurance: "tos_chain_verified", IdentityRef: ref("tos-test", "identity-requester", 9)}
	p.ProviderIdentity = Identity{AgentID: "provider-1", CanonicalURI: "tos://agent/provider-1", Controllers: []string{"0:" + strings.Repeat("2", 64)}, Assurance: "tos_chain_verified", IdentityRef: ref("tos-test", "identity-provider", 9)}
	p.ProviderAgentID = "provider-1"
	p.Quote.CanonicalCBOR, _ = quotecommitment.Bytes(qi)
	p.Quote.CommitmentDigest, _ = quotecommitment.Digest(qi)
	ei := &atostosv1.VerifiedEscrowTerms{Version: escrowcommitment.Version, Canonicalization: escrowcommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", EscrowId: "esc-1", JobId: "job-1", QuoteId: "quote-1", QuoteCommitmentDigest: p.Quote.CommitmentDigest, QuoteCommitmentRef: &atostosv1.NetworkReference{Network: "tos-test", Reference: "quote"}, PrincipalId: "principal-1", RequesterAgentId: "agent-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", ManifestDigest: pd(d(1)), TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Reserve: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, AssetDecimals: 9, SettlementBackend: "tos", SettlementAsset: "TOS", FundingModel: "gateway_sponsored", AcceptanceDeadlineUnixMillis: 1, ExecutionDeadlineUnixMillis: 3, EscrowDeadlineUnixMillis: 4, UnderlyingServiceQuoteRef: "service-quote", DisputePolicyDigest: pd(d(4)), TermsDigest: pd(d(3)), Subtotal: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, Fees: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "0"}, SignerAuthorizationId: "auth-1", SignerAuthorizationRef: &atostosv1.NetworkReference{Network: "tos-test", Reference: "auth"}}
	p.Escrow.CanonicalCBOR, _ = escrowcommitment.Bytes(ei)
	p.Escrow.ReservationDigest, _ = escrowcommitment.Digest(ei)
	env := &atostosv1.ExecutionReceiptEnvelope{ReceiptId: "receipt-1", QuoteId: "quote-1", EscrowId: "esc-1", JobId: "job-1", PrincipalId: "principal-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Result: atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS, InputCommitment: pd(d(8)), OutputCommitment: pd(d(9)), UsageCommitment: pd(d(10)), NetworkCharge: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "700"}, ExecutionSignerId: "signer-1", SignerAuthorizationId: "auth-1", SignatureAlgorithm: "ed25519", StartedUnixMillis: 10, CompletedUnixMillis: 20}
	p.Receipt.CanonicalCBOR, _ = receiptcommitment.Bytes(env)
	raw, receiptDigest, err := ReceiptSigningDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Receipt.ReceiptDigest = receiptDigest
	p.Receipt.Signature = ed25519.Sign(priv, raw)
	pos := &atostosv1.ProofOfServiceEvidenceInput{EvidenceId: "pos-1", ReceiptId: "receipt-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", Result: atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS, EvidenceDigest: pd(d(12)), SettlementVolume: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "700"}, ObservedUnixMillis: 20}
	p.ProofOfService.CanonicalCBOR, _ = poscommitment.Bytes(pos)
	p.ProofOfService.EvidenceDigest, _ = poscommitment.Digest(pos)
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
func TestNormativeVector(t *testing.T) {
	p := fixture(t)
	b, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Digest(p)
	if err != nil {
		t.Fatal(err)
	}
	const expectedDigest = "sha256:39dedf1543cad32e3e592b5dc12c5d6d80941c4956bec5de155aadeeda4535a2"
	if d != expectedDigest {
		t.Fatalf("digest=%s\ncbor=%x", d, b)
	}
	vector := struct {
		Version  string `json:"version"`
		Positive struct {
			CanonicalCBORBase64 string `json:"canonical_cbor_base64"`
			PackageDigest       string `json:"package_digest"`
		} `json:"positive"`
		NegativeMutations []string `json:"negative_mutations"`
	}{}
	path := filepath.Join("testdata", "tos_verified_v1.json")
	if os.Getenv("UPDATE_VERIFIED_PROOF_VECTOR") == "1" {
		vector.Version = Version
		vector.Positive.CanonicalCBORBase64 = base64.StdEncoding.EncodeToString(b)
		vector.Positive.PackageDigest = d
		vector.NegativeMutations = []string{"requester_agent_id", "requester_identity.controller", "provider_identity.canonical_uri", "subtotal_atomic", "execution_deadline_unix_nanos", "underlying_service_quote_ref", "receipt.started_unix_nanos", "receipt.signature_algorithm", "signer_authorization.signature_algorithm", "requester_release.partial_refund", "dispute_resolution.outcome", "dispute_resolution.resolution_digest", "finality_checkpoint_regression", "network_id"}
		encoded, marshalErr := json.MarshalIndent(vector, "", "  ")
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.MkdirAll(filepath.Dir(path), 0755); writeErr != nil {
			t.Fatal(writeErr)
		}
		if writeErr := os.WriteFile(path, append(encoded, '\n'), 0644); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	encoded, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if unmarshalErr := json.Unmarshal(encoded, &vector); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if vector.Version != Version || vector.Positive.PackageDigest != d || vector.Positive.CanonicalCBORBase64 != base64.StdEncoding.EncodeToString(b) || len(vector.NegativeMutations) < 12 {
		t.Fatalf("normative vector artifact differs from implementation")
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

func TestRejectsEveryRepeatedCanonicalFieldMutation(t *testing.T) {
	base := fixture(t)
	observer := fixedIdentityObserver{testObserver{SignerObservation{Found: true, Network: base.NetworkID, AuthorizationID: base.SignerAuthorization.AuthorizationID, ProviderID: base.ProviderID, CapabilityID: base.Capability.CapabilityID, CapabilityVersion: base.Capability.CapabilityVersion, SignerID: base.SignerAuthorization.ExecutionSignerID, Reference: base.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: base.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100000000}}}
	cases := map[string]func(*Package){
		"requester agent":         func(p *Package) { p.RequesterAgentID = "attacker-agent" },
		"requester controller":    func(p *Package) { p.RequesterIdentity.Controllers = []string{"0:" + strings.Repeat("3", 64)} },
		"provider canonical URI":  func(p *Package) { p.ProviderIdentity.CanonicalURI = "tos://agent/attacker" },
		"subtotal":                func(p *Package) { p.Quote.SubtotalAtomic = "1" },
		"execution deadline":      func(p *Package) { p.Quote.ExecutionDeadlineUnixNanos = 99_000_000 },
		"underlying quote":        func(p *Package) { p.Quote.UnderlyingServiceQuoteRef = "attacker-quote" },
		"receipt start":           func(p *Package) { p.Receipt.StartedUnixNanos = 1 },
		"receipt algorithm":       func(p *Package) { p.Receipt.SignatureAlgorithm = "attacker" },
		"authorization algorithm": func(p *Package) { p.SignerAuthorization.SignatureAlgorithm = "attacker" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if got := (Verifier{Observer: observer, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p); got.Valid {
				t.Fatalf("mutated package verified: %+v", got)
			}
		})
	}
}

func TestRequesterReleaseRequiresFullRefund(t *testing.T) {
	p := fixture(t)
	p.SignerAuthorization, p.Receipt, p.ProofOfService = nil, nil, nil
	p.Outcome = Outcome{Kind: "requester_release", OutcomeRef: ref("tos-test", "release", 15), ChargedAtomic: "500", RefundedAtomic: "500", ReleaseDigest: d(13), ReasonCode: "canceled"}
	if got := (Verifier{Observer: testObserver{}, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p); got.Valid {
		t.Fatal("partial requester release verified")
	}
}

func TestSignerRevocationIsEvaluatedAtReceiptTime(t *testing.T) {
	p := fixture(t)
	base := SignerObservation{Found: true, Revoked: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100000000}
	after := base
	after.RevokedUnixNanos = p.Receipt.CompletedUnixNanos + 1
	if got := (Verifier{Observer: testObserver{after}, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p); !got.Valid {
		t.Fatalf("post-execution revocation invalidated history: %+v", got.Failures)
	}
	before := base
	before.RevokedUnixNanos = p.Receipt.CompletedUnixNanos
	if got := (Verifier{Observer: testObserver{before}, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p); got.Valid {
		t.Fatal("revocation effective at execution was accepted")
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

func TestDisputeOutcomeDoesNotRewriteSignedReceiptCharge(t *testing.T) {
	p := fixture(t)
	resolution := &atostosv1.VerifiedDisputeResolution{Version: "atos_verified_dispute_resolution_v1", NetworkId: "tos-test", GatewayDomain: "atos.im", DisputeId: "dispute-1", EscrowId: "esc-1", JobId: "job-1", QuoteId: "quote-1", ReceiptId: "receipt-1", DisputeDigest: d(13), Outcome: "principal", ReviewerPrincipalId: "reviewer-1", Reserved: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, ProviderPayout: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "0"}, RequesterRefund: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, ResolvedUnixMillis: 21}
	resolutionCBOR, _ := disputecommitment.ResolutionBytes(resolution)
	resolutionDigest, _ := disputecommitment.ResolutionDigest(resolution)
	p.Outcome = Outcome{Kind: "dispute_resolution", OutcomeRef: ref("tos-test", "resolution", 18), ChargedAtomic: "0", RefundedAtomic: "1000", DisputeDigest: d(13), DisputeRef: ref("tos-test", "dispute", 17), ResolutionDigest: resolutionDigest, ResolutionRef: ref("tos-test", "resolution-commitment", 18), DisputeOutcome: "principal", ResolutionCBOR: resolutionCBOR}
	o := testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidFromUnixNanos: 0, ValidUntilUnixNanos: 100000000, FinalizedCheckpoint: 11}}
	r := (Verifier{Observer: o, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p)
	if !r.Valid {
		t.Fatalf("a dispute payout must not rewrite the signed Receipt charge: %+v", r.Failures)
	}
	p.Outcome.DisputeOutcome = "attacker"
	if got := (Verifier{Observer: o, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p); got.Valid {
		t.Fatal("self-attested dispute outcome verified")
	}
}
