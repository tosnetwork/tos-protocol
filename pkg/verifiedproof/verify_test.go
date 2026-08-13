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
	"strconv"
	"strings"
	"testing"
)

type testObserver struct{ signer SignerObservation }

func (o testObserver) Observe(_ context.Context, r EvidenceRequest) (EvidenceObservation, error) {
	observation := EvidenceObservation{Found: true, Network: r.Reference.Network, Kind: r.Kind, ObjectID: r.ObjectID, Digest: r.Digest, Reference: r.Reference.Reference, Finalized: true, FinalizedCheckpoint: r.Reference.FinalizedCheckpoint}
	if r.Kind == "verified-receipt" {
		observation.ObservedUnixNanos = 20_000_000
	}
	return observation, nil
}
func (o testObserver) ResolveSigner(_ context.Context, _ Package, _ int64) (SignerObservation, error) {
	return o.signer, nil
}

type receiptTimeObserver struct {
	testObserver
	observedUnixNanos int64
	wantSignerTime    int64
}

func (o receiptTimeObserver) Observe(ctx context.Context, r EvidenceRequest) (EvidenceObservation, error) {
	observation, err := o.testObserver.Observe(ctx, r)
	if r.Kind == "verified-receipt" {
		observation.ObservedUnixNanos = o.observedUnixNanos
	}
	return observation, err
}

func (o receiptTimeObserver) ResolveSigner(ctx context.Context, p Package, effectiveReceiptUnixNanos int64) (SignerObservation, error) {
	if effectiveReceiptUnixNanos != o.wantSignerTime {
		return SignerObservation{}, errors.New("signer resolution did not use canonical receipt authority time")
	}
	return o.testObserver.ResolveSigner(ctx, p, effectiveReceiptUnixNanos)
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
	p := Package{Version: Version, Canonicalization: Canonicalization, NetworkID: "tos-test", GatewayDomain: "atos.im", PrincipalID: "principal-1", RequesterAgentID: "agent-1", RequesterIdentityRef: ref("tos-test", "id-requester", 10), ProviderID: "provider-1", ProviderIdentityRef: ref("tos-test", "id-provider", 10), Capability: Capability{"cap-1", "1.0.0", d(1), d(15), ref("tos-test", "ownership", 11)}, Quote: Quote{QuoteID: "quote-1", CommitmentDigest: d(2), CommitmentRef: ref("tos-test", "quote", 12), TermsDigest: d(3), TrustMode: "verified", ProofProfile: "tos_verified_v1", SettlementBackend: "tos", SettlementAsset: "TOS", AssetDecimals: 9, SubtotalAtomic: "1000", FeesAtomic: "0", TotalMaxAtomic: "1000", AcceptanceDeadlineUnixNanos: 10_000_000, QuoteExpiryUnixNanos: 20_000_000, ExecutionDeadlineUnixNanos: 30_000_000, UnderlyingServiceQuoteRef: "service-quote", DisputePolicyDigest: d(4)}, Escrow: Escrow{EscrowID: "esc-1", JobID: "job-1", ContractRef: ref("tos-test", "contract", 13), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("5", 64), ReservationDigest: d(6), ReservationRef: ref("tos-test", "reserve", 13), ReservedAtomic: "1000", EscrowDeadlineUnixNanos: 40_000_000, FundingModel: "gateway_sponsored"}, SignerAuthorization: &SignerAuthorization{"auth-1", "signer-1", ref("tos-test", "auth", 11), "ed25519", pub, 0, 100000000}, Receipt: &Receipt{"receipt-1", "", ref("tos-test", "receipt", 14), "success", d(8), d(9), d(10), 10000000, 20000000, "700", "ed25519", nil, nil}, Outcome: Outcome{Kind: "provider_settlement", OutcomeRef: ref("tos-test", "settle", 15), ChargedAtomic: "700", RefundedAtomic: "300"}, ProofOfService: &ProofOfService{EvidenceID: "pos-1", EvidenceRef: ref("tos-test", "pos", 16), ContentDigest: d(12)}}
	qi := &atostosv1.QuoteCommitmentInput{Version: quotecommitment.Version, Canonicalization: quotecommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", QuoteId: "quote-1", PrincipalId: "principal-1", RequesterAgentId: "agent-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", ManifestDigest: pd(d(1)), TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Subtotal: &atostosv1.Money{Amount: "0.000001000", Currency: "TOS"}, Fees: &atostosv1.Money{Amount: "0.000000000", Currency: "TOS"}, TotalMax: &atostosv1.Money{Amount: "0.000001000", Currency: "TOS"}, AssetDecimals: 9, TermsDigest: pd(d(3)), DisputePolicyDigest: pd(d(4)), AcceptanceDeadlineUnixMillis: 10, ExpiresUnixMillis: 20, ExecutionDeadlineUnixMillis: 30, SettlementBackend: "tos", SettlementAsset: "TOS", UnderlyingServiceQuoteRef: "service-quote", SignerAuthorizationId: "auth-1", SignerAuthorizationRef: &atostosv1.NetworkReference{Network: "tos-test", Reference: "auth"}}
	p.RequesterIdentity = Identity{AgentID: "agent-1", CanonicalURI: "tos://agent/agent-1", Controllers: []string{"0:" + strings.Repeat("1", 64)}, Assurance: "tos_chain_verified", IdentityRef: ref("tos-test", "identity-requester", 9)}
	p.ProviderIdentity = Identity{AgentID: "provider-1", CanonicalURI: "tos://agent/provider-1", Controllers: []string{"0:" + strings.Repeat("2", 64)}, Assurance: "tos_chain_verified", IdentityRef: ref("tos-test", "identity-provider", 9)}
	p.ProviderAgentID = "provider-1"
	p.Quote.CanonicalCBOR, _ = quotecommitment.Bytes(qi)
	p.Quote.CommitmentDigest, _ = quotecommitment.Digest(qi)
	ei := &atostosv1.VerifiedEscrowTerms{Version: escrowcommitment.Version, Canonicalization: escrowcommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", EscrowId: "esc-1", JobId: "job-1", QuoteId: "quote-1", QuoteCommitmentDigest: p.Quote.CommitmentDigest, QuoteCommitmentRef: &atostosv1.NetworkReference{Network: "tos-test", Reference: "quote"}, PrincipalId: "principal-1", RequesterAgentId: "agent-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", ManifestDigest: pd(d(1)), TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Reserve: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, AssetDecimals: 9, SettlementBackend: "tos", SettlementAsset: "TOS", FundingModel: "gateway_sponsored", AcceptanceDeadlineUnixMillis: 10, ExecutionDeadlineUnixMillis: 30, EscrowDeadlineUnixMillis: 40, UnderlyingServiceQuoteRef: "service-quote", DisputePolicyDigest: pd(d(4)), TermsDigest: pd(d(3)), Subtotal: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, Fees: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "0"}, SignerAuthorizationId: "auth-1", SignerAuthorizationRef: &atostosv1.NetworkReference{Network: "tos-test", Reference: "auth"}}
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

func TestVerifierRejectsMissingNetworkOrDomainPin(t *testing.T) {
	p := fixture(t)
	o := testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100000000}}
	for name, verifier := range map[string]Verifier{
		"network": {Observer: o, GatewayDomain: "atos.im"},
		"domain":  {Observer: o, Network: "tos-test"},
		"both":    {Observer: o},
	} {
		t.Run(name, func(t *testing.T) {
			result := verifier.Verify(context.Background(), p)
			if result.Valid || len(result.Failures) != 1 || result.Failures[0].Field != "verifier" {
				t.Fatalf("unpinned verifier result=%+v", result)
			}
		})
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
	const expectedDigest = "sha256:c2a6baf7e500b98062f86f84a52ebf18e7d81c96fa14d725b88a9e822047f09a"
	if d != expectedDigest {
		t.Fatalf("digest=%s\ncbor_base64=%s", d, base64.StdEncoding.EncodeToString(b))
	}
	vector := struct {
		Version  string `json:"version"`
		Positive struct {
			CanonicalCBORBase64 string `json:"canonical_cbor_base64"`
			PackageDigest       string `json:"package_digest"`
		} `json:"positive"`
		NegativeMutations []struct {
			Name      string `json:"name"`
			Operation struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value any    `json:"value"`
			} `json:"operation"`
			ExpectedCode  Code   `json:"expected_code"`
			ExpectedField string `json:"expected_field"`
		} `json:"negative_mutations"`
	}{}
	path := filepath.Join("testdata", "tos_verified_v1.json")
	if os.Getenv("UPDATE_VERIFIED_PROOF_VECTOR") == "1" {
		vector.Version = Version
		vector.Positive.CanonicalCBORBase64 = base64.StdEncoding.EncodeToString(b)
		vector.Positive.PackageDigest = d
		t.Fatal("UPDATE_VERIFIED_PROOF_VECTOR must not discard executable negative mutation contracts")
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
		t.Fatalf("normative vector artifact differs from implementation: digest=%s cbor_base64=%s", d, base64.StdEncoding.EncodeToString(b))
	}
	for _, mutation := range vector.NegativeMutations {
		if mutation.Name == "" || mutation.Operation.Op != "replace" || !strings.HasPrefix(mutation.Operation.Path, "/") || mutation.ExpectedCode == "" || mutation.ExpectedField == "" {
			t.Fatalf("negative mutation is not executable: %+v", mutation)
		}
		t.Run(mutation.Name, func(t *testing.T) {
			mutated := applyJSONReplace(t, p, mutation.Operation.Path, mutation.Operation.Value)
			observer := fixedIdentityObserver{testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100000000, FinalizedCheckpoint: 11}}}
			got := (Verifier{Observer: observer, Network: "tos-test", GatewayDomain: "atos.im", MinimumCheckpoint: 9}).Verify(context.Background(), mutated)
			if got.Valid {
				t.Fatal("negative normative vector verified as VALID")
			}
			for _, failure := range got.Failures {
				if failure.Code == mutation.ExpectedCode && failure.Field == mutation.ExpectedField {
					return
				}
			}
			t.Fatalf("failures=%+v, want code=%s field=%s", got.Failures, mutation.ExpectedCode, mutation.ExpectedField)
		})
	}
}

func applyJSONReplace(t *testing.T, input Package, pointer string, value any) Package {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	var current = document
	for _, part := range parts[:len(parts)-1] {
		switch node := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = node[part]
			if !ok {
				t.Fatalf("RFC 6901 path does not exist: %s", pointer)
			}
		case []any:
			index, parseErr := strconv.Atoi(part)
			if parseErr != nil || index < 0 || index >= len(node) {
				t.Fatalf("invalid RFC 6901 array path: %s", pointer)
			}
			current = node[index]
		default:
			t.Fatalf("RFC 6901 path traverses scalar: %s", pointer)
		}
	}
	last := parts[len(parts)-1]
	switch node := current.(type) {
	case map[string]any:
		if _, ok := node[last]; !ok {
			t.Fatalf("RFC 6901 replace target does not exist: %s", pointer)
		}
		node[last] = value
	case []any:
		index, parseErr := strconv.Atoi(last)
		if parseErr != nil || index < 0 || index >= len(node) {
			t.Fatalf("invalid RFC 6901 array target: %s", pointer)
		}
		node[index] = value
	default:
		t.Fatalf("RFC 6901 replace target is scalar: %s", pointer)
	}
	mutatedJSON, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var output Package
	if err := json.Unmarshal(mutatedJSON, &output); err != nil {
		t.Fatalf("mutated package is not typed: %v", err)
	}
	return output
}
func TestRejectsNetworkSignerOutcomeAndNonCanonicalCBOR(t *testing.T) {
	p := fixture(t)
	o := testObserver{SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100000000}}
	p.NetworkID = "tos-other"
	p.Outcome.RefundedAtomic = "301"
	r := (Verifier{Observer: o, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p)
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

func TestSignerRevocationCannotBeBypassedByBackdatedReceipt(t *testing.T) {
	p := fixture(t)
	signer := SignerObservation{Found: true, Revoked: true, RevokedUnixNanos: 21_000_000, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100_000_000}
	observer := receiptTimeObserver{testObserver: testObserver{signer: signer}, observedUnixNanos: 25_000_000, wantSignerTime: 25_000_000}
	if got := (Verifier{Observer: observer, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p); got.Valid {
		t.Fatal("receipt anchored after signer revocation was accepted using its backdated completion time")
	}
}

func TestReceiptAuthorityTimeIsRequiredAndMustPrecedeDeadlines(t *testing.T) {
	p := fixture(t)
	signer := SignerObservation{Found: true, Network: p.NetworkID, AuthorizationID: p.SignerAuthorization.AuthorizationID, ProviderID: p.ProviderID, CapabilityID: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, SignerID: p.SignerAuthorization.ExecutionSignerID, Reference: p.SignerAuthorization.AuthorizationRef.Reference, SignatureAlgorithm: "ed25519", PublicKey: p.SignerAuthorization.SignerPublicKey, ValidUntilUnixNanos: 100_000_000}
	for name, observed := range map[string]int64{"missing": 0, "after execution deadline": 31_000_000} {
		t.Run(name, func(t *testing.T) {
			observer := receiptTimeObserver{testObserver: testObserver{signer: signer}, observedUnixNanos: observed, wantSignerTime: max(p.Receipt.CompletedUnixNanos, observed)}
			if got := (Verifier{Observer: observer, Network: "tos-test", GatewayDomain: "atos.im"}).Verify(context.Background(), p); got.Valid {
				t.Fatalf("receipt authority time %d was accepted", observed)
			}
		})
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
