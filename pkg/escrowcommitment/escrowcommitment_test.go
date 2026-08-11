package escrowcommitment

import (
	"strings"
	"testing"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

func vectorTerms() *atostosv1.VerifiedEscrowTerms {
	ref := func(value string) *atostosv1.NetworkReference {
		return &atostosv1.NetworkReference{Network: "tos-test", Reference: value, Finalized: true, FinalizedCheckpoint: 42}
	}
	digest := func(value string) *atostosv1.Digest {
		return &atostosv1.Digest{Algorithm: "sha256", Value: []byte(strings.Repeat(value, 32))}
	}
	v := &atostosv1.VerifiedEscrowTerms{Version: Version, Canonicalization: Canonicalization, NetworkId: "tos-test", Domain: "atos.im", JobId: "job-01", QuoteId: "quote-01", QuoteCommitmentDigest: "sha256:" + strings.Repeat("11", 32), QuoteCommitmentRef: ref("quote-tx"), PrincipalId: "principal-01", RequesterAgentId: "agent-requester-01", ProviderId: "provider-01", CapabilityId: "capability-01", CapabilityVersion: "1.0.0", ManifestDigest: digest("m"), OwnershipRef: ref("ownership-tx"), TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Reserve: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1050000000"}, Subtotal: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000000000"}, Fees: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "50000000"}, AssetDecimals: 9, SettlementBackend: "tos", SettlementAsset: "TOS", FundingModel: "gateway_sponsored", AcceptanceDeadlineUnixMillis: 1800000000000, ExecutionDeadlineUnixMillis: 1800000300000, EscrowDeadlineUnixMillis: 1800000300000, UnderlyingServiceQuoteRef: "service-quote-01", DisputePolicyDigest: digest("d"), SignerAuthorizationId: "auth-01", SignerAuthorizationRef: ref("auth-tx"), TermsDigest: digest("t")}
	v.EscrowId = EscrowID(v.NetworkId, v.Domain, v.QuoteId, v.JobId)
	return v
}

func TestNormativeVector(t *testing.T) {
	v := vectorTerms()
	encoded, err := Bytes(v)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(v)
	if err != nil {
		t.Fatal(err)
	}
	if v.EscrowId != "esc_07dc7a9bb743b890a44312c5d6d85a8a" ||
		digest != "sha256:271b8392229e741f86cbd9366f4fd35c09ce22b4a6a92f96bb7cdc68932149b5" || len(encoded) != 1384 {
		t.Fatalf("normative vector changed: id=%s digest=%s bytes=%d", v.EscrowId, digest, len(encoded))
	}
}
