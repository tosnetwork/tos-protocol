package disputecommitment

import (
	"strings"
	"testing"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

func testDigest(b byte) *atostosv1.Digest {
	return &atostosv1.Digest{Algorithm: "sha256", Value: []byte(strings.Repeat(string([]byte{b}), 32))}
}

func TestNormativeVerifiedDisputeVectors(t *testing.T) {
	open := &atostosv1.VerifiedDisputeOpen{Version: "atos_verified_dispute_open_v1", NetworkId: "tos-test", GatewayDomain: "atos.im", DisputeId: "dispute-1", EscrowId: "escrow-1", JobId: "job-1", QuoteId: "quote-1", ReceiptId: "receipt-1", PrincipalId: "principal-1", ProviderId: "provider-1", CapabilityId: "cap-1", CapabilityVersion: "1.0.0", QuoteCommitmentDigest: "sha256:" + strings.Repeat("11", 32), ReservationDigest: "sha256:" + strings.Repeat("22", 32), ReceiptDigest: "sha256:" + strings.Repeat("33", 32), DisputePolicyDigest: testDigest(0x44), ReasonCode: "OUTPUT_MISMATCH", EvidenceDigests: []*atostosv1.Digest{testDigest(0x66), testDigest(0x55)}, OpenedUnixMillis: 1800000000123}
	got, err := OpenDigest(open)
	if err != nil {
		t.Fatal(err)
	}
	const wantOpen = "sha256:143021614f8f6c93619a50f1a352937403c33d89a7dfd1c1cf1444f42ae486b8"
	if got != wantOpen {
		t.Fatalf("open digest=%s want=%s", got, wantOpen)
	}
	open.EvidenceDigests[0], open.EvidenceDigests[1] = open.EvidenceDigests[1], open.EvidenceDigests[0]
	if reordered, err := OpenDigest(open); err != nil || reordered != wantOpen {
		t.Fatalf("evidence ordering changed commitment: %s %v", reordered, err)
	}
	resolution := &atostosv1.VerifiedDisputeResolution{Version: "atos_verified_dispute_resolution_v1", NetworkId: "tos-test", GatewayDomain: "atos.im", DisputeId: "dispute-1", EscrowId: "escrow-1", JobId: "job-1", QuoteId: "quote-1", ReceiptId: "receipt-1", DisputeDigest: wantOpen, Outcome: "principal", ReviewerPrincipalId: "reviewer-1", Reserved: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, ProviderPayout: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "0"}, RequesterRefund: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, ResolvedUnixMillis: 1800000100123}
	got, err = ResolutionDigest(resolution)
	if err != nil {
		t.Fatal(err)
	}
	const wantResolution = "sha256:bf86f1a0e42166185db786ff2c1dc5ffc5a60cb17e95a27160800ac0febb399b"
	if got != wantResolution {
		t.Fatalf("resolution digest=%s want=%s", got, wantResolution)
	}
	open.EvidenceDigests = append(open.EvidenceDigests, open.EvidenceDigests[0])
	if _, err := OpenDigest(open); err == nil {
		t.Fatal("duplicate evidence digest accepted")
	}
}
