package poscommitment

import (
	"encoding/hex"
	"testing"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

func TestNormativeVectorAndRoundTrip(t *testing.T) {
	b, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	v := &atostosv1.ProofOfServiceEvidenceInput{EvidenceId: "pos_receipt-1", ReceiptId: "receipt-1", ProviderId: "provider-1", CapabilityId: "capability-1", CapabilityVersion: "1.2.3", Result: atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS, LatencyMillis: 42, SettlementVolume: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "700"}, EvidenceDigest: &atostosv1.Digest{Algorithm: "sha256", Value: b}, ObservedUnixMillis: 1_800_000_000_123}
	encoded, err := Bytes(v)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(v)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:039eb30e9a6af1d33a8cc49f4b6c2dc5446572da1fa59d7e33d2af87eba4cb64"
	if digest != want {
		t.Fatalf("digest=%s\ncbor=%x", digest, encoded)
	}
	rebuilt, err := Proto(encoded)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Digest(rebuilt)
	if err != nil || again != digest {
		t.Fatalf("round trip digest=%s err=%v", again, err)
	}
}
