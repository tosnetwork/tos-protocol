package receiptcommitment

import (
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"testing"
)

func TestCanonicalReceiptRejectsUnknownAndSignatureIsExcluded(t *testing.T) {
	r := &atostosv1.ExecutionReceiptEnvelope{ReceiptId: "r", QuoteId: "q", EscrowId: "e", JobId: "j", PrincipalId: "p", ProviderId: "v", CapabilityId: "c", CapabilityVersion: "1", TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Result: atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS, SignatureAlgorithm: "ed25519"}
	a, e := Digest(r)
	if e != nil {
		t.Fatal(e)
	}
	r.Signature = []byte{1, 2, 3}
	b, e := Digest(r)
	if e != nil {
		t.Fatal(e)
	}
	if a != b {
		t.Fatal("signature changed semantic digest")
	}
	r.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if _, e := Digest(r); e == nil {
		t.Fatal("unknown field accepted")
	}
}
