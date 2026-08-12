package atosrpc

import (
	"bytes"
	"testing"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"google.golang.org/protobuf/proto"
)

func deterministicMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		t.Fatalf("deterministic marshal: %v", err)
	}
	return encoded
}

func sampleAipowAttribution() *atostosv1.AipowWorkAttribution {
	return &atostosv1.AipowWorkAttribution{
		CapabilityClass: "text-generation",
		Unit:            "kilo-output-tokens",
		WorkUnits:       42,
		RateCardVersion: "v0",
		EvidenceLevel:   atostosv1.AipowEvidenceLevel_AIPOW_EVIDENCE_LEVEL_ATTESTED,
		EarnerIdentityCommitment: &atostosv1.Digest{
			Algorithm: "sha256", Value: bytes.Repeat([]byte{0x11}, 32),
		},
		PayerIdentityCommitment: &atostosv1.Digest{
			Algorithm: "sha256", Value: bytes.Repeat([]byte{0x22}, 32),
		},
		ChallengeTask: true,
	}
}

// The proto comment on ExecutionReceiptEnvelope.aipow promises that an
// absent attribution leaves the canonical (deterministic proto) encoding
// of pre-existing receipts unchanged. Pin that promise: setting the field
// changes the canonical bytes, clearing it restores them exactly, and a
// populated attribution round-trips losslessly.
func TestAipowAttributionAbsenceKeepsReceiptCanonicalBytesStable(t *testing.T) {
	envelope := &atostosv1.ExecutionReceiptEnvelope{
		ReceiptId:         "rcp-aipow-stability",
		QuoteId:           "q-aipow-stability",
		EscrowId:          "esc-aipow-stability",
		JobId:             "job-aipow-stability",
		PrincipalId:       "prn-aipow-stability",
		ProviderId:        "agt-aipow-stability",
		CapabilityId:      "cap-aipow-stability",
		CapabilityVersion: "1.0.0",
		TrustMode:         atostosv1.TrustMode_TRUST_MODE_MANAGED,
		Result:            atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS,
	}
	withoutAttribution := deterministicMarshal(t, envelope)

	attributed, ok := proto.Clone(envelope).(*atostosv1.ExecutionReceiptEnvelope)
	if !ok {
		t.Fatal("clone did not return an ExecutionReceiptEnvelope")
	}
	attributed.Aipow = sampleAipowAttribution()
	withAttribution := deterministicMarshal(t, attributed)
	if bytes.Equal(withoutAttribution, withAttribution) {
		t.Fatal("setting aipow attribution must change the canonical receipt bytes")
	}

	attributed.Aipow = nil
	cleared := deterministicMarshal(t, attributed)
	if !bytes.Equal(withoutAttribution, cleared) {
		t.Fatal("clearing aipow attribution must restore the exact pre-existing canonical bytes")
	}

	decoded := &atostosv1.ExecutionReceiptEnvelope{}
	if err := proto.Unmarshal(withAttribution, decoded); err != nil {
		t.Fatalf("unmarshal attributed receipt: %v", err)
	}
	if !proto.Equal(decoded.Aipow, sampleAipowAttribution()) {
		t.Fatalf("aipow attribution did not round-trip: %v", decoded.Aipow)
	}
}

// The same absence guarantee holds for proof-of-service evidence rows.
func TestAipowAttributionAbsenceKeepsEvidenceCanonicalBytesStable(t *testing.T) {
	evidence := &atostosv1.ProofOfServiceEvidenceInput{
		EvidenceId:   "ev-aipow-stability",
		ReceiptId:    "rcp-aipow-stability",
		ProviderId:   "agt-aipow-stability",
		CapabilityId: "cap-aipow-stability",
		Result:       atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS,
	}
	withoutAttribution := deterministicMarshal(t, evidence)

	attributed, ok := proto.Clone(evidence).(*atostosv1.ProofOfServiceEvidenceInput)
	if !ok {
		t.Fatal("clone did not return a ProofOfServiceEvidenceInput")
	}
	attributed.Aipow = sampleAipowAttribution()
	if bytes.Equal(withoutAttribution, deterministicMarshal(t, attributed)) {
		t.Fatal("setting aipow attribution must change the canonical evidence bytes")
	}
	attributed.Aipow = nil
	if !bytes.Equal(withoutAttribution, deterministicMarshal(t, attributed)) {
		t.Fatal("clearing aipow attribution must restore the exact pre-existing canonical bytes")
	}
}
