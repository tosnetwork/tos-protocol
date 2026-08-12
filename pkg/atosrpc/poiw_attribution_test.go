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

func samplePoiwAttribution() *atostosv1.PoiwWorkAttribution {
	return &atostosv1.PoiwWorkAttribution{
		CapabilityClass: "text-generation",
		Unit:            "kilo-output-tokens",
		WorkUnits:       42,
		RateCardVersion: "v0",
		EvidenceLevel:   atostosv1.PoiwEvidenceLevel_POIW_EVIDENCE_LEVEL_ATTESTED,
		EarnerIdentityCommitment: &atostosv1.Digest{
			Algorithm: "sha256", Value: bytes.Repeat([]byte{0x11}, 32),
		},
		PayerIdentityCommitment: &atostosv1.Digest{
			Algorithm: "sha256", Value: bytes.Repeat([]byte{0x22}, 32),
		},
		ChallengeTask: true,
	}
}

// The proto comment on ExecutionReceiptEnvelope.poiw promises that an
// absent attribution leaves the canonical (deterministic proto) encoding
// of pre-existing receipts unchanged. Pin that promise: setting the field
// changes the canonical bytes, clearing it restores them exactly, and a
// populated attribution round-trips losslessly.
func TestPoiwAttributionAbsenceKeepsReceiptCanonicalBytesStable(t *testing.T) {
	envelope := &atostosv1.ExecutionReceiptEnvelope{
		ReceiptId:         "rcp-poiw-stability",
		QuoteId:           "q-poiw-stability",
		EscrowId:          "esc-poiw-stability",
		JobId:             "job-poiw-stability",
		PrincipalId:       "prn-poiw-stability",
		ProviderId:        "agt-poiw-stability",
		CapabilityId:      "cap-poiw-stability",
		CapabilityVersion: "1.0.0",
		TrustMode:         atostosv1.TrustMode_TRUST_MODE_MANAGED,
		Result:            atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS,
	}
	withoutAttribution := deterministicMarshal(t, envelope)

	attributed, ok := proto.Clone(envelope).(*atostosv1.ExecutionReceiptEnvelope)
	if !ok {
		t.Fatal("clone did not return an ExecutionReceiptEnvelope")
	}
	attributed.Poiw = samplePoiwAttribution()
	withAttribution := deterministicMarshal(t, attributed)
	if bytes.Equal(withoutAttribution, withAttribution) {
		t.Fatal("setting poiw attribution must change the canonical receipt bytes")
	}

	attributed.Poiw = nil
	cleared := deterministicMarshal(t, attributed)
	if !bytes.Equal(withoutAttribution, cleared) {
		t.Fatal("clearing poiw attribution must restore the exact pre-existing canonical bytes")
	}

	decoded := &atostosv1.ExecutionReceiptEnvelope{}
	if err := proto.Unmarshal(withAttribution, decoded); err != nil {
		t.Fatalf("unmarshal attributed receipt: %v", err)
	}
	if !proto.Equal(decoded.Poiw, samplePoiwAttribution()) {
		t.Fatalf("poiw attribution did not round-trip: %v", decoded.Poiw)
	}
}

// The same absence guarantee holds for proof-of-service evidence rows.
func TestPoiwAttributionAbsenceKeepsEvidenceCanonicalBytesStable(t *testing.T) {
	evidence := &atostosv1.ProofOfServiceEvidenceInput{
		EvidenceId:   "ev-poiw-stability",
		ReceiptId:    "rcp-poiw-stability",
		ProviderId:   "agt-poiw-stability",
		CapabilityId: "cap-poiw-stability",
		Result:       atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS,
	}
	withoutAttribution := deterministicMarshal(t, evidence)

	attributed, ok := proto.Clone(evidence).(*atostosv1.ProofOfServiceEvidenceInput)
	if !ok {
		t.Fatal("clone did not return a ProofOfServiceEvidenceInput")
	}
	attributed.Poiw = samplePoiwAttribution()
	if bytes.Equal(withoutAttribution, deterministicMarshal(t, attributed)) {
		t.Fatal("setting poiw attribution must change the canonical evidence bytes")
	}
	attributed.Poiw = nil
	if !bytes.Equal(withoutAttribution, deterministicMarshal(t, attributed)) {
		t.Fatal("clearing poiw attribution must restore the exact pre-existing canonical bytes")
	}
}
