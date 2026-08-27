package agentguarantor

import "testing"

func FuzzDecodeRegisteredObjectV1(f *testing.F) {
	f.Add("quote-request", []byte{0xa0})
	f.Add("unknown", []byte{0xff})
	f.Fuzz(func(t *testing.T, kind string, canonical []byte) {
		if len(kind) > 256 || len(canonical) > MaxCanonicalObjectBytes+1 {
			t.Skip()
		}
		_, _ = DecodeRegisteredObjectV1(kind, canonical)
	})
}

func FuzzDecodeMutationRequestV1(f *testing.F) {
	f.Add("commercial.quote.issue", "firm-offer-issuance", []byte{0xa0})
	f.Add("unknown", "unknown", []byte{0xff})
	f.Fuzz(func(t *testing.T, actionKind, purpose string, canonical []byte) {
		if len(actionKind) > 256 || len(purpose) > 256 || len(canonical) > MaxCanonicalObjectBytes+1 {
			t.Skip()
		}
		_, _ = DecodeMutationRequestV1(actionKind, purpose, canonical)
	})
}
