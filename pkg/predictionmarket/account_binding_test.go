package predictionmarket

import "testing"

func TestPredictionAccountBindingDigestV1GoldenAndCanonicalAddress(t *testing.T) {
	digest, err := PredictionAccountBindingDigestV1(
		"-1:2222222222222222222222222222222222222222222222222222222222222222",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := digest.SHA256String(),
		"sha256:f10865e27a24d230e1342f118d5103d3619cc8dbb5d41d9beca324b184bfa9fc"; got != want {
		t.Fatalf("account binding digest = %s, want %s", got, want)
	}
	for _, invalid := range []string{
		"EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
		"1:2222222222222222222222222222222222222222222222222222222222222222",
		"-1:2222",
	} {
		if _, err := PredictionAccountBindingDigestV1(invalid); err == nil {
			t.Fatalf("accepted noncanonical Prediction account %q", invalid)
		}
	}
}
