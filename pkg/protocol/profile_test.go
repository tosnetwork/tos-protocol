package protocol

import "testing"

func TestNegotiateProfileChoosesHighestCommonVersion(t *testing.T) {
	result, err := NegotiateProfile(
		ProfileRequest{
			ID:                  "tos.ai.inference",
			SupportedVersions:   []string{"0.1.0", "0.2.0", "1.0.0"},
			SupportedExtensions: []string{"urn:tos:extension:receipts"},
		},
		ProfileOffer{
			ID:                 "tos.ai.inference",
			Versions:           []string{"0.1.0", "0.2.0"},
			CriticalExtensions: []string{"urn:tos:extension:receipts"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != "0.2.0" {
		t.Fatalf("version = %q", result.Version)
	}
}

func TestNegotiateProfileRejectsUnknownCriticalExtension(t *testing.T) {
	_, err := NegotiateProfile(
		ProfileRequest{ID: "tos.ai.inference", SupportedVersions: []string{"0.1.0"}},
		ProfileOffer{
			ID:                 "tos.ai.inference",
			Versions:           []string{"0.1.0"},
			CriticalExtensions: []string{"urn:tos:extension:unknown"},
		},
	)
	if err == nil {
		t.Fatal("unknown critical extension accepted")
	}
}

func TestNegotiateProfileRejectsNonCanonicalVersion(t *testing.T) {
	_, err := NegotiateProfile(
		ProfileRequest{ID: "tos.ai.inference", SupportedVersions: []string{"0.01.0"}},
		ProfileOffer{ID: "tos.ai.inference", Versions: []string{"0.1.0"}},
	)
	if err == nil {
		t.Fatal("non-canonical semantic version accepted")
	}
}
