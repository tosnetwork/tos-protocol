package poiw

import (
	"bytes"
	"strings"
	"testing"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

func TestTextGenerationNormalization(t *testing.T) {
	cases := []struct {
		tokens uint64
		units  uint64
	}{
		{0, 0}, {1, 1}, {999, 1}, {1000, 1}, {1999, 1}, {2000, 2}, {123456, 123},
	}
	for _, tc := range cases {
		if got := textGenerationUnits(tc.tokens); got != tc.units {
			t.Fatalf("textGenerationUnits(%d) = %d, want %d", tc.tokens, got, tc.units)
		}
	}
}

func TestAttributionFromUsageMeasuresTokensOrFallsToDefault(t *testing.T) {
	measured := AttributionFromUsage(
		&atostosv1.Usage{OutputTokens: 2500}, 7_000,
		atostosv1.PoiwEvidenceLevel_POIW_EVIDENCE_LEVEL_OBSERVED,
	)
	if measured.CapabilityClass != ClassTextGeneration || measured.Unit != "kilo-output-tokens" {
		t.Fatalf("token usage must map to text-generation: %v", measured)
	}
	if measured.WorkUnits != 2 || measured.RateCardVersion != RateCardVersion {
		t.Fatalf("unexpected normalization: %v", measured)
	}
	if err := Validate(measured); err != nil {
		t.Fatalf("measured attribution must validate: %v", err)
	}

	fallback := AttributionFromUsage(
		&atostosv1.Usage{InputBytes: 10}, 7_000,
		atostosv1.PoiwEvidenceLevel_POIW_EVIDENCE_LEVEL_OBSERVED,
	)
	if fallback.CapabilityClass != ClassDefault || fallback.Unit != "settled-nanotos" {
		t.Fatalf("tokenless usage must fall to the default class: %v", fallback)
	}
	if fallback.WorkUnits != 7_000 {
		t.Fatalf("default class must carry the settled amount: %v", fallback)
	}
	if err := Validate(fallback); err != nil {
		t.Fatalf("fallback attribution must validate: %v", err)
	}

	zeroCharge := AttributionFromUsage(
		nil, 0, atostosv1.PoiwEvidenceLevel_POIW_EVIDENCE_LEVEL_OBSERVED,
	)
	if err := Validate(zeroCharge); err != nil {
		t.Fatalf("zero-charge default attribution must validate: %v", err)
	}
}

func TestValidateRejectsMalformedNeverRepairs(t *testing.T) {
	good := func() *atostosv1.PoiwWorkAttribution {
		return &atostosv1.PoiwWorkAttribution{
			CapabilityClass: ClassEmbedding,
			Unit:            "call",
			WorkUnits:       1,
			RateCardVersion: RateCardVersion,
			EvidenceLevel:   atostosv1.PoiwEvidenceLevel_POIW_EVIDENCE_LEVEL_OBSERVED,
		}
	}
	if err := Validate(nil); err != nil {
		t.Fatalf("absent attribution is valid: %v", err)
	}
	if err := Validate(good()); err != nil {
		t.Fatalf("well-formed attribution must validate: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*atostosv1.PoiwWorkAttribution)
		expect string
	}{
		{"unknown class", func(a *atostosv1.PoiwWorkAttribution) { a.CapabilityClass = "rumor-mill" }, "unknown capability class"},
		{"wrong unit", func(a *atostosv1.PoiwWorkAttribution) { a.Unit = "token" }, "requires unit"},
		{"unknown version", func(a *atostosv1.PoiwWorkAttribution) { a.RateCardVersion = "v99" }, "unknown rate card version"},
		{"zero units non-default", func(a *atostosv1.PoiwWorkAttribution) { a.WorkUnits = 0 }, "zero work units"},
		{"unspecified evidence", func(a *atostosv1.PoiwWorkAttribution) {
			a.EvidenceLevel = atostosv1.PoiwEvidenceLevel_POIW_EVIDENCE_LEVEL_UNSPECIFIED
		}, "invalid evidence level"},
		{"out-of-range evidence", func(a *atostosv1.PoiwWorkAttribution) { a.EvidenceLevel = 99 }, "invalid evidence level"},
		{"short commitment", func(a *atostosv1.PoiwWorkAttribution) {
			a.EarnerIdentityCommitment = &atostosv1.Digest{Algorithm: "sha256", Value: []byte{1, 2}}
		}, "must be 32 bytes"},
		{"wrong commitment algorithm", func(a *atostosv1.PoiwWorkAttribution) {
			a.PayerIdentityCommitment = &atostosv1.Digest{
				Algorithm: "md5", Value: bytes.Repeat([]byte{9}, 32),
			}
		}, "must be sha256"},
	}
	for _, tc := range cases {
		attribution := good()
		tc.mutate(attribution)
		err := Validate(attribution)
		if err == nil || !strings.Contains(err.Error(), tc.expect) {
			t.Fatalf("%s: want error containing %q, got %v", tc.name, tc.expect, err)
		}
	}

	// Well-formed 32-byte sha256 commitments are accepted.
	committed := good()
	committed.EarnerIdentityCommitment = &atostosv1.Digest{
		Algorithm: "sha256", Value: bytes.Repeat([]byte{7}, 32),
	}
	committed.PayerIdentityCommitment = &atostosv1.Digest{
		Algorithm: "sha256", Value: bytes.Repeat([]byte{8}, 32),
	}
	if err := Validate(committed); err != nil {
		t.Fatalf("committed attribution must validate: %v", err)
	}
}
