package protocol

import (
	"strings"
	"testing"
)

func TestRequestIntentDigestIsProfileBoundAndDeterministic(t *testing.T) {
	payload := []byte(`{"model":"qwen3","prompt":"hello"}`)
	digest, err := RequestIntentDigest(
		"tos.ai.inference",
		"0.1.0",
		nil,
		"invoke",
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:39762bf77aec64e6a7a8a0872487f9b6ecff552b161ac65a087b45fee48b2c5b"
	if digest != expected {
		t.Fatalf("digest = %q, want %q", digest, expected)
	}
	payload[0] ^= 1
	recomputed, err := RequestIntentDigest(
		"tos.ai.inference",
		"0.1.0",
		nil,
		"invoke",
		[]byte(`{"model":"qwen3","prompt":"hello"}`),
	)
	if err != nil || recomputed != digest {
		t.Fatalf("recomputed digest = %q, err = %v", recomputed, err)
	}
	for name, change := range map[string]func() (string, error){
		"profile": func() (string, error) {
			return RequestIntentDigest(
				"tos.storage", "0.1.0", nil, "invoke",
				[]byte(`{"model":"qwen3","prompt":"hello"}`),
			)
		},
		"version": func() (string, error) {
			return RequestIntentDigest(
				"tos.ai.inference", "0.2.0", nil, "invoke",
				[]byte(`{"model":"qwen3","prompt":"hello"}`),
			)
		},
		"operation": func() (string, error) {
			return RequestIntentDigest(
				"tos.ai.inference", "0.1.0", nil, "embed",
				[]byte(`{"model":"qwen3","prompt":"hello"}`),
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := change()
			if err != nil {
				t.Fatal(err)
			}
			if changed == digest {
				t.Fatal("changed intent retained original digest")
			}
		})
	}
}

func TestRequestIntentDigestCanonicalizesAndBindsExtensions(t *testing.T) {
	payload := []byte("intent")
	first, err := RequestIntentDigest(
		"tos.ai.inference", "0.1.0",
		[]string{"urn:tos:extension:z", "urn:tos:extension:a"},
		"invoke", payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := RequestIntentDigest(
		"tos.ai.inference", "0.1.0",
		[]string{"urn:tos:extension:a", "urn:tos:extension:z"},
		"invoke", payload,
	)
	if err != nil || reordered != first {
		t.Fatalf("reordered digest = %q, err = %v", reordered, err)
	}
	changed, err := RequestIntentDigest(
		"tos.ai.inference", "0.1.0",
		[]string{"urn:tos:extension:a"},
		"invoke", payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("changed extension set retained original digest")
	}
	if _, err := RequestIntentDigest(
		"tos.ai.inference", "0.1.0",
		[]string{"urn:tos:extension:a", "urn:tos:extension:a"},
		"invoke", payload,
	); err == nil {
		t.Fatal("duplicate extension accepted")
	}
}

func TestRequestIntentDigestRejectsInvalidAndOversizedValues(t *testing.T) {
	if _, err := RequestIntentDigest("BAD", "0.1.0", nil, "invoke", nil); err == nil {
		t.Fatal("invalid profile accepted")
	}
	if _, err := RequestIntentDigest(
		"tos.ai.inference", "01.0.0", nil, "invoke", nil,
	); err == nil {
		t.Fatal("noncanonical profile version accepted")
	}
	if _, err := RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "", nil,
	); err == nil {
		t.Fatal("empty operation accepted")
	}
	if _, err := RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "invoke",
		[]byte(strings.Repeat("x", MaxRequestIntentBytes+1)),
	); err == nil {
		t.Fatal("oversized intent accepted")
	}
}
