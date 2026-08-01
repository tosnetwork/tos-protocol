package ard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDecodeWorkerCatalogExtensionStrictlyValidatesKnownExtension(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	catalog, err := BuildWorkerCatalog(
		testWorkerCatalogConfig(), testWorkerCatalogResponse(now), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	extension, present, err := DecodeWorkerCatalogExtension(catalog.Entries[0])
	if err != nil || !present || len(extension.Capabilities) != 2 {
		t.Fatalf("extension=%#v present=%v err=%v", extension, present, err)
	}
	withoutExtension := catalog.Entries[0]
	withoutExtension.Extensions = nil
	if _, present, err := DecodeWorkerCatalogExtension(withoutExtension); err != nil || present {
		t.Fatalf("absent extension present=%v err=%v", present, err)
	}

	validRaw := catalog.Entries[0].Extensions[WorkerCatalogExtensionName]
	tests := []struct {
		name string
		raw  json.RawMessage
	}{
		{"unknown field", append(validRaw[:len(validRaw)-1], []byte(`,"unknown":true}`)...)},
		{"duplicate field", []byte(`{"version":"0.1","version":"0.2","terminalRevision":"r","capabilities":[]}`)},
		{"zero bytes", []byte(`{"version":"0.1","terminalRevision":"r","capabilities":[{"serviceId":"tos.ai.mock","operation":"generate","model":"m","modelDigest":"sha256:` + strings.Repeat("a", 64) + `","runtime":"r","runtimeRevision":"r1","maxInputBytes":"0","maxOutputBytes":"1"}]}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := catalog.Entries[0]
			entry.Extensions = map[string]json.RawMessage{
				WorkerCatalogExtensionName: test.raw,
			}
			if _, present, err := DecodeWorkerCatalogExtension(entry); err == nil || !present {
				t.Fatalf("invalid known extension accepted: present=%v err=%v", present, err)
			}
		})
	}
}

func TestCatalogValidationRejectsMalformedKnownWorkerExtension(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	catalog, err := BuildWorkerCatalog(
		testWorkerCatalogConfig(), testWorkerCatalogResponse(now), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Entries[0].Extensions[WorkerCatalogExtensionName] = []byte(
		`{"version":"0.1","terminalRevision":"worker-v1","capabilities":[],"unknown":true}`,
	)
	if err := catalog.Validate(DefaultLimits()); err == nil {
		t.Fatal("catalog boundary accepted a malformed known Worker extension")
	}
}
