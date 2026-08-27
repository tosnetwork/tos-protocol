package agentguarantor

import (
	"math"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestRegisteredObjectDispatcherIsExhaustiveAndStrict(t *testing.T) {
	factories := guarantorObjectFactoriesV1()
	registry := ReleasedObjectVerifierRegistryV1()
	if len(factories) != len(registry.Entries) {
		t.Fatalf("dispatcher has %d factories for %d released objects", len(factories), len(registry.Entries))
	}
	for _, entry := range registry.Entries {
		if factories[entry.ObjectKind] == nil {
			t.Fatalf("released object %q has no decoder", entry.ObjectKind)
		}
	}
	canonical, err := codec.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRegisteredObjectV1("object-verifier-registry", canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRegisteredObjectV1("not-released", canonical); err == nil {
		t.Fatal("unknown Guarantor object kind was decoded")
	}
	wrongVersion := registry
	wrongVersion.SchemaVersion = 2
	canonical, err = codec.Marshal(wrongVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRegisteredObjectV1("object-verifier-registry", canonical); err == nil {
		t.Fatal("wrong Guarantor schema version was decoded")
	}
	unknownField, err := codec.Marshal(map[string]any{"schema_version": uint64(1), "registry_version": uint64(1),
		"entries": []any{}, "unexpected": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRegisteredObjectV1("object-verifier-registry", unknownField); err == nil {
		t.Fatal("unknown Guarantor object field was decoded")
	}
}

func TestRegisteredObjectDecoderRejectsUnixTimestampWraparound(t *testing.T) {
	claim := AuthorizedCoverageClaimV1{Body: CoverageClaimBodyV1{CreatedAtUnix: math.MaxUint64}}
	canonical, err := codec.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRegisteredObjectV1("claim", canonical); err == nil {
		t.Fatal("registered object decoder accepted a uint64 timestamp that wraps signed time")
	}
}
