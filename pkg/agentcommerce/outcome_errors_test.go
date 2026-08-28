package agentcommerce

import "testing"

func TestOutcomeErrorRegistryV1IsStableSortedAndUnique(t *testing.T) {
	registry := OutcomeErrorRegistryV1()
	if registry.Schema != "tos.operation-outcome-error-registry.v1" || registry.Version != 1 || len(registry.Entries) != 9 {
		t.Fatalf("unexpected registry: %+v", registry)
	}
	for index, entry := range registry.Entries {
		if entry.Code == "" || entry.RetryClass == "" || entry.Meaning == "" {
			t.Fatalf("empty registry entry: %+v", entry)
		}
		if index > 0 && registry.Entries[index-1].Code >= entry.Code {
			t.Fatalf("registry is not strictly sorted: %q, %q", registry.Entries[index-1].Code, entry.Code)
		}
	}
}
