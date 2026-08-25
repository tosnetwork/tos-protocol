// Command agentcommerce-registry emits the released semantic-action registry
// in stable JSON for cross-implementation conformance checks.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func main() {
	registry := agentcommerce.SemanticActionRegistry()
	kinds := make([]string, 0, len(registry))
	for kind := range registry {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	entries := make([]agentcommerce.SemanticActionEntry, 0, len(kinds))
	for _, kind := range kinds {
		entries = append(entries, registry[kind])
	}
	document := struct {
		Schema  string                              `json:"schema"`
		Entries []agentcommerce.SemanticActionEntry `json:"entries"`
	}{Schema: "tos.semantic-action-registry.v1", Entries: entries}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
