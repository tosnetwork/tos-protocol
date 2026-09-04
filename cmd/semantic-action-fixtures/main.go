package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type positive struct {
	Name           string         `json:"name"`
	ActionKind     string         `json:"action_kind"`
	Fields         map[string]any `json:"fields"`
	PreimageHex    string         `json:"preimage_hex"`
	StableActionID string         `json:"stable_action_id"`
}
type negative struct {
	Name       string         `json:"name"`
	ActionKind string         `json:"action_kind"`
	Fields     map[string]any `json:"fields"`
}
type document struct {
	Schema   string     `json:"schema"`
	Positive []positive `json:"positive_vectors"`
	Negative []negative `json:"negative_vectors"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: semantic-action-fixtures OUTPUT")
	}
	registry := commerce.SemanticActionRegistry()
	kinds := make([]string, 0, len(registry))
	for kind := range registry {
		kinds = append(kinds, kind)
	}
	// Additive namespaces are appended after every pre-existing V1 kind so a
	// newly released kind cannot renumber and silently rewrite older golden
	// inputs or stable action IDs. Entries remain lexicographic within each
	// partition.
	sort.Slice(kinds, func(left, right int) bool {
		leftPrediction := strings.HasPrefix(kinds[left], "prediction.")
		rightPrediction := strings.HasPrefix(kinds[right], "prediction.")
		if leftPrediction != rightPrediction {
			return !leftPrediction
		}
		return kinds[left] < kinds[right]
	})
	doc := document{Schema: "tos.semantic-action-conformance.v1"}
	for actionIndex, kind := range kinds {
		entry := registry[kind]
		typed := map[string]commerce.SemanticValue{}
		display := map[string]any{}
		for fieldIndex, field := range entry.Fields {
			var value commerce.SemanticValue
			var shown any
			switch field.Type {
			case commerce.SemanticDigest32:
				text := "sha256:" + fmt.Sprintf("%064x", actionIndex*128+fieldIndex+1)
				value = commerce.Digest32(text)
				shown = text
			case commerce.SemanticU64:
				value = commerce.U64(uint64(fieldIndex + 1))
				shown = uint64(fieldIndex + 1)
			case commerce.SemanticState:
				value = commerce.State("terminal")
				shown = "terminal"
			case commerce.SemanticKind:
				value = commerce.Kind("bounded")
				shown = "bounded"
			default:
				text := "id:" + strings.ReplaceAll(kind, ".", "-") + ":" + field.Name
				if field.Name == "amount_atomic" {
					text = "10"
				}
				value = commerce.ID(text)
				shown = text
			}
			typed[field.Name] = value
			display[field.Name] = shown
		}
		id, preimage, err := commerce.DeriveStableActionID(kind, typed)
		if err != nil {
			panic(err)
		}
		doc.Positive = append(doc.Positive, positive{kind, kind, display, hex.EncodeToString(preimage), id})
	}
	doc.Negative = []negative{{"unknown-action", "unknown.action", map[string]any{}}, {"missing-field", "agreement.propose", map[string]any{"owner_id": "owner:test"}}}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(raw, '\n'), 0o644); err != nil {
		panic(err)
	}
}
