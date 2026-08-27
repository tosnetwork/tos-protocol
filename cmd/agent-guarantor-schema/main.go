// Command agent-guarantor-schema emits the structural JSON Schema for every
// released Guarantor V1 object and mutation request. Semantic constraints,
// canonical CBOR ordering, digest relations and authority checks remain the
// responsibility of pkg/agentguarantor's verifiers.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
)

type schema map[string]any

type generator struct {
	defs map[string]schema
}

func main() {
	output := flag.String("output", "", "write schema to this path instead of stdout")
	flag.Parse()
	g := &generator{defs: map[string]schema{}}
	objectSamples := guarantor.ReleasedObjectSchemaSamplesV1()
	mutationSamples := guarantor.ReleasedMutationSchemaSamplesV1()

	objectKinds := sortedKeys(objectSamples)
	objectMap := map[string]string{}
	rootRefs := make([]any, 0, len(objectKinds)+len(mutationSamples))
	for _, kind := range objectKinds {
		name := dereference(reflect.TypeOf(objectSamples[kind])).Name()
		g.ensure(reflect.TypeOf(objectSamples[kind]))
		objectMap[kind] = "#/$defs/" + name
		rootRefs = append(rootRefs, schema{"$ref": "#/$defs/" + name})
	}
	mutationKeys := make([]guarantor.MutationDispatchKeyV1, 0, len(mutationSamples))
	for key := range mutationSamples {
		mutationKeys = append(mutationKeys, key)
	}
	sort.Slice(mutationKeys, func(i, j int) bool {
		return mutationKeys[i].ActionKind+"\x00"+mutationKeys[i].OperationPurpose <
			mutationKeys[j].ActionKind+"\x00"+mutationKeys[j].OperationPurpose
	})
	mutationMap := map[string]string{}
	for _, key := range mutationKeys {
		name := dereference(reflect.TypeOf(mutationSamples[key])).Name()
		g.ensure(reflect.TypeOf(mutationSamples[key]))
		wireKey := key.ActionKind + "/" + key.OperationPurpose
		mutationMap[wireKey] = "#/$defs/" + name
		rootRefs = append(rootRefs, schema{"$ref": "#/$defs/" + name})
	}
	document := schema{
		"$schema":                        "https://json-schema.org/draft/2020-12/schema",
		"$id":                            "https://tos.network/schemas/agent-guarantor-service-v1.json",
		"title":                          "TOS Decentralized Agent Guarantor Service V1",
		"description":                    "Closed structural schema generated from the released Go wire types. The reference verifier additionally enforces canonical CBOR, bounds, digests, signatures, authority history, state transitions, and cross-object bindings.",
		"x-object-kind-definitions":      objectMap,
		"x-mutation-request-definitions": mutationMap,
		"anyOf":                          rootRefs,
		"$defs":                          g.defs,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if *output == "" {
		_, err = os.Stdout.Write(encoded)
	} else {
		err = os.WriteFile(*output, encoded, 0o644)
	}
	if err != nil {
		fatal(err)
	}
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func dereference(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func (g *generator) ensure(t reflect.Type) schema {
	if t.Kind() == reflect.Pointer {
		return g.ensure(t.Elem())
	}
	switch t.Kind() {
	case reflect.Bool:
		return schema{"type": "boolean"}
	case reflect.String:
		if values := enumValues(t.Name()); len(values) > 0 {
			return schema{"type": "string", "enum": values}
		}
		return schema{"type": "string"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return schema{"type": "integer", "minimum": 0}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return schema{"type": "integer"}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return schema{"type": "string", "contentEncoding": "base64"}
		}
		return schema{"type": "array", "items": g.ensure(t.Elem())}
	case reflect.Array:
		return schema{"type": "array", "minItems": t.Len(), "maxItems": t.Len(), "items": g.ensure(t.Elem())}
	case reflect.Map:
		return schema{"type": "object", "additionalProperties": g.ensure(t.Elem())}
	case reflect.Interface:
		return schema{}
	case reflect.Struct:
		name := t.Name()
		if name == "" {
			return g.structSchema(t)
		}
		if _, exists := g.defs[name]; !exists {
			g.defs[name] = schema{}
			g.defs[name] = g.structSchema(t)
		}
		return schema{"$ref": "#/$defs/" + name}
	default:
		panic("unsupported schema kind: " + t.String())
	}
}

func (g *generator) structSchema(t reflect.Type) schema {
	properties := map[string]any{}
	required := []string{}
	for index := 0; index < t.NumField(); index++ {
		field := t.Field(index)
		if field.PkgPath != "" {
			continue
		}
		parts := strings.Split(field.Tag.Get("json"), ",")
		name := parts[0]
		if name == "" {
			name = field.Name
		}
		if name == "-" {
			continue
		}
		optional := false
		for _, option := range parts[1:] {
			optional = optional || option == "omitempty"
		}
		property := g.ensure(field.Type)
		if name == "schema_version" {
			property = schema{"type": "integer", "const": 1}
		} else if strings.HasSuffix(name, "_digest") || strings.HasSuffix(name, "_root") || strings.HasSuffix(name, "_hash") {
			if field.Type.Kind() == reflect.String {
				property["pattern"] = "^(sha256|tvm-cell-sha256):[0-9a-f]{64}$"
			}
		}
		properties[name] = property
		if !optional {
			required = append(required, name)
		}
	}
	result := schema{"type": "object", "additionalProperties": false, "properties": properties}
	if len(required) > 0 {
		result["required"] = required
	}
	return result
}

func enumValues(name string) []string {
	values := map[string][]string{
		"AssuranceLevel":      {"unsecured-signed", "collateral-attested", "independently-enforceable"},
		"BenefitKind":         {"fixed_benefit", "indemnity"},
		"ClaimDecisionResult": {"approved", "partially_approved", "denied", "evidence_required", "disputed"},
		"CollateralStatus":    {"UNPROVEN", "LOCK_PENDING", "LOCKED", "ENCUMBERED", "PAYOUT_PENDING", "PARTIALLY_CONSUMED", "DEPLETED", "RELEASE_PENDING", "RELEASED", "AMBIGUOUS", "REORGED", "DEFAULTED"},
		"ClaimStatus":         {"FILED", "REVIEWING", "EVIDENCE_REQUIRED", "DISPUTED", "FINAL_APPROVED", "FINAL_PARTIALLY_APPROVED", "FINAL_DENIED"},
		"PayoutStatus":        {"NOT_APPLICABLE", "PENDING", "PARTIALLY_PAID", "PAID", "DEFAULTED"},
		"CoverageStatus":      {"ACCEPTED", "ACTIVATION_PENDING", "ACTIVE", "NOT_ACTIVATED_CONFIRMED", "COVERAGE_ENDED", "CLAIMS_FROZEN", "RELEASE_PENDING", "CLOSED", "DEFAULTED"},
	}
	return values[name]
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
