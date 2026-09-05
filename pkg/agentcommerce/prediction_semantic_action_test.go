package agentcommerce

import (
	"strings"
	"testing"
)

func TestPredictionSemanticActionRegistryIsClosedAndDomainBound(t *testing.T) {
	kinds := []string{
		"prediction.market.deploy", "prediction.collateral.deposit", "prediction.reserve.top-up",
		"prediction.trading-key.rotate", "prediction.order.authorize", "prediction.order.publish",
		"prediction.order.cancel-exact", "prediction.order.nonce-floor.raise", "prediction.match.submit",
		"prediction.position.split", "prediction.position.merge", "prediction.position.claim",
		"prediction.collateral.withdraw", "prediction.resolution.report", "prediction.resolution.challenge",
		"prediction.resolution.finalize", "prediction.challenge-bond.withdraw", "prediction.market.advance-phase",
		"prediction.market.compact", "prediction.terminal-surplus.withdraw",
	}
	registry := SemanticActionRegistry()
	for index, kind := range kinds {
		candidate, ok := registry[kind]
		if !ok {
			t.Fatalf("missing prediction semantic action %q", kind)
		}
		if candidate.RegistryVersion != 1 || candidate.EntryVersion != 1 || candidate.DomainTag != "tos.semantic-action."+kind+".v1" {
			t.Fatalf("prediction action has an unstable version/domain: %+v", candidate)
		}
		if len(candidate.Fields) < 4 || candidate.Fields[0].Name != "owner_id" || candidate.Fields[1].Name != "agent_id" ||
			candidate.Fields[2].Name != "network_domain_digest" || candidate.Fields[3].Name != "market_id" {
			t.Fatalf("prediction action lacks the common network/market binding: %+v", candidate.Fields)
		}
		values := predictionSemanticValues(candidate, uint64(index+1))
		first, _, err := DeriveStableActionID(kind, values)
		if err != nil {
			t.Fatalf("derive %s: %v", kind, err)
		}
		replacement := "sha256:" + strings.Repeat("f", 64)
		if string(values["market_id"].bytes) == replacement {
			replacement = "sha256:" + strings.Repeat("e", 64)
		}
		values["market_id"] = Digest32(replacement)
		second, _, err := DeriveStableActionID(kind, values)
		if err != nil || first == second {
			t.Fatalf("%s stable identity did not bind the market", kind)
		}
		values["transport_retry"] = U64(99)
		if _, _, err := DeriveStableActionID(kind, values); err == nil {
			t.Fatalf("%s accepted a transport-only extra field", kind)
		}
	}
}

func TestPredictionAtomicAmountsAreCanonicalUnsignedDecimals(t *testing.T) {
	entry := SemanticActionRegistry()["prediction.collateral.deposit"]
	values := predictionSemanticValues(entry, 1)
	for _, invalid := range []string{"", "01", "-1", "+1", "1.0", " 1"} {
		values["amount_atomic"] = ID(invalid)
		if _, _, err := DeriveStableActionID(entry.ActionKind, values); err == nil {
			t.Fatalf("accepted non-canonical amount %q", invalid)
		}
	}
}

func predictionSemanticValues(entry SemanticActionEntry, seed uint64) map[string]SemanticValue {
	values := make(map[string]SemanticValue, len(entry.Fields))
	for index, field := range entry.Fields {
		switch field.Type {
		case SemanticID:
			if field.Name == "amount_atomic" {
				values[field.Name] = ID("1000000000")
			} else {
				values[field.Name] = ID(field.Name + ":test")
			}
		case SemanticDigest32:
			digit := "123456789abcdef0"[(int(seed)+index)%16]
			values[field.Name] = Digest32("sha256:" + strings.Repeat(string(digit), 64))
		case SemanticU64:
			values[field.Name] = U64(seed + uint64(index))
		case SemanticKind:
			values[field.Name] = Kind("normal")
		case SemanticState:
			values[field.Name] = State("trading")
		}
	}
	return values
}
