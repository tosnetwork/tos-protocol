package paiddemand

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

func TestGenericExecutionReceiptUsesCanonicalEscrowShape(t *testing.T) {
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	receipt, commitment, err := BuildExecutionReceiptV1(ExecutionReceiptV1{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("1", 64),
		ExecutionID: digest("2"), InputSetDigest: digest("3"), ResultDigest: digest("4"), ArtifactSetDigest: digest("5"),
		EvaluationDigest: digest("6"), SourceSetDigest: digest("7"), ExecutorDigest: digest("8"), IsolationDigest: digest("9"),
		ChargedAtomicAmount: "100", ProviderAgentID: "agent_" + strings.Repeat("a", 64), CompletedAtUnix: 2_000_000_000})
	if err != nil || commitment == "" {
		t.Fatal(err)
	}
	decoded, err := nativecore.DecodeSoftwareWorkReceiptCellV1(receipt)
	if err != nil || decoded.ResultDigest != digest("4") || decoded.ProviderAgentID != "agent_"+strings.Repeat("a", 64) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}
