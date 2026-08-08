package taskescrowpublisher

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

func TestTosctlArgumentsPreserveAtomicEconomics(t *testing.T) {
	backend := &TosctlBackend{
		wallets: map[string]string{
			"0:" + strings.Repeat("11", 32): "creator",
			"0:" + strings.Repeat("22", 32): "agent",
			"0:" + strings.Repeat("33", 32): "verifier",
		},
		executorWallet: "executor", workchain: 0,
		operationValue: 10_000_000,
	}
	action := testAction(time.Unix(1_800_000_000, 0))
	deploy := strings.Join(backend.publishArgs(action, "0:"+strings.Repeat("44", 32)), " ")
	for _, required := range []string{
		"--budget-nanotos 1000000000",
		"--amount-nanotos 1100000000",
		"--permission-hash " + strings.Repeat("bb", 32),
		"--policy-hash " + strings.Repeat("aa", 32),
		"--from creator",
	} {
		if !strings.Contains(deploy, required) {
			t.Fatalf("deploy args missing %q: %s", required, deploy)
		}
	}
	action.Kind = chain.TaskEscrowActionSettle
	action.ContractAddress = "0:" + strings.Repeat("44", 32)
	action.QueryID = 42
	action.PayoutNanoTOS = 333_333_333
	action.ExpectedBodyHash = "tvm-cell-sha256:" + strings.Repeat("cc", 32)
	settle := strings.Join(backend.publishArgs(action, action.ContractAddress), " ")
	for _, required := range []string{
		"--from verifier", "--query-id 42", "--payout-nanotos 333333333",
		"--amount-nanotos 10000000",
	} {
		if !strings.Contains(settle, required) {
			t.Fatalf("settle args missing %q: %s", required, settle)
		}
	}
}

func TestStableRecordNameDoesNotExposeActionID(t *testing.T) {
	first := recordName("secret/action/id")
	second := recordName("secret/action/id")
	if first != second || strings.Contains(first, "secret") || len(first) != len("atos-")+16 {
		t.Fatalf("unexpected record name %q", first)
	}
}
