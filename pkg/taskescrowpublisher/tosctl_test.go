package taskescrowpublisher

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/address"
)

func TestEnrolledExecutableRejectsWritableOrReplacedBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tosctl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := captureExecutableIdentity(path); err == nil {
		t.Fatal("publisher-owned executable was accepted as immutable")
	}
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return
	}
	path = "/usr/bin/true"
	identity, err := captureExecutableIdentity(path)
	if err != nil {
		t.Fatalf("trusted system executable unavailable: %v", err)
	}
	configFile, err := pinnedTaskEscrowConfig([]byte(`{"chain_rpc":{"url":"http://127.0.0.1:1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer configFile.Close()
	backend := &TosctlBackend{
		binary: path, binaryIdentity: identity, configFile: configFile,
		commandTimeout: time.Second, environment: []string{"PATH=/usr/bin:/bin"},
	}
	if output, err := backend.run(context.Background(), "version"); err != nil || string(output) != "" {
		t.Fatalf("execute pinned descriptor: output=%q err=%v", output, err)
	}
	changed := identity
	changed.inode++
	if _, err := openVerifiedExecutable(path, changed); err == nil {
		t.Fatal("executable with a different enrolled inode was accepted")
	}
}

func TestTosctlBackendRejectsUnsupportedProductionPlatform(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux is the explicitly supported production platform")
	}
	if _, err := NewTosctlBackend(TosctlBackendConfig{}); err == nil || !strings.Contains(err.Error(), "only on Linux") {
		t.Fatalf("unsupported platform did not fail closed: %v", err)
	}
}

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

func TestTaskEscrowCLICapabilityContract(t *testing.T) {
	valid := []byte(`{
		"schema_version":"tosctl.task-escrow-cli.v1",
		"action_encoding":"tos.task-escrow.action.v1",
		"commands":["agent task build-state","agent task create","agent task send"],
		"create_flags":["--name","--creator","--agent","--verifier","--budget-nanotos","--deadline","--review-period","--policy-hash","--permission-hash","--from","--amount-nanotos","--workchain","--yes","--format"],
		"send_flags":["--operation","--address","--from","--query-id","--amount-nanotos","--yes","--result-hash","--evidence-hash","--dispute-hash","--payout-nanotos"],
		"send_operations":["accept","reject","result","dispute","resolve","settle","cancel","timeout","claim"]
	}`)
	if err := validateTaskEscrowCLICapabilities(valid); err != nil {
		t.Fatalf("valid capability contract rejected: %v", err)
	}
	for name, broken := range map[string][]byte{
		"missing create":    bytes.Replace(valid, []byte(`,"agent task create"`), nil, 1),
		"missing send flag": bytes.Replace(valid, []byte(`,"--payout-nanotos"`), nil, 1),
		"wrong schema":      bytes.Replace(valid, []byte(taskEscrowCLISchemaVersion), []byte("legacy"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTaskEscrowCLICapabilities(broken); err == nil {
				t.Fatal("incompatible tosctl capability contract was accepted")
			}
		})
	}
}

func TestWalletLsEntryAcceptsTosctlOutputFields(t *testing.T) {
	// tosctl's `wallet ls --format json` emits balance/state/wallet_type/seqno
	// alongside name/address; jsonstrict.Decode rejects unknown fields, so this
	// guards against walletLsEntry drifting out of sync with that output.
	payload := []byte(`[
		{
			"name": "creator",
			"address": "0:` + strings.Repeat("11", 32) + `",
			"balance": "12.5",
			"state": "active",
			"wallet_type": "V3R2",
			"seqno": 3
		},
		{
			"name": "provider",
			"address": null,
			"balance": null,
			"state": null,
			"wallet_type": null,
			"seqno": null
		}
	]`)
	var listed []walletLsEntry
	if err := jsonstrict.Decode(payload, &listed); err != nil {
		t.Fatalf("decode tosctl wallet ls payload: %v", err)
	}
	if len(listed) != 2 || listed[0].Name != "creator" || listed[1].Address != "" {
		t.Fatalf("unexpected decode result: %+v", listed)
	}
}

func TestStableRecordNameDoesNotExposeActionID(t *testing.T) {
	first := recordName("secret/action/id")
	second := recordName("secret/action/id")
	if first != second || strings.Contains(first, "secret") || len(first) != len("atos-")+16 {
		t.Fatalf("unexpected record name %q", first)
	}
}

func TestCanonicalWalletAddressAcceptsTosctlPresentationWithoutWeakeningReferences(t *testing.T) {
	raw := "0:" + strings.Repeat("11", 32)
	parsed, err := address.ParseRawAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	friendly := parsed.String()
	if friendly == raw {
		t.Fatal("expected a user-friendly tosctl presentation")
	}
	for _, input := range []string{raw, friendly} {
		got, err := canonicalWalletAddress(input)
		if err != nil {
			t.Fatalf("normalize %q: %v", input, err)
		}
		if got != raw {
			t.Fatalf("normalize %q = %q, want %q", input, got, raw)
		}
	}
	if _, err := toschain.CanonicalAddress(friendly); err == nil {
		t.Fatal("public chain references must continue rejecting user-friendly addresses")
	}
}

func TestTaskStateViewAcceptsTosctlOutputFields(t *testing.T) {
	// tosctl's `agent task build-state --format json` emits every field of
	// AgentTaskStateView, not just address/permission_hash/policy_hash;
	// jsonstrict.Decode rejects unknown fields, so this guards against
	// taskStateView drifting out of sync with that output.
	payload := []byte(`{
		"creator": "0:` + strings.Repeat("11", 32) + `",
		"assigned_agent": "0:` + strings.Repeat("22", 32) + `",
		"verifier": null,
		"permission_id": null,
		"permission_hash": "` + strings.Repeat("aa", 32) + `",
		"budget": "5",
		"deadline": 1900000000,
		"review_period": 3600,
		"workchain": 0,
		"address": "0:` + strings.Repeat("33", 32) + `",
		"policy_hash": "` + strings.Repeat("bb", 32) + `",
		"state_init_boc": "base64==",
		"code_hash": "` + strings.Repeat("cc", 32) + `",
		"data_hash": "` + strings.Repeat("dd", 32) + `"
	}`)
	var state taskStateView
	if err := jsonstrict.Decode(payload, &state); err != nil {
		t.Fatalf("decode tosctl build-state payload: %v", err)
	}
	if state.Address != "0:"+strings.Repeat("33", 32) || state.PolicyHash != strings.Repeat("bb", 32) {
		t.Fatalf("unexpected decode result: %+v", state)
	}
}

func TestAccountInformationAcceptsFullGetAddressInformationShape(t *testing.T) {
	// TOS JSON-RPC getAddressInformation returns balance/code/data/block_id/
	// sync_utime/extra_currencies/frozen_hash alongside @type/state/
	// last_transaction_id; jsonstrict.Decode rejects unknown fields, so this
	// guards against accountInformation drifting out of sync with that response.
	payload := []byte(`{
		"@type": "raw.fullAccountState",
		"balance": "5000000000",
		"code": "te6cckEB",
		"data": "te6cckEB",
		"last_transaction_id": {"@type": "internal.transactionId", "lt": "123", "hash": "aGFzaA=="},
		"block_id": {"@type": "tos.blockIdExt", "workchain": 0, "shard": "-9223372036854775808", "seqno": 1, "root_hash": "r", "file_hash": "f"},
		"sync_utime": 1700000000,
		"extra_currencies": [],
		"state": "active",
		"frozen_hash": ""
	}`)
	var info accountInformation
	if err := jsonstrict.Decode(payload, &info); err != nil {
		t.Fatalf("decode getAddressInformation payload: %v", err)
	}
	if info.State != "active" || info.LastTransactionID.LT != "123" {
		t.Fatalf("unexpected decode result: %+v", info)
	}
}

func TestMasterchainInformationAcceptsRealDaemonShape(t *testing.T) {
	payload := []byte(`{
		"@type":"blocks.masterchainInfo",
		"last":{"@type":"tos.blockIdExt","workchain":-1,"shard":"-9223372036854775808","seqno":64,"root_hash":"root","file_hash":"file"},
		"state_root_hash":"state",
		"init":{"@type":"tos.blockIdExt","workchain":-1,"shard":"-9223372036854775808","seqno":0,"root_hash":"genesis-root","file_hash":"genesis-file"}
	}`)
	var info masterchainInformation
	if err := jsonstrict.Decode(payload, &info); err != nil {
		t.Fatalf("decode real getMasterchainInfo payload: %v", err)
	}
	if info.Type != "blocks.masterchainInfo" || info.Last.Seqno != 64 || info.Init.RootHash != "genesis-root" {
		t.Fatalf("unexpected masterchain info: %+v", info)
	}
}

func TestRawTransactionAcceptsFullGetTransactionsShape(t *testing.T) {
	// TOS JSON-RPC getTransactions includes fee and in_msg_hash whenever the
	// daemon can parse the fee or the transaction carries an inbound message;
	// jsonstrict.Decode rejects unknown fields, so this guards against
	// rawTransaction drifting out of sync with that response.
	payload := []byte(`[{
		"@type": "raw.transaction",
		"block_id": {"@type": "tos.blockIdExt", "workchain": 0, "shard": "-9223372036854775808", "seqno": 1, "root_hash": "r", "file_hash": "f"},
		"data": "te6cckEB",
		"utime": 1700000000,
		"transaction_id": {"@type": "internal.transactionId", "lt": "123", "hash": "aGFzaA=="},
		"fee": "1000000",
		"account": "` + strings.Repeat("11", 32) + `",
		"in_msg_hash": "aGFzaA=="
	}]`)
	var transactions []rawTransaction
	if err := jsonstrict.Decode(payload, &transactions); err != nil {
		t.Fatalf("decode getTransactions payload: %v", err)
	}
	if len(transactions) != 1 || transactions[0].TransactionID.LT != "123" {
		t.Fatalf("unexpected decode result: %+v", transactions)
	}
}
