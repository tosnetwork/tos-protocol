package chainactionpublisher_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/chainactionpublisher"
)

func TestTosctlBackendRecoversLostSendByExactChainLookup(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "sent")
	payee := "0:e586e0e4737c347d727d3c38092aa23776966c3d6b54af98ef3cf9c87d93c363"
	payer := "-1:0000000000000000000000000000000000000000000000000000000000000000"
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&call)
		var result any
		switch call.Method {
		case "getMasterchainInfo":
			result = map[string]any{"ok": true}
		case "getAddressInformation":
			result = map[string]any{"@type": "raw.fullAccountState", "balance": "1", "code": "", "data": "", "last_transaction_id": map[string]any{"@type": "internal.transactionId", "lt": "153078000001", "hash": "BHDYVQ6yv+8IBrJMfE3lpseJKCsED8XAX2scl+ImJKc="}, "block_id": map[string]any{}, "sync_utime": 0, "extra_currencies": []any{}, "state": "active", "frozen_hash": ""}
		case "getTransactions":
			if _, err := os.Stat(marker); err != nil {
				result = []any{}
			} else {
				result = []any{map[string]any{"@type": "raw.transaction", "block_id": map[string]any{"@type": "tos.blockIdExt", "workchain": 0, "shard": "-9223372036854775808", "seqno": 125496, "root_hash": "y6+fQZXsBYyjDuRf4bcZkIeLsto9MijbkbSKfpKGfXI=", "file_hash": "6QmXHpL97/WEwuWWPPKPwvEqaIREQE4uNQzKCQNcxg8="}, "data": "te6ccgECBQEAAQYAA69+WG4ORzfDR9cn08OAkqojd2lmw9a1SvmO88+ch9k8NjAAAAI6Qo6YEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamyewQABgIAQIDAQGgBACCcpCuyJZa+rsW68PLm0COuucbYY14eIvIDQmENZPKyY2k6PEOPKoGZZOcJVKj5p3j1qS3WQGKEfL9najjaauNfxoADwwJDuaygAEgAKtJ/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADlhuDkc3w0fXJ9PDgJKqI3dpZsPWtUr5jvPPnIfZPDY0O5rKAAAAAAAR0eauATU2T1+QA==", "utime": 1785503425, "transaction_id": map[string]any{"@type": "internal.transactionId", "lt": "153078000001", "hash": "BHDYVQ6yv+8IBrJMfE3lpseJKCsED8XAX2scl+ImJKc="}, "fee": "0", "account": "E586E0E4737C347D727D3C38092AA23776966C3D6B54AF98EF3CF9C87D93C363", "in_msg_hash": ""}}
			}
		default:
			t.Fatalf("unexpected RPC %s", call.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "jsonrpc": "2.0", "id": call.ID, "result": result})
	}))
	defer rpc.Close()
	script := filepath.Join(dir, "tosctl")
	content := "#!/bin/sh\nif [ \"$1 $2\" = \"wallet ls\" ]; then echo '[{\"name\":\"anchor\",\"address\":\"" + payer + "\",\"balance\":0,\"state\":\"active\",\"wallet_type\":\"V3R2\",\"seqno\":1}]'; exit 0; fi\ntouch '" + marker + "'\nexit 1\n"
	if err := os.WriteFile(script, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "tosctl.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := chainactionpublisher.NewTosctlBackend(chainactionpublisher.TosctlBackendConfig{Network: "tos-test", Binary: script, ConfigPath: configPath, VaultURL: "file:///vault", RPCURL: rpc.URL, WalletName: "anchor", Payer: payer, RecoveryWaitMillis: 1000, PollMillis: 100})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.CheckReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := chain.Action{Version: "1", ActionID: "anchor-test", Network: "tos-test", Kind: chain.ActionKindAnchor, CommitmentKind: "quote", ObjectID: "q", Digest: "sha256:x", Payer: payer, Payee: payee, AmountNanoTOS: 1_000_000_000}
	receipt, err := b.Publish(context.Background(), a, false)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := base64.StdEncoding.DecodeString("BHDYVQ6yv+8IBrJMfE3lpseJKCsED8XAX2scl+ImJKc=")
	if receipt.Reference == "" || len(hash) != 32 {
		t.Fatalf("recovery did not return exact receipt: %+v", receipt)
	}
}
