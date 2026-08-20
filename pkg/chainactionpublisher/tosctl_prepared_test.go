package chainactionpublisher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/chain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestBroadcastPreparedContractCellValidatesTOSStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		result map[string]any
		ok     bool
	}{
		{name: "accepted", result: map[string]any{"status": 1}, ok: true},
		{name: "rejected", result: map[string]any{"status": -1}},
		{name: "unknown response field", result: map[string]any{"status": 1, "unbound": true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				var call struct {
					JSONRPC string `json:"jsonrpc"`
					ID      uint64 `json:"id"`
					Method  string `json:"method"`
				}
				if err := json.NewDecoder(request.Body).Decode(&call); err != nil || call.JSONRPC != "2.0" || call.Method != "sendBoc" {
					t.Fatalf("unexpected JSON-RPC call: %+v err=%v", call, err)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "ok": true, "result": test.result})
			}))
			defer server.Close()
			client, err := chain.NewClient(server.URL, time.Second, 4096)
			if err != nil {
				t.Fatal(err)
			}
			backend := &TosctlBackend{client: client}
			boc := base64.StdEncoding.EncodeToString([]byte("signed-wallet-message"))
			err = backend.BroadcastPreparedContractCell(context.Background(), boc, sha256Text([]byte("signed-wallet-message")))
			if (err == nil) != test.ok {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, test.ok, err)
			}
		})
	}
}

func TestPreparedContractCellRequiresExactSemanticConfirmation(t *testing.T) {
	body := cell.BeginCell().MustStoreUInt(0x4e560001, 32).EndCell()
	stateInit := cell.BeginCell().MustStoreUInt(0x11, 8).EndCell()
	message := cell.BeginCell().MustStoreUInt(0x22, 8).EndCell()
	bodyHash := "tvm-cell-sha256:" + fmt.Sprintf("%x", body.Hash())
	stateInitHash := "tvm-cell-sha256:" + fmt.Sprintf("%x", stateInit.Hash())
	value := preparedContractCell{Version: PreparedContractCellVersion,
		MessageBOCBase64: base64.StdEncoding.EncodeToString(message.ToBOC()), Wallet: "relay",
		Payer: "0:" + strings.Repeat("11", 32), Destination: "0:" + strings.Repeat("22", 32),
		AmountNanoTOS: 200_000_000, BodyHash: bodyHash, StateInitHash: stateInitHash}
	encode := func(t *testing.T, item preparedContractCell) []byte {
		t.Helper()
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, _, err := validatePreparedContractCell(encode(t, value), value.Wallet, value.Payer,
		value.Destination, value.AmountNanoTOS, bodyHash, stateInitHash); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*preparedContractCell){
		func(v *preparedContractCell) { v.Destination = "0:" + strings.Repeat("33", 32) },
		func(v *preparedContractCell) { v.AmountNanoTOS++ },
		func(v *preparedContractCell) { v.BodyHash = "tvm-cell-sha256:" + strings.Repeat("44", 32) },
		func(v *preparedContractCell) { v.StateInitHash = "" },
		func(v *preparedContractCell) { v.Wallet = "other" },
	}
	for i, mutate := range mutations {
		changed := value
		mutate(&changed)
		if _, _, err := validatePreparedContractCell(encode(t, changed), value.Wallet, value.Payer,
			value.Destination, value.AmountNanoTOS, bodyHash, stateInitHash); err == nil {
			t.Fatalf("semantic mutation %d was accepted", i)
		}
	}
}
