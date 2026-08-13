package chainactionpublisher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
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
