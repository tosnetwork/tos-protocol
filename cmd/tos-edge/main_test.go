package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/protocol"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const startupTestAccount = "0:3056aee1f503fe98293c0189b779cb88e696e28e74814ac8a7fc866e0dfb3c3e"

func TestLoadTOSChainRuntimePreflightsAuthority(t *testing.T) {
	code := cell.BeginCell().MustStoreUInt(1, 1).EndCell()
	servers := []*httptest.Server{
		startupRPCServer(t, code), startupRPCServer(t, code), startupRPCServer(t, code),
	}
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()
	endpoints := make([]string, len(servers))
	for index, server := range servers {
		endpoints[index] = server.URL
	}
	config := toschain.StartupConfig{
		Version: toschain.StartupConfigVersion, Network: "tos-test",
		Endpoints: endpoints, Quorum: 2,
		AllowedServiceCodeHashes: []string{
			"tvm-cell-sha256:" + hex.EncodeToString(code.Hash()),
		},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "tos-chain.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, readiness, err := loadTOSChainRuntime(
		configPath,
		protocol.ServiceDescriptor{
			Network: "tos-test", ServiceID: "service-e2e", Controller: startupTestAccount,
		},
		time.Unix(1_800_000_001, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil || runtime.Authority == nil || runtime.ClientKeys == nil ||
		runtime.Payments == nil || readiness.ObservedMasterSeqno != 700 ||
		readiness.QuorumEndpoints != 2 {
		t.Fatalf("incomplete startup runtime: runtime=%#v readiness=%#v", runtime, readiness)
	}
}

func TestLoadTOSChainRuntimeRejectsAmbiguousConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "tos-chain.json")
	config := `{"version":"1","network":"tos-test","network":"other"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadTOSChainRuntime(
		configPath,
		protocol.ServiceDescriptor{Network: "tos-test"},
		time.Unix(1_800_000_001, 0),
	); err == nil {
		t.Fatal("ambiguous startup configuration accepted")
	}
}

func startupRPCServer(t *testing.T, code *cell.Cell) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var call struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&call); err != nil {
			t.Errorf("decode RPC request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var result any
		switch call.Method {
		case "getConsensusBlock":
			result = map[string]any{
				"@type": "ext.blocks.consensusBlock", "consensus_block": 700,
				"timestamp": 1_800_000_001, "last_block_utime": 1_800_000_000,
			}
		case "getAddressInformation":
			result = map[string]any{
				"@type": "raw.fullAccountState", "balance": "200000000",
				"code": base64.StdEncoding.EncodeToString(code.ToBOC()),
				"data": base64.StdEncoding.EncodeToString(cell.BeginCell().EndCell().ToBOC()),
				"last_transaction_id": map[string]any{
					"@type": "internal.transactionId", "lt": "1",
					"hash": base64.StdEncoding.EncodeToString(make([]byte, 32)),
				},
				"block_id": map[string]any{
					"@type": "tos.blockIdExt", "workchain": -1,
					"shard": "-9223372036854775808", "seqno": 700,
					"root_hash": base64.StdEncoding.EncodeToString(make([]byte, 32)),
					"file_hash": base64.StdEncoding.EncodeToString(make([]byte, 32)),
				},
				"sync_utime": 1_800_000_000, "extra_currencies": []any{},
				"state": "active", "frozen_hash": "",
			}
		case "runGetMethodStd":
			result = map[string]any{
				"@type": "smc.runResult", "gas_used": 100, "exit_code": 0,
				"stack": []any{
					startupStackNumber("0"), startupStackNumber("0"), startupStackNumber("0"),
					startupStackNumber(new(big.Int).SetBytes(startupBytes(0x11)).String()),
					startupStackNumber(new(big.Int).SetBytes(startupBytes(0x55)).String()),
					startupStackNumber("3600"), startupStackNumber("10000000000"),
					startupStackNumber("1000000000"),
					startupStackNumber(new(big.Int).SetBytes(startupBytes(0x22)).String()),
					map[string]any{"@type": "tvm.stackEntrySlice", "slice": map[string]any{}},
				},
			}
		default:
			t.Errorf("unexpected RPC method %q", call.Method)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]any{
			"ok": true, "jsonrpc": "2.0", "id": call.ID, "result": result,
		}); err != nil {
			t.Errorf("encode RPC response: %v", err)
		}
	}))
}

func startupStackNumber(value string) map[string]any {
	return map[string]any{
		"@type":  "tvm.stackEntryNumber",
		"number": map[string]any{"@type": "tvm.numberDecimal", "number": value},
	}
}

func startupBytes(value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), 32))
}
