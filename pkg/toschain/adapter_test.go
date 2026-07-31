package toschain

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const (
	testAgentAccount = "0:3056aee1f503fe98293c0189b779cb88e696e28e74814ac8a7fc866e0dfb3c3e"
	testPaymentPayee = "0:e586e0e4737c347d727d3c38092aa23776966c3d6b54af98ef3cf9c87d93c363"
	testPaymentPayer = "-1:0000000000000000000000000000000000000000000000000000000000000000"
	testPaymentLT    = uint64(153078000001)
	testPaymentHash  = "0470d8550eb2bfef0806b24c7c4de5a6c789282b040fc5c05f6b1c97e22624a7"
	testPaymentBOC   = "te6ccgECBQEAAQYAA69+WG4ORzfDR9cn08OAkqojd2lmw9a1SvmO88+ch9k8NjAAAAI6Qo6YEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAamyewQABgIAQIDAQGgBACCcpCuyJZa+rsW68PLm0COuucbYY14eIvIDQmENZPKyY2k6PEOPKoGZZOcJVKj5p3j1qS3WQGKEfL9najjaauNfxoADwwJDuaygAEgAKtJ/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADlhuDkc3w0fXJ9PDgJKqI3dpZsPWtUr5jvPPnIfZPDY0O5rKAAAAAAAR0eauATU2T1+QA=="
)

type fakeRPCBehavior struct {
	manifest        []byte
	missingManifest bool
	controller      []byte
	transactionMode string
}

func fakeRPCServer(t *testing.T, behavior fakeRPCBehavior) *httptest.Server {
	t.Helper()
	code := cell.BeginCell().MustStoreUInt(1, 1).EndCell()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var call struct {
			ID     uint64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&call); err != nil {
			t.Errorf("decode fake RPC request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		result := any(nil)
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
			controller := behavior.controller
			if len(controller) == 0 {
				controller = bytesOf(0x22)
			}
			manifest := behavior.manifest
			if len(manifest) == 0 {
				manifest = bytesOf(0x11)
			}
			manifestNumber := new(big.Int).SetBytes(manifest).String()
			if behavior.missingManifest {
				manifestNumber = "-1"
			}
			result = map[string]any{
				"@type": "smc.runResult", "gas_used": 100, "exit_code": 0,
				"stack": []any{
					stackNumberValue("0"), stackNumberValue("0"), stackNumberValue("0"),
					stackNumberValue(manifestNumber),
					stackNumberValue(new(big.Int).SetBytes(bytesOf(0x55)).String()),
					stackNumberValue("3600"), stackNumberValue("10000000000"),
					stackNumberValue("1000000000"),
					stackNumberValue(new(big.Int).SetBytes(controller).String()),
					map[string]any{"@type": "tvm.stackEntrySlice", "slice": map[string]any{}},
				},
			}
		case "getTransactions":
			switch behavior.transactionMode {
			case "missing":
				_ = json.NewEncoder(writer).Encode(map[string]any{
					"ok": false, "jsonrpc": "2.0", "id": call.ID,
					"error": "getTransactions: cannot locate transaction in block with specified logical time",
					"code":  -32603,
				})
				return
			case "malformed":
				transaction := testRawTransaction()
				transaction.Data = "te6ccgEBAQEA"
				result = []rawTransaction{transaction}
			default:
				result = []rawTransaction{testRawTransaction()}
			}
		default:
			t.Errorf("unexpected fake RPC method %q", call.Method)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(writer).Encode(map[string]any{
			"ok": true, "jsonrpc": "2.0", "id": call.ID, "result": result,
		}); err != nil {
			t.Errorf("encode fake RPC response: %v", err)
		}
	}))
}

func TestAdapterResolvesQuorumAuthorityAndClientKey(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{manifest: bytesOf(0x33)}),
	}
	defer closeServers(servers)
	adapter := newTestAdapter(t, servers)

	service, err := adapter.ResolveService(context.Background(), chain.ServiceReference{
		Network: "tos-test", Address: testAgentAccount, ServiceID: "service-e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedController := "ed25519:" + strings.Repeat("22", 32)
	if service.Controller != expectedController ||
		service.ManifestDigest != "sha256:"+strings.Repeat("11", 32) ||
		!service.Active || !service.Finalized || service.ObservedMasterSeqno != 700 ||
		!strings.HasPrefix(service.CodeHash, codeHashPrefix) {
		t.Fatalf("unexpected service state: %#v", service)
	}
	clientKeyID, err := FormatAgentClientKeyID(testAgentAccount, bytesOf(0x22))
	if err != nil {
		t.Fatal(err)
	}
	key, err := adapter.ResolveClientKey(context.Background(), authorization.ClientKeyReference{
		Network: "tos-test", ServiceID: "service-e2e", KeyID: clientKeyID,
		MinimumMasterSeqno: 700,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.Principal != testAgentAccount || hex.EncodeToString(key.PublicKey) != strings.Repeat("22", 32) ||
		key.ObservedMasterSeqno != 700 || !key.NotAfter.After(key.NotBefore) {
		t.Fatalf("unexpected client-key state: %#v", key)
	}
	if _, err := adapter.ResolveClientKey(context.Background(), authorization.ClientKeyReference{
		Network: "tos-test", ServiceID: "service-e2e", KeyID: clientKeyID,
		MinimumMasterSeqno: 701,
	}); err == nil {
		t.Fatal("client key below high-water mark accepted")
	}
	staleKeyID, err := FormatAgentClientKeyID(testAgentAccount, bytesOf(0x44))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ResolveClientKey(context.Background(), authorization.ClientKeyReference{
		Network: "tos-test", ServiceID: "service-e2e", KeyID: staleKeyID,
	}); err == nil {
		t.Fatal("non-current Agent Account controller accepted")
	}
}

func TestClientKeyDoesNotRequireServiceManifestCommitment(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{missingManifest: true}),
		fakeRPCServer(t, fakeRPCBehavior{missingManifest: true}),
		fakeRPCServer(t, fakeRPCBehavior{missingManifest: true}),
	}
	defer closeServers(servers)
	adapter := newTestAdapter(t, servers)
	if _, err := adapter.ResolveService(context.Background(), chain.ServiceReference{
		Network: "tos-test", Address: testAgentAccount, ServiceID: "service-e2e",
	}); err == nil {
		t.Fatal("service authority without manifest commitment accepted")
	}
	clientKeyID, err := FormatAgentClientKeyID(testAgentAccount, bytesOf(0x22))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ResolveClientKey(
		context.Background(),
		authorization.ClientKeyReference{
			Network: "tos-test", ServiceID: "service-e2e", KeyID: clientKeyID,
		},
	); err != nil {
		t.Fatalf("client account unnecessarily required a service manifest: %v", err)
	}
}

func TestAdapterObservesExactRawPaymentWithQuorum(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{transactionMode: "missing"}),
	}
	defer closeServers(servers)
	adapter := newTestAdapter(t, servers)
	hash, _ := hex.DecodeString(testPaymentHash)
	reference, err := FormatTransactionReference(testPaymentPayee, testPaymentLT, hash)
	if err != nil {
		t.Fatal(err)
	}
	state, err := adapter.ObservePayment(context.Background(), chain.PaymentReference{
		Network: "tos-test", AuthorizationID: "authorization-e2e", QuoteID: "quote-e2e",
		RequestID: "request-e2e", Reference: reference,
		Payer: testPaymentPayer, Payee: testPaymentPayee, AmountNanoTOS: 1_000_000_000,
		MinimumMasterSeqno: 699,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !state.Confirmed || !state.Finalized || state.Reorganized ||
		state.Payer != testPaymentPayer || state.Payee != testPaymentPayee ||
		state.AmountNanoTOS != 1_000_000_000 || state.ObservedMasterSeqno != 700 {
		t.Fatalf("unexpected payment state: %#v", state)
	}
}

func TestAdapterRejectsMalformedTransactionQuorum(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{transactionMode: "malformed"}),
		fakeRPCServer(t, fakeRPCBehavior{transactionMode: "malformed"}),
		fakeRPCServer(t, fakeRPCBehavior{}),
	}
	defer closeServers(servers)
	adapter := newTestAdapter(t, servers)
	hash, _ := hex.DecodeString(testPaymentHash)
	reference, _ := FormatTransactionReference(testPaymentPayee, testPaymentLT, hash)
	if _, err := adapter.ObservePayment(context.Background(), chain.PaymentReference{
		Network: "tos-test", AuthorizationID: "authorization-e2e", QuoteID: "quote-e2e",
		RequestID: "request-e2e", Reference: reference,
		Payer: testPaymentPayer, Payee: testPaymentPayee, AmountNanoTOS: 1_000_000_000,
	}); err == nil {
		t.Fatal("malformed transaction BOC quorum accepted")
	}
}

func TestAdapterReturnsStatelessNegativePayment(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{transactionMode: "missing"}),
		fakeRPCServer(t, fakeRPCBehavior{transactionMode: "missing"}),
		fakeRPCServer(t, fakeRPCBehavior{transactionMode: "missing"}),
	}
	defer closeServers(servers)
	adapter := newTestAdapter(t, servers)
	hash, _ := hex.DecodeString(testPaymentHash)
	reference, _ := FormatTransactionReference(testPaymentPayee, testPaymentLT, hash)
	state, err := adapter.ObservePayment(context.Background(), chain.PaymentReference{
		Network: "tos-test", AuthorizationID: "authorization-e2e", QuoteID: "quote-e2e",
		RequestID: "request-e2e", Reference: reference,
		Payer: testPaymentPayer, Payee: testPaymentPayee, AmountNanoTOS: 1_000_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Confirmed || state.Reorganized || !state.Finalized ||
		state.Payer != testPaymentPayer || state.Payee != testPaymentPayee ||
		state.AmountNanoTOS != 1_000_000_000 {
		t.Fatalf("unexpected negative payment state: %#v", state)
	}
}

func TestAdapterRequiresStrictMajorityAndUniqueEndpoints(t *testing.T) {
	server := fakeRPCServer(t, fakeRPCBehavior{})
	defer server.Close()
	if _, err := New(Config{
		Network: "tos-test", Endpoints: []string{server.URL, server.URL}, Quorum: 2,
	}); err == nil {
		t.Fatal("duplicate endpoints accepted")
	}
	if _, err := New(Config{
		Network: "tos-test", Endpoints: []string{"https://one", "https://two", "https://three"}, Quorum: 1,
	}); err == nil {
		t.Fatal("non-majority quorum accepted")
	}
}

func TestAdapterRejectsInsecureOrRepeatedEndpointAuthorities(t *testing.T) {
	if _, err := New(Config{
		Network: "tos-test",
		Endpoints: []string{
			"http://rpc-1.example/jsonRPC", "https://rpc-2.example/jsonRPC",
			"https://rpc-3.example/jsonRPC",
		},
		Quorum: 2,
	}); err == nil {
		t.Fatal("insecure remote endpoint accepted")
	}
	if _, err := New(Config{
		Network: "tos-test",
		Endpoints: []string{
			"https://rpc.example/one", "https://rpc.example/two",
			"https://other.example/jsonRPC",
		},
		Quorum: 2,
	}); err == nil {
		t.Fatal("one endpoint authority counted as multiple observers")
	}
}

func TestAdapterReadinessRequiresRecentStrictMajority(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
	}
	adapter := newTestAdapter(t, servers)
	servers[2].Close()
	defer servers[0].Close()
	defer servers[1].Close()
	now := time.Unix(1_800_000_001, 0).UTC()
	readiness, err := adapter.Readiness(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Network != "tos-test" || readiness.ObservedMasterSeqno != 700 ||
		readiness.QuorumEndpoints != 2 || !readiness.ObservedAt.Equal(time.Unix(1_800_000_000, 0)) {
		t.Fatalf("unexpected readiness snapshot: %#v", readiness)
	}
	if _, err := adapter.Readiness(
		context.Background(), readiness.ObservedAt.Add(DefaultReadinessMaxAge),
	); err == nil {
		t.Fatal("stale TOS chain reported ready")
	}
}

func TestStackNumberRejectsDuplicateFields(t *testing.T) {
	raw := json.RawMessage(`{"@type":"tvm.stackEntryNumber","number":{"@type":"tvm.numberDecimal","number":"1"},"number":{"@type":"tvm.numberDecimal","number":"2"}}`)
	if _, err := decodeStackUint256(raw, false); err == nil {
		t.Fatal("ambiguous TVM stack number accepted")
	}
}

func TestNewRuntimeComposesAllThreeResolvers(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
	}
	defer closeServers(servers)
	code := cell.BeginCell().MustStoreUInt(1, 1).EndCell()
	codeHash := codeHashPrefix + hex.EncodeToString(code.Hash())
	endpoints := make([]string, len(servers))
	for index, server := range servers {
		endpoints[index] = server.URL
	}
	runtime, err := NewRuntime(Config{
		Network: "tos-test", Endpoints: endpoints, Quorum: 2,
	}, []string{codeHash}, payment.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Chain == nil || runtime.Authority == nil ||
		runtime.ClientKeys == nil || runtime.Payments == nil {
		t.Fatalf("incomplete TOS runtime composition: %#v", runtime)
	}
	readiness, err := runtime.CheckServiceReady(
		context.Background(),
		authorization.Reference{
			Network: "tos-test", Address: testAgentAccount, ServiceID: "service-e2e",
		},
		time.Unix(1_800_000_001, 0),
	)
	if err != nil || readiness.ObservedMasterSeqno != 700 || readiness.QuorumEndpoints != 2 {
		t.Fatalf("unexpected service readiness: readiness=%#v err=%v", readiness, err)
	}
	wrongRuntime, err := NewRuntime(Config{
		Network: "tos-test", Endpoints: endpoints, Quorum: 2,
	}, []string{codeHashPrefix + strings.Repeat("ff", 32)}, payment.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongRuntime.CheckServiceReady(
		context.Background(),
		authorization.Reference{
			Network: "tos-test", Address: testAgentAccount, ServiceID: "service-e2e",
		},
		time.Unix(1_800_000_001, 0),
	); err == nil {
		t.Fatal("service with non-allowlisted code reported ready")
	}
}

func newTestAdapter(t *testing.T, servers []*httptest.Server) *Adapter {
	t.Helper()
	endpoints := make([]string, len(servers))
	for index, server := range servers {
		endpoints[index] = server.URL
	}
	adapter, err := New(Config{
		Network: "tos-test", Endpoints: endpoints, Quorum: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testRawTransaction() rawTransaction {
	return rawTransaction{
		Type: "raw.transaction",
		BlockID: blockID{
			Type: "tos.blockIdExt", Workchain: 0, Shard: "-9223372036854775808",
			Seqno:    125496,
			RootHash: "y6+fQZXsBYyjDuRf4bcZkIeLsto9MijbkbSKfpKGfXI=",
			FileHash: "6QmXHpL97/WEwuWWPPKPwvEqaIREQE4uNQzKCQNcxg8=",
		},
		Data: testPaymentBOC, Utime: 1785503425,
		TransactionID: transactionID{
			Type: "internal.transactionId", LT: "153078000001",
			Hash: "BHDYVQ6yv+8IBrJMfE3lpseJKCsED8XAX2scl+ImJKc=",
		},
		Fee: "0", Account: "E586E0E4737C347D727D3C38092AA23776966C3D6B54AF98EF3CF9C87D93C363",
		InMsgHash: "pyxX/alGQ2344iPglLlVqPmErl1DbrznAm60B/Ajhys=",
	}
}

func stackNumberValue(value string) map[string]any {
	return map[string]any{
		"@type":  "tvm.stackEntryNumber",
		"number": map[string]any{"@type": "tvm.numberDecimal", "number": value},
	}
}

func bytesOf(value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), 32))
}

func closeServers(servers []*httptest.Server) {
	for _, server := range servers {
		server.Close()
	}
}
