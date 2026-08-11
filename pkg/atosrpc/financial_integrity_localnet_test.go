package atosrpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/gen/atos/tos/v1/atostosv1connect"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

type localnetFinancialRuntime struct {
	adapter *toschain.Adapter
	client  *chain.Client
}

func (r *localnetFinancialRuntime) CheckServiceReady(ctx context.Context, reference authorization.Reference, _ time.Time) (toschain.ReadinessSnapshot, error) {
	var result map[string]any
	if err := r.client.Call(ctx, "getMasterchainInfo", struct{}{}, &result); err != nil {
		return toschain.ReadinessSnapshot{}, err
	}
	last, _ := result["last"].(map[string]any)
	seqno := jsonUint(last["seqno"])
	if seqno == 0 || reference.Network == "" {
		return toschain.ReadinessSnapshot{}, fmt.Errorf("localnet masterchain is not ready")
	}
	return toschain.ReadinessSnapshot{Network: reference.Network, ObservedMasterSeqno: seqno, ObservedAt: time.Now().UTC(), QuorumEndpoints: 3}, nil
}

func (r *localnetFinancialRuntime) ObservePayment(ctx context.Context, reference chain.PaymentReference) (chain.PaymentState, error) {
	return r.adapter.ObservePayment(ctx, reference)
}

type latestTransaction struct {
	LT   string `json:"lt"`
	Hash string `json:"hash"`
}

type localnetTosctlPublisher struct {
	network, binary, config, wallet, endpoint, payee string
	client                                           *chain.Client
	mu                                               sync.Mutex
	receipts                                         map[string]chain.ActionReceipt
}

func (p *localnetTosctlPublisher) CheckReady(ctx context.Context) error {
	var result map[string]any
	return p.client.Call(ctx, "getMasterchainInfo", struct{}{}, &result)
}
func (p *localnetTosctlPublisher) Close() error { return nil }

func (p *localnetTosctlPublisher) latest(ctx context.Context) (latestTransaction, error) {
	var result map[string]any
	if err := p.client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
	}{p.payee}, &result); err != nil {
		return latestTransaction{}, err
	}
	last, _ := result["last_transaction_id"].(map[string]any)
	return latestTransaction{LT: fmt.Sprint(last["lt"]), Hash: fmt.Sprint(last["hash"])}, nil
}

func jsonUint(value any) uint64 {
	switch number := value.(type) {
	case json.Number:
		result, _ := strconv.ParseUint(number.String(), 10, 64)
		return result
	case float64:
		return uint64(number)
	default:
		result, _ := strconv.ParseUint(fmt.Sprint(value), 10, 64)
		return result
	}
}

func (p *localnetTosctlPublisher) Publish(ctx context.Context, action chain.Action) (chain.ActionReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if receipt, ok := p.receipts[action.ActionID]; ok {
		return receipt, nil
	}
	before, err := p.latest(ctx)
	if err != nil {
		return chain.ActionReceipt{}, err
	}
	amount := strconv.FormatUint(action.AmountNanoTOS, 10)
	command := exec.CommandContext(ctx, p.binary, "wallet", "send", "--from", p.wallet,
		"--to", action.Payee, "--amount-nanotos", amount, "--message", action.Comment, "--yes", "-c", p.config)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		return chain.ActionReceipt{}, fmt.Errorf("tosctl anchor transfer: %w: %s", err, strings.TrimSpace(string(output)))
	}
	deadline := time.Now().Add(60 * time.Second)
	var after latestTransaction
	for time.Now().Before(deadline) {
		after, err = p.latest(ctx)
		if err == nil && after.LT != "" && (after.LT != before.LT || after.Hash != before.Hash) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	lt, err := strconv.ParseUint(after.LT, 10, 64)
	hash, hashErr := base64.StdEncoding.DecodeString(after.Hash)
	if err != nil || hashErr != nil || len(hash) != 32 {
		return chain.ActionReceipt{}, fmt.Errorf("anchor transaction was not observed")
	}
	reference, err := toschain.FormatTransactionReference(action.Payee, lt, hash)
	if err != nil {
		return chain.ActionReceipt{}, err
	}
	receipt := chain.ActionReceipt{Version: action.Version, ActionID: action.ActionID, Network: action.Network,
		Kind: action.Kind, CommitmentKind: action.CommitmentKind, ObjectID: action.ObjectID, Digest: action.Digest, Reference: reference,
		Payer: action.Payer, Payee: action.Payee, AmountNanoTOS: action.AmountNanoTOS, Comment: action.Comment}
	p.receipts[action.ActionID] = receipt
	return receipt, nil
}

func TestManagedFinancialAnchorRealTOSLocalnet(t *testing.T) {
	endpointsText := os.Getenv("TOS_FINANCIAL_LOCALNET_ENDPOINTS")
	if endpointsText == "" {
		t.Skip("TOS_FINANCIAL_LOCALNET_ENDPOINTS is required")
	}
	endpoints := strings.Split(endpointsText, ",")
	if len(endpoints) != 3 {
		t.Fatal("three independent localnet endpoints are required")
	}
	network := "tos-localnet"
	chainConfig := toschain.Config{Network: network, Endpoints: endpoints, Quorum: 2, QueryTimeout: 15 * time.Second}
	adapter, err := toschain.New(chainConfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := chain.NewClient(endpoints[0], 15*time.Second, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	payer, payee := os.Getenv("TOS_FINANCIAL_LOCALNET_PAYER"), os.Getenv("TOS_FINANCIAL_LOCALNET_PAYEE")
	publisher := &localnetTosctlPublisher{network: network, binary: os.Getenv("TOS_FINANCIAL_LOCALNET_TOSCTL"),
		config: os.Getenv("TOS_FINANCIAL_LOCALNET_TOSCTL_CONFIG"), wallet: os.Getenv("TOS_FINANCIAL_LOCALNET_WALLET"),
		endpoint: endpoints[0], payee: payee, client: client, receipts: make(map[string]chain.ActionReceipt)}
	runtime := &localnetFinancialRuntime{adapter: adapter, client: client}
	authority, err := newChainAuthority(runtime, authorization.Reference{Network: network, Address: payer, ServiceID: "financial-anchor-localnet"},
		publisher, payer, payee, 1, 90*time.Second, 5*time.Minute, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	router, _ := NewStaticRouter(nil)
	server, err := Open(Config{StatePath: t.TempDir() + "/rpc.db", BearerToken: "localnet-financial-token", Authority: authority, Router: router, CallTimeout: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	rpc := atostosv1connect.NewFinancialIntegrityServiceClient(httpServer.Client(), httpServer.URL)
	digest := func(value byte) *atostosv1.Digest {
		return &atostosv1.Digest{Algorithm: "sha256", Value: []byte(strings.Repeat(string(value), 32))}
	}
	anchor := &atostosv1.ManagedFinancialAnchorInput{Version: managedFinancialAnchorVersion, BatchId: "fbat_localnet_phase7a", BatchSequence: 1,
		FirstSequence: 1, LastSequence: 1, CommitmentCount: 1, PreviousMerkleRoot: digest(0), MerkleRoot: digest(1),
		ManifestDigest: digest(2), SignatureDigest: digest(3), SigningKeyId: "kms-localnet-1", Canonicalization: managedFinancialCanonical,
		GatewayId: "gateway-localnet-phase7a", NetworkId: network}
	anchor.AnchorId, err = managedFinancialAnchorID(anchor)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := managedFinancialPayloadDigest(anchor)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := authority.Commit(context.Background(), "managed-financial-ledger-root", anchor.AnchorId, payloadDigest)
	if err != nil {
		t.Fatalf("real-chain authority preflight: %v", err)
	}
	if !preflight.Finalized || !strings.HasPrefix(preflight.Reference, "tos:tx:v1:") {
		t.Fatalf("real-chain authority returned non-finalized preflight: network=%q reference=%q finalized=%t checkpoint=%d",
			preflight.Network, preflight.Reference, preflight.Finalized, preflight.FinalizedCheckpoint)
	}
	request := connect.NewRequest(&atostosv1.PublishManagedFinancialAnchorRequest{Context: &atostosv1.RequestContext{RequestId: strings.Repeat("a", 32), TraceId: strings.Repeat("b", 32), IdempotencyKey: anchor.AnchorId, CallerId: anchor.GatewayId, DeadlineUnixMillis: time.Now().Add(80 * time.Second).UnixMilli()}, Anchor: anchor})
	request.Header().Set("Authorization", "Bearer localnet-financial-token")
	first, err := rpc.PublishManagedFinancialAnchor(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Msg.Finalized || first.Msg.FinalizedCheckpoint == 0 || first.Msg.AnchorRef == nil || !strings.HasPrefix(first.Msg.AnchorRef.Reference, "tos:tx:v1:") {
		encoded, _ := json.Marshal(first.Msg)
		t.Fatalf("anchor was not finalized on TOS: %s", encoded)
	}
	// Same semantic retry must converge without a second wallet transfer.
	replay := connect.NewRequest(&atostosv1.PublishManagedFinancialAnchorRequest{Context: request.Msg.Context, Anchor: anchor})
	replay.Header().Set("Authorization", "Bearer localnet-financial-token")
	second, err := rpc.PublishManagedFinancialAnchor(context.Background(), replay)
	if err != nil || second.Msg.AnchorRef.Reference != first.Msg.AnchorRef.Reference {
		t.Fatalf("anchor retry did not converge: %v", err)
	}
	resolve := connect.NewRequest(&atostosv1.ResolveManagedFinancialAnchorRequest{Context: &atostosv1.RequestContext{RequestId: strings.Repeat("c", 32), TraceId: strings.Repeat("d", 32), CallerId: anchor.GatewayId, DeadlineUnixMillis: time.Now().Add(30 * time.Second).UnixMilli()}, AnchorId: anchor.AnchorId, NetworkId: network})
	resolve.Header().Set("Authorization", "Bearer localnet-financial-token")
	resolved, err := rpc.ResolveManagedFinancialAnchor(context.Background(), resolve)
	if err != nil || !resolved.Msg.Found || resolved.Msg.AnchorRef.Reference != first.Msg.AnchorRef.Reference {
		t.Fatalf("finalized anchor did not resolve: %v", err)
	}
	t.Logf("finalized TOS anchor %s checkpoint=%d", first.Msg.AnchorRef.Reference, first.Msg.FinalizedCheckpoint)
}

var _ chain.ActionPublisher = (*localnetTosctlPublisher)(nil)
