package executiongate

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

type escrowFake struct{ value *toschain.FinalizedEscrowV1 }

func (f escrowFake) ResolveFinalized(context.Context, string) (*toschain.FinalizedEscrowV1, bool, error) {
	return f.value, true, nil
}

type nativeFake struct {
	values map[string]*nativev1.NativeStateV1
}

func (f nativeFake) ResolveFinalizedState(_ context.Context, objectID, _ string) (*nativev1.NativeStateV1, bool, time.Time, error) {
	state, ok := f.values[objectID]
	if !ok {
		return nil, false, time.Time{}, nil
	}
	return proto.Clone(state).(*nativev1.NativeStateV1), true, time.Unix(2_000_000_000, 0), nil
}

func TestGateAtomicallyBindsOnePaidQuoteExecution(t *testing.T) {
	g, req := fixture(t)
	first, err := g.ClaimExecution(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.EscrowFinalizedCheckpoint != 10 || first.AgentFinalizedCheckpoint != 11 || first.CapabilityFinalizedCheckpoint != 12 {
		t.Fatal("missing finalized evidence")
	}
	if _, err = g.ClaimExecution(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	conflict := req
	conflict.ExecutionID = "sha256:" + strings.Repeat("99", 32)
	if _, err = g.ClaimExecution(context.Background(), conflict); err == nil {
		t.Fatal("paid Quote admitted a second execution")
	}
}

func TestGateSerializesConflictingTransportClaims(t *testing.T) {
	g, first := fixture(t)
	second := first
	second.ExecutionID = digest("91")
	second.InputDigest = digest("92")
	second.SourceDigest = digest("93")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, req := range []Request{first, second} {
		go func(request Request) {
			<-start
			_, err := g.ClaimExecution(context.Background(), request)
			results <- err
		}(req)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("conflicting transports produced %d successful claims, want 1", successes)
	}
}

func TestGateRejectsExpiredExecutionWindow(t *testing.T) {
	g, req := fixture(t)
	g.escrow.(escrowFake).value.State.RefundAvailableAt = uint64(g.now().Unix())
	if _, err := g.ClaimExecution(context.Background(), req); err == nil {
		t.Fatal("expired funded escrow executed")
	}
}

func TestGateRejectsTombstonedProviderAgent(t *testing.T) {
	g, req := fixture(t)
	state := g.native.(nativeFake).values[g.providerAgent]
	state.GetAgent().Tombstoned = true
	if _, err := g.ClaimExecution(context.Background(), req); err == nil {
		t.Fatal("tombstoned provider Agent executed work")
	}
}

func TestStorePersistsNewFinalityHighWater(t *testing.T) {
	g, req := fixture(t)
	if _, err := g.ClaimExecution(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	escrow := g.escrow.(escrowFake).value
	escrow.Reference.FinalizedCheckpoint = 20
	escrow.Reference.TransactionHash = digest("20")
	values := g.native.(nativeFake).values
	values[g.providerAgent].Reference.FinalizedCheckpoint = 21
	values[g.providerAgent].Reference.TransactionHash = digest("21")
	for id, state := range values {
		if strings.HasPrefix(id, "cap_") {
			state.Reference.FinalizedCheckpoint = 22
			state.Reference.TransactionHash = digest("22")
		}
	}
	if _, err := g.ClaimExecution(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	escrow.Reference.FinalizedCheckpoint = 19
	if _, err := g.ClaimExecution(context.Background(), req); err == nil {
		t.Fatal("persisted escrow checkpoint accepted a regression")
	}
}

func fixture(t *testing.T) (*Gate, Request) {
	t.Helper()
	now := time.Unix(2_000_000_000, 0)
	network := &nativev1.NetworkDomain{
		NetworkId: "gate-test", GenesisRootHash: digest("11"), GenesisFileHash: digest("22"),
	}
	capID := "cap_" + strings.Repeat("33", 32)
	agentID := "agent_" + strings.Repeat("44", 32)
	manifest := digest("55")
	transport := digest("66")
	signer := digest("77")
	provider := "0:" + strings.Repeat("88", 32)
	asset := &nativev1.TOSAssetIdentityV1{
		Master: &nativev1.TOSContractIdentityV1{
			Workchain: 0, AccountId: bytes32(0x99), CodeHash: cellHash("aa"),
		},
		WalletCodeHash: cellHash("bb"), Decimals: 6,
	}
	proposal := &nativev1.QuoteProposalV1{
		CapabilityId: capID, CapabilityVersion: "1", ProviderAgentId: agentID,
		ManifestDigest: manifest, TransportBindingDigest: transport,
		MaximumPrice:      &nativev1.MoneyV1{Asset: asset, AtomicAmount: "100"},
		EscrowTermsDigest: digest("cc"), DisputePolicyDigest: digest("dd"),
		ExpiresAtUnixSeconds: uint64(now.Add(time.Hour).Unix()),
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal, signer)
	if err != nil {
		t.Fatal(err)
	}
	escrowAddress := "0:" + strings.Repeat("ee", 32)
	escrow := &toschain.FinalizedEscrowV1{
		State: &nativecore.EscrowStateV1{
			Status: nativecore.EscrowStatusFunded, QuoteCommitment: commitment,
			ProviderAddress: provider, RefundAvailableAt: uint64(now.Add(time.Hour).Unix()),
			FundedAtomicAmount: "100", AcceptedQuote: quote,
		},
		Reference: reference(10, cellHash("ef"), "10"),
	}
	codeHash := cellHash("12")
	agentState := &nativev1.NativeStateV1{
		Network: proto.Clone(network).(*nativev1.NetworkDomain), TvmStateHash: cellHash("13"),
		Reference: reference(11, codeHash, "11"),
		State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{
			AgentId: agentID, Generation: 1, Sequence: 1, LastActionHash: digest("14"),
		}},
	}
	capabilityState := &nativev1.NativeStateV1{
		Network: proto.Clone(network).(*nativev1.NetworkDomain), TvmStateHash: cellHash("15"),
		Reference: reference(12, codeHash, "12"),
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
			CapabilityId: capID, OwnerAgentId: agentID, Generation: 1, Sequence: 1,
			LastActionHash: digest("16"),
			Versions:       []*nativev1.CapabilityVersionV1{{Version: "1", ManifestDigest: manifest}},
		}},
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{
		Directory: dir, EscrowResolver: escrowFake{escrow},
		NativeResolver: nativeFake{map[string]*nativev1.NativeStateV1{agentID: agentState, capID: capabilityState}},
		Network:        network, RegistryCodeHash: codeHash, ProviderAgentID: agentID,
		ProviderAddress: provider, ManifestDigest: manifest, TransportDigest: transport,
		ExecutionSignerAuthorization: signer, Timeout: time.Second,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, Request{
		EscrowAddress: escrowAddress, QuoteCommitment: commitment,
		ExecutionID: digest("17"), InputDigest: digest("18"), SourceDigest: digest("19"),
	}
}

func reference(checkpoint uint64, codeHash, txSuffix string) *nativev1.ChainReference {
	return &nativev1.ChainReference{
		ContractCodeHash: codeHash, TransactionHash: digest(txSuffix), FinalizedCheckpoint: checkpoint,
	}
}

func digest(pair string) string   { return "sha256:" + strings.Repeat(pair, 32) }
func cellHash(pair string) string { return "tvm-cell-sha256:" + strings.Repeat(pair, 32) }
func bytes32(v byte) []byte       { return []byte(strings.Repeat(string([]byte{v}), 32)) }
