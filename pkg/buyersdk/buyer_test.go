package buyersdk

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type buyerNativeFake struct{ state *nativev1.NativeStateV1 }

func (f *buyerNativeFake) ResolveNativeState(_ context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	if f.state == nil || f.state.GetCapability().CapabilityId != request.ObjectId {
		return &nativev1.ResolveNativeStateResponse{}, nil
	}
	return &nativev1.ResolveNativeStateResponse{Found: true, State: proto.Clone(f.state).(*nativev1.NativeStateV1)}, nil
}

type assetFake struct{ observation *AssetObservation }

func (f *assetFake) ResolveBuyerAsset(_ context.Context, _ *nativev1.TOSAssetIdentityV1, _ string) (*AssetObservation, error) {
	result := *f.observation
	result.Asset = proto.Clone(f.observation.Asset).(*nativev1.TOSAssetIdentityV1)
	return &result, nil
}

type escrowFake struct {
	state *toschain.FinalizedEscrowV1
}

func (f *escrowFake) ResolveFinalized(_ context.Context, _ string) (*toschain.FinalizedEscrowV1, bool, error) {
	if f.state == nil {
		return nil, false, nil
	}
	state := *f.state.State
	reference := proto.Clone(f.state.Reference).(*nativev1.ChainReference)
	return &toschain.FinalizedEscrowV1{State: &state, Reference: reference, FinalizedAt: f.state.FinalizedAt}, true, nil
}

type fundingFake struct {
	escrow *escrowFake
	calls  int
	fail   bool
}

func (f *fundingFake) SendStablecoinFunding(_ context.Context, intent FundingIntent) error {
	f.calls++
	if f.fail {
		return errors.New("injected wallet ambiguity")
	}
	f.escrow.state.State.Status = nativecore.EscrowStatusFunded
	f.escrow.state.State.FundedAtomicAmount = intent.AmountAtomic
	return nil
}

type buyerFixture struct {
	buyer    *Buyer
	input    PurchaseInput
	escrow   *escrowFake
	sender   *fundingFake
	journal  *FileBudgetJournal
	now      time.Time
	codeHash string
}

func TestBuyerPreparesAndFundsExactFinalizedPurchaseOnce(t *testing.T) {
	fixture := newBuyerFixture(t, BudgetLimits{Window: time.Hour, MaxPurchases: 2,
		MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "150"})
	prepared, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	installEscrow(t, fixture, prepared)
	resolved, err := fixture.buyer.FundPurchase(context.Background(), prepared, "buyer-request-one")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State.Status != nativecore.EscrowStatusFunded || resolved.State.FundedAtomicAmount != "100" || fixture.sender.calls != 1 {
		t.Fatal("buyer SDK did not finalize the exact stablecoin funding")
	}
	if _, err := fixture.buyer.FundPurchase(context.Background(), prepared, "buyer-request-two"); err != nil {
		t.Fatal(err)
	}
	if fixture.sender.calls != 1 {
		t.Fatal("finalized purchase was funded twice")
	}
}

func TestBuyerRefusesAmbiguousBroadcastRecovery(t *testing.T) {
	fixture := newBuyerFixture(t, BudgetLimits{Window: time.Hour, MaxPurchases: 2,
		MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "200"})
	prepared, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	installEscrow(t, fixture, prepared)
	intent, err := fixture.buyer.fundingIntent(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if phase, err := fixture.journal.begin("ambiguous", intent, fixture.buyer.limits, fixture.now); err != nil || phase != budgetPrepared {
		t.Fatalf("claim phase=%s err=%v", phase, err)
	}
	if acquired, _, err := fixture.journal.acquire(intent); err != nil || !acquired {
		t.Fatalf("acquire=%v err=%v", acquired, err)
	}
	if _, err := fixture.buyer.FundPurchase(context.Background(), prepared, "ambiguous"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous funding recovery err=%v", err)
	}
	if fixture.sender.calls != 0 {
		t.Fatal("ambiguous purchase was rebroadcast")
	}
}

func TestBuyerPreparedCrashRemainsSafelyRecoverable(t *testing.T) {
	fixture := newBuyerFixture(t, BudgetLimits{Window: time.Hour, MaxPurchases: 2,
		MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "200"})
	prepared, _ := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	installEscrow(t, fixture, prepared)
	intent, _ := fixture.buyer.fundingIntent(prepared)
	if _, err := fixture.journal.begin("prepared", intent, fixture.buyer.limits, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.buyer.FundPurchase(context.Background(), prepared, "prepared"); err != nil {
		t.Fatal(err)
	}
	if fixture.sender.calls != 1 {
		t.Fatal("prepared crash state did not grant one recoverable lease")
	}
}

func TestBuyerBudgetIsAtomicAcrossPurchases(t *testing.T) {
	directory := privateDirectory(t)
	journal, err := NewFileBudgetJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	limits := BudgetLimits{Window: time.Hour, MaxPurchases: 3, MaxPerPurchaseAtomic: "75", MaxTotalAtomic: "100"}
	now := time.Unix(2_000_000_000, 0)
	first := testIntent("one", "60")
	second := testIntent("two", "60")
	if _, err := journal.begin("one", first, limits, now); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.begin("two", second, limits, now); err == nil {
		t.Fatal("buyer total stablecoin budget was exceeded")
	}
}

func TestBuyerRejectsReviewedPurchaseMutation(t *testing.T) {
	fixture := newBuyerFixture(t, BudgetLimits{Window: time.Hour, MaxPurchases: 2,
		MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "200"})
	prepared, _ := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	installEscrow(t, fixture, prepared)
	prepared.ManifestCBOR[0] ^= 0xff
	if _, err := fixture.buyer.FundPurchase(context.Background(), prepared, "mutated"); err == nil {
		t.Fatal("mutated purchase reached buyer wallet")
	}
	if fixture.sender.calls != 0 {
		t.Fatal("mutated purchase was broadcast")
	}
}

func TestBuyerRejectsProposalMutationAfterReview(t *testing.T) {
	fixture := newBuyerFixture(t, BudgetLimits{Window: time.Hour, MaxPurchases: 2,
		MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "200"})
	prepared, _ := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	installEscrow(t, fixture, prepared)
	prepared.Proposal.TransportBindingDigest = "sha256:" + strings.Repeat("12", 32)
	if _, err := fixture.buyer.FundPurchase(context.Background(), prepared, "mutated-proposal"); err == nil {
		t.Fatal("mutated Quote Proposal reached buyer wallet")
	}
	if fixture.sender.calls != 0 {
		t.Fatal("mutated Quote Proposal was broadcast")
	}
}

func newBuyerFixture(t *testing.T, limits BudgetLimits) buyerFixture {
	t.Helper()
	now := time.Unix(1_900_000_000, 0)
	network := &nativev1.NetworkDomain{NetworkId: "buyer-sdk-test",
		GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	manifestRaw, err := os.ReadFile("../nativecore/testdata/software_work_manifest_v1_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if err := json.Unmarshal(manifestRaw, &vector); err != nil {
		t.Fatal(err)
	}
	manifest, err := nativecore.DecodeSoftwareWorkManifestJSON(vector.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, manifestDigest, _ := nativecore.CanonicalSoftwareWorkManifest(manifest)
	capabilityID := "cap_" + strings.Repeat("55", 32)
	providerID := "agent_" + strings.Repeat("66", 32)
	registryCodeHash := "tvm-cell-sha256:" + strings.Repeat("77", 32)
	capabilityState := &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("88", 32),
		Reference:    &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: registryCodeHash},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
			CapabilityId: capabilityID, OwnerAgentId: providerID, Generation: 1, Sequence: 1,
			Versions: []*nativev1.CapabilityVersionV1{{Version: manifest.Version, ManifestDigest: manifestDigest}}}}}
	buyerAddress := "0:" + strings.Repeat("99", 32)
	providerAddress := "0:" + strings.Repeat("aa", 32)
	terms := nativecore.EscrowTermsV1{BuyerAddress: buyerAddress, ProviderAddress: providerAddress,
		FundingDeadline: uint64(now.Add(time.Hour).Unix()), RefundAvailableAt: uint64(now.Add(2 * time.Hour).Unix())}
	termsCell, _ := nativecore.BuildEscrowTermsCellV1(terms)
	signer := bytes32(0xbb)
	authorization, _ := nativecore.BuildEscrowAuthorizationCellV1(signer)
	transport := nativecore.TransportBindingV1{SecurityMode: 0, MaxRequestBytes: 1 << 20, BaseURL: "http://127.0.0.1:8080"}
	_, transportDigest, _ := nativecore.BuildTransportBindingCellV1(transport)
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	walletCode := cell.BeginCell().MustStoreUInt(0x1234, 16).EndCell()
	escrowCode := cell.BeginCell().MustStoreUInt(0x5678, 16).EndCell()
	asset := &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{Workchain: 0,
		AccountId: bytes32(0xcc), CodeHash: "tvm-cell-sha256:" + strings.Repeat("dd", 32)},
		WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletCode.Hash()), Decimals: 6}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "proposal-local", CapabilityId: capabilityID,
		CapabilityVersion: manifest.Version, ProviderAgentId: providerID, ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, MaximumPrice: &nativev1.MoneyV1{Asset: asset, AtomicAmount: "100"},
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(termsCell.Hash()), DisputePolicyDigest: disputeDigest,
		ExpiresAtUnixSeconds: uint64(now.Add(time.Hour).Unix())}
	masterAddress := "0:" + hex.EncodeToString(asset.Master.AccountId)
	assetResolver := &assetFake{observation: &AssetObservation{Asset: proto.Clone(asset).(*nativev1.TOSAssetIdentityV1),
		MasterAddress: masterAddress, BuyerWalletAddress: "0:" + strings.Repeat("ee", 32),
		BuyerBalanceAtomic: "1000", FinalizedCheckpoint: 11}}
	escrowResolver := &escrowFake{}
	sender := &fundingFake{escrow: escrowResolver}
	journal, err := NewFileBudgetJournal(privateDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := New(Config{NativeClient: &buyerNativeFake{state: capabilityState}, AssetResolver: assetResolver,
		EscrowResolver: escrowResolver, FundingSender: sender, BudgetJournal: journal, BudgetLimits: limits,
		Network: network, RegistryCodeHash: registryCodeHash, BuyerAddress: buyerAddress,
		EscrowCode: escrowCode, AssetWalletCode: walletCode, CallerID: "buyer-test",
		PollInterval: 10 * time.Millisecond, FinalityTimeout: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_ = authorization
	return buyerFixture{buyer: buyer, input: PurchaseInput{Proposal: proposal, ManifestJSON: vector.Manifest,
		EscrowTerms: terms, ExecutionSignerEd25519: signer, TransportBinding: transport}, escrow: escrowResolver,
		sender: sender, journal: journal, now: now, codeHash: registryCodeHash}
}

func installEscrow(t *testing.T, fixture buyerFixture, prepared *PreparedPurchase) {
	t.Helper()
	state, err := nativecore.DecodeEscrowDataV1(prepared.Escrow.Data)
	if err != nil {
		t.Fatal(err)
	}
	fixture.escrow.state = &toschain.FinalizedEscrowV1{State: state,
		Reference:   &nativev1.ChainReference{ContractCodeHash: prepared.Escrow.CodeHash, FinalizedCheckpoint: 12},
		FinalizedAt: fixture.now}
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func testIntent(name, amount string) fundingIntent {
	return fundingIntent{Identity: "sha256:" + strings.Repeat(name[:1], 64), NetworkID: "test",
		EscrowAddress: "0:" + strings.Repeat(name[:1], 64), QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat(name[:1], 64),
		AssetIdentity: "asset", BuyerWallet: "0:" + strings.Repeat("1", 64), AmountAtomic: amount, QueryID: uint64(name[0])}
}

func bytes32(value byte) []byte { return []byte(strings.Repeat(string([]byte{value}), 32)) }

func TestFileBudgetJournalRejectsNonPrivateDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileBudgetJournal(directory); err == nil {
		t.Fatal("public buyer budget directory accepted")
	}
}

func TestFileBudgetJournalRejectsTamperedRecordPermissions(t *testing.T) {
	directory := privateDirectory(t)
	journal, err := NewFileBudgetJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent("one", "10")
	limits := BudgetLimits{Window: time.Hour, MaxPurchases: 2, MaxPerPurchaseAtomic: "10", MaxTotalAtomic: "20"}
	if _, err := journal.begin("one", intent, limits, time.Unix(2_000_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(journal.recordPath(intent.Identity), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.begin("two", intent, limits, time.Unix(2_000_000_000, 0)); err == nil {
		t.Fatal("buyer accepted a budget record readable by other users")
	}
}

func TestFileBudgetJournalFailsClosedWhenClaimRecordIsMissing(t *testing.T) {
	directory := privateDirectory(t)
	journal, err := NewFileBudgetJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent("one", "10")
	limits := BudgetLimits{Window: time.Hour, MaxPurchases: 2, MaxPerPurchaseAtomic: "10", MaxTotalAtomic: "20"}
	now := time.Unix(2_000_000_000, 0)
	if _, err := journal.begin("one", intent, limits, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(journal.recordPath(intent.Identity)); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.begin("one", intent, limits, now); err == nil {
		t.Fatal("buyer recreated a missing claim and could have paid twice")
	}
}
