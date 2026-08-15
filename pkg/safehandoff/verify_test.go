package safehandoff

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

type fixedResolver struct {
	value *toschain.FinalizedEscrowV1
	err   error
}

func (r fixedResolver) ResolveFinalized(context.Context, string) (*toschain.FinalizedEscrowV1, bool, error) {
	return r.value, r.value != nil, r.err
}

func fixture(t *testing.T, status uint8) (Bundle, fixedResolver) {
	t.Helper()
	raw, err := os.ReadFile("../nativecore/testdata/software_work_manifest_v1_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	manifest, err := nativecore.DecodeSoftwareWorkManifestJSON(vector.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestCBOR, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	buyer, provider := "0:"+strings.Repeat("11", 32), "0:"+strings.Repeat("22", 32)
	terms, err := nativecore.BuildEscrowTermsCellV1(nativecore.EscrowTermsV1{BuyerAddress: buyer,
		ProviderAddress: provider, FundingDeadline: 1_700_001_200, RefundAvailableAt: 1_700_003_600})
	if err != nil {
		t.Fatal(err)
	}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(nativecore.TransportBindingV1{
		SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	if err != nil {
		t.Fatal(err)
	}
	dispute, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	account, _ := hex.DecodeString(strings.Repeat("33", 32))
	proposal := &nativev1.QuoteProposalV1{ProposalId: "portable-proposal", CapabilityId: "cap_" + strings.Repeat("44", 32),
		CapabilityVersion: manifest.Version, ProviderAgentId: "agent_" + strings.Repeat("55", 32), ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, EscrowTermsDigest: "sha256:" + hex.EncodeToString(terms.Hash()),
		DisputePolicyDigest: disputeDigest, ExpiresAtUnixSeconds: 1_700_001_800,
		MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: 0, AccountId: account, CodeHash: "tvm-cell-sha256:" + strings.Repeat("66", 32)},
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("77", 32), Decimals: 6}, AtomicAmount: "25000000"}}
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("88", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("99", 32)}
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	authorization, _ := nativecore.BuildEscrowAuthorizationCellV1(publicKey)
	accepted, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal, "sha256:"+hex.EncodeToString(authorization.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	receipt, receiptCommitment, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment: commitment, ExecutionID: "sha256:" + strings.Repeat("a1", 32), InputDigest: "sha256:" + strings.Repeat("a2", 32),
		ResultDigest: "sha256:" + strings.Repeat("a3", 32), ArtifactDigest: "sha256:" + strings.Repeat("a4", 32),
		ReportDigest: "sha256:" + strings.Repeat("a5", 32), SourceDigest: "sha256:" + strings.Repeat("a6", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("a7", 32), SandboxDigest: "sha256:" + strings.Repeat("a8", 32),
		ChargedAtomicAmount: "25000000", ProviderAgentID: proposal.ProviderAgentId, CompletedAt: 1_700_001_700})
	if err != nil {
		t.Fatal(err)
	}
	escrow := "0:" + strings.Repeat("ee", 32)
	intent, _ := nativecore.BuildEscrowSettlementIntentV1(escrow, accepted, receipt, big.NewInt(25_000_000), 42)
	bundle := Bundle{Network: network, QuoteRequest: &nativev1.RequestQuoteProposalRequest{CapabilityId: proposal.CapabilityId,
		CapabilityVersion: proposal.CapabilityVersion, BuyerAddress: buyer}, QuotePackage: &nativev1.QuoteProposalPackageV1{
		Proposal: proposal, CanonicalManifestCbor: manifestCBOR, EscrowTermsBoc: terms.ToBOC(),
		TransportBindingBoc: transport.ToBOC(), DisputePolicyBoc: dispute.ToBOC()}, ExecutionSignerPublicKey: publicKey,
		EscrowAddress: escrow, ExpectedEscrowCodeHash: "tvm-cell-sha256:" + strings.Repeat("cc", 32),
		ReceiptBOC: receipt.ToBOC(), SettlementQueryID: 42,
		SettlementSignature: ed25519.Sign(privateKey, intent.Hash())}
	state := &nativecore.EscrowStateV1{Status: status, QuoteCommitment: commitment, AcceptedQuote: accepted,
		ExecutionSignerEd25519: publicKey, FundedAtomicAmount: "25000000", SettledAtomicAmount: "0"}
	if status == nativecore.EscrowStatusReleasePending {
		state.ReceiptCommitment, state.PendingQueryID, state.SettledAtomicAmount = receiptCommitment, 42, "25000000"
	}
	resolver := fixedResolver{value: &toschain.FinalizedEscrowV1{State: state, Reference: &nativev1.ChainReference{
		Account: escrow, FinalizedCheckpoint: 900, ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("cc", 32)}}}
	return bundle, resolver
}

func TestVerifyFundedHandoffNeedsNoGateway(t *testing.T) {
	bundle, resolver := fixture(t, nativecore.EscrowStatusFunded)
	result, err := Verify(context.Background(), resolver, bundle)
	if err != nil || !result.ReadyToBroadcast || result.AlreadyPending || result.FinalizedCheckpoint != 900 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestVerifyReleasePendingIsIdempotent(t *testing.T) {
	bundle, resolver := fixture(t, nativecore.EscrowStatusReleasePending)
	result, err := Verify(context.Background(), resolver, bundle)
	if err != nil || result.ReadyToBroadcast || !result.AlreadyPending {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestVerifyFailsClosedOnEveryAuthorityBoundary(t *testing.T) {
	tests := []func(*Bundle, *fixedResolver){
		func(b *Bundle, _ *fixedResolver) { b.QuotePackage.CanonicalManifestCbor[0] ^= 1 },
		func(b *Bundle, _ *fixedResolver) { b.ReceiptBOC[0] ^= 1 },
		func(b *Bundle, _ *fixedResolver) { b.SettlementSignature[0] ^= 1 },
		func(_ *Bundle, r *fixedResolver) {
			r.value.State.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("dd", 32)
		},
		func(_ *Bundle, r *fixedResolver) { r.err = errors.New("finality unavailable") },
	}
	for index, mutate := range tests {
		bundle, resolver := fixture(t, nativecore.EscrowStatusFunded)
		mutate(&bundle, &resolver)
		if _, err := Verify(context.Background(), resolver, bundle); err == nil {
			t.Fatalf("authority mutation %d accepted", index)
		}
	}
}

func TestPortableQuoteCanBeCheckedAfterExpiry(t *testing.T) {
	bundle, resolver := fixture(t, nativecore.EscrowStatusFunded)
	if time.Now().Unix() <= int64(bundle.QuotePackage.Proposal.ExpiresAtUnixSeconds) {
		t.Fatal("test fixture must represent an expired, already accepted Quote")
	}
	if _, err := Verify(context.Background(), resolver, bundle); err != nil {
		t.Fatal(err)
	}
}
