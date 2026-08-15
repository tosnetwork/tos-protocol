package quoteexchange

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
)

func validPackage(t *testing.T) (*nativev1.NetworkDomain, *nativev1.RequestQuoteProposalRequest, *nativev1.QuoteProposalPackageV1, time.Time) {
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
	now := time.Unix(2_000_000_000, 0)
	buyer, provider := "0:"+strings.Repeat("11", 32), "0:"+strings.Repeat("22", 32)
	terms, err := nativecore.BuildEscrowTermsCellV1(nativecore.EscrowTermsV1{BuyerAddress: buyer,
		ProviderAddress: provider, FundingDeadline: uint64(now.Add(20 * time.Minute).Unix()),
		RefundAvailableAt: uint64(now.Add(time.Hour).Unix())})
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
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-proposal-1",
		CapabilityId: "cap_" + strings.Repeat("44", 32), CapabilityVersion: manifest.Version,
		ProviderAgentId: "agent_" + strings.Repeat("55", 32), ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{
			Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: account,
				CodeHash: "tvm-cell-sha256:" + strings.Repeat("66", 32)},
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("77", 32), Decimals: 6}, AtomicAmount: "25000000"},
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(terms.Hash()), DisputePolicyDigest: disputeDigest,
		ExpiresAtUnixSeconds: uint64(now.Add(30 * time.Minute).Unix())}
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("88", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("99", 32)}
	request := &nativev1.RequestQuoteProposalRequest{CapabilityId: proposal.CapabilityId,
		CapabilityVersion: proposal.CapabilityVersion, BuyerAddress: buyer}
	value := &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR,
		EscrowTermsBoc: terms.ToBOC(), TransportBindingBoc: transport.ToBOC(), DisputePolicyBoc: dispute.ToBOC()}
	return network, request, value, now
}

func TestValidateCompleteQuoteProposalPackage(t *testing.T) {
	network, request, value, now := validPackage(t)
	validated, err := Validate(network, request, value, now)
	if err != nil || validated.EscrowTerms.BuyerAddress != request.BuyerAddress ||
		validated.TransportBinding.BaseURL != "https://provider.example" {
		t.Fatalf("validated=%+v err=%v", validated, err)
	}
}

func TestValidateRejectsEveryConflictingPreimage(t *testing.T) {
	mutations := []func(*nativev1.QuoteProposalPackageV1){
		func(v *nativev1.QuoteProposalPackageV1) { v.CanonicalManifestCbor[0] ^= 1 },
		func(v *nativev1.QuoteProposalPackageV1) { v.EscrowTermsBoc[0] ^= 1 },
		func(v *nativev1.QuoteProposalPackageV1) { v.TransportBindingBoc[0] ^= 1 },
		func(v *nativev1.QuoteProposalPackageV1) { v.DisputePolicyBoc[0] ^= 1 },
	}
	for index, mutate := range mutations {
		network, request, value, now := validPackage(t)
		mutate(value)
		if _, err := Validate(network, request, value, now); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}

func TestValidateRejectsWrongBuyerOrExpiredProposal(t *testing.T) {
	network, request, value, now := validPackage(t)
	request.BuyerAddress = "0:" + strings.Repeat("aa", 32)
	if _, err := Validate(network, request, value, now); err == nil {
		t.Fatal("wrong buyer accepted")
	}
	network, request, value, now = validPackage(t)
	if _, err := Validate(network, request, value, now.Add(time.Hour)); err == nil {
		t.Fatal("expired proposal accepted")
	}
}
