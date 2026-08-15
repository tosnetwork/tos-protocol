package quoteprovider

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/quoteexchange"
)

type resolver struct {
	response *nativev1.ResolveNativeStateResponse
}

func (r resolver) ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	return r.response, nil
}

func setup(t *testing.T) (*Provider, *nativev1.RequestQuoteProposalRequest, *nativev1.NetworkDomain, time.Time) {
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
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	capabilityID, agentID := "cap_"+strings.Repeat("33", 32), "agent_"+strings.Repeat("44", 32)
	codeHash := "tvm-cell-sha256:" + strings.Repeat("55", 32)
	state := &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("66", 32),
		Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: codeHash,
			TransactionHash: "sha256:" + strings.Repeat("77", 32)},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID,
			OwnerAgentId: agentID, Versions: []*nativev1.CapabilityVersionV1{{Version: manifest.Version, ManifestDigest: manifestDigest}}}}}
	account, _ := hex.DecodeString(strings.Repeat("88", 32))
	now := time.Unix(2_000_000_000, 0)
	provider, err := New(Config{Resolver: resolver{&nativev1.ResolveNativeStateResponse{Found: true, State: state}}, Network: network,
		RegistryCodeHash: codeHash, ProviderAgentID: agentID, ProviderAddress: "0:" + strings.Repeat("99", 32),
		ManifestCBOR: manifestCBOR, Transport: nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS,
			MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"},
		MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: 0, AccountId: account, CodeHash: "tvm-cell-sha256:" + strings.Repeat("aa", 32)},
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("bb", 32), Decimals: 6}, AtomicAmount: "25000000"},
		CallerID: "provider", Now: func() time.Time { return now }, Random: func(value []byte) error {
			for i := range value {
				value[i] = byte(i + 1)
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	request := &nativev1.RequestQuoteProposalRequest{Context: &nativev1.RequestContext{RequestId: "buyer-request"},
		CapabilityId: capabilityID, CapabilityVersion: manifest.Version, BuyerAddress: "0:" + strings.Repeat("cc", 32)}
	return provider, request, network, now
}

func TestProviderConstructsValidatedPackageFromFinalizedCapability(t *testing.T) {
	provider, request, network, now := setup(t)
	value, err := provider.RequestQuoteProposal(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := quoteexchange.Validate(network, request, value, now)
	if err != nil || validated.EscrowTerms.BuyerAddress != request.BuyerAddress ||
		value.Proposal.ProposalId != "provider-0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("validated=%+v proposal=%+v err=%v", validated, value.Proposal, err)
	}
}

func TestProviderRejectsWrongVersionAndOwner(t *testing.T) {
	provider, request, _, _ := setup(t)
	request.CapabilityVersion = "other"
	if _, err := provider.RequestQuoteProposal(context.Background(), request); err == nil {
		t.Fatal("wrong version accepted")
	}
	provider, request, _, _ = setup(t)
	provider.config.ProviderAgentID = "agent_" + strings.Repeat("dd", 32)
	if _, err := provider.RequestQuoteProposal(context.Background(), request); err == nil {
		t.Fatal("wrong owner accepted")
	}
}
