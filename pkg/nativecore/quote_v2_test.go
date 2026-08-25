package nativecore

import (
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func TestAcceptedQuoteV2RoundTripsTypedPaidDemandExtension(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	master, _ := hex.DecodeString("ca11200a7d4a3c6822af077f035131868584f40f48fb1b7b7b1889ae51f9926a")
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("33", 32), CapabilityVersion: "1.0.0",
		ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: "sha256:" + strings.Repeat("66", 32), MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{
			Master:         &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: master, CodeHash: "tvm-cell-sha256:" + strings.Repeat("77", 32)},
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), Decimals: 6}, AtomicAmount: "1000"},
		EscrowTermsDigest: "sha256:" + strings.Repeat("99", 32), DisputePolicyDigest: "sha256:" + strings.Repeat("aa", 32), ExpiresAtUnixSeconds: 2000}
	extension := PaidDemandQuoteExtensionV1{ProviderOfferCanonical: bytesOf(600, 0x42), ProviderOfferBindingDigest: "sha256:" + strings.Repeat("bb", 32),
		ProviderOfferDigest: "sha256:" + strings.Repeat("cc", 32), AcceptByUnix: 2000, ExecutionDeadline: 3000}
	root, commitment, projection, err := BuildAcceptedQuoteCommitmentV2(network, proposal, "sha256:"+strings.Repeat("dd", 32), extension)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAcceptedQuoteV2(root, network)
	if err != nil || decoded.NativeTermsProjection != projection || decoded.Terms.Proposal.CapabilityId != proposal.CapabilityId ||
		string(decoded.Extension.ProviderOfferCanonical) != string(extension.ProviderOfferCanonical) ||
		decoded.Extension.ProviderOfferBindingDigest != extension.ProviderOfferBindingDigest {
		t.Fatalf("decoded=%+v commitment=%s err=%v", decoded, commitment, err)
	}
	changed := extension
	changed.ProviderOfferDigest = "sha256:" + strings.Repeat("ce", 32)
	_, changedCommitment, changedProjection, err := BuildAcceptedQuoteCommitmentV2(network, proposal, "sha256:"+strings.Repeat("dd", 32), changed)
	if err != nil || changedCommitment == commitment || changedProjection != projection {
		t.Fatal("extension mutation did not change only the final Quote commitment")
	}
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}
