package nativecore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/internal/referencecodec"
)

func TestGatewayProposalBecomesCanonicalOnlyThroughTermsCommitment(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	master, err := hex.DecodeString("ca11200a7d4a3c6822af077f035131868584f40f48fb1b7b7b1889ae51f9926a")
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "gateway-a-local-1", CapabilityId: "cap_" + strings.Repeat("33", 32),
		CapabilityVersion: "1.0.0", ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: "sha256:" + strings.Repeat("66", 32), MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{
			Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: master,
				CodeHash: "tvm-cell-sha256:18d5b6e780ff0bb451254c2c760d09d6e485638cd1407abb97078752c3c1c9ee"},
			WalletCodeHash: "tvm-cell-sha256:8f452d7a4dfd74066b682365177259ed05734435be76b5fd4bd5d8af2b7c3d68", Decimals: 6}, AtomicAmount: "1000"},
		EscrowTermsDigest: "sha256:" + strings.Repeat("77", 32), DisputePolicyDigest: "sha256:" + strings.Repeat("88", 32), ExpiresAtUnixSeconds: 12345}
	_, first, err := BuildAcceptedQuoteCommitment(network, proposal, "sha256:"+strings.Repeat("99", 32))
	if err != nil {
		t.Fatal(err)
	}
	proposal.ProposalId = "gateway-b-different-local-id"
	_, second, err := BuildAcceptedQuoteCommitment(network, proposal, "sha256:"+strings.Repeat("99", 32))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("gateway-local proposal ID changed canonical Accepted Quote")
	}
}

func TestProductionAcceptedQuoteFrozenVector(t *testing.T) {
	data, err := os.ReadFile("../../internal/referencecodec/testdata/accepted_quote_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector referencecodec.QuoteVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	account, err := hex.DecodeString(vector.Quote.Asset.MasterAccountID)
	if err != nil {
		t.Fatal(err)
	}
	network := &nativev1.NetworkDomain{NetworkId: vector.Network.NetworkID, GenesisRootHash: vector.Network.GenesisRootHash, GenesisFileHash: vector.Network.GenesisFileHash}
	proposal := &nativev1.QuoteProposalV1{ProposalId: vector.Quote.ProposalID, CapabilityId: vector.Quote.CapabilityID,
		CapabilityVersion: vector.Quote.CapabilityVersion, ProviderAgentId: vector.Quote.ProviderAgentID,
		ManifestDigest: vector.Quote.ManifestDigest, TransportBindingDigest: vector.Quote.TransportBindingDigest,
		MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: vector.Quote.Asset.Workchain, AccountId: account, CodeHash: vector.Quote.Asset.MasterCodeHash},
			WalletCodeHash: vector.Quote.Asset.WalletCodeHash, Decimals: vector.Quote.Asset.Decimals}, AtomicAmount: vector.Quote.MaximumAtomicAmount},
		EscrowTermsDigest: vector.Quote.EscrowTermsDigest, DisputePolicyDigest: vector.Quote.DisputePolicyDigest,
		ExpiresAtUnixSeconds: vector.Quote.ExpiresAtUnixSeconds}
	root, commitment, err := BuildAcceptedQuoteCommitment(network, proposal, vector.Quote.SignerAuthorizationDigest)
	if err != nil {
		t.Fatal(err)
	}
	actualBOC := base64.StdEncoding.EncodeToString(root.ToBOC())
	if commitment != vector.Expected.Commitment || actualBOC != vector.Expected.BOCBase64 {
		t.Logf("replacement expected: commitment=%s boc_base64=%s", commitment, actualBOC)
		index := 0
		for index < len(actualBOC) && index < len(vector.Expected.BOCBase64) && actualBOC[index] == vector.Expected.BOCBase64[index] {
			index++
		}
		start := index - 16
		if start < 0 {
			start = 0
		}
		endActual, endExpected := index+32, index+32
		if endActual > len(actualBOC) {
			endActual = len(actualBOC)
		}
		if endExpected > len(vector.Expected.BOCBase64) {
			endExpected = len(vector.Expected.BOCBase64)
		}
		t.Fatalf("production Accepted Quote vector mismatch: commitment=%s actual_len=%d expected_len=%d first_diff=%d actual=%q expected=%q", commitment, len(actualBOC), len(vector.Expected.BOCBase64), index, actualBOC[start:endActual], vector.Expected.BOCBase64[start:endExpected])
	}
	terms, err := BuildEscrowTermsCellV1(EscrowTermsV1{
		BuyerAddress: vector.Quote.EscrowTerms.BuyerAddress, ProviderAddress: vector.Quote.EscrowTerms.ProviderAddress,
		FundingDeadline: vector.Quote.EscrowTerms.FundingDeadline, RefundAvailableAt: vector.Quote.EscrowTerms.RefundAvailableAt,
	})
	if err != nil || "sha256:"+hex.EncodeToString(terms.Hash()) != vector.Quote.EscrowTermsDigest {
		t.Fatalf("Accepted Quote escrow terms preimage mismatch: %v", err)
	}
	signerKey, err := hex.DecodeString(vector.Quote.ExecutionSignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := BuildEscrowAuthorizationCellV1(signerKey)
	if err != nil || "sha256:"+hex.EncodeToString(authorization.Hash()) != vector.Quote.SignerAuthorizationDigest {
		t.Fatalf("Accepted Quote execution authorization preimage mismatch: %v", err)
	}
	_, transportDigest, err := BuildTransportBindingCellV1(TransportBindingV1{
		SecurityMode: vector.Quote.TransportBinding.SecurityMode, MaxRequestBytes: vector.Quote.TransportBinding.MaxRequestBytes,
		BaseURL: vector.Quote.TransportBinding.BaseURL,
	})
	if err != nil || transportDigest != vector.Quote.TransportBindingDigest {
		t.Fatalf("Accepted Quote transport preimage mismatch: %v", err)
	}
	dispute, disputeDigest := BuildObjectiveDisputePolicyCellV1()
	if vector.Quote.DisputePolicy.Mode != ObjectiveDisputeMode || vector.Quote.DisputePolicy.ReleaseRule != ReceiptReleaseRule ||
		vector.Quote.DisputePolicy.RefundRule != TimeoutRefundRule || disputeDigest != vector.Quote.DisputePolicyDigest ||
		ValidateObjectiveDisputePolicyCellV1(dispute) != nil {
		t.Fatal("Accepted Quote dispute policy preimage mismatch")
	}
}

func TestAcceptedQuoteRejectsDisplayTickerAsAssetIdentity(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("33", 32), CapabilityVersion: "1.0.0",
		ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: "sha256:" + strings.Repeat("66", 32), MaximumPrice: &nativev1.MoneyV1{AtomicAmount: "1000"},
		EscrowTermsDigest: "sha256:" + strings.Repeat("77", 32), DisputePolicyDigest: "sha256:" + strings.Repeat("88", 32), ExpiresAtUnixSeconds: 12345}
	if _, _, err := BuildAcceptedQuoteCommitment(network, proposal, "sha256:"+strings.Repeat("99", 32)); err == nil {
		t.Fatal("Accepted Quote accepted an absent contract-bound asset identity")
	}
}
