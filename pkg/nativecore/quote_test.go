package nativecore

import (
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

func TestGatewayProposalBecomesCanonicalOnlyThroughTermsCommitment(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "gateway-a-local-1", CapabilityId: "cap_" + strings.Repeat("33", 32),
		CapabilityVersion: "1.0.0", ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: "sha256:" + strings.Repeat("66", 32), MaximumPrice: &nativev1.MoneyV1{Asset: "TOS", AtomicAmount: "1000"},
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
