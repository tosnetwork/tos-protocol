// Command native-quote-vector derives an Accepted Quote vector from its typed
// preimages. It never accepts caller-supplied expected hashes as authority.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

func main() {
	input := flag.String("input", "", "Quote vector JSON whose expected values will be derived")
	flag.Parse()
	if *input == "" {
		fail(fmt.Errorf("--input is required"))
	}
	var vector referencecodec.QuoteVector
	raw, err := os.ReadFile(*input)
	if err != nil {
		fail(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		fail(err)
	}
	terms, err := nativecore.BuildEscrowTermsCellV1(nativecore.EscrowTermsV1{
		BuyerAddress: vector.Quote.EscrowTerms.BuyerAddress, ProviderAddress: vector.Quote.EscrowTerms.ProviderAddress,
		FundingDeadline: vector.Quote.EscrowTerms.FundingDeadline, RefundAvailableAt: vector.Quote.EscrowTerms.RefundAvailableAt,
	})
	if err != nil {
		fail(err)
	}
	vector.Quote.EscrowTermsDigest = "sha256:" + hex.EncodeToString(terms.Hash())
	account, err := hex.DecodeString(vector.Quote.Asset.MasterAccountID)
	if err != nil || len(account) != 32 {
		fail(fmt.Errorf("invalid asset account"))
	}
	network := &nativev1.NetworkDomain{NetworkId: vector.Network.NetworkID,
		GenesisRootHash: vector.Network.GenesisRootHash, GenesisFileHash: vector.Network.GenesisFileHash}
	proposal := &nativev1.QuoteProposalV1{ProposalId: vector.Quote.ProposalID,
		CapabilityId: vector.Quote.CapabilityID, CapabilityVersion: vector.Quote.CapabilityVersion,
		ProviderAgentId: vector.Quote.ProviderAgentID, ManifestDigest: vector.Quote.ManifestDigest,
		TransportBindingDigest: vector.Quote.TransportBindingDigest, EscrowTermsDigest: vector.Quote.EscrowTermsDigest,
		DisputePolicyDigest: vector.Quote.DisputePolicyDigest, ExpiresAtUnixSeconds: vector.Quote.ExpiresAtUnixSeconds,
		MaximumPrice: &nativev1.MoneyV1{AtomicAmount: vector.Quote.MaximumAtomicAmount,
			Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
				Workchain: vector.Quote.Asset.Workchain, AccountId: account, CodeHash: vector.Quote.Asset.MasterCodeHash},
				WalletCodeHash: vector.Quote.Asset.WalletCodeHash, Decimals: vector.Quote.Asset.Decimals}}}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal, vector.Quote.SignerAuthorizationDigest)
	if err != nil {
		fail(err)
	}
	vector.Expected.Commitment = commitment
	vector.Expected.BOCBase64 = base64.StdEncoding.EncodeToString(quote.ToBOC())
	encoded, _ := json.MarshalIndent(vector, "", "  ")
	fmt.Println(string(encoded))
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
