// Command native-escrow-vector derives the unique Gate D escrow StateInit
// from a frozen Accepted Quote vector and reviewed contract artifacts.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type output struct {
	Schema              string `json:"schema"`
	EscrowAddress       string `json:"escrow_address"`
	EscrowCodeHash      string `json:"escrow_code_hash"`
	EscrowDataHash      string `json:"escrow_data_hash"`
	QuoteCommitment     string `json:"accepted_quote_commitment"`
	EscrowTermsDigest   string `json:"escrow_terms_digest"`
	AuthorizationDigest string `json:"execution_signer_authorization"`
	TransportDigest     string `json:"transport_binding_digest"`
	DisputePolicyDigest string `json:"dispute_policy_digest"`
	AssetMasterAddress  string `json:"asset_master_address"`
	AssetWalletCodeHash string `json:"asset_wallet_code_hash"`
	AcceptedQuoteBOC    string `json:"accepted_quote_boc_base64"`
	EscrowStateInitBOC  string `json:"escrow_state_init_boc_base64"`
}

func main() {
	quotePath := flag.String("quote-vector", "internal/referencecodec/testdata/accepted_quote_v1.json", "Accepted Quote vector")
	escrowCodePath := flag.String("escrow-code", "", "frozen escrow code BOC Base64")
	walletCodePath := flag.String("wallet-code", "", "frozen stablecoin wallet code BOC Base64")
	flag.Parse()
	if *escrowCodePath == "" || *walletCodePath == "" {
		fail(errors.New("--escrow-code and --wallet-code are required"))
	}
	var vector referencecodec.QuoteVector
	if err := decodeJSONFile(*quotePath, &vector); err != nil {
		fail(err)
	}
	escrowCode, err := decodeCode(*escrowCodePath)
	if err != nil {
		fail(err)
	}
	walletCode, err := decodeCode(*walletCodePath)
	if err != nil {
		fail(err)
	}
	accountID, err := hex.DecodeString(vector.Quote.Asset.MasterAccountID)
	if err != nil || len(accountID) != 32 {
		fail(errors.New("invalid stablecoin master account ID"))
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
				Workchain: vector.Quote.Asset.Workchain, AccountId: accountID, CodeHash: vector.Quote.Asset.MasterCodeHash},
				WalletCodeHash: vector.Quote.Asset.WalletCodeHash, Decimals: vector.Quote.Asset.Decimals}}}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal, vector.Quote.SignerAuthorizationDigest)
	if err != nil || commitment != vector.Expected.Commitment || base64.StdEncoding.EncodeToString(quote.ToBOC()) != vector.Expected.BOCBase64 {
		fail(errors.New("Accepted Quote does not reproduce the frozen vector"))
	}
	signer, err := hex.DecodeString(vector.Quote.ExecutionSignerPublicKey)
	if err != nil {
		fail(err)
	}
	master := fmt.Sprintf("%d:%s", vector.Quote.Asset.Workchain, vector.Quote.Asset.MasterAccountID)
	identity, err := nativecore.BuildEscrowStateInitV1(0, escrowCode, nativecore.EscrowInitV1{
		AcceptedQuote: quote, Terms: nativecore.EscrowTermsV1{
			BuyerAddress: vector.Quote.EscrowTerms.BuyerAddress, ProviderAddress: vector.Quote.EscrowTerms.ProviderAddress,
			FundingDeadline: vector.Quote.EscrowTerms.FundingDeadline, RefundAvailableAt: vector.Quote.EscrowTerms.RefundAvailableAt},
		ExecutionSignerEd25519: signer, TransportBinding: nativecore.TransportBindingV1{
			SecurityMode: vector.Quote.TransportBinding.SecurityMode, MaxRequestBytes: vector.Quote.TransportBinding.MaxRequestBytes,
			BaseURL: vector.Quote.TransportBinding.BaseURL},
		AssetMasterAddress: master, AssetWalletCode: walletCode,
	})
	if err != nil {
		fail(err)
	}
	state, err := nativecore.DecodeEscrowDataV1(identity.Data)
	if err != nil || state.AssetWalletCodeHash != vector.Quote.Asset.WalletCodeHash {
		fail(errors.New("canonical escrow StateInit failed independent typed decoding"))
	}
	result := output{Schema: "tos.service.escrow-state-init.v1", EscrowAddress: identity.Address,
		EscrowCodeHash: identity.CodeHash, EscrowDataHash: "tvm-cell-sha256:" + hex.EncodeToString(identity.Data.Hash()),
		QuoteCommitment:   identity.QuoteCommitment,
		EscrowTermsDigest: identity.EscrowTermsDigest, AuthorizationDigest: identity.AuthorizationDigest,
		TransportDigest: identity.TransportDigest, DisputePolicyDigest: identity.DisputePolicyDigest,
		AssetMasterAddress: master, AssetWalletCodeHash: state.AssetWalletCodeHash,
		AcceptedQuoteBOC: vector.Expected.BOCBase64, EscrowStateInitBOC: identity.StateInitBOC}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
}

func decodeJSONFile(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func decodeCode(path string) (*cell.Cell, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	boc, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		return nil, err
	}
	return cell.FromBOC(boc)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
