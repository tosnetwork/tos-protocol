// paid-demand-v2-fixture emits a deterministic, typed V2 escrow deployment
// fixture for a real local TOS network. It is deliberately a fixture builder,
// not an authority bypass: production OpenFox builds the same cells only after
// Agreement and Provider Offer verification.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type output struct {
	Network           *nativev1.NetworkDomain `json:"network"`
	EscrowAddress     string                  `json:"escrow_address"`
	StateInitBOC      string                  `json:"state_init_boc_base64"`
	StateInitHash     string                  `json:"state_init_hash"`
	CodeHash          string                  `json:"code_hash"`
	QuoteCommitment   string                  `json:"quote_commitment"`
	ProviderOffer     string                  `json:"provider_offer_digest"`
	AcceptBodyBOC     string                  `json:"accept_body_boc_base64"`
	AcceptBodyHash    string                  `json:"accept_body_hash"`
	AcceptByUnix      uint64                  `json:"accept_by_unix"`
	FundingDeadline   uint64                  `json:"funding_deadline"`
	ExecutionDeadline uint64                  `json:"execution_deadline"`
	RefundAvailable   uint64                  `json:"refund_available_at"`
}

func main() {
	var networkID, genesisRoot, genesisFile, buyer, provider, codePath string
	var queryID uint64
	flag.StringVar(&networkID, "network", "tos:local-three-node", "canonical network ID")
	flag.StringVar(&genesisRoot, "genesis-root", "", "sha256 genesis root")
	flag.StringVar(&genesisFile, "genesis-file", "", "sha256 genesis file")
	flag.StringVar(&buyer, "buyer", "", "raw buyer wallet address")
	flag.StringVar(&provider, "provider", "", "raw provider wallet address")
	flag.StringVar(&codePath, "code-boc", "", "frozen V2 contract BOC path")
	flag.Uint64Var(&queryID, "query-id", 1, "non-zero deterministic accept query ID")
	flag.Parse()
	if networkID == "" || !validDigest(genesisRoot, "sha256:") || !validDigest(genesisFile, "sha256:") ||
		!rawAddress(buyer) || !rawAddress(provider) || queryID == 0 || codePath == "" {
		fatal("invalid fixture arguments")
	}
	rawCode, err := os.ReadFile(codePath)
	if err != nil {
		fatal(err.Error())
	}
	code, err := cell.FromBOC(rawCode)
	if err != nil {
		fatal("invalid contract BOC")
	}
	now := uint64(time.Now().UTC().Unix())
	acceptBy, funding, execution, refund := now+900, now+1800, now+2700, now+3600
	network := &nativev1.NetworkDomain{NetworkId: networkID, GenesisRootHash: genesisRoot, GenesisFileHash: genesisFile}
	transport := nativecore.TransportBindingV1{SecurityMode: nativecore.TransportLoopbackHTTP,
		MaxRequestBytes: 1 << 20, BaseURL: "http://127.0.0.1:18080"}
	terms := nativecore.EscrowTermsV1{BuyerAddress: buyer, ProviderAddress: provider,
		FundingDeadline: funding, RefundAvailableAt: refund}
	termsCell, err := nativecore.BuildEscrowTermsCellV1(terms)
	if err != nil {
		fatal(err.Error())
	}
	signer := sha256.Sum256([]byte("tos-paid-demand-v2-three-node-fixture-execution-signer"))
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(signer[:])
	if err != nil {
		fatal(err.Error())
	}
	_, transportDigest, err := nativecore.BuildTransportBindingCellV1(transport)
	if err != nil {
		fatal(err.Error())
	}
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	masterBytes := sha256.Sum256([]byte("tos-paid-demand-v2-three-node-fixture-master"))
	master := address.NewAddress(0, 0, masterBytes[:]).StringRaw()
	walletCode := cell.BeginCell().MustStoreUInt(0x50445732, 32).EndCell()
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("33", 32), CapabilityVersion: "1.0.0",
		ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: acceptBy,
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(termsCell.Hash()), DisputePolicyDigest: disputeDigest,
		MaximumPrice: &nativev1.MoneyV1{AtomicAmount: "25000000", Asset: &nativev1.TOSAssetIdentityV1{
			Master:         &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: masterBytes[:], CodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32)},
			WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletCode.Hash()), Decimals: 6}}}
	offerDigest := "sha256:" + strings.Repeat("77", 32)
	extension := nativecore.PaidDemandQuoteExtensionV1{ProviderOfferCanonical: []byte("canonical-three-node-provider-offer-fixture"),
		ProviderOfferBindingDigest: "sha256:" + strings.Repeat("66", 32), ProviderOfferDigest: offerDigest,
		AcceptByUnix: acceptBy, ExecutionDeadline: execution}
	quote, _, _, err := nativecore.BuildAcceptedQuoteCommitmentV2(network, proposal,
		"sha256:"+hex.EncodeToString(authorization.Hash()), extension)
	if err != nil {
		fatal(err.Error())
	}
	identity, err := nativecore.BuildEscrowStateInitV2(0, code, nativecore.EscrowInitV2{Network: network,
		AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signer[:], TransportBinding: transport,
		AssetMasterAddress: master, AssetWalletCode: walletCode})
	if err != nil {
		fatal(err.Error())
	}
	body, err := nativecore.BuildPaidDemandAcceptBodyV2(queryID, identity.QuoteCommitment, offerDigest)
	if err != nil {
		fatal(err.Error())
	}
	stateInitRaw, err := base64.StdEncoding.DecodeString(identity.StateInitBOC)
	if err != nil {
		fatal(err.Error())
	}
	stateInit, err := cell.FromBOC(stateInitRaw)
	if err != nil {
		fatal(err.Error())
	}
	value := output{Network: network, EscrowAddress: identity.Address, StateInitBOC: identity.StateInitBOC,
		StateInitHash: "tvm-cell-sha256:" + hex.EncodeToString(stateInit.Hash()), CodeHash: identity.CodeHash,
		QuoteCommitment: identity.QuoteCommitment, ProviderOffer: offerDigest,
		AcceptBodyBOC: base64.StdEncoding.EncodeToString(body.ToBOCWithOptions(cell.BOCSerializeOptions{})), AcceptBodyHash: "tvm-cell-sha256:" + hex.EncodeToString(body.Hash()),
		AcceptByUnix: acceptBy, FundingDeadline: funding, ExecutionDeadline: execution, RefundAvailable: refund}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fatal(err.Error())
	}
}

func rawAddress(value string) bool {
	parsed, err := address.ParseRawAddr(value)
	return err == nil && parsed != nil && parsed.Workchain() == 0 && parsed.StringRaw() == value
}

func validDigest(value, prefix string) bool {
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func fatal(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
