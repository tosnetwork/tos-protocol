package referencecodec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const quoteMagic = 0x4e415131

var amountPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type QuoteVector struct {
	Schema   string        `json:"schema"`
	Network  Network       `json:"network"`
	Quote    Quote         `json:"quote"`
	Expected QuoteExpected `json:"expected"`
}

type Quote struct {
	ProposalID                string           `json:"proposal_id"`
	CapabilityID              string           `json:"capability_id"`
	CapabilityVersion         string           `json:"capability_version"`
	ProviderAgentID           string           `json:"provider_agent_id"`
	ManifestDigest            string           `json:"manifest_digest"`
	TransportBindingDigest    string           `json:"transport_binding_digest"`
	Asset                     Asset            `json:"asset"`
	MaximumAtomicAmount       string           `json:"maximum_atomic_amount"`
	EscrowTermsDigest         string           `json:"escrow_terms_digest"`
	DisputePolicyDigest       string           `json:"dispute_policy_digest"`
	ExpiresAtUnixSeconds      uint64           `json:"expires_at_unix_seconds"`
	SignerAuthorizationDigest string           `json:"execution_signer_authorization"`
	EscrowTerms               EscrowTerms      `json:"escrow_terms"`
	ExecutionSignerPublicKey  string           `json:"execution_signer_public_key_hex"`
	TransportBinding          TransportBinding `json:"transport_binding"`
	DisputePolicy             DisputePolicy    `json:"dispute_policy"`
}

type TransportBinding struct {
	SecurityMode    uint8  `json:"security_mode"`
	MaxRequestBytes uint32 `json:"max_request_bytes"`
	BaseURL         string `json:"base_url"`
}

type DisputePolicy struct {
	Mode        uint8 `json:"mode"`
	ReleaseRule uint8 `json:"release_rule"`
	RefundRule  uint8 `json:"refund_rule"`
}

type EscrowTerms struct {
	BuyerAddress      string `json:"buyer_address"`
	ProviderAddress   string `json:"provider_address"`
	FundingDeadline   uint64 `json:"funding_deadline_unix_seconds"`
	RefundAvailableAt uint64 `json:"refund_available_at_unix_seconds"`
}

type Asset struct {
	Workchain       int32  `json:"workchain"`
	MasterAccountID string `json:"master_account_id"`
	MasterCodeHash  string `json:"master_code_hash"`
	WalletCodeHash  string `json:"wallet_code_hash"`
	Decimals        uint32 `json:"decimals"`
}

type QuoteExpected struct {
	Commitment string `json:"commitment"`
	BOCBase64  string `json:"boc_base64"`
}

// ComputeAcceptedQuote is the independent conformance encoder. It intentionally
// has its own wire structs and does not import nativecore or generated protobufs.
func ComputeAcceptedQuote(vector QuoteVector) (*cell.Cell, string, error) {
	quote := vector.Quote
	domain, err := identityDomain(vector.Network)
	if err != nil {
		return nil, "", err
	}
	capability, err := objectID(quote.CapabilityID, "cap_")
	if err != nil {
		return nil, "", err
	}
	provider, err := objectID(quote.ProviderAgentID, "agent_")
	if err != nil {
		return nil, "", err
	}
	if !validText(quote.CapabilityVersion, 128) || quote.ExpiresAtUnixSeconds == 0 ||
		len(quote.MaximumAtomicAmount) > 128 || !amountPattern.MatchString(quote.MaximumAtomicAmount) {
		return nil, "", errors.New("invalid quote text or amount")
	}
	manifest, err := nonZeroDigest(quote.ManifestDigest, "sha256:")
	if err != nil {
		return nil, "", err
	}
	transport, err := nonZeroDigest(quote.TransportBindingDigest, "sha256:")
	if err != nil {
		return nil, "", err
	}
	escrow, err := nonZeroDigest(quote.EscrowTermsDigest, "sha256:")
	if err != nil {
		return nil, "", err
	}
	dispute, err := nonZeroDigest(quote.DisputePolicyDigest, "sha256:")
	if err != nil {
		return nil, "", err
	}
	transportPreimage, err := quoteTransportBindingCell(quote.TransportBinding)
	if err != nil || !bytes.Equal(transport, transportPreimage.Hash()) {
		return nil, "", errors.New("transport digest does not match typed preimage")
	}
	disputePreimage, err := quoteDisputePolicyCell(quote.DisputePolicy)
	if err != nil || !bytes.Equal(dispute, disputePreimage.Hash()) {
		return nil, "", errors.New("dispute digest does not match typed preimage")
	}
	signer, err := nonZeroDigest(quote.SignerAuthorizationDigest, "sha256:")
	if err != nil {
		return nil, "", err
	}
	escrowPreimage, err := quoteEscrowTermsCell(quote.EscrowTerms)
	if err != nil || !bytes.Equal(escrow, escrowPreimage.Hash()) || quote.EscrowTerms.FundingDeadline > quote.ExpiresAtUnixSeconds {
		return nil, "", errors.New("escrow terms digest does not match typed preimage")
	}
	signerKey, err := hex.DecodeString(quote.ExecutionSignerPublicKey)
	if err != nil || len(signerKey) != 32 || zero(signerKey) {
		return nil, "", errors.New("invalid execution signer public key")
	}
	signerPreimage := cell.BeginCell().MustStoreUInt(0x4e454131, 32).MustStoreUInt(1, 16).
		MustStoreSlice(signerKey, 256).EndCell()
	if !bytes.Equal(signer, signerPreimage.Hash()) {
		return nil, "", errors.New("execution signer digest does not match typed preimage")
	}
	assetAccount, err := hex32(quote.Asset.MasterAccountID)
	if err != nil || zero(assetAccount) || quote.Asset.Workchain != 0 || quote.Asset.Decimals == 0 || quote.Asset.Decimals > 18 {
		return nil, "", errors.New("invalid asset identity")
	}
	masterCode, err := nonZeroDigest(quote.Asset.MasterCodeHash, "tvm-cell-sha256:")
	if err != nil {
		return nil, "", err
	}
	walletCode, err := nonZeroDigest(quote.Asset.WalletCodeHash, "tvm-cell-sha256:")
	if err != nil {
		return nil, "", err
	}
	versionHash := sha256Bytes([]byte(quote.CapabilityVersion))
	version := cell.BeginCell().MustStoreSlice(versionHash, 256).MustStoreSlice(manifest, 256).
		MustStoreSlice(transport, 256).MustStoreUInt(quote.ExpiresAtUnixSeconds, 64).
		MustStoreRef(snake(quote.CapabilityVersion)).EndCell()
	identity := cell.BeginCell().MustStoreSlice(capability, 256).MustStoreSlice(provider, 256).MustStoreRef(version).EndCell()
	assetCell := cell.BeginCell().MustStoreInt(int64(quote.Asset.Workchain), 32).MustStoreSlice(assetAccount, 256).
		MustStoreSlice(masterCode, 256).MustStoreSlice(walletCode, 256).MustStoreUInt(uint64(quote.Asset.Decimals), 8).EndCell()
	economic := cell.BeginCell().MustStoreSlice(escrow, 256).MustStoreSlice(dispute, 256).
		MustStoreRef(assetCell).MustStoreRef(snake(quote.MaximumAtomicAmount)).EndCell()
	authority := cell.BeginCell().MustStoreSlice(signer, 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(quoteMagic, 32).MustStoreUInt(1, 16).
		MustStoreRef(domain).MustStoreRef(identity).MustStoreRef(economic).MustStoreRef(authority).EndCell()
	return root, "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), nil
}

func quoteTransportBindingCell(value TransportBinding) (*cell.Cell, error) {
	if value.MaxRequestBytes == 0 || value.MaxRequestBytes > 16<<20 || !validText(value.BaseURL, 120) || strings.HasSuffix(value.BaseURL, "/") {
		return nil, errors.New("invalid transport binding bounds")
	}
	parsed, err := url.Parse(value.BaseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.Opaque != "" || parsed.ForceQuery ||
		parsed.String() != value.BaseURL || parsed.Host != strings.ToLower(parsed.Host) {
		return nil, errors.New("non-canonical transport endpoint")
	}
	if value.SecurityMode == 0 {
		ip := net.ParseIP(parsed.Hostname())
		loopback := strings.EqualFold(strings.TrimSuffix(parsed.Hostname(), "."), "localhost") || (ip != nil && ip.IsLoopback())
		if parsed.Scheme != "http" || !loopback {
			return nil, errors.New("invalid loopback transport")
		}
	} else if value.SecurityMode != 1 || parsed.Scheme != "https" {
		return nil, errors.New("invalid secure transport")
	}
	return cell.BeginCell().MustStoreUInt(0x4e544231, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(value.SecurityMode), 8).MustStoreUInt(uint64(value.MaxRequestBytes), 32).
		MustStoreRef(snake(value.BaseURL)).EndCell(), nil
}

func quoteDisputePolicyCell(value DisputePolicy) (*cell.Cell, error) {
	if value.Mode != 0 || value.ReleaseRule != 1 || value.RefundRule != 1 {
		return nil, errors.New("unsupported dispute policy")
	}
	return cell.BeginCell().MustStoreUInt(0x4e445031, 32).MustStoreUInt(1, 16).
		MustStoreUInt(0, 8).MustStoreUInt(1, 8).MustStoreUInt(1, 8).EndCell(), nil
}

func quoteEscrowTermsCell(value EscrowTerms) (*cell.Cell, error) {
	buyer, err := address.ParseRawAddr(value.BuyerAddress)
	if err != nil || buyer == nil || buyer.Type() != address.StdAddress || buyer.Workchain() != 0 || buyer.StringRaw() != value.BuyerAddress {
		return nil, errors.New("invalid escrow buyer")
	}
	provider, err := address.ParseRawAddr(value.ProviderAddress)
	if err != nil || provider == nil || provider.Type() != address.StdAddress || provider.Workchain() != 0 || provider.StringRaw() != value.ProviderAddress {
		return nil, errors.New("invalid escrow provider")
	}
	if value.FundingDeadline == 0 || value.RefundAvailableAt <= value.FundingDeadline {
		return nil, errors.New("invalid escrow deadlines")
	}
	return cell.BeginCell().MustStoreUInt(0x4e455431, 32).MustStoreUInt(1, 16).
		MustStoreAddr(buyer).MustStoreAddr(provider).MustStoreUInt(value.FundingDeadline, 64).
		MustStoreUInt(value.RefundAvailableAt, 64).EndCell(), nil
}

func nonZeroDigest(value, prefix string) ([]byte, error) {
	decoded, err := digest(value, prefix)
	if err != nil || zero(decoded) {
		return nil, errors.New("invalid non-zero digest")
	}
	return decoded, nil
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func snake(value string) *cell.Cell {
	return cell.BeginCell().MustStoreBinarySnake([]byte(value)).EndCell()
}
