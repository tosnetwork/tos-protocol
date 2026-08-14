package nativecore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const (
	escrowDataMagic          = 0x4e455331 // NES1
	escrowTermsMagic         = 0x4e455431 // NET1
	escrowAuthorizationMagic = 0x4e454131 // NEA1
	escrowRuntimeMagic       = 0x4e455231 // NER1
	escrowAssetRouteMagic    = 0x4e455031 // NEP1
	escrowSchema             = 1

	EscrowStatusAwaitingFunding uint8 = 0
	EscrowStatusFunded          uint8 = 1
	EscrowStatusReleasePending  uint8 = 2
	EscrowStatusRefundPending   uint8 = 3
)

// EscrowTermsV1 is the concrete preimage committed by escrow_terms_digest in
// an Accepted Quote. Addresses are canonical raw TOS addresses.
type EscrowTermsV1 struct {
	BuyerAddress      string
	ProviderAddress   string
	FundingDeadline   uint64
	RefundAvailableAt uint64
}

// EscrowInitV1 contains every value needed to derive and independently decode
// the escrow StateInit. The full Accepted Quote is embedded, not merely its
// hash. V1 starts with no stablecoin balance and no settlement result.
type EscrowInitV1 struct {
	AcceptedQuote          *cell.Cell
	Terms                  EscrowTermsV1
	ExecutionSignerEd25519 []byte
	TransportBinding       TransportBindingV1
	AssetMasterAddress     string
	AssetWalletCode        *cell.Cell
}

// EscrowIdentityV1 is the deterministic result of building an escrow StateInit.
type EscrowIdentityV1 struct {
	Address             string
	CodeHash            string
	QuoteCommitment     string
	EscrowTermsDigest   string
	AuthorizationDigest string
	TransportDigest     string
	DisputePolicyDigest string
	StateInitBOC        string
	Data                *cell.Cell
}

// EscrowStateV1 is the typed on-chain projection. Amounts are canonical base-10
// strings so callers never lose precision in JSON or protobuf transports.
type EscrowStateV1 struct {
	Status                 uint8
	QuoteCommitment        string
	EscrowTermsDigest      string
	AuthorizationDigest    string
	TransportDigest        string
	DisputePolicyDigest    string
	TransportBinding       TransportBindingV1
	BuyerAddress           string
	ProviderAddress        string
	AssetMasterAddress     string
	AssetWalletCodeHash    string
	AssetWalletCode        *cell.Cell
	FundingDeadline        uint64
	RefundAvailableAt      uint64
	FundedAtomicAmount     string
	SettledAtomicAmount    string
	ReceiptCommitment      string
	PendingQueryID         uint64
	AcceptedQuote          *cell.Cell
	ExecutionSignerEd25519 []byte
}

func escrowAddress(value string) (*address.Address, error) {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 ||
		parsed.Workchain() != 0 || parsed.StringRaw() != value {
		return nil, errors.New("escrow addresses must be canonical raw addr_std values")
	}
	return parsed, nil
}

// BuildEscrowTermsCellV1 builds the typed preimage whose cell hash is supplied
// as QuoteProposalV1.escrow_terms_digest.
func BuildEscrowTermsCellV1(value EscrowTermsV1) (*cell.Cell, error) {
	buyer, err := escrowAddress(value.BuyerAddress)
	if err != nil {
		return nil, err
	}
	provider, err := escrowAddress(value.ProviderAddress)
	if err != nil {
		return nil, err
	}
	if value.FundingDeadline == 0 || value.RefundAvailableAt <= value.FundingDeadline {
		return nil, errors.New("invalid escrow deadlines")
	}
	return cell.BeginCell().MustStoreUInt(escrowTermsMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreAddr(buyer).MustStoreAddr(provider).MustStoreUInt(value.FundingDeadline, 64).
		MustStoreUInt(value.RefundAvailableAt, 64).EndCell(), nil
}

// BuildEscrowAuthorizationCellV1 builds the typed preimage whose cell hash is
// supplied as AcceptedQuoteV1.execution_signer_authorization.
func BuildEscrowAuthorizationCellV1(publicKey []byte) (*cell.Cell, error) {
	if len(publicKey) != 32 || equalBytes(publicKey, make([]byte, 32)) {
		return nil, errors.New("execution signer must be a non-zero Ed25519 public key")
	}
	return cell.BeginCell().MustStoreUInt(escrowAuthorizationMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreSlice(publicKey, 256).EndCell(), nil
}

// BuildEscrowStateInitV1 validates all cross-cell commitments before deriving
// the contract address. A quote with opaque or mismatched escrow/authorization
// digests cannot produce a deployable escrow identity.
func BuildEscrowStateInitV1(workchain int32, code *cell.Cell, init EscrowInitV1) (EscrowIdentityV1, error) {
	if workchain != 0 || code == nil || init.AcceptedQuote == nil {
		return EscrowIdentityV1{}, errors.New("invalid escrow code, quote, or workchain")
	}
	terms, err := BuildEscrowTermsCellV1(init.Terms)
	if err != nil {
		return EscrowIdentityV1{}, err
	}
	authorization, err := BuildEscrowAuthorizationCellV1(init.ExecutionSignerEd25519)
	if err != nil {
		return EscrowIdentityV1{}, err
	}
	masterAddress, err := escrowAddress(init.AssetMasterAddress)
	if err != nil || init.AssetWalletCode == nil {
		if err == nil {
			err = errors.New("missing stablecoin wallet code")
		}
		return EscrowIdentityV1{}, err
	}
	transport, _, err := BuildTransportBindingCellV1(init.TransportBinding)
	if err != nil {
		return EscrowIdentityV1{}, err
	}
	dispute, _ := BuildObjectiveDisputePolicyCellV1()
	quoteTerms, quoteAuthorization, quoteExpiry, quoteMaximum, err := acceptedQuoteBoundValues(init.AcceptedQuote)
	if err != nil {
		return EscrowIdentityV1{}, err
	}
	quoteTransport, quoteDispute, err := acceptedQuotePolicyDigests(init.AcceptedQuote)
	if err != nil {
		return EscrowIdentityV1{}, err
	}
	if !equalBytes(quoteTerms, terms.Hash()) {
		return EscrowIdentityV1{}, errors.New("escrow terms do not match Accepted Quote")
	}
	if !equalBytes(quoteAuthorization, authorization.Hash()) {
		return EscrowIdentityV1{}, errors.New("execution authorization does not match Accepted Quote")
	}
	if !equalBytes(quoteTransport, transport.Hash()) || !equalBytes(quoteDispute, dispute.Hash()) {
		return EscrowIdentityV1{}, errors.New("transport or dispute policy does not match Accepted Quote")
	}
	if init.Terms.FundingDeadline > quoteExpiry || quoteMaximum.Sign() <= 0 || quoteMaximum.BitLen() > 120 {
		return EscrowIdentityV1{}, errors.New("escrow deadlines or amount exceed Accepted Quote")
	}
	quoteMaster, quoteWalletCode, err := acceptedQuoteAssetRoute(init.AcceptedQuote)
	if err != nil || init.AssetMasterAddress != quoteMaster || !equalBytes(init.AssetWalletCode.Hash(), quoteWalletCode) {
		return EscrowIdentityV1{}, errors.New("escrow asset route does not match Accepted Quote")
	}
	route := cell.BeginCell().MustStoreUInt(escrowAssetRouteMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreAddr(masterAddress).MustStoreSlice(init.AssetWalletCode.Hash(), 256).
		MustStoreRef(init.AssetWalletCode).EndCell()
	runtime := cell.BeginCell().MustStoreUInt(escrowRuntimeMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreBigUInt(new(big.Int), 128).MustStoreBigUInt(new(big.Int), 128).
		MustStoreSlice(make([]byte, 32), 256).MustStoreUInt(0, 64).MustStoreRef(route).
		MustStoreRef(transport).MustStoreRef(dispute).EndCell()
	data := cell.BeginCell().MustStoreUInt(escrowDataMagic, 32).MustStoreUInt(escrowSchema, 16).
		MustStoreUInt(uint64(EscrowStatusAwaitingFunding), 8).MustStoreSlice(init.AcceptedQuote.Hash(), 256).
		MustStoreSlice(terms.Hash(), 256).MustStoreSlice(authorization.Hash(), 256).
		MustStoreRef(init.AcceptedQuote).MustStoreRef(terms).MustStoreRef(authorization).MustStoreRef(runtime).EndCell()
	stateInit := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(code).MustStoreBoolBit(true).MustStoreRef(data).
		MustStoreBoolBit(false).EndCell()
	return EscrowIdentityV1{
		Address:             fmt.Sprintf("%d:%s", workchain, hex.EncodeToString(stateInit.Hash())),
		CodeHash:            "tvm-cell-sha256:" + hex.EncodeToString(code.Hash()),
		QuoteCommitment:     "tvm-cell-sha256:" + hex.EncodeToString(init.AcceptedQuote.Hash()),
		EscrowTermsDigest:   "tvm-cell-sha256:" + hex.EncodeToString(terms.Hash()),
		AuthorizationDigest: "tvm-cell-sha256:" + hex.EncodeToString(authorization.Hash()),
		TransportDigest:     "tvm-cell-sha256:" + hex.EncodeToString(transport.Hash()),
		DisputePolicyDigest: "tvm-cell-sha256:" + hex.EncodeToString(dispute.Hash()),
		StateInitBOC:        base64.StdEncoding.EncodeToString(stateInit.ToBOC()), Data: data,
	}, nil
}

// DecodeEscrowDataV1 rejects alternate encodings, broken commitment links,
// impossible initial values, and trailing data.
func DecodeEscrowDataV1(data *cell.Cell) (*EscrowStateV1, error) {
	if data == nil {
		return nil, errors.New("missing escrow data")
	}
	s := data.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowDataMagic {
		return nil, errors.New("invalid escrow data magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowSchema {
		return nil, errors.New("unsupported escrow data schema")
	}
	status, err := s.LoadUInt(8)
	if err != nil || status > uint64(EscrowStatusRefundPending) {
		return nil, errors.New("invalid escrow status")
	}
	quoteHash, err := s.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid quote commitment")
	}
	termsHash, err := s.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid terms commitment")
	}
	authorizationHash, err := s.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid authorization commitment")
	}
	quote, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing Accepted Quote")
	}
	terms, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing escrow terms")
	}
	authorization, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing execution authorization")
	}
	runtime, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, errors.New("invalid escrow root shape")
	}
	if !equalBytes(quoteHash, quote.Hash()) || !equalBytes(termsHash, terms.Hash()) || !equalBytes(authorizationHash, authorization.Hash()) {
		return nil, errors.New("escrow root commitment mismatch")
	}
	quoteTerms, quoteAuthorization, _, quoteMaximum, err := acceptedQuoteBoundValues(quote)
	if err != nil || !equalBytes(quoteTerms, termsHash) || !equalBytes(quoteAuthorization, authorizationHash) {
		return nil, errors.New("Accepted Quote does not bind escrow cells")
	}
	quoteTransport, quoteDispute, err := acceptedQuotePolicyDigests(quote)
	if err != nil {
		return nil, err
	}
	decodedTerms, err := decodeEscrowTerms(terms)
	if err != nil {
		return nil, err
	}
	publicKey, err := decodeEscrowAuthorization(authorization)
	if err != nil {
		return nil, err
	}
	r := runtime.BeginParse()
	runtimeMagic, err := r.LoadUInt(32)
	if err != nil || runtimeMagic != escrowRuntimeMagic {
		return nil, errors.New("invalid escrow runtime magic")
	}
	runtimeSchema, err := r.LoadUInt(16)
	if err != nil || runtimeSchema != escrowSchema {
		return nil, errors.New("unsupported escrow runtime schema")
	}
	funded, err := r.LoadBigUInt(128)
	if err != nil {
		return nil, errors.New("invalid funded amount")
	}
	settled, err := r.LoadBigUInt(128)
	if err != nil {
		return nil, errors.New("invalid settled amount")
	}
	receipt, err := r.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Receipt commitment")
	}
	pendingQueryID, err := r.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid pending query ID")
	}
	route, err := r.LoadRefCell()
	transport, transportErr := r.LoadRefCell()
	dispute, disputeErr := r.LoadRefCell()
	if err != nil || transportErr != nil || disputeErr != nil || r.BitsLeft() != 0 || r.RefsNum() != 0 || settled.Cmp(funded) > 0 || funded.Cmp(quoteMaximum) > 0 {
		return nil, errors.New("invalid escrow runtime")
	}
	transportBinding, transportErr := DecodeTransportBindingCellV1(transport)
	disputeErr = ValidateObjectiveDisputePolicyCellV1(dispute)
	if transportErr != nil || disputeErr != nil || !equalBytes(quoteTransport, transport.Hash()) || !equalBytes(quoteDispute, dispute.Hash()) {
		return nil, errors.New("escrow transport or dispute policy does not match Accepted Quote")
	}
	assetMaster, walletCodeHash, walletCode, err := decodeEscrowAssetRoute(route)
	quoteMaster, quoteWalletCode, quoteRouteErr := acceptedQuoteAssetRoute(quote)
	if err != nil || quoteRouteErr != nil || assetMaster != quoteMaster || !equalBytes(walletCodeHash, quoteWalletCode) {
		return nil, errors.New("escrow asset route does not match Accepted Quote")
	}
	receiptIsZero := equalBytes(receipt, make([]byte, 32))
	switch uint8(status) {
	case EscrowStatusAwaitingFunding:
		if funded.Sign() != 0 || settled.Sign() != 0 || !receiptIsZero || pendingQueryID != 0 {
			return nil, errors.New("invalid awaiting-funding runtime")
		}
	case EscrowStatusFunded:
		if funded.Cmp(quoteMaximum) != 0 || settled.Sign() != 0 || !receiptIsZero || pendingQueryID != 0 {
			return nil, errors.New("invalid funded runtime")
		}
	case EscrowStatusReleasePending:
		if funded.Cmp(quoteMaximum) != 0 || settled.Cmp(funded) != 0 || receiptIsZero || pendingQueryID == 0 {
			return nil, errors.New("invalid release runtime")
		}
	case EscrowStatusRefundPending:
		if funded.Cmp(quoteMaximum) != 0 || settled.Sign() != 0 || !receiptIsZero || pendingQueryID == 0 {
			return nil, errors.New("invalid refund runtime")
		}
	}
	return &EscrowStateV1{
		Status: uint8(status), QuoteCommitment: digestString(quoteHash), EscrowTermsDigest: digestString(termsHash),
		AuthorizationDigest: digestString(authorizationHash), BuyerAddress: decodedTerms.BuyerAddress,
		TransportDigest: digestString(transport.Hash()), DisputePolicyDigest: digestString(dispute.Hash()),
		TransportBinding: transportBinding,
		ProviderAddress:  decodedTerms.ProviderAddress, AssetMasterAddress: assetMaster,
		AssetWalletCodeHash: digestString(walletCodeHash), AssetWalletCode: walletCode,
		FundingDeadline: decodedTerms.FundingDeadline, RefundAvailableAt: decodedTerms.RefundAvailableAt,
		FundedAtomicAmount: funded.String(), SettledAtomicAmount: settled.String(), ReceiptCommitment: func() string {
			if receiptIsZero {
				return ""
			}
			return digestString(receipt)
		}(),
		PendingQueryID: pendingQueryID, AcceptedQuote: quote, ExecutionSignerEd25519: publicKey,
	}, nil
}

func decodeEscrowTerms(value *cell.Cell) (EscrowTermsV1, error) {
	s := value.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowTermsMagic {
		return EscrowTermsV1{}, errors.New("invalid escrow terms magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowSchema {
		return EscrowTermsV1{}, errors.New("unsupported escrow terms schema")
	}
	buyer, err := s.LoadAddr()
	if err != nil || buyer == nil || buyer.Type() != address.StdAddress || buyer.Workchain() != 0 {
		return EscrowTermsV1{}, errors.New("invalid escrow buyer")
	}
	provider, err := s.LoadAddr()
	if err != nil || provider == nil || provider.Type() != address.StdAddress || provider.Workchain() != 0 {
		return EscrowTermsV1{}, errors.New("invalid escrow provider")
	}
	funding, err := s.LoadUInt(64)
	if err != nil {
		return EscrowTermsV1{}, errors.New("invalid funding deadline")
	}
	refund, err := s.LoadUInt(64)
	if err != nil || funding == 0 || refund <= funding || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return EscrowTermsV1{}, errors.New("invalid escrow deadlines or shape")
	}
	return EscrowTermsV1{buyer.StringRaw(), provider.StringRaw(), funding, refund}, nil
}

func decodeEscrowAuthorization(value *cell.Cell) ([]byte, error) {
	s := value.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowAuthorizationMagic {
		return nil, errors.New("invalid execution authorization magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowSchema {
		return nil, errors.New("unsupported execution authorization schema")
	}
	key, err := s.LoadSlice(256)
	if err != nil || equalBytes(key, make([]byte, 32)) || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, errors.New("invalid execution authorization")
	}
	return key, nil
}

func decodeEscrowAssetRoute(value *cell.Cell) (string, []byte, *cell.Cell, error) {
	s := value.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowAssetRouteMagic {
		return "", nil, nil, errors.New("invalid escrow asset-route magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowSchema {
		return "", nil, nil, errors.New("unsupported escrow asset-route schema")
	}
	master, err := s.LoadAddr()
	if err != nil || master == nil || master.Type() != address.StdAddress || master.Workchain() != 0 {
		return "", nil, nil, errors.New("invalid escrow stablecoin master")
	}
	walletCodeHash, err := s.LoadSlice(256)
	if err != nil || equalBytes(walletCodeHash, make([]byte, 32)) {
		return "", nil, nil, errors.New("invalid stablecoin wallet code hash")
	}
	walletCode, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 || !equalBytes(walletCodeHash, walletCode.Hash()) {
		return "", nil, nil, errors.New("stablecoin wallet code preimage mismatch")
	}
	return master.StringRaw(), walletCodeHash, walletCode, nil
}

// DeriveEscrowAssetWalletV1 independently reproduces the standard stablecoin
// wallet address committed by escrow state. The wallet data always starts with
// unlocked status and zero balance; live balance is account state, not address
// identity.
func DeriveEscrowAssetWalletV1(escrowAccount string, state *EscrowStateV1) (string, error) {
	owner, err := escrowAddress(escrowAccount)
	if err != nil || state == nil || state.AssetWalletCode == nil {
		return "", errors.New("invalid escrow wallet derivation input")
	}
	master, err := escrowAddress(state.AssetMasterAddress)
	if err != nil {
		return "", err
	}
	data := cell.BeginCell().MustStoreUInt(0, 4).MustStoreCoins(0).
		MustStoreAddr(owner).MustStoreAddr(master).EndCell()
	init := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(state.AssetWalletCode).
		MustStoreBoolBit(true).MustStoreRef(data).MustStoreBoolBit(false).EndCell()
	return address.NewAddress(0, 0, init.Hash()).StringRaw(), nil
}

func acceptedQuoteAssetRoute(quote *cell.Cell) (string, []byte, error) {
	if quote == nil {
		return "", nil, errors.New("missing Accepted Quote")
	}
	s := quote.BeginParse()
	if _, err := s.LoadUInt(32); err != nil {
		return "", nil, errors.New("invalid Accepted Quote")
	}
	if _, err := s.LoadUInt(16); err != nil {
		return "", nil, errors.New("invalid Accepted Quote")
	}
	if _, err := s.LoadRefCell(); err != nil {
		return "", nil, errors.New("missing Quote network")
	}
	if _, err := s.LoadRefCell(); err != nil {
		return "", nil, errors.New("missing Quote identity")
	}
	economic, err := s.LoadRefCell()
	if err != nil {
		return "", nil, errors.New("missing Quote economic terms")
	}
	e := economic.BeginParse()
	if _, err := e.LoadSlice(256); err != nil {
		return "", nil, errors.New("invalid Quote escrow terms")
	}
	if _, err := e.LoadSlice(256); err != nil {
		return "", nil, errors.New("invalid Quote dispute terms")
	}
	asset, err := e.LoadRefCell()
	if err != nil {
		return "", nil, errors.New("missing Quote asset")
	}
	as := asset.BeginParse()
	wc, err := as.LoadInt(32)
	if err != nil || wc != 0 {
		return "", nil, errors.New("invalid Quote asset workchain")
	}
	masterID, err := as.LoadSlice(256)
	if err != nil || equalBytes(masterID, make([]byte, 32)) {
		return "", nil, errors.New("invalid Quote stablecoin master")
	}
	if _, err := as.LoadSlice(256); err != nil {
		return "", nil, errors.New("invalid Quote master code hash")
	}
	walletCodeHash, err := as.LoadSlice(256)
	if err != nil || equalBytes(walletCodeHash, make([]byte, 32)) {
		return "", nil, errors.New("invalid Quote wallet code hash")
	}
	master := address.NewAddress(0, 0, masterID)
	return master.StringRaw(), walletCodeHash, nil
}

func acceptedQuoteBoundValues(quote *cell.Cell) ([]byte, []byte, uint64, *big.Int, error) {
	s := quote.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != acceptedQuoteMagic {
		return nil, nil, 0, nil, errors.New("invalid Accepted Quote magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, nil, 0, nil, errors.New("unsupported Accepted Quote schema")
	}
	network, err := s.LoadRefCell()
	if err != nil || network.BeginParse().BitsLeft() != 768 || network.BeginParse().RefsNum() != 0 {
		return nil, nil, 0, nil, errors.New("invalid Quote network")
	}
	identity, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, 0, nil, errors.New("missing Quote identity")
	}
	economic, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, 0, nil, errors.New("missing Quote economic terms")
	}
	authority, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, nil, 0, nil, errors.New("invalid Accepted Quote shape")
	}
	i := identity.BeginParse()
	capability, err := i.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote Capability")
	}
	provider, err := i.LoadSlice(256)
	if err != nil || equalBytes(capability, make([]byte, 32)) || equalBytes(provider, make([]byte, 32)) {
		return nil, nil, 0, nil, errors.New("invalid Quote identity")
	}
	version, err := i.LoadRefCell()
	if err != nil || i.BitsLeft() != 0 || i.RefsNum() != 0 {
		return nil, nil, 0, nil, errors.New("invalid Quote identity shape")
	}
	v := version.BeginParse()
	versionHash, err := v.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote version hash")
	}
	manifest, err := v.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote manifest")
	}
	transport, err := v.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote transport")
	}
	expiry, err := v.LoadUInt(64)
	if err != nil || expiry == 0 || equalBytes(manifest, make([]byte, 32)) || equalBytes(transport, make([]byte, 32)) {
		return nil, nil, 0, nil, errors.New("invalid Quote version")
	}
	versionTextCell, err := v.LoadRefCell()
	if err != nil || v.BitsLeft() != 0 || v.RefsNum() != 0 {
		return nil, nil, 0, nil, errors.New("invalid Quote version shape")
	}
	versionText, err := decodeProtocolText(versionTextCell, 128)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote version text")
	}
	computedVersion := sha256.Sum256([]byte(versionText))
	if !equalBytes(versionHash, computedVersion[:]) {
		return nil, nil, 0, nil, errors.New("Quote version hash mismatch")
	}
	e := economic.BeginParse()
	terms, err := e.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote escrow digest")
	}
	dispute, err := e.LoadSlice(256)
	if err != nil || equalBytes(terms, make([]byte, 32)) || equalBytes(dispute, make([]byte, 32)) {
		return nil, nil, 0, nil, errors.New("invalid Quote economic digest")
	}
	asset, err := e.LoadRefCell()
	if err != nil {
		return nil, nil, 0, nil, errors.New("missing Quote asset")
	}
	amountCell, err := e.LoadRefCell()
	if err != nil || e.BitsLeft() != 0 || e.RefsNum() != 0 {
		return nil, nil, 0, nil, errors.New("invalid Quote economic shape")
	}
	as := asset.BeginParse()
	wc, err := as.LoadInt(32)
	if err != nil || wc != 0 {
		return nil, nil, 0, nil, errors.New("invalid Quote asset workchain")
	}
	master, err := as.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote asset master")
	}
	masterCode, err := as.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote master code")
	}
	walletCode, err := as.LoadSlice(256)
	if err != nil {
		return nil, nil, 0, nil, errors.New("invalid Quote wallet code")
	}
	decimals, err := as.LoadUInt(8)
	if err != nil || decimals == 0 || decimals > 18 || as.BitsLeft() != 0 || as.RefsNum() != 0 ||
		equalBytes(master, make([]byte, 32)) || equalBytes(masterCode, make([]byte, 32)) || equalBytes(walletCode, make([]byte, 32)) {
		return nil, nil, 0, nil, errors.New("invalid Quote asset")
	}
	amountText, err := decodeProtocolText(amountCell, 128)
	if err != nil || !atomicAmountPattern.MatchString(amountText) {
		return nil, nil, 0, nil, errors.New("invalid Quote amount")
	}
	maximum, ok := new(big.Int).SetString(amountText, 10)
	if !ok || maximum.Sign() <= 0 || maximum.BitLen() > 120 {
		return nil, nil, 0, nil, errors.New("unsupported Quote amount")
	}
	a := authority.BeginParse()
	auth, err := a.LoadSlice(256)
	if err != nil || equalBytes(auth, make([]byte, 32)) || a.BitsLeft() != 0 || a.RefsNum() != 0 {
		return nil, nil, 0, nil, errors.New("invalid Quote authority shape")
	}
	return terms, auth, expiry, maximum, nil
}

func acceptedQuotePolicyDigests(quote *cell.Cell) ([]byte, []byte, error) {
	if quote == nil {
		return nil, nil, errors.New("missing Accepted Quote")
	}
	s := quote.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != acceptedQuoteMagic {
		return nil, nil, errors.New("invalid Accepted Quote magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, nil, errors.New("unsupported Accepted Quote schema")
	}
	if _, err := s.LoadRefCell(); err != nil {
		return nil, nil, errors.New("missing Quote network")
	}
	identity, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("missing Quote identity")
	}
	economic, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("missing Quote economic terms")
	}
	i := identity.BeginParse()
	if _, err := i.LoadSlice(256); err != nil {
		return nil, nil, errors.New("invalid Quote Capability")
	}
	if _, err := i.LoadSlice(256); err != nil {
		return nil, nil, errors.New("invalid Quote provider")
	}
	version, err := i.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("missing Quote version")
	}
	v := version.BeginParse()
	if _, err := v.LoadSlice(256); err != nil {
		return nil, nil, errors.New("invalid Quote version hash")
	}
	if _, err := v.LoadSlice(256); err != nil {
		return nil, nil, errors.New("invalid Quote manifest digest")
	}
	transport, err := v.LoadSlice(256)
	if err != nil || equalBytes(transport, make([]byte, 32)) {
		return nil, nil, errors.New("invalid Quote transport digest")
	}
	e := economic.BeginParse()
	if _, err := e.LoadSlice(256); err != nil {
		return nil, nil, errors.New("invalid Quote escrow terms digest")
	}
	dispute, err := e.LoadSlice(256)
	if err != nil || equalBytes(dispute, make([]byte, 32)) {
		return nil, nil, errors.New("invalid Quote dispute policy digest")
	}
	return transport, dispute, nil
}

func digestString(value []byte) string { return "tvm-cell-sha256:" + hex.EncodeToString(value) }
