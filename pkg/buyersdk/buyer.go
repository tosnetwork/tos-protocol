// Package buyersdk prepares canonical software-work purchases and funds only
// already-finalized awaiting-funding escrows through a crash-safe bounded
// wallet journal. Gateways remain transport and discovery helpers only.
package buyersdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type NativeClient interface {
	ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error)
}

type AssetObservation = toschain.StablecoinAssetObservation

type AssetResolver interface {
	ResolveBuyerAsset(context.Context, *nativev1.TOSAssetIdentityV1, string) (*AssetObservation, error)
}

type EscrowResolver interface {
	ResolveFinalized(context.Context, string) (*toschain.FinalizedEscrowV1, bool, error)
}

type FundingIntent struct {
	NetworkID       string
	EscrowAddress   string
	QuoteCommitment string
	Asset           *nativev1.TOSAssetIdentityV1
	BuyerAddress    string
	BuyerWallet     string
	AmountAtomic    string
	QueryID         uint64
}

type FundingSender interface {
	PrepareStablecoinFunding(context.Context, FundingIntent) (*PreparedFunding, error)
	BroadcastStablecoinFunding(context.Context, *PreparedFunding) error
}

// PreparedFunding binds the exact signed external message to its reviewed
// semantic intent. The buyer acquires its one-way broadcast lease only after
// this object has been constructed and verified.
type PreparedFunding struct {
	Intent           FundingIntent
	MessageBOCBase64 string
	MessageHash      string
}

type Config struct {
	NativeClient     NativeClient
	AssetResolver    AssetResolver
	EscrowResolver   EscrowResolver
	FundingSender    FundingSender
	BudgetJournal    *FileBudgetJournal
	BudgetLimits     BudgetLimits
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	BuyerAddress     string
	EscrowCode       *cell.Cell
	AssetWalletCode  *cell.Cell
	CallerID         string
	PollInterval     time.Duration
	FinalityTimeout  time.Duration
	Now              func() time.Time
}

type Buyer struct {
	nativeClient     NativeClient
	assetResolver    AssetResolver
	escrowResolver   EscrowResolver
	fundingSender    FundingSender
	journal          *FileBudgetJournal
	limits           BudgetLimits
	network          *nativev1.NetworkDomain
	registryCodeHash string
	buyerAddress     string
	escrowCode       *cell.Cell
	walletCode       *cell.Cell
	callerID         string
	pollInterval     time.Duration
	finalityTimeout  time.Duration
	now              func() time.Time
}

type PurchaseInput struct {
	Proposal               *nativev1.QuoteProposalV1
	ManifestJSON           []byte
	ManifestCBOR           []byte
	EscrowTerms            nativecore.EscrowTermsV1
	ExecutionSignerEd25519 []byte
	TransportBinding       nativecore.TransportBindingV1
}

type PreparedPurchase struct {
	Proposal           *nativev1.QuoteProposalV1
	ManifestCBOR       []byte
	ManifestDigest     string
	QuoteCommitment    string
	QuoteBOCBase64     string
	Escrow             nativecore.EscrowIdentityV1
	AssetMasterAddress string
	BuyerWalletAddress string
	AmountAtomic       string
}

func New(config Config) (*Buyer, error) {
	if config.NativeClient == nil || config.AssetResolver == nil || config.EscrowResolver == nil ||
		config.FundingSender == nil || config.BudgetJournal == nil || config.Network == nil ||
		config.RegistryCodeHash == "" || config.BuyerAddress == "" || config.CallerID == "" ||
		config.EscrowCode == nil || config.AssetWalletCode == nil || !config.BudgetLimits.permits("1") {
		return nil, errors.New("invalid buyer SDK configuration")
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.FinalityTimeout == 0 {
		config.FinalityTimeout = 5 * time.Minute
	}
	if config.PollInterval < 10*time.Millisecond || config.PollInterval > time.Minute ||
		config.FinalityTimeout <= config.PollInterval || config.FinalityTimeout > time.Hour {
		return nil, errors.New("invalid buyer finality policy")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Buyer{nativeClient: config.NativeClient, assetResolver: config.AssetResolver,
		escrowResolver: config.EscrowResolver, fundingSender: config.FundingSender,
		journal: config.BudgetJournal, limits: config.BudgetLimits,
		network: proto.Clone(config.Network).(*nativev1.NetworkDomain), registryCodeHash: config.RegistryCodeHash,
		buyerAddress: config.BuyerAddress, escrowCode: config.EscrowCode, walletCode: config.AssetWalletCode,
		callerID: config.CallerID, pollInterval: config.PollInterval,
		finalityTimeout: config.FinalityTimeout, now: config.Now}, nil
}

func (b *Buyer) PreparePurchase(ctx context.Context, input PurchaseInput) (*PreparedPurchase, error) {
	if b == nil || ctx == nil || input.Proposal == nil ||
		(len(input.ManifestJSON) == 0) == (len(input.ManifestCBOR) == 0) ||
		len(input.ManifestJSON) > 1<<20 || len(input.ManifestCBOR) > 1<<20 {
		return nil, errors.New("invalid buyer purchase input")
	}
	if input.EscrowTerms.BuyerAddress != b.buyerAddress || input.Proposal.ExpiresAtUnixSeconds <= uint64(b.now().Unix()) ||
		input.EscrowTerms.FundingDeadline <= uint64(b.now().Unix()) {
		return nil, errors.New("buyer or Quote deadline is invalid")
	}
	var manifest nativecore.SoftwareWorkManifestV1
	var err error
	if len(input.ManifestCBOR) != 0 {
		manifest, err = nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(input.ManifestCBOR)
	} else {
		manifest, err = nativecore.DecodeSoftwareWorkManifestJSON(input.ManifestJSON)
	}
	if err != nil {
		return nil, fmt.Errorf("decode purchase manifest: %w", err)
	}
	manifestCBOR, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || manifestDigest != input.Proposal.ManifestDigest {
		return nil, errors.New("manifest does not match Quote Proposal")
	}
	if err := b.validateCapability(ctx, input.Proposal); err != nil {
		return nil, err
	}
	asset, err := b.resolveAsset(ctx, input.Proposal)
	if err != nil {
		return nil, err
	}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(input.ExecutionSignerEd25519)
	if err != nil {
		return nil, err
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(b.network, input.Proposal,
		"sha256:"+hex.EncodeToString(authorization.Hash()))
	if err != nil {
		return nil, err
	}
	identity, err := nativecore.BuildEscrowStateInitV1(0, b.escrowCode, nativecore.EscrowInitV1{
		AcceptedQuote: quote, Terms: input.EscrowTerms,
		ExecutionSignerEd25519: append([]byte(nil), input.ExecutionSignerEd25519...),
		TransportBinding:       input.TransportBinding, AssetMasterAddress: asset.MasterAddress,
		AssetWalletCode: b.walletCode,
	})
	if err != nil || identity.QuoteCommitment != commitment {
		return nil, errors.New("build canonical purchase escrow")
	}
	return &PreparedPurchase{Proposal: proto.Clone(input.Proposal).(*nativev1.QuoteProposalV1),
		ManifestCBOR: append([]byte(nil), manifestCBOR...), ManifestDigest: manifestDigest,
		QuoteCommitment: commitment, QuoteBOCBase64: base64.StdEncoding.EncodeToString(quote.ToBOC()),
		Escrow: identity, AssetMasterAddress: asset.MasterAddress,
		BuyerWalletAddress: asset.BuyerWalletAddress, AmountAtomic: input.Proposal.MaximumPrice.AtomicAmount}, nil
}

func (b *Buyer) FundPurchase(ctx context.Context, purchase *PreparedPurchase, requestKey string) (*toschain.FinalizedEscrowV1, error) {
	if b == nil || ctx == nil || purchase == nil || requestKey == "" || len(requestKey) > 256 {
		return nil, errors.New("invalid buyer funding request")
	}
	state, err := b.revalidatePurchase(ctx, purchase)
	if err != nil {
		return nil, err
	}
	if state.State.Status == nativecore.EscrowStatusFunded {
		return state, nil
	}
	if state.State.Status != nativecore.EscrowStatusAwaitingFunding {
		return nil, errors.New("purchase escrow is not awaiting funding")
	}
	intent, err := b.fundingIntent(purchase)
	if err != nil {
		return nil, err
	}
	phase, err := b.journal.begin(requestKey, intent, b.limits, b.now())
	if err != nil {
		return nil, err
	}
	if phase == budgetBroadcasting || phase == budgetComplete {
		resolved, err := b.resolveExactEscrow(ctx, purchase)
		if err != nil {
			return nil, err
		}
		if resolved.State.Status == nativecore.EscrowStatusFunded {
			if phase == budgetBroadcasting {
				_ = b.journal.complete(intent)
			}
			return resolved, nil
		}
		return nil, errors.New("stablecoin funding outcome is ambiguous; refusing to rebroadcast")
	}
	fundingRequest := FundingIntent{
		NetworkID: intent.NetworkID, EscrowAddress: intent.EscrowAddress,
		QuoteCommitment: intent.QuoteCommitment, Asset: proto.Clone(purchase.Proposal.MaximumPrice.Asset).(*nativev1.TOSAssetIdentityV1),
		BuyerAddress: b.buyerAddress, BuyerWallet: intent.BuyerWallet,
		AmountAtomic: intent.AmountAtomic, QueryID: intent.QueryID,
	}
	funding, err := b.fundingSender.PrepareStablecoinFunding(ctx, fundingRequest)
	if err != nil {
		return nil, err
	}
	if funding == nil || !equalFundingIntent(funding.Intent, fundingRequest) {
		return nil, errors.New("prepared stablecoin funding changed the reviewed intent")
	}
	acquired, phase, err := b.journal.acquire(intent)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, fmt.Errorf("buyer funding lease unavailable in phase %s", phase)
	}
	if err := b.fundingSender.BroadcastStablecoinFunding(ctx, funding); err != nil {
		return nil, err
	}
	if err := b.journal.complete(intent); err != nil {
		return nil, err
	}
	return b.waitFunded(ctx, purchase)
}

func equalFundingIntent(left, right FundingIntent) bool {
	return left.NetworkID == right.NetworkID && left.EscrowAddress == right.EscrowAddress &&
		left.QuoteCommitment == right.QuoteCommitment && proto.Equal(left.Asset, right.Asset) &&
		left.BuyerAddress == right.BuyerAddress && left.BuyerWallet == right.BuyerWallet &&
		left.AmountAtomic == right.AmountAtomic && left.QueryID == right.QueryID
}

func (b *Buyer) revalidatePurchase(ctx context.Context, purchase *PreparedPurchase) (*toschain.FinalizedEscrowV1, error) {
	manifestHash := sha256.Sum256(purchase.ManifestCBOR)
	if "sha256:"+hex.EncodeToString(manifestHash[:]) != purchase.ManifestDigest || purchase.Proposal == nil ||
		purchase.Proposal.ManifestDigest != purchase.ManifestDigest || purchase.Proposal.MaximumPrice == nil ||
		purchase.AmountAtomic != purchase.Proposal.MaximumPrice.AtomicAmount {
		return nil, errors.New("prepared purchase changed after review")
	}
	if err := b.validateCapability(ctx, purchase.Proposal); err != nil {
		return nil, err
	}
	asset, err := b.resolveAsset(ctx, purchase.Proposal)
	if err != nil {
		return nil, err
	}
	if asset.MasterAddress != purchase.AssetMasterAddress || asset.BuyerWalletAddress != purchase.BuyerWalletAddress ||
		positiveAtomic(asset.BuyerBalanceAtomic).Cmp(positiveAtomic(purchase.AmountAtomic)) < 0 {
		return nil, errors.New("buyer stablecoin wallet cannot fund exact purchase")
	}
	decoded, err := nativecore.DecodeEscrowDataV1(purchase.Escrow.Data)
	if err != nil {
		return nil, errors.New("prepared escrow data changed after review")
	}
	if purchase.Proposal.ExpiresAtUnixSeconds <= uint64(b.now().Unix()) ||
		decoded.FundingDeadline <= uint64(b.now().Unix()) {
		return nil, errors.New("purchase funding deadline expired")
	}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(decoded.ExecutionSignerEd25519)
	if err != nil {
		return nil, errors.New("prepared execution authorization changed after review")
	}
	quote, quoteCommitment, err := nativecore.BuildAcceptedQuoteCommitment(b.network, purchase.Proposal,
		"sha256:"+hex.EncodeToString(authorization.Hash()))
	if err != nil || quoteCommitment != purchase.QuoteCommitment ||
		purchase.QuoteBOCBase64 != base64.StdEncoding.EncodeToString(quote.ToBOC()) {
		return nil, errors.New("prepared Quote changed after review")
	}
	rebuilt, err := nativecore.BuildEscrowStateInitV1(0, b.escrowCode, nativecore.EscrowInitV1{
		AcceptedQuote: decoded.AcceptedQuote,
		Terms: nativecore.EscrowTermsV1{BuyerAddress: decoded.BuyerAddress, ProviderAddress: decoded.ProviderAddress,
			FundingDeadline: decoded.FundingDeadline, RefundAvailableAt: decoded.RefundAvailableAt},
		ExecutionSignerEd25519: decoded.ExecutionSignerEd25519, TransportBinding: decoded.TransportBinding,
		AssetMasterAddress: decoded.AssetMasterAddress, AssetWalletCode: b.walletCode,
	})
	if err != nil || rebuilt.Address != purchase.Escrow.Address || rebuilt.CodeHash != purchase.Escrow.CodeHash ||
		rebuilt.StateInitBOC != purchase.Escrow.StateInitBOC ||
		rebuilt.QuoteCommitment != purchase.QuoteCommitment || purchase.QuoteBOCBase64 != base64.StdEncoding.EncodeToString(decoded.AcceptedQuote.ToBOC()) {
		return nil, errors.New("prepared purchase identity changed after review")
	}
	return b.resolveExactEscrow(ctx, purchase)
}

func (b *Buyer) validateCapability(ctx context.Context, proposal *nativev1.QuoteProposalV1) error {
	return b.ValidateCapability(ctx, proposal.CapabilityId, proposal.ProviderAgentId, proposal.CapabilityVersion, proposal.ManifestDigest)
}

// ValidateCapability verifies that a finalized Capability exists and matches the
// expected owner Agent, version, and manifest digest against this buyer's
// network and registry code hash. It is the single authority for capability
// validation: the internal quote flow calls it, and it is exported so an
// external caller resolving the same Capability independently performs the exact
// same finalized check rather than re-deriving it.
func (b *Buyer) ValidateCapability(ctx context.Context, capabilityID, ownerAgentID, version, manifestDigest string) error {
	requestContext, err := b.requestContext()
	if err != nil {
		return err
	}
	response, err := b.nativeClient.ResolveNativeState(ctx, &nativev1.ResolveNativeStateRequest{
		Context: requestContext, ObjectId: capabilityID,
	})
	if err != nil {
		return err
	}
	if response == nil || !response.Found || response.State == nil || !proto.Equal(response.State.Network, b.network) ||
		response.State.TvmStateHash == "" || response.State.Reference == nil ||
		response.State.Reference.FinalizedCheckpoint == 0 || response.State.Reference.ContractCodeHash != b.registryCodeHash {
		return errors.New("Capability is not available from finalized typed state")
	}
	capability := response.State.GetCapability()
	if capability == nil || capability.CapabilityId != capabilityID || capability.OwnerAgentId != ownerAgentID || capability.Tombstoned {
		return errors.New("Quote provider does not own the finalized Capability")
	}
	for _, capabilityVersion := range capability.Versions {
		if capabilityVersion != nil && capabilityVersion.Version == version && capabilityVersion.ManifestDigest == manifestDigest && !capabilityVersion.Revoked {
			return nil
		}
	}
	return errors.New("Quote Capability version is absent or revoked")
}

func (b *Buyer) resolveAsset(ctx context.Context, proposal *nativev1.QuoteProposalV1) (*AssetObservation, error) {
	if proposal.MaximumPrice == nil || proposal.MaximumPrice.Asset == nil || !b.limits.permits(proposal.MaximumPrice.AtomicAmount) {
		return nil, errors.New("Quote exceeds buyer wallet budget")
	}
	observation, err := b.assetResolver.ResolveBuyerAsset(ctx, proposal.MaximumPrice.Asset, b.buyerAddress)
	if err != nil {
		return nil, err
	}
	expectedMaster := fmt.Sprintf("%d:%s", proposal.MaximumPrice.Asset.Master.Workchain,
		hex.EncodeToString(proposal.MaximumPrice.Asset.Master.AccountId))
	if observation == nil || !proto.Equal(observation.Asset, proposal.MaximumPrice.Asset) ||
		observation.MasterAddress != expectedMaster || observation.BuyerWalletAddress == "" ||
		observation.FinalizedCheckpoint == 0 || positiveAtomic(observation.BuyerBalanceAtomic) == nil ||
		!bytes.Equal(b.walletCode.Hash(), mustDigest(proposal.MaximumPrice.Asset.WalletCodeHash)) {
		return nil, errors.New("stablecoin asset observation does not match Quote")
	}
	return observation, nil
}

func (b *Buyer) resolveExactEscrow(ctx context.Context, purchase *PreparedPurchase) (*toschain.FinalizedEscrowV1, error) {
	resolved, found, err := b.escrowResolver.ResolveFinalized(ctx, purchase.Escrow.Address)
	if err != nil {
		return nil, err
	}
	if !found || resolved == nil || resolved.State == nil || resolved.Reference == nil ||
		resolved.Reference.FinalizedCheckpoint == 0 || resolved.Reference.ContractCodeHash != purchase.Escrow.CodeHash ||
		resolved.State.QuoteCommitment != purchase.QuoteCommitment || resolved.State.BuyerAddress != b.buyerAddress ||
		resolved.State.AssetMasterAddress != purchase.AssetMasterAddress ||
		resolved.State.AssetWalletCodeHash != purchase.Proposal.MaximumPrice.Asset.WalletCodeHash {
		return nil, errors.New("finalized escrow does not match prepared purchase")
	}
	if resolved.State.Status == nativecore.EscrowStatusFunded && resolved.State.FundedAtomicAmount != purchase.AmountAtomic {
		return nil, errors.New("finalized escrow funding does not match Quote")
	}
	return resolved, nil
}

func (b *Buyer) waitFunded(ctx context.Context, purchase *PreparedPurchase) (*toschain.FinalizedEscrowV1, error) {
	waitCtx, cancel := context.WithTimeout(ctx, b.finalityTimeout)
	defer cancel()
	ticker := time.NewTicker(b.pollInterval)
	defer ticker.Stop()
	for {
		resolved, err := b.resolveExactEscrow(waitCtx, purchase)
		if err != nil {
			return nil, err
		}
		if resolved.State.Status == nativecore.EscrowStatusFunded {
			return resolved, nil
		}
		if resolved.State.Status != nativecore.EscrowStatusAwaitingFunding {
			return nil, errors.New("escrow entered conflicting state while funding")
		}
		select {
		case <-waitCtx.Done():
			return nil, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func (b *Buyer) fundingIntent(purchase *PreparedPurchase) (fundingIntent, error) {
	asset := purchase.Proposal.MaximumPrice.Asset
	assetIdentity := fmt.Sprintf("%d:%s:%s:%s:%d", asset.Master.Workchain,
		hex.EncodeToString(asset.Master.AccountId), asset.Master.CodeHash, asset.WalletCodeHash, asset.Decimals)
	seed := struct {
		Network, Escrow, Quote, Asset, Wallet, Amount string
	}{b.network.NetworkId, purchase.Escrow.Address, purchase.QuoteCommitment, assetIdentity,
		purchase.BuyerWalletAddress, purchase.AmountAtomic}
	raw, err := json.Marshal(seed)
	if err != nil {
		return fundingIntent{}, err
	}
	hash := sha256.Sum256(append([]byte("atos.native.buyer.funding.v1"), raw...))
	queryID := binary.BigEndian.Uint64(hash[:8])
	if queryID == 0 {
		queryID = 1
	}
	return fundingIntent{Identity: "sha256:" + hex.EncodeToString(hash[:]), NetworkID: b.network.NetworkId,
		EscrowAddress: purchase.Escrow.Address, QuoteCommitment: purchase.QuoteCommitment,
		AssetIdentity: assetIdentity, BuyerWallet: purchase.BuyerWalletAddress,
		AmountAtomic: purchase.AmountAtomic, QueryID: queryID}, nil
}

func (b *Buyer) requestContext() (*nativev1.RequestContext, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("generate buyer Native request identity")
	}
	return &nativev1.RequestContext{RequestId: hex.EncodeToString(nonce[:]), CallerId: b.callerID,
		DeadlineUnixMillis: b.now().Add(b.finalityTimeout).UnixMilli()}, nil
}

func mustDigest(value string) []byte {
	raw, _ := hex.DecodeString(strings.TrimPrefix(value, "tvm-cell-sha256:"))
	return raw
}
