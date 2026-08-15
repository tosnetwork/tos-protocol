// Package quoteprovider constructs non-canonical, complete-preimage Quote
// Proposal packages from provider policy and freshly finalized Capability state.
package quoteprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

type NativeResolver interface {
	ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error)
}

type Config struct {
	Resolver          NativeResolver
	Network           *nativev1.NetworkDomain
	RegistryCodeHash  string
	ProviderAgentID   string
	ProviderAddress   string
	ManifestCBOR      []byte
	Transport         nativecore.TransportBindingV1
	MaximumPrice      *nativev1.MoneyV1
	ProposalTTL       time.Duration
	FundingWindow     time.Duration
	RefundDelay       time.Duration
	ResolutionTimeout time.Duration
	CallerID          string
	Now               func() time.Time
	Random            func([]byte) error
}

type Provider struct {
	config         Config
	manifestDigest string
	version        string
}

func New(config Config) (*Provider, error) {
	if config.Resolver == nil || config.Network == nil || config.Network.NetworkId == "" ||
		config.RegistryCodeHash == "" || config.ProviderAgentID == "" || config.ProviderAddress == "" ||
		len(config.ManifestCBOR) == 0 || config.MaximumPrice == nil || config.CallerID == "" || len(config.CallerID) > 256 {
		return nil, errors.New("invalid Quote provider configuration")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(config.ManifestCBOR)
	if err != nil {
		return nil, errors.New("Quote provider manifest is not canonical")
	}
	canonical, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, config.ManifestCBOR) {
		return nil, errors.New("Quote provider manifest cannot be reproduced")
	}
	termsProbe, termsErr := nativecore.BuildEscrowTermsCellV1(nativecore.EscrowTermsV1{
		BuyerAddress: "0:" + strings.Repeat("01", 32), ProviderAddress: config.ProviderAddress,
		FundingDeadline: 1, RefundAvailableAt: 2})
	_, transportDigest, transportErr := nativecore.BuildTransportBindingCellV1(config.Transport)
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	probe := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("02", 32),
		CapabilityVersion: manifest.Version, ProviderAgentId: config.ProviderAgentID, ManifestDigest: digest,
		TransportBindingDigest: transportDigest, MaximumPrice: config.MaximumPrice,
		DisputePolicyDigest: disputeDigest, ExpiresAtUnixSeconds: 1}
	if termsErr == nil {
		probe.EscrowTermsDigest = "sha256:" + hex.EncodeToString(termsProbe.Hash())
	}
	if termsErr != nil || transportErr != nil || !cellDigest(config.RegistryCodeHash) {
		return nil, errors.New("invalid Quote provider policy preimage")
	}
	if _, _, err := nativecore.BuildAcceptedQuoteCommitment(config.Network, probe, "sha256:"+strings.Repeat("03", 32)); err != nil {
		return nil, errors.New("invalid Quote provider commercial policy")
	}
	if config.ProposalTTL == 0 {
		config.ProposalTTL = 15 * time.Minute
	}
	if config.FundingWindow == 0 {
		config.FundingWindow = 10 * time.Minute
	}
	if config.RefundDelay == 0 {
		config.RefundDelay = 30 * time.Minute
	}
	if config.ResolutionTimeout == 0 {
		config.ResolutionTimeout = 30 * time.Second
	}
	if config.ProposalTTL < time.Minute || config.ProposalTTL > time.Hour || config.FundingWindow < time.Minute ||
		config.FundingWindow > config.ProposalTTL || config.RefundDelay <= config.FundingWindow ||
		config.RefundDelay > 24*time.Hour || config.ResolutionTimeout < time.Second || config.ResolutionTimeout > time.Minute {
		return nil, errors.New("invalid Quote provider timing policy")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	config.Network = proto.Clone(config.Network).(*nativev1.NetworkDomain)
	config.ManifestCBOR = append([]byte(nil), config.ManifestCBOR...)
	config.MaximumPrice = proto.Clone(config.MaximumPrice).(*nativev1.MoneyV1)
	return &Provider{config: config, manifestDigest: digest, version: manifest.Version}, nil
}

func cellDigest(value string) bool {
	if len(value) != len("tvm-cell-sha256:")+64 || !strings.HasPrefix(value, "tvm-cell-sha256:") || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "tvm-cell-sha256:"))
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}

func (p *Provider) RequestQuoteProposal(ctx context.Context, request *nativev1.RequestQuoteProposalRequest) (*nativev1.QuoteProposalPackageV1, error) {
	if p == nil || ctx == nil || request == nil || request.Context == nil || request.Context.RequestId == "" ||
		request.CapabilityId == "" || request.CapabilityVersion != p.version || request.BuyerAddress == "" {
		return nil, errors.New("invalid provider Quote request")
	}
	call, cancel := context.WithTimeout(ctx, p.config.ResolutionTimeout)
	defer cancel()
	resolved, err := p.config.Resolver.ResolveNativeState(call, &nativev1.ResolveNativeStateRequest{Context: &nativev1.RequestContext{
		RequestId: request.Context.RequestId + "-quote-state", CallerId: p.config.CallerID,
		DeadlineUnixMillis: p.config.Now().Add(p.config.ResolutionTimeout).UnixMilli()}, ObjectId: request.CapabilityId})
	if err != nil || resolved == nil || !resolved.Found || resolved.State == nil {
		return nil, errors.New("Quote Capability is not available from finalized state")
	}
	state := resolved.State
	capability := state.GetCapability()
	if !proto.Equal(state.Network, p.config.Network) || state.Reference == nil || state.Reference.FinalizedCheckpoint == 0 ||
		state.Reference.ContractCodeHash != p.config.RegistryCodeHash || capability == nil || capability.Tombstoned ||
		capability.CapabilityId != request.CapabilityId || capability.OwnerAgentId != p.config.ProviderAgentID {
		return nil, errors.New("Quote Capability does not match provider authority")
	}
	active := false
	for _, version := range capability.Versions {
		if version != nil && version.Version == p.version && version.ManifestDigest == p.manifestDigest && !version.Revoked {
			active = true
		}
	}
	if !active {
		return nil, errors.New("Quote Capability version is not active")
	}
	now := p.config.Now()
	terms, err := nativecore.BuildEscrowTermsCellV1(nativecore.EscrowTermsV1{BuyerAddress: request.BuyerAddress,
		ProviderAddress: p.config.ProviderAddress, FundingDeadline: uint64(now.Add(p.config.FundingWindow).Unix()),
		RefundAvailableAt: uint64(now.Add(p.config.RefundDelay).Unix())})
	if err != nil {
		return nil, err
	}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(p.config.Transport)
	if err != nil {
		return nil, err
	}
	dispute, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	nonce := make([]byte, 16)
	if err := p.config.Random(nonce); err != nil {
		return nil, errors.New("generate Quote Proposal identity")
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-" + hex.EncodeToString(nonce),
		CapabilityId: request.CapabilityId, CapabilityVersion: p.version, ProviderAgentId: p.config.ProviderAgentID,
		ManifestDigest: p.manifestDigest, TransportBindingDigest: transportDigest,
		MaximumPrice:      proto.Clone(p.config.MaximumPrice).(*nativev1.MoneyV1),
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(terms.Hash()), DisputePolicyDigest: disputeDigest,
		ExpiresAtUnixSeconds: uint64(now.Add(p.config.ProposalTTL).Unix())}
	value := &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: append([]byte(nil), p.config.ManifestCBOR...),
		EscrowTermsBoc: terms.ToBOC(), TransportBindingBoc: transport.ToBOC(), DisputePolicyBoc: dispute.ToBOC()}
	if _, err := quoteexchange.Validate(p.config.Network, request, value, now); err != nil {
		return nil, errors.New("constructed Quote Proposal package failed validation")
	}
	return value, nil
}
