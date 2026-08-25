package paiddemand

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"google.golang.org/protobuf/proto"
)

const (
	PublicTermsContentType        = "application/vnd.tos.paid-demand-public-terms.v1+cbor"
	NegotiationPackageContentType = "application/vnd.tos.paid-demand-negotiation-package.v1+cbor"
)

// PublicTermsV1 contains only issuer-approved public Adapter parameters. It
// carries no key, credential, delegation, or authorization proof.
type PublicTermsV1 struct {
	SchemaVersion          uint16                        `json:"schema_version"`
	ProviderWallet         string                        `json:"provider_wallet"`
	AssetMasterAddress     string                        `json:"asset_master_address"`
	AssetMasterCodeHash    string                        `json:"asset_master_code_hash"`
	AssetWalletCodeHash    string                        `json:"asset_wallet_code_hash"`
	AssetDecimals          uint32                        `json:"asset_decimals"`
	CapabilityID           string                        `json:"capability_id"`
	CapabilityVersion      string                        `json:"capability_version"`
	ExecutionSignerEd25519 []byte                        `json:"execution_signer_ed25519"`
	TransportBinding       nativecore.TransportBindingV1 `json:"transport_binding"`
	ExecutionProfileURI    string                        `json:"execution_profile_uri"`
	FundingWindowSeconds   uint32                        `json:"funding_window_seconds"`
	ExecutionWindowSeconds uint32                        `json:"execution_window_seconds"`
	RefundDelaySeconds     uint32                        `json:"refund_delay_seconds"`
}

type NegotiationPackageV1 struct {
	SchemaVersion          uint16                              `json:"schema_version"`
	AgreementBodyDigest    string                              `json:"agreement_body_digest"`
	ProposalProto          []byte                              `json:"quote_proposal_proto"`
	ManifestCanonical      []byte                              `json:"manifest_canonical"`
	EscrowTerms            nativecore.EscrowTermsV1            `json:"escrow_terms"`
	ExecutionSignerEd25519 []byte                              `json:"execution_signer_ed25519"`
	TransportBinding       nativecore.TransportBindingV1       `json:"transport_binding"`
	ExecutionDeadlineUnix  uint64                              `json:"execution_deadline_unix"`
	Binding                commerce.PaidDemandQuoteBindingBody `json:"binding"`
}

func CanonicalPublicTerms(terms PublicTermsV1) ([]byte, error) {
	if validatePublicTerms(terms) != nil {
		return nil, errors.New("invalid Paid Demand public terms")
	}
	return codec.Marshal(terms)
}

func DecodeCanonicalPublicTerms(canonical []byte) (PublicTermsV1, error) {
	var terms PublicTermsV1
	if len(canonical) == 0 || len(canonical) > 64<<10 || codec.Unmarshal(canonical, &terms) != nil || validatePublicTerms(terms) != nil {
		return PublicTermsV1{}, errors.New("invalid Paid Demand public terms")
	}
	reencoded, err := codec.Marshal(terms)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return PublicTermsV1{}, errors.New("Paid Demand public terms are not canonical")
	}
	return terms, nil
}

func CanonicalNegotiationPackage(value NegotiationPackageV1) ([]byte, error) {
	if value.SchemaVersion != 1 || !canonicalSHA256(value.AgreementBodyDigest) || len(value.ProposalProto) == 0 ||
		len(value.ProposalProto) > 1<<20 || len(value.ManifestCanonical) == 0 || len(value.ManifestCanonical) > 1<<20 ||
		len(value.ExecutionSignerEd25519) != 32 || value.ExecutionDeadlineUnix == 0 ||
		commerce.ValidatePaidDemandQuoteBinding(value.Binding) != nil {
		return nil, errors.New("invalid Paid Demand negotiation package")
	}
	return codec.Marshal(value)
}

func DecodeCanonicalNegotiationPackage(canonical []byte) (NegotiationPackageV1, error) {
	var value NegotiationPackageV1
	if len(canonical) == 0 || len(canonical) > 2<<20 || codec.Unmarshal(canonical, &value) != nil {
		return NegotiationPackageV1{}, errors.New("invalid Paid Demand negotiation package")
	}
	reencoded, err := CanonicalNegotiationPackage(value)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return NegotiationPackageV1{}, errors.New("Paid Demand negotiation package is not canonical")
	}
	return value, nil
}

func EncodeQuoteProposal(proposal *nativev1.QuoteProposalV1) ([]byte, error) {
	if proposal == nil {
		return nil, errors.New("missing Quote proposal")
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(proposal)
}

func DecodeQuoteProposal(canonical []byte) (*nativev1.QuoteProposalV1, error) {
	if len(canonical) == 0 || len(canonical) > 1<<20 {
		return nil, errors.New("invalid Quote proposal encoding")
	}
	proposal := new(nativev1.QuoteProposalV1)
	if (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(canonical, proposal) != nil {
		return nil, errors.New("invalid Quote proposal encoding")
	}
	reencoded, err := EncodeQuoteProposal(proposal)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return nil, errors.New("Quote proposal protobuf is not deterministic")
	}
	return proposal, nil
}

// ValidateNegotiationPackage proves that the generic Agreement, public
// Adapter offer, native Quote projection, manifest and all deadlines are the
// same proposal before the Provider reserves exposure or signs an Offer.
func ValidateNegotiationPackage(agreement commerce.AgentAgreementBody, public PublicTermsV1,
	value NegotiationPackageV1, now time.Time) (*nativev1.QuoteProposalV1, error) {
	if validatePublicTerms(public) != nil || commerce.ValidateAgreementBody(agreement) != nil || now.IsZero() ||
		value.SchemaVersion != 1 || value.Binding.AcceptByUnix <= uint64(now.UTC().Unix()) ||
		value.ExecutionDeadlineUnix <= value.Binding.AcceptByUnix || value.ExecutionDeadlineUnix >= value.EscrowTerms.RefundAvailableAt ||
		value.ExecutionDeadlineUnix > agreement.ExpiresAtUnix {
		return nil, errors.New("Paid Demand negotiation context or deadline is invalid")
	}
	agreementDigest, err := commerce.AgreementBodyDigest(agreement)
	if err != nil || agreementDigest != value.AgreementBodyDigest || agreementDigest != value.Binding.AgreementBodyDigest ||
		commerce.ValidatePaidDemandAgreementBinding(agreement, value.Binding) != nil {
		return nil, errors.New("Paid Demand package targets another Agreement")
	}
	proposal, err := DecodeQuoteProposal(value.ProposalProto)
	if err != nil || proposal.MaximumPrice == nil || proposal.MaximumPrice.Asset == nil || proposal.MaximumPrice.Asset.Master == nil {
		return nil, errors.New("Paid Demand Quote proposal is incomplete")
	}
	manifest, manifestDigest, err := decodeManifestAndDigest(value.ManifestCanonical)
	if err != nil || manifest.AgreementBodyDigest != agreementDigest || proposal.ManifestDigest != manifestDigest ||
		!manifestWorkMatches(agreement, value.Binding, manifest) {
		return nil, errors.New("Paid Demand execution manifest differs from Agreement work")
	}
	if value.Binding.ProviderWallet != public.ProviderWallet || value.EscrowTerms.ProviderAddress != public.ProviderWallet ||
		value.Binding.BuyerWallet != value.EscrowTerms.BuyerAddress || proposal.CapabilityId != public.CapabilityID ||
		proposal.CapabilityVersion != public.CapabilityVersion || proposal.ProviderAgentId != value.Binding.ProviderAgentID ||
		proposal.ExpiresAtUnixSeconds != value.Binding.AcceptByUnix || !bytes.Equal(value.ExecutionSignerEd25519, public.ExecutionSignerEd25519) ||
		!sameTransportBinding(value.TransportBinding, public.TransportBinding) {
		return nil, errors.New("Paid Demand package substitutes public Provider terms")
	}
	asset, err := assetFromPublic(public)
	if err != nil || !proto.Equal(asset, proposal.MaximumPrice.Asset) {
		return nil, errors.New("Paid Demand package substitutes the public asset identity")
	}
	terms, err := nativecore.BuildEscrowTermsCellV1(value.EscrowTerms)
	if err != nil || proposal.EscrowTermsDigest != "sha256:"+hex.EncodeToString(terms.Hash()) {
		return nil, errors.New("Paid Demand escrow terms digest mismatch")
	}
	return proposal, nil
}

func ValidateNegotiationPackageOnNetwork(agreement commerce.AgentAgreementBody, public PublicTermsV1,
	value NegotiationPackageV1, network *nativev1.NetworkDomain, now time.Time) (*nativev1.QuoteProposalV1, error) {
	if network == nil || network.NetworkId != value.Binding.NetworkContext {
		return nil, errors.New("Paid Demand package targets another network")
	}
	proposal, err := ValidateNegotiationPackage(agreement, public, value, now)
	if err != nil {
		return nil, err
	}
	authorization, _ := nativecore.BuildEscrowAuthorizationCellV1(value.ExecutionSignerEd25519)
	_, projection, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal,
		"sha256:"+hex.EncodeToString(authorization.Hash()))
	if err != nil || projection != value.Binding.NativeQuoteTermsProjectionDigest {
		return nil, errors.New("Paid Demand network-bound Quote projection mismatch")
	}
	return proposal, nil
}

func validatePublicTerms(terms PublicTermsV1) error {
	if terms.SchemaVersion != 1 || rawWC0(terms.ProviderWallet) == nil || rawWC0(terms.AssetMasterAddress) == nil ||
		!stringsHasCellDigest(terms.AssetMasterCodeHash) || !stringsHasCellDigest(terms.AssetWalletCodeHash) ||
		terms.AssetDecimals == 0 || terms.AssetDecimals > 18 || !boundedManifestText(terms.CapabilityID, 256) ||
		!boundedManifestText(terms.CapabilityVersion, 64) || len(terms.ExecutionSignerEd25519) != 32 ||
		!boundedManifestText(terms.ExecutionProfileURI, 256) || terms.FundingWindowSeconds < 60 ||
		terms.FundingWindowSeconds > 7*86400 || terms.ExecutionWindowSeconds < 60 || terms.ExecutionWindowSeconds > 30*86400 ||
		terms.RefundDelaySeconds < 60 || terms.RefundDelaySeconds > 90*86400 {
		return errors.New("invalid Paid Demand public terms")
	}
	_, digest, err := nativecore.BuildTransportBindingCellV1(terms.TransportBinding)
	if err != nil || digest == "" {
		return errors.New("invalid Paid Demand transport binding")
	}
	return nil
}

func assetFromPublic(terms PublicTermsV1) (*nativev1.TOSAssetIdentityV1, error) {
	master := rawWC0(terms.AssetMasterAddress)
	if master == nil {
		return nil, errors.New("invalid asset master")
	}
	return &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{Workchain: 0,
		AccountId: append([]byte(nil), master.Data()...), CodeHash: terms.AssetMasterCodeHash},
		WalletCodeHash: terms.AssetWalletCodeHash, Decimals: terms.AssetDecimals}, nil
}

func AssetFromPublicTerms(terms PublicTermsV1) (*nativev1.TOSAssetIdentityV1, error) {
	if err := validatePublicTerms(terms); err != nil {
		return nil, err
	}
	return assetFromPublic(terms)
}

func rawWC0(value string) *address.Address {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Workchain() != 0 || parsed.StringRaw() != value {
		return nil
	}
	return parsed
}

func stringsHasCellDigest(value string) bool {
	return len(value) == 80 && len(value) > 16 && value[:16] == "tvm-cell-sha256:" && canonicalSHA256("sha256:"+value[16:])
}

func sameTransportBinding(left, right nativecore.TransportBindingV1) bool {
	_, leftDigest, leftErr := nativecore.BuildTransportBindingCellV1(left)
	_, rightDigest, rightErr := nativecore.BuildTransportBindingCellV1(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func decodeManifestAndDigest(canonical []byte) (ExecutionManifestV1, string, error) {
	manifest, err := DecodeCanonicalExecutionManifest(canonical)
	if err != nil {
		return ExecutionManifestV1{}, "", err
	}
	_, digest, err := CanonicalExecutionManifest(manifest)
	return manifest, digest, err
}

func manifestWorkMatches(agreement commerce.AgentAgreementBody, binding commerce.PaidDemandQuoteBindingBody,
	manifest ExecutionManifestV1) bool {
	bound := make(map[string]bool, len(binding.AgreementObligationIDs))
	for _, id := range binding.AgreementObligationIDs {
		bound[id] = true
	}
	want := make([]string, 0)
	for _, obligation := range agreement.Obligations {
		if bound[obligation.ObligationID] && obligation.Amount == nil &&
			obligation.ObligorAgentID == binding.ProviderAgentID && obligation.BeneficiaryAgentID == binding.BuyerAgentID {
			want = append(want, obligation.ObligationID)
		}
	}
	sort.Strings(want)
	return len(want) == len(manifest.WorkObligationIDs) && sort.StringsAreSorted(manifest.WorkObligationIDs) &&
		bytes.Equal([]byte(joinIDs(want)), []byte(joinIDs(manifest.WorkObligationIDs)))
}

func joinIDs(values []string) string {
	var output []byte
	for _, value := range values {
		output = append(output, byte(len(value)>>8), byte(len(value)))
		output = append(output, value...)
	}
	return string(output)
}
