package toschain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const AgentAccountNativeSendRelayProfileURI = "tos.transaction.agent-account-native-send.v1"

type agentAccountNativeSendProfileDescriptor struct {
	ProfileURI                   string `json:"profile_uri"`
	Opcode                       uint32 `json:"opcode"`
	MaximumSignedBytes           uint32 `json:"maximum_signed_bytes"`
	InspectableSourceSequence    bool   `json:"inspectable_source_sequence"`
	InspectableTransactionExpiry bool   `json:"inspectable_transaction_expiry"`
	CanonicalBOCRequired         bool   `json:"canonical_boc_required"`
}

func AgentAccountNativeSendRelayProfileDigest() string {
	digest, err := codec.Digest("tos.agent-relay-transaction-profile.v1", agentAccountNativeSendProfileDescriptor{
		ProfileURI: AgentAccountNativeSendRelayProfileURI, Opcode: agentgift.AgentNativeSendOpcode,
		MaximumSignedBytes: agentgift.MaxSignedBOCBytes, InspectableSourceSequence: true,
		InspectableTransactionExpiry: true, CanonicalBOCRequired: true})
	if err != nil {
		panic(err)
	}
	return digest
}

func AgentAccountNativeSendRelayProfile() agentrelay.TransactionProfile {
	return agentrelay.TransactionProfile{ProfileURI: AgentAccountNativeSendRelayProfileURI,
		ProfileDigest: AgentAccountNativeSendRelayProfileDigest(), MaximumSignedBytes: agentgift.MaxSignedBOCBytes,
		InspectableSourceSequence: true, InspectableTransactionExpiry: true}
}

type FinalizedAgentAccountResolver interface {
	ResolveFinalizedAgentAccount(context.Context, agentrelay.NetworkDomain, string) (ResolvedRelayAgentAccount, error)
}

type ResolvedRelayAgentAccount struct {
	Account           agentgift.FinalizedAgentAccount
	FinalizedTime     uint32
	AuthorizedAgentID string
}

// AgentAccountRelayAuthority is the stable authority projection committed by
// RelayQuoteRequestBody.SourceAccountAuthorityDigest. Mutable balance, seqno,
// and spend-limit state is deliberately excluded and is revalidated at each
// admission/broadcast boundary instead.
type AgentAccountRelayAuthority struct {
	SchemaVersion       uint16 `json:"schema_version"`
	NetworkDigest       string `json:"network_digest"`
	SourceAccount       string `json:"source_account"`
	OwnerAddress        string `json:"owner_address"`
	CodeHash            string `json:"code_hash"`
	DeploymentID        string `json:"deployment_id"`
	GlobalID            int32  `json:"global_id"`
	TVMVersion          uint32 `json:"tvm_version"`
	AuthorizedAgentID   string `json:"authorized_agent_id"`
	ControllerPublicKey string `json:"controller_public_key"`
	ControllerEpoch     uint64 `json:"controller_epoch"`
}

func AgentAccountRelayAuthorityDigest(network agentrelay.NetworkDomain,
	resolved ResolvedRelayAgentAccount) (string, error) {
	account := resolved.Account
	source, sourceErr := address.ParseRawAddr(account.Address)
	owner, ownerErr := address.ParseRawAddr(account.OwnerAddress)
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil || !account.Active || account.Address == "" || account.OwnerAddress == "" ||
		sourceErr != nil || source == nil || source.StringRaw() != account.Address || source.Workchain() != network.WorkchainID ||
		ownerErr != nil || owner == nil || owner.StringRaw() != account.OwnerAddress ||
		account.CodeHash != agentgift.AgentAccountCodeHash || account.DeploymentID == "" ||
		account.GlobalID != network.GlobalID || account.TVMVersion < agentgift.MinimumAgentAccountTVMVersion ||
		!canonicalSHA256Digest(account.DeploymentID) || len(resolved.AuthorizedAgentID) == 0 ||
		len(resolved.AuthorizedAgentID) > 256 || strings.TrimSpace(resolved.AuthorizedAgentID) != resolved.AuthorizedAgentID ||
		len(account.ControllerPublicKey) != ed25519.PublicKeySize {
		return "", errors.New("finalized Agent Account authority projection is invalid")
	}
	return codec.Digest("tos.agent-relay-source-authority.agent-account.v1", AgentAccountRelayAuthority{
		SchemaVersion: 1, NetworkDigest: networkDigest, SourceAccount: account.Address,
		OwnerAddress: account.OwnerAddress, CodeHash: account.CodeHash, DeploymentID: account.DeploymentID,
		GlobalID: account.GlobalID, TVMVersion: account.TVMVersion, AuthorizedAgentID: resolved.AuthorizedAgentID,
		ControllerPublicKey: "ed25519:" + hex.EncodeToString(account.ControllerPublicKey),
		ControllerEpoch:     account.ControllerEpoch})
}

func canonicalSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

type AgentAccountNativeSendInspector struct {
	Accounts               FinalizedAgentAccountResolver
	NativeAsset            agentrelay.AssetIdentity
	FeeReserveAtomic       uint64
	MinimumInclusionMargin uint32
}

type AgentAccountNativeSendIntent struct {
	SchemaVersion   uint16 `json:"schema_version"`
	NetworkDigest   string `json:"network_digest"`
	SourceAccount   string `json:"source_account"`
	ControllerEpoch uint64 `json:"controller_epoch"`
	SourceSequence  uint64 `json:"source_sequence"`
	ValidUntilUnix  uint64 `json:"valid_until_unix"`
	Destination     string `json:"destination"`
	ValueAtomic     string `json:"value_atomic"`
}

func AgentAccountNativeSendIntentDigest(intent AgentAccountNativeSendIntent) (string, error) {
	if intent.SchemaVersion != 1 || intent.NetworkDigest == "" || intent.SourceAccount == "" ||
		intent.ValidUntilUnix == 0 || intent.Destination == "" || intent.ValueAtomic == "" {
		return "", errors.New("Agent Account native-send intent is incomplete")
	}
	return codec.Digest("tos.agent-relay-transaction-intent.agent-account-native-send.v1", intent)
}

func (inspector AgentAccountNativeSendInspector) InspectTransaction(ctx context.Context, request agentrelay.RelayQuoteRequestBody,
	profile agentrelay.TransactionProfile, exactBOC []byte,
	phase agentrelay.TransactionInspectionPhase) (agentrelay.InspectedTransaction, error) {
	var zero agentrelay.InspectedTransaction
	network := request.Network
	if profile != AgentAccountNativeSendRelayProfile() || inspector.Accounts == nil || inspector.FeeReserveAtomic == 0 ||
		inspector.MinimumInclusionMargin == 0 || inspector.NativeAsset.AssetNamespace == "" {
		return zero, errors.New("Agent Account relay inspector is incomplete or profile-mismatched")
	}
	var projectedCredit uint64
	switch phase {
	case agentrelay.InspectionAdmission:
		if request.RequestedSponsorship != nil {
			if request.Mode == agentrelay.ModeRelayExact || request.RequestedSponsorship.Asset != inspector.NativeAsset {
				return zero, errors.New("pending sponsorship is not the selected network native asset")
			}
			var err error
			projectedCredit, err = strconv.ParseUint(request.RequestedSponsorship.AmountAtomic, 10, 64)
			if err != nil || projectedCredit == 0 {
				return zero, errors.New("pending sponsorship amount is invalid for this transaction profile")
			}
		}
	case agentrelay.InspectionReadyToBroadcast:
		// The sponsorship, if any, must already be visible in the finalized
		// account returned by Accounts. Counting it again would permit an
		// underfunded transaction to reach the broadcaster.
	default:
		return zero, errors.New("unknown relay transaction inspection phase")
	}
	parsed, err := agentgift.ParseAgentNativeSendBOC(exactBOC)
	if err != nil || parsed.GlobalID != network.GlobalID {
		return zero, errors.New("exact BOC does not match the selected TOS network")
	}
	resolved, err := inspector.Accounts.ResolveFinalizedAgentAccount(ctx, network, parsed.SenderAgentAccount)
	if err != nil {
		return zero, fmt.Errorf("resolve finalized Agent Account: %w", err)
	}
	authorityDigest, err := AgentAccountRelayAuthorityDigest(network, resolved)
	if err != nil {
		return zero, errors.New("finalized Agent Account has no canonical Agent authorization proof")
	}
	parsed, err = agentgift.VerifyAgentNativeSendAuthority(agentgift.VerifyNativeSendAuthorityInput{
		ExactSignedBOC: exactBOC, Account: resolved.Account, ExpectedGlobalID: network.GlobalID,
		ExpectedSourceAccount: parsed.SenderAgentAccount, ExpectedSequence: parsed.Seqno,
		MaximumValidUntil: parsed.ValidUntil, FeeReserveAtomic: inspector.FeeReserveAtomic,
		PermittedIncomingCreditAtomic: projectedCredit,
		FinalizedChainTime:            resolved.FinalizedTime, MinimumInclusionMargin: inspector.MinimumInclusionMargin})
	if err != nil {
		return zero, err
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil {
		return zero, err
	}
	intent := AgentAccountNativeSendIntent{SchemaVersion: 1, NetworkDigest: networkDigest,
		SourceAccount: parsed.SenderAgentAccount, ControllerEpoch: parsed.ControllerEpoch,
		SourceSequence: uint64(parsed.Seqno), ValidUntilUnix: uint64(parsed.ValidUntil),
		Destination: parsed.DestinationAddress, ValueAtomic: strconv.FormatUint(parsed.AmountAtomic, 10)}
	intentDigest, err := AgentAccountNativeSendIntentDigest(intent)
	if err != nil {
		return zero, err
	}
	root, err := cell.FromBOC(exactBOC)
	if err != nil || !bytes.Equal(exactBOC, root.ToBOCWithFlags(false)) {
		return zero, errors.New("exact relay BOC is not canonical")
	}
	return agentrelay.InspectedTransaction{NetworkDigest: networkDigest, SourceAccount: parsed.SenderAgentAccount,
		SourceAccountAuthorityDigest: authorityDigest, AuthorizedAgentID: resolved.AuthorizedAgentID,
		ControllerEpoch: parsed.ControllerEpoch, SourceSequence: uint64(parsed.Seqno), ValidUntilUnix: uint64(parsed.ValidUntil),
		Destination: parsed.DestinationAddress, ValueAtomic: strconv.FormatUint(parsed.AmountAtomic, 10),
		TransactionIntentDigest: intentDigest, SignedTransactionCellHash: fmt.Sprintf("tvm-cell-sha256:%x", root.Hash()),
		MaximumNetworkFeeAtomic:       strconv.FormatUint(inspector.FeeReserveAtomic, 10),
		MaximumTransactionValueAtomic: strconv.FormatUint(parsed.AmountAtomic, 10)}, nil
}

// AgentAccountDirectPaymentBinder is the released V1 mapping from a generic
// payment.direct action to an Agent Account native-send transaction.
type AgentAccountDirectPaymentBinder struct {
	NativeAsset agentrelay.AssetIdentity
}

func (binder AgentAccountDirectPaymentBinder) VerifyActionTransaction(request agentrelay.RelayExecutionRequest,
	inspected agentrelay.InspectedTransaction) error {
	if request.AuthorizedAction.ActionKind != "payment.direct" || binder.NativeAsset.AssetNamespace == "" {
		return errors.New("unsupported relay action-to-transaction profile")
	}
	var payment agentcommerce.AgreementPaymentRequest
	if err := codec.Unmarshal(request.UnderlyingActionRequest, &payment); err != nil ||
		agentcommerce.ValidateAgreementPaymentRequest(payment) != nil || payment.SchemaVersion != 3 ||
		payment.StableActionID != request.AuthorizedAction.StableActionID || payment.AgentID != request.QuoteRequest.Body.RequesterAgentID ||
		payment.NetworkID != request.QuoteRequest.Body.Network.NetworkID ||
		payment.NetworkDomainDigest != inspected.NetworkDigest ||
		payment.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI || string(payment.Destination) != inspected.Destination ||
		payment.Amount.AmountAtomic != inspected.ValueAtomic || payment.Amount.AssetNamespace != binder.NativeAsset.AssetNamespace ||
		payment.Amount.AssetIdentifier != binder.NativeAsset.AssetIdentifier || payment.Amount.Unit != binder.NativeAsset.Unit ||
		payment.ExpiresAtUnix < inspected.ValidUntilUnix {
		return errors.New("payment.direct request conflicts with the exact Agent Account transaction")
	}
	intent, err := AgentAccountNativeSendIntentDigest(AgentAccountNativeSendIntent{SchemaVersion: 1,
		NetworkDigest: inspected.NetworkDigest, SourceAccount: inspected.SourceAccount, ControllerEpoch: inspected.ControllerEpoch,
		SourceSequence: inspected.SourceSequence, ValidUntilUnix: inspected.ValidUntilUnix,
		Destination: inspected.Destination, ValueAtomic: inspected.ValueAtomic})
	if err != nil || intent != request.QuoteRequest.Body.TransactionIntentDigest {
		return errors.New("payment.direct transaction intent digest mismatch")
	}
	return nil
}
