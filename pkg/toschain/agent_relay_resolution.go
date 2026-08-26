package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const TOSRelayRPCObservationProfileURI = "tos.relay.rpc-checkpoint-observation.v1"
const TOSRelayProviderCorroboratedTerminalProfileURI = "tos.relay.provider-corroborated-terminal.v1"

type tosRelayRPCObservationProfileDescriptor struct {
	ProfileURI                   string `json:"profile_uri"`
	CheckpointPinnedAccountReads bool   `json:"checkpoint_pinned_account_reads"`
	ExactExternalMessageMatch    bool   `json:"exact_external_message_match"`
	ExactDestinationCreditMatch  bool   `json:"exact_destination_credit_match"`
	StrictEndpointQuorum         bool   `json:"strict_endpoint_quorum"`
	NodeAcknowledgementFinality  bool   `json:"node_acknowledgement_finality"`
}

func TOSRelayRPCObservationProfileDigest() string {
	digest, err := codec.Digest("tos.agent-relay-rpc-observation-profile.v1",
		tosRelayRPCObservationProfileDescriptor{ProfileURI: TOSRelayRPCObservationProfileURI,
			CheckpointPinnedAccountReads: true, ExactExternalMessageMatch: true,
			ExactDestinationCreditMatch: true, StrictEndpointQuorum: true,
			NodeAcknowledgementFinality: false})
	if err != nil {
		panic(err)
	}
	return digest
}

// TOSRelayObserverBinding is owner-pinned provenance for one configured RPC
// endpoint, in Adapter endpoint order. It prevents several URLs operated by
// one party from being counted as independent operator domains. The endpoint
// authority digest is an audit binding, not a substitute for a signed chain
// proof; see TOSRelayRPCObservationReference below.
type TOSRelayObserverBinding struct {
	ObserverID              string `json:"observer_id"`
	OperatorDomainID        string `json:"operator_domain_id"`
	EndpointAuthorityDigest string `json:"endpoint_authority_digest"`
}

// TOSRelayRPCObservationReference is the deterministic content addressed
// record behind a ChainResolution evidence ref. It records exactly what an
// owner-pinned RPC observer corroborated at two finalized checkpoints. The
// current TOS RPC does not return a signed inclusion proof, so this record MUST
// NOT be presented as independently verifiable validator evidence.
type TOSRelayRPCObservationReference struct {
	SchemaVersion                 uint16                     `json:"schema_version"`
	ObservationProfileURI         string                     `json:"observation_profile_uri"`
	ObservationProfileDigest      string                     `json:"observation_profile_digest"`
	Observer                      TOSRelayObserverBinding    `json:"observer"`
	NetworkDigest                 string                     `json:"network_digest"`
	StableActionID                string                     `json:"stable_action_id"`
	ExactRequestDigest            string                     `json:"exact_request_digest"`
	RelayExecutionDigest          string                     `json:"relay_execution_request_digest"`
	SignedTransactionDigest       string                     `json:"signed_transaction_digest"`
	SignedTransactionCellHash     string                     `json:"signed_transaction_cell_hash"`
	SourceAccount                 string                     `json:"source_account"`
	SourceSequence                uint64                     `json:"source_sequence"`
	FinalizedCheckpointID         string                     `json:"finalized_checkpoint_id"`
	FinalizedCheckpointSequence   uint64                     `json:"finalized_checkpoint_sequence"`
	DepthAnchorCheckpointID       string                     `json:"depth_anchor_checkpoint_id"`
	DepthAnchorCheckpointSequence uint64                     `json:"depth_anchor_checkpoint_sequence"`
	ConfirmationDepth             uint32                     `json:"confirmation_depth"`
	SourceExecutionReference      string                     `json:"source_execution_reference,omitempty"`
	DestinationCreditReference    string                     `json:"destination_credit_reference,omitempty"`
	ObservedOutcome               agentrelay.TerminalOutcome `json:"observed_outcome"`
	ObservedAtUnix                uint64                     `json:"observed_at_unix"`
}

func TOSRelayRPCObservationReferenceDigest(reference TOSRelayRPCObservationReference) (string, error) {
	_, sourceErr := CanonicalAddress(reference.SourceAccount)
	confirmationDepth := reference.FinalizedCheckpointSequence - reference.DepthAnchorCheckpointSequence + 1
	success := reference.ObservedOutcome == agentrelay.OutcomeCorroboratedSuccess
	terminalOutcome := success || reference.ObservedOutcome == agentrelay.OutcomeCorroboratedExpired ||
		reference.ObservedOutcome == agentrelay.OutcomeCorroboratedInvalidated
	if reference.SchemaVersion != 1 || reference.ObservationProfileURI != TOSRelayRPCObservationProfileURI ||
		reference.ObservationProfileDigest != TOSRelayRPCObservationProfileDigest() ||
		!validRelayObserverBinding(reference.Observer) || !canonicalSHA256Digest(reference.NetworkDigest) ||
		!canonicalSHA256Digest(reference.StableActionID) || !canonicalSHA256Digest(reference.ExactRequestDigest) ||
		!canonicalSHA256Digest(reference.RelayExecutionDigest) ||
		!canonicalSHA256Digest(reference.SignedTransactionDigest) ||
		!canonicalTVMCellHash(reference.SignedTransactionCellHash) || sourceErr != nil ||
		!validRelayCheckpointIdentifier(reference.FinalizedCheckpointID) || reference.FinalizedCheckpointSequence == 0 ||
		!validRelayCheckpointIdentifier(reference.DepthAnchorCheckpointID) || reference.DepthAnchorCheckpointSequence == 0 ||
		reference.DepthAnchorCheckpointSequence > reference.FinalizedCheckpointSequence ||
		confirmationDepth > uint64(^uint32(0)) || reference.ConfirmationDepth != uint32(confirmationDepth) ||
		!terminalOutcome || reference.ObservedAtUnix == 0 ||
		success && (!validRelayEvidenceReference(reference.SourceExecutionReference) ||
			!canonicalSHA256Digest(reference.DestinationCreditReference)) ||
		!success && (reference.SourceExecutionReference != "" || reference.DestinationCreditReference != "") {
		return "", errors.New("invalid TOS relay RPC observation reference")
	}
	return codec.Digest("tos.agent-relay-rpc-observation-reference.v1", reference)
}

func validRelayCheckpointIdentifier(value string) bool {
	return len(value) > len("tos-masterchain:") && len(value) <= 1024 &&
		strings.HasPrefix(value, "tos-masterchain:") && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func validRelayEvidenceReference(value string) bool {
	return len(value) > 0 && len(value) <= 1024 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func canonicalTVMCellHash(value string) bool {
	if !strings.HasPrefix(value, "tvm-cell-sha256:") || len(value) != len("tvm-cell-sha256:")+64 ||
		value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "tvm-cell-sha256:"))
	return err == nil && len(raw) == 32
}

func validRelayObserverBinding(binding TOSRelayObserverBinding) bool {
	return validRelayAgentIdentifier(binding.ObserverID) && validRelayAgentIdentifier(binding.OperatorDomainID) &&
		canonicalSHA256Digest(binding.EndpointAuthorityDigest)
}

type tosRelayCheckpointQuorumFinalityDescriptor struct {
	ProfileURI               string                           `json:"profile_uri"`
	NetworkDigest            string                           `json:"network_digest"`
	ObservationProfileURI    string                           `json:"observation_profile_uri"`
	ObservationProfileDigest string                           `json:"observation_profile_digest"`
	Observers                []TOSRelayObserverBinding        `json:"observers"`
	MinimumConfirmationDepth uint32                           `json:"minimum_confirmation_depth"`
	MinimumObservers         uint16                           `json:"minimum_observers"`
	MinimumOperatorDomains   uint16                           `json:"minimum_operator_domains"`
	ReorgWindowSeconds       uint32                           `json:"reorg_window_seconds"`
	MaximumResolutionSeconds uint32                           `json:"maximum_resolution_seconds"`
	ValidatorSignedProofs    bool                             `json:"validator_signed_proofs"`
	TerminalEvidenceClass    agentrelay.TerminalEvidenceClass `json:"terminal_evidence_class"`
}

// TOSRelayCheckpointQuorumFinalityProfile freezes the exact owner-pinned RPC
// corroboration policy into the profile digest. ValidatorSignedProofs is false
// because the current RPC surface does not provide them; clients that require
// cryptographically portable finality must reject this profile.
func TOSRelayCheckpointQuorumFinalityProfile(network agentrelay.NetworkDomain,
	observers []TOSRelayObserverBinding, minimumConfirmationDepth uint32, minimumObservers,
	minimumOperatorDomains uint16, reorgWindowSeconds, maximumResolutionSeconds uint32) (agentrelay.FinalityProfile, error) {
	var zero agentrelay.FinalityProfile
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil || len(observers) < 3 || len(observers) > 8 || minimumConfirmationDepth == 0 ||
		minimumObservers <= uint16(len(observers)/2) || int(minimumObservers) > len(observers) ||
		minimumOperatorDomains == 0 || minimumOperatorDomains > minimumObservers ||
		maximumResolutionSeconds == 0 || maximumResolutionSeconds > 24*60*60 ||
		reorgWindowSeconds > maximumResolutionSeconds {
		return zero, errors.New("invalid TOS relay checkpoint-quorum finality policy")
	}
	canonical := append([]TOSRelayObserverBinding(nil), observers...)
	sort.Slice(canonical, func(left, right int) bool { return canonical[left].ObserverID < canonical[right].ObserverID })
	domains := make(map[string]struct{}, len(canonical))
	authorities := make(map[string]struct{}, len(canonical))
	previous := ""
	for _, observer := range canonical {
		if !validRelayObserverBinding(observer) || observer.ObserverID <= previous {
			return zero, errors.New("invalid or duplicate TOS relay observer binding")
		}
		previous = observer.ObserverID
		if _, duplicate := authorities[observer.EndpointAuthorityDigest]; duplicate {
			return zero, errors.New("TOS relay finality policy repeats an endpoint authority")
		}
		authorities[observer.EndpointAuthorityDigest] = struct{}{}
		domains[observer.OperatorDomainID] = struct{}{}
	}
	if len(domains) < int(minimumOperatorDomains) {
		return zero, errors.New("TOS relay finality policy lacks independent operator domains")
	}
	descriptor := tosRelayCheckpointQuorumFinalityDescriptor{ProfileURI: TOSRelayProviderCorroboratedTerminalProfileURI,
		NetworkDigest: networkDigest, ObservationProfileURI: TOSRelayRPCObservationProfileURI,
		ObservationProfileDigest: TOSRelayRPCObservationProfileDigest(), Observers: canonical,
		MinimumConfirmationDepth: minimumConfirmationDepth, MinimumObservers: minimumObservers,
		MinimumOperatorDomains: minimumOperatorDomains, ReorgWindowSeconds: reorgWindowSeconds,
		MaximumResolutionSeconds: maximumResolutionSeconds, ValidatorSignedProofs: false,
		TerminalEvidenceClass: agentrelay.RelayTerminalProviderCorroborated}
	digest, err := codec.Digest("tos.agent-relay-checkpoint-quorum-finality-profile.v1", descriptor)
	if err != nil {
		return zero, err
	}
	return agentrelay.FinalityProfile{ProfileURI: TOSRelayProviderCorroboratedTerminalProfileURI,
		ProfileDigest: digest, TerminalEvidenceClass: agentrelay.RelayTerminalProviderCorroborated,
		MinimumConfirmationDepth: minimumConfirmationDepth,
		MinimumObservers:         minimumObservers, MinimumOperatorDomains: minimumOperatorDomains,
		ReorgWindowSeconds: reorgWindowSeconds, MaximumResolutionSeconds: maximumResolutionSeconds}, nil
}

type exactAgentNativeSendCheckpointReader interface {
	ObserveExactAgentNativeSend(context.Context, agentrelay.Record) (tosExactRelayObservation, error)
}

type tosExactRelayObservation struct {
	CheckpointID                  string
	CheckpointSequence            uint64
	DepthAnchorCheckpointID       string
	DepthAnchorCheckpointSequence uint64
	ObservedAtUnix                uint64
	Outcome                       agentrelay.TerminalOutcome
	SafeToRebroadcastExact        bool
	TransactionReference          string
	SourceExecutionReference      string
	DestinationCreditReference    string
	AgreedObserverIndexes         []int
}

// TOSExactRelayResolutionSource is the concrete query-before-retry resolver
// used by TOSExactRelayBroadcaster. It never calls a write RPC and it never
// upgrades a sendBocReturnHash acknowledgement to finality.
type TOSExactRelayResolutionSource struct {
	reader     exactAgentNativeSendCheckpointReader
	network    agentrelay.NetworkDomain
	observers  []TOSRelayObserverBinding
	quorum     int
	checkpoint *tosRelayCheckpointFence
	evidence   *tosRelayObservationStore
}

func NewTOSExactRelayResolutionSource(reader *AgentGiftReader,
	accounts *AgentGiftFinalizedAgentAccountResolver, network agentrelay.NetworkDomain,
	observers []TOSRelayObserverBinding, checkpointPath string) (*TOSExactRelayResolutionSource, error) {
	if reader == nil || accounts == nil || accounts.reader != reader || accounts.network != network ||
		reader.chain == nil || len(observers) != len(reader.chain.nodes) {
		return nil, errors.New("invalid TOS exact relay resolution configuration")
	}
	for index, observer := range observers {
		digest, err := reader.chain.nodes[index].client.EndpointAuthorityDigest()
		if err != nil || observer.EndpointAuthorityDigest != digest {
			return nil, errors.New("TOS relay observer provenance is not bound to the configured endpoint")
		}
	}
	chainReader := &agentGiftExactRelayCheckpointReader{reader: reader, accounts: accounts, network: network}
	return newTOSExactRelayResolutionSource(chainReader, network, observers, reader.chain.quorum, checkpointPath)
}

func newTOSExactRelayResolutionSource(reader exactAgentNativeSendCheckpointReader,
	network agentrelay.NetworkDomain, observers []TOSRelayObserverBinding, quorum int,
	checkpointPath string) (*TOSExactRelayResolutionSource, error) {
	if reader == nil || len(observers) < 3 || quorum <= len(observers)/2 || quorum > len(observers) {
		return nil, errors.New("TOS exact relay resolution requires a reader and at least three observers")
	}
	if _, err := agentrelay.NetworkDomainDigest(network); err != nil {
		return nil, errors.New("TOS exact relay resolution network is invalid")
	}
	seenObservers := make(map[string]struct{}, len(observers))
	seenAuthorities := make(map[string]struct{}, len(observers))
	for _, observer := range observers {
		if !validRelayObserverBinding(observer) {
			return nil, errors.New("TOS relay observer binding is invalid")
		}
		if _, duplicate := seenObservers[observer.ObserverID]; duplicate {
			return nil, errors.New("TOS relay observer identity is duplicated")
		}
		if _, duplicate := seenAuthorities[observer.EndpointAuthorityDigest]; duplicate {
			return nil, errors.New("TOS relay endpoint authority is duplicated")
		}
		seenObservers[observer.ObserverID] = struct{}{}
		seenAuthorities[observer.EndpointAuthorityDigest] = struct{}{}
	}
	fence, err := newTOSRelayCheckpointFence(checkpointPath)
	if err != nil {
		return nil, err
	}
	evidence, err := newTOSRelayObservationStore(filepath.Dir(checkpointPath))
	if err != nil {
		return nil, err
	}
	return &TOSExactRelayResolutionSource{reader: reader, network: network,
		observers: append([]TOSRelayObserverBinding(nil), observers...), quorum: quorum,
		checkpoint: fence, evidence: evidence}, nil
}

// Observation returns the exact durable body behind an evidence reference.
// Consumers must still apply the documented evidence profile and must not
// reinterpret this Provider-side RPC record as a validator-signed proof.
func (source *TOSExactRelayResolutionSource) Observation(referenceDigest string) (TOSRelayRPCObservationReference, error) {
	if source == nil || source.evidence == nil {
		return TOSRelayRPCObservationReference{}, errors.New("TOS relay observation evidence is unavailable")
	}
	return source.evidence.get(referenceDigest)
}

// SupportsRelayEvidenceCapability reports only the exact lower-assurance TOS
// tuple implemented by this RPC-corroboration source. Empty action kinds are
// never wildcards and this local source never claims autonomous finality.
func (source *TOSExactRelayResolutionSource) SupportsRelayEvidenceCapability(
	capability agentrelay.RelayEvidenceCapability) bool {
	if source == nil || capability.Mode != agentrelay.ModeRelayExact ||
		capability.Network != source.network ||
		capability.TransactionProfileURI != AgentAccountNativeSendRelayProfileURI ||
		capability.TransactionProfileDigest != AgentAccountNativeSendRelayProfileDigest() ||
		capability.UnderlyingActionKind != "payment.direct" ||
		capability.AssuranceLevel == agentrelay.AssuranceAutonomousDecentralized {
		return false
	}
	if capability.RelayTerminalEvidenceClass != agentrelay.RelayTerminalProviderCorroborated ||
		capability.RelayFinalityProfile == nil {
		return false
	}
	profile := capability.RelayFinalityProfile
	expected, err := TOSRelayCheckpointQuorumFinalityProfile(source.network, source.observers,
		profile.MinimumConfirmationDepth, profile.MinimumObservers, profile.MinimumOperatorDomains,
		profile.ReorgWindowSeconds, profile.MaximumResolutionSeconds)
	if err != nil || *profile != expected || int(profile.MinimumObservers) < source.quorum {
		return false
	}
	return capability.SponsorshipTerminalEvidenceClass == "" &&
		capability.SponsorshipTerminalProfile == nil &&
		capability.SponsorshipReleaseProfile == (agentrelay.SponsorshipReleaseProfile{})
}

// SupportsRelayEvidenceRendering reports whether this source can render an
// already-terminal, protocol-validated journal record for the exact lower
// TOS tuple. It is deliberately separate from SupportsRelayEvidenceCapability:
// rendering component evidence does not mean this source can produce or
// independently verify sponsorship/absence evidence. A composite runtime must
// conjunct this renderer with the concrete sponsorship producer and client
// verifier capabilities before advertising a sponsorship pair.
func (source *TOSExactRelayResolutionSource) SupportsRelayEvidenceRendering(
	capability agentrelay.RelayEvidenceCapability) bool {
	if source == nil || capability.Network != source.network ||
		capability.TransactionProfileURI != AgentAccountNativeSendRelayProfileURI ||
		capability.TransactionProfileDigest != AgentAccountNativeSendRelayProfileDigest() ||
		capability.UnderlyingActionKind != "payment.direct" ||
		(capability.AssuranceLevel != agentrelay.AssuranceTrustedLocal &&
			capability.AssuranceLevel != agentrelay.AssuranceAuthorizedSingleProvider) {
		return false
	}
	if capability.Mode == agentrelay.ModeRelayExact {
		return source.SupportsRelayEvidenceCapability(capability)
	}
	if capability.Mode != agentrelay.ModeSponsorOnly && capability.Mode != agentrelay.ModeSponsorAndRelay ||
		capability.SponsorshipReleaseProfile.EvidenceClass != agentrelay.SponsorshipReleaseObservedUnproven ||
		capability.SponsorshipReleaseProfile.ProfileURI != agentrelay.RPCCorroborationEvidenceProfileURI ||
		!canonicalSHA256Digest(capability.SponsorshipReleaseProfile.ProfileDigest) ||
		capability.SponsorshipTerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		capability.SponsorshipTerminalProfile == nil ||
		capability.SponsorshipTerminalProfile.ProfileURI != agentrelay.ClientCorroboratedTerminalProfileURI ||
		capability.SponsorshipTerminalProfile.TerminalEvidenceClass !=
			agentrelay.SponsorshipTerminalClientCorroborated {
		return false
	}
	if capability.Mode == agentrelay.ModeSponsorOnly {
		return capability.RelayTerminalEvidenceClass == "" && capability.RelayFinalityProfile == nil
	}
	relayOnly := capability
	relayOnly.Mode = agentrelay.ModeRelayExact
	relayOnly.SponsorshipTerminalEvidenceClass = ""
	relayOnly.SponsorshipTerminalProfile = nil
	relayOnly.SponsorshipReleaseProfile = agentrelay.SponsorshipReleaseProfile{}
	relayOnly.AbsenceProofProfileURI = ""
	relayOnly.AbsenceProofProfileDigest = ""
	return source.SupportsRelayEvidenceCapability(relayOnly)
}

// The current source can verify and archive exact relay observations, but the
// provider-side sponsorship absence resolver has not supplied retrievable
// typed dual-absence bodies through this store. It therefore cannot advertise
// sponsorship readiness yet, even though positive sponsorship evidence can be
// rendered for an already terminal record.
func (source *TOSExactRelayResolutionSource) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return false
}

// SupportsRelaySponsorshipComponentAbsenceEvidence remains false for this
// in-process RPC resolver.  The stock component-absence implementation is the
// snapshot-bound tosctl producer/verifier pair: advertising it here would let
// callers skip the independent client re-query and accept Provider-local
// observations as terminal evidence.
func (*TOSExactRelayResolutionSource) SupportsRelaySponsorshipComponentAbsenceEvidence(
	agentrelay.RelayEvidenceCapability) bool {
	return false
}

// SupportsRelayTransactionComponentAbsenceEvidence remains false for the same
// reason.  Combined-mode readiness is exposed only by the adapter that has all
// three concrete tosctl proof scopes wired (sponsorship, transaction, and
// dual), never by command presence or by this observation store alone.
func (*TOSExactRelayResolutionSource) SupportsRelayTransactionComponentAbsenceEvidence(
	agentrelay.RelayEvidenceCapability) bool {
	return false
}

// The current three-node RPC corroboration profile stores local observation
// records; it does not expose a portable validator-authenticated proof bundle.
func (source *TOSExactRelayResolutionSource) HasRetrievableIndependentProofs() bool { return false }

// Its checkpoint high-water file is owner-private and can be restored from an
// old snapshot. A production implementation must inject monotonic CAS storage
// shared with custody or Action Authority before returning true here.
func (source *TOSExactRelayResolutionSource) HasRollbackResistantCheckpoint() bool { return false }

// The local development journal does not atomically anchor the signed
// evidence digest and signing-key epoch in rollback-resistant authority state.
func (source *TOSExactRelayResolutionSource) HasRollbackResistantTerminalCommitment() bool {
	return false
}

// Evidence constructs the Provider's signed-evidence body exclusively from a
// terminal journal record and the exact durable RPC observations whose digests
// the record already contains. It performs no moving-head query and cannot
// replace an observation after the economic state became terminal.
//
// The returned profile remains explicitly RPC-checkpoint corroboration, not a
// validator-signed proof. ProviderService signs this body for transport, but
// that signature does not upgrade its finality class.
func (source *TOSExactRelayResolutionSource) Evidence(ctx context.Context,
	record agentrelay.Record) (agentrelay.RelayFinalityEvidenceBody, error) {
	var zero agentrelay.RelayFinalityEvidenceBody
	if source == nil || source.evidence == nil || source.checkpoint == nil || ctx == nil {
		return zero, errors.New("TOS relay finality evidence source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if record.State != agentcommerce.ActionTerminal || len(record.EvidenceRefs) == 0 ||
		(record.TerminalOutcome != agentrelay.OutcomeCorroboratedSuccess &&
			record.TerminalOutcome != agentrelay.OutcomeCorroboratedRelayOnly &&
			record.TerminalOutcome != agentrelay.OutcomeCorroboratedExpired &&
			record.TerminalOutcome != agentrelay.OutcomeCorroboratedAbsent &&
			record.TerminalOutcome != agentrelay.OutcomeCorroboratedInvalidated &&
			record.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly) {
		return zero, errors.New("terminal TOS relay evidence is unavailable for this outcome")
	}
	request := record.ExecutionRequest()
	quoted := request.QuoteRequest.Body
	if quoted.Network != source.network || quoted.TransactionProfileURI != AgentAccountNativeSendRelayProfileURI ||
		quoted.TransactionProfileDigest != AgentAccountNativeSendRelayProfileDigest() ||
		request.AuthorizedAction.ActionKind != "payment.direct" ||
		record.StableActionID != request.AuthorizedAction.StableActionID ||
		record.ExactRequestDigest != request.AuthorizedAction.ExactRequestDigest {
		return zero, errors.New("terminal record is not a supported TOS Agent Account relay")
	}
	if record.SponsorshipStableActionID != "" && (record.SponsorshipExactRequestDigest == "" ||
		record.SponsorshipValidUntilUnix == 0) {
		return zero, errors.New("TOS relay evidence has an incomplete sponsorship identity")
	}
	hasSponsorshipAbsence := len(record.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(record.TransactionAbsenceObservations) != 0
	if record.SponsorshipStableActionID != "" && record.SponsorshipTransferReference == "" &&
		record.TerminalOutcome != agentrelay.OutcomeCorroboratedRelayOnly {
		return source.sponsorshipAbsenceEvidence(record)
	}
	if record.TerminalOutcome == agentrelay.OutcomeCorroboratedSponsorshipOnly {
		return source.sponsorshipOnlyEvidence(record, request.ProviderQuote.Body.SponsorshipTerminalProfile)
	}
	profile := request.ProviderQuote.Body.RelayFinalityProfile
	if profile == nil {
		return zero, errors.New("terminal relay record lacks its selected relay profile")
	}
	expectedProfile, err := TOSRelayCheckpointQuorumFinalityProfile(source.network, source.observers,
		profile.MinimumConfirmationDepth, profile.MinimumObservers, profile.MinimumOperatorDomains,
		profile.ReorgWindowSeconds, profile.MaximumResolutionSeconds)
	if err != nil || *profile != expectedProfile || int(profile.MinimumObservers) < source.quorum {
		return zero, errors.New("terminal record uses an unsupported TOS checkpoint-quorum finality profile")
	}
	var first TOSRelayRPCObservationReference
	loaded := 0
	relayObservationDigests := make([]string, 0, len(record.EvidenceRefs))
	observerIDs := make(map[string]struct{}, len(source.observers))
	operatorDomains := make(map[string]struct{}, len(source.observers))
	for _, digest := range record.EvidenceRefs {
		reference, readErr := source.evidence.get(digest)
		if errors.Is(readErr, os.ErrNotExist) {
			// Combined mode may also contain exact sponsorship-payment evidence
			// owned by that payment Adapter. It remains in ObservationDigests but
			// is not relabelled as a relay RPC observation.
			continue
		}
		if readErr != nil {
			return zero, readErr
		}
		actualDigest, digestErr := TOSRelayRPCObservationReferenceDigest(reference)
		if digestErr != nil || actualDigest != digest ||
			reference.NetworkDigest != record.NetworkDigest ||
			reference.StableActionID != record.StableActionID ||
			reference.ExactRequestDigest != record.ExactRequestDigest ||
			reference.RelayExecutionDigest != record.RelayExecutionDigest ||
			reference.SignedTransactionDigest != record.SignedTransactionDigest ||
			reference.SignedTransactionCellHash != quoted.SignedTransactionCellHash ||
			reference.SourceAccount != quoted.SourceAccount || reference.SourceSequence != quoted.SourceSequence ||
			reference.ObservedOutcome != relayObservationOutcomeForRecord(record.TerminalOutcome) ||
			!source.hasObserverBinding(reference.Observer) {
			return zero, errors.New("durable TOS relay observation conflicts with the terminal record")
		}
		if loaded == 0 {
			first = reference
		} else if reference.FinalizedCheckpointID != first.FinalizedCheckpointID ||
			reference.FinalizedCheckpointSequence != first.FinalizedCheckpointSequence ||
			reference.DepthAnchorCheckpointID != first.DepthAnchorCheckpointID ||
			reference.DepthAnchorCheckpointSequence != first.DepthAnchorCheckpointSequence ||
			reference.ConfirmationDepth != first.ConfirmationDepth ||
			reference.SourceExecutionReference != first.SourceExecutionReference ||
			reference.DestinationCreditReference != first.DestinationCreditReference ||
			reference.ObservedAtUnix != first.ObservedAtUnix {
			return zero, errors.New("terminal TOS relay observations disagree")
		}
		if _, duplicate := observerIDs[reference.Observer.ObserverID]; duplicate {
			return zero, errors.New("terminal TOS relay evidence repeats an observer")
		}
		observerIDs[reference.Observer.ObserverID] = struct{}{}
		operatorDomains[reference.Observer.OperatorDomainID] = struct{}{}
		relayObservationDigests = append(relayObservationDigests, digest)
		loaded++
	}
	if loaded < int(profile.MinimumObservers) || len(operatorDomains) < int(profile.MinimumOperatorDomains) {
		return zero, errors.New("terminal TOS relay evidence no longer meets its corroboration threshold")
	}
	// This is an immutable historical read. The observation store's digest and
	// the terminal journal binding authenticate the exact archived checkpoint.
	// Comparing it with today's moving high-water would incorrectly reject old
	// valid evidence after any newer action advances the fence. Only a newly
	// observed chain checkpoint in ResolveExactRelay may advance monotonic CAS.
	body := agentrelay.RelayFinalityEvidenceBody{SchemaVersion: 1,
		ProviderAgentID: record.ProviderAgentID, Network: source.network, AssuranceLevel: quoted.AssuranceLevel,
		StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		RelayExecutionDigest: record.RelayExecutionDigest, SignedTransactionDigest: record.SignedTransactionDigest,
		SignedTransactionCellHash: quoted.SignedTransactionCellHash,
		TransactionValidUntilUnix: quoted.TransactionValidUntilUnix, SourceAccount: quoted.SourceAccount,
		SourceSequence: quoted.SourceSequence, SponsorshipStableActionID: record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest:            record.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:                record.SponsorshipValidUntilUnix,
		SponsorshipTransferReference:             record.SponsorshipTransferReference,
		RelayTerminalEvidenceClass:               agentrelay.RelayTerminalProviderCorroborated,
		RelayValidatorAuthenticatedPortableProof: false,
		RelayFinalizedCheckpointID:               first.FinalizedCheckpointID,
		RelayFinalizedCheckpointSequence:         first.FinalizedCheckpointSequence,
		RelayFinalizedCheckpointUnix:             first.ObservedAtUnix,
		RelayConfirmationDepth:                   first.ConfirmationDepth,
		RelayFinalityProfile:                     profile,
		RelayObservationDigests:                  relayObservationDigests,
		Outcome:                                  record.TerminalOutcome, ObservedAtUnix: first.ObservedAtUnix}
	if quoted.Mode == agentrelay.ModeSponsorAndRelay {
		body.SponsorshipTerminalProfile = request.ProviderQuote.Body.SponsorshipTerminalProfile
		switch record.TerminalOutcome {
		case agentrelay.OutcomeCorroboratedRelayOnly:
			if record.SponsorshipTransactionEvidence != nil || record.SponsorshipTransferReference != "" ||
				!hasSponsorshipAbsence || hasTransactionAbsence {
				return zero, errors.New("relay-only terminal record has inconsistent sponsorship component evidence")
			}
		case agentrelay.OutcomeCorroboratedSuccess:
			if record.SponsorshipTransactionEvidence == nil ||
				request.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
				return zero, errors.New("combined terminal record lacks exact sponsorship transaction evidence")
			}
			sponsorship := *record.SponsorshipTransactionEvidence
			body.SponsorshipTransactionEvidence = &sponsorship
		default:
			return zero, errors.New("combined relay-positive record has an unsupported component outcome")
		}
	}
	if record.TerminalOutcome == agentrelay.OutcomeCorroboratedSuccess ||
		record.TerminalOutcome == agentrelay.OutcomeCorroboratedRelayOnly {
		if record.TransactionReference != quoted.SignedTransactionCellHash ||
			first.SourceExecutionReference == "" || !canonicalSHA256Digest(first.DestinationCreditReference) {
			return zero, errors.New("successful terminal TOS relay record lacks exact value-effect evidence")
		}
		body.SubmittedTransactionHash = record.TransactionReference
		body.SourceExecutionReference = first.SourceExecutionReference
		body.DestinationCreditReferences = []string{first.DestinationCreditReference}
	} else if record.TransactionReference != "" || first.SourceExecutionReference != "" ||
		first.DestinationCreditReference != "" {
		return zero, errors.New("unsuccessful terminal TOS relay record contains success references")
	}
	if hasSponsorshipAbsence || hasTransactionAbsence {
		if err := attachRecordAbsenceEvidence(&body, record); err != nil {
			return zero, err
		}
		for _, reference := range append(append([]agentrelay.RelayAbsenceObservationReference(nil),
			record.SponsorshipAbsenceObservations...), record.TransactionAbsenceObservations...) {
			if reference.ObservedAtUnix > body.ObservedAtUnix {
				body.ObservedAtUnix = reference.ObservedAtUnix
			}
		}
	}
	return body, nil
}

func relayObservationOutcomeForRecord(outcome agentrelay.TerminalOutcome) agentrelay.TerminalOutcome {
	if outcome == agentrelay.OutcomeCorroboratedRelayOnly {
		return agentrelay.OutcomeCorroboratedSuccess
	}
	return outcome
}

func (source *TOSExactRelayResolutionSource) sponsorshipAbsenceEvidence(
	record agentrelay.Record) (agentrelay.RelayFinalityEvidenceBody, error) {
	var zero agentrelay.RelayFinalityEvidenceBody
	request := record.ExecutionRequest()
	quoted := request.QuoteRequest.Body
	hasSponsorshipAbsence := len(record.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(record.TransactionAbsenceObservations) != 0
	validScope := quoted.Mode == agentrelay.ModeSponsorOnly && hasSponsorshipAbsence && !hasTransactionAbsence ||
		quoted.Mode == agentrelay.ModeSponsorAndRelay && hasSponsorshipAbsence && hasTransactionAbsence
	if !validScope || request.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
		len(record.SponsorshipAbsenceObservationDigests) == 0 ||
		hasTransactionAbsence != (len(record.TransactionAbsenceObservationDigests) != 0) {
		return zero, errors.New("terminal TOS sponsorship absence lacks its durable typed observations")
	}
	observedAt := record.UpdatedAtUnix
	for _, reference := range append(append([]agentrelay.RelayAbsenceObservationReference(nil),
		record.SponsorshipAbsenceObservations...), record.TransactionAbsenceObservations...) {
		if reference.ObservedAtUnix > observedAt {
			observedAt = reference.ObservedAtUnix
		}
	}
	body := agentrelay.RelayFinalityEvidenceBody{SchemaVersion: 1,
		ProviderAgentID: record.ProviderAgentID, Network: source.network, AssuranceLevel: quoted.AssuranceLevel,
		StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		RelayExecutionDigest: record.RelayExecutionDigest, SignedTransactionDigest: record.SignedTransactionDigest,
		SignedTransactionCellHash: quoted.SignedTransactionCellHash,
		TransactionValidUntilUnix: quoted.TransactionValidUntilUnix, SourceAccount: quoted.SourceAccount,
		SourceSequence: quoted.SourceSequence, SponsorshipStableActionID: record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: record.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:     record.SponsorshipValidUntilUnix,
		SponsorshipAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			record.SponsorshipAbsenceObservations...),
		TransactionAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil),
			record.TransactionAbsenceObservations...),
		SponsorshipTerminalProfile: request.ProviderQuote.Body.SponsorshipTerminalProfile,
		Outcome:                    record.TerminalOutcome, ObservedAtUnix: observedAt}
	if err := attachRecordAbsenceEvidence(&body, record); err != nil {
		return zero, err
	}
	if quoted.Mode == agentrelay.ModeSponsorAndRelay {
		body.RelayFinalityProfile = request.ProviderQuote.Body.RelayFinalityProfile
	}
	return body, nil
}

func attachRecordAbsenceEvidence(body *agentrelay.RelayFinalityEvidenceBody,
	record agentrelay.Record) error {
	if body == nil || record.AbsenceProofBundleDigest == "" || len(record.AbsenceProofBundle) == 0 {
		return errors.New("terminal TOS component absence lacks its exact proof bundle")
	}
	digest, err := agentrelay.RelayAbsenceProofBundleDigest(record.AbsenceProofBundle)
	if err != nil || digest != record.AbsenceProofBundleDigest {
		return errors.New("terminal TOS component absence proof bundle digest is inconsistent")
	}
	body.SponsorshipAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil),
		record.SponsorshipAbsenceObservations...)
	body.TransactionAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil),
		record.TransactionAbsenceObservations...)
	body.AbsenceProofBundleDigest = record.AbsenceProofBundleDigest
	body.AbsenceProofBundle = append([]byte(nil), record.AbsenceProofBundle...)
	return nil
}

func (source *TOSExactRelayResolutionSource) sponsorshipOnlyEvidence(record agentrelay.Record,
	profile *agentrelay.FinalityProfile) (agentrelay.RelayFinalityEvidenceBody, error) {
	var zero agentrelay.RelayFinalityEvidenceBody
	request := record.ExecutionRequest()
	quoted := request.QuoteRequest.Body
	if record.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly ||
		record.SponsorshipTransactionEvidence == nil || record.SponsorshipTransferReference == "" || profile == nil {
		return zero, errors.New("sponsor-only terminal record lacks exact sponsorship transaction evidence")
	}
	sponsorship := *record.SponsorshipTransactionEvidence
	if sponsorship.SubmittedTransactionHash != record.SponsorshipTransferReference ||
		sponsorship.SponsorshipTerminalProfileDigest != profile.ProfileDigest ||
		sponsorship.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated ||
		sponsorship.ValidatorAuthenticatedPortableProof ||
		sponsorship.ConfirmationDepth < profile.MinimumConfirmationDepth ||
		len(sponsorship.ObservationDigests) < int(profile.MinimumObservers) {
		return zero, errors.New("sponsor-only transaction evidence does not meet the selected finality profile")
	}
	body := agentrelay.RelayFinalityEvidenceBody{SchemaVersion: 1,
		ProviderAgentID: record.ProviderAgentID, Network: source.network, AssuranceLevel: quoted.AssuranceLevel,
		StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		RelayExecutionDigest: record.RelayExecutionDigest, SignedTransactionDigest: record.SignedTransactionDigest,
		SignedTransactionCellHash: quoted.SignedTransactionCellHash,
		TransactionValidUntilUnix: quoted.TransactionValidUntilUnix, SourceAccount: quoted.SourceAccount,
		SourceSequence: quoted.SourceSequence, SponsorshipStableActionID: record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest:  record.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:      record.SponsorshipValidUntilUnix,
		SponsorshipTransferReference:   record.SponsorshipTransferReference,
		SponsorshipTransactionEvidence: &sponsorship,
		SponsorshipTerminalProfile:     profile,
		Outcome:                        record.TerminalOutcome,
		ObservedAtUnix:                 sponsorship.ObservedAtUnix}
	if quoted.Mode == agentrelay.ModeSponsorAndRelay {
		body.RelayFinalityProfile = request.ProviderQuote.Body.RelayFinalityProfile
	}
	if len(record.TransactionAbsenceObservations) != 0 {
		if quoted.Mode != agentrelay.ModeSponsorAndRelay || len(record.SponsorshipAbsenceObservations) != 0 {
			return zero, errors.New("sponsorship-only terminal record has an invalid absence component scope")
		}
		if err := attachRecordAbsenceEvidence(&body, record); err != nil {
			return zero, err
		}
		for _, reference := range record.TransactionAbsenceObservations {
			if reference.ObservedAtUnix > body.ObservedAtUnix {
				body.ObservedAtUnix = reference.ObservedAtUnix
			}
		}
	}
	return body, nil
}

func (source *TOSExactRelayResolutionSource) hasObserverBinding(binding TOSRelayObserverBinding) bool {
	for _, candidate := range source.observers {
		if candidate == binding {
			return true
		}
	}
	return false
}

func (source *TOSExactRelayResolutionSource) ResolveExactRelay(ctx context.Context,
	record agentrelay.Record) (agentrelay.ChainResolution, error) {
	var zero agentrelay.ChainResolution
	if source == nil || source.reader == nil || source.checkpoint == nil || ctx == nil {
		return zero, errors.New("TOS exact relay resolution source is unavailable")
	}
	request := record.ExecutionRequest()
	if request.QuoteRequest.Body.Network != source.network ||
		request.QuoteRequest.Body.TransactionProfileURI != AgentAccountNativeSendRelayProfileURI ||
		request.QuoteRequest.Body.TransactionProfileDigest != AgentAccountNativeSendRelayProfileDigest() ||
		request.AuthorizedAction.ActionKind != "payment.direct" ||
		request.QuoteRequest.Body.Mode == agentrelay.ModeSponsorOnly {
		return zero, errors.New("relay record is not a supported TOS Agent Account payment")
	}
	observation, err := source.reader.ObserveExactAgentNativeSend(ctx, record)
	if err != nil {
		return zero, err
	}
	if observation.CheckpointSequence == 0 || observation.CheckpointID == "" ||
		observation.DepthAnchorCheckpointSequence == 0 || observation.DepthAnchorCheckpointID == "" ||
		observation.DepthAnchorCheckpointSequence > observation.CheckpointSequence ||
		observation.ObservedAtUnix == 0 {
		return zero, errors.New("TOS exact relay reader returned an invalid checkpoint")
	}
	if err := source.checkpoint.checkAndAdvance(observation.CheckpointSequence, observation.CheckpointID); err != nil {
		return zero, err
	}
	if observation.SafeToRebroadcastExact {
		if observation.Outcome != "" || observation.TransactionReference != "" ||
			observation.SourceExecutionReference != "" || observation.DestinationCreditReference != "" {
			return zero, errors.New("safe exact rebroadcast observation contains terminal data")
		}
		return agentrelay.ChainResolution{SafeToRebroadcastExact: true}, nil
	}
	observation.Outcome = tosProviderCorroboratedOutcome(observation.Outcome)
	if observation.Outcome == "" {
		return zero, nil
	}
	profile := request.ProviderQuote.Body.RelayFinalityProfile
	if profile == nil {
		return zero, errors.New("relay record lacks its selected terminal profile")
	}
	expectedProfile, err := TOSRelayCheckpointQuorumFinalityProfile(source.network, source.observers,
		profile.MinimumConfirmationDepth, profile.MinimumObservers, profile.MinimumOperatorDomains,
		profile.ReorgWindowSeconds, profile.MaximumResolutionSeconds)
	if err != nil || *profile != expectedProfile || int(profile.MinimumObservers) < source.quorum {
		return zero, errors.New("relay record selected an unsupported TOS checkpoint-quorum finality profile")
	}
	if err := validateTOSRelayObservationForProfile(observation, *profile, source.observers); err != nil {
		return zero, err
	}
	confirmationDepth := observation.CheckpointSequence - observation.DepthAnchorCheckpointSequence + 1
	indexes := append([]int(nil), observation.AgreedObserverIndexes...)
	networkDigest, err := agentrelay.NetworkDomainDigest(source.network)
	if err != nil {
		return zero, err
	}
	references := make([]string, 0, len(indexes))
	for _, index := range indexes {
		reference := TOSRelayRPCObservationReference{SchemaVersion: 1,
			ObservationProfileURI:    TOSRelayRPCObservationProfileURI,
			ObservationProfileDigest: TOSRelayRPCObservationProfileDigest(), Observer: source.observers[index],
			NetworkDigest: networkDigest, StableActionID: record.StableActionID,
			ExactRequestDigest: record.ExactRequestDigest, RelayExecutionDigest: record.RelayExecutionDigest,
			SignedTransactionDigest:   request.QuoteRequest.Body.SignedTransactionDigest,
			SignedTransactionCellHash: request.QuoteRequest.Body.SignedTransactionCellHash,
			SourceAccount:             request.QuoteRequest.Body.SourceAccount, SourceSequence: request.QuoteRequest.Body.SourceSequence,
			FinalizedCheckpointID:         observation.CheckpointID,
			FinalizedCheckpointSequence:   observation.CheckpointSequence,
			DepthAnchorCheckpointID:       observation.DepthAnchorCheckpointID,
			DepthAnchorCheckpointSequence: observation.DepthAnchorCheckpointSequence,
			ConfirmationDepth:             uint32(confirmationDepth), SourceExecutionReference: observation.SourceExecutionReference,
			DestinationCreditReference: observation.DestinationCreditReference,
			ObservedOutcome:            observation.Outcome, ObservedAtUnix: observation.ObservedAtUnix}
		digest, digestErr := source.evidence.put(reference)
		if digestErr != nil {
			return zero, digestErr
		}
		references = append(references, digest)
	}
	sort.Strings(references)
	if observation.Outcome == agentrelay.OutcomeCorroboratedSuccess {
		if observation.TransactionReference != request.QuoteRequest.Body.SignedTransactionCellHash ||
			observation.SourceExecutionReference == "" || observation.DestinationCreditReference == "" {
			return zero, errors.New("successful TOS relay observation is incomplete")
		}
	} else if observation.TransactionReference != "" || observation.SourceExecutionReference != "" ||
		observation.DestinationCreditReference != "" {
		return zero, errors.New("unsuccessful TOS relay observation contains success references")
	}
	return agentrelay.ChainResolution{State: agentcommerce.ActionTerminal,
		TransactionReference: observation.TransactionReference, EvidenceRefs: references,
		TerminalOutcome: observation.Outcome}, nil
}

func validateTOSRelayObservationForProfile(observation tosExactRelayObservation,
	profile agentrelay.FinalityProfile, observers []TOSRelayObserverBinding) error {
	if observation.CheckpointSequence == 0 || observation.DepthAnchorCheckpointSequence == 0 ||
		observation.DepthAnchorCheckpointSequence > observation.CheckpointSequence ||
		observation.CheckpointID == "" || observation.DepthAnchorCheckpointID == "" {
		return errors.New("TOS exact relay observation has an invalid checkpoint range")
	}
	confirmationDepth := observation.CheckpointSequence - observation.DepthAnchorCheckpointSequence + 1
	if confirmationDepth > uint64(^uint32(0)) || uint32(confirmationDepth) < profile.MinimumConfirmationDepth {
		return errors.New("TOS exact relay observation does not meet confirmation depth")
	}
	indexes := observation.AgreedObserverIndexes
	if len(indexes) < int(profile.MinimumObservers) {
		return errors.New("TOS exact relay observation does not meet observer threshold")
	}
	operatorDomains := make(map[string]struct{}, len(indexes))
	previous := -1
	for _, index := range indexes {
		if index <= previous || index < 0 || index >= len(observers) {
			return errors.New("TOS exact relay observation contains invalid observer indexes")
		}
		previous = index
		operatorDomains[observers[index].OperatorDomainID] = struct{}{}
	}
	if len(operatorDomains) < int(profile.MinimumOperatorDomains) {
		return errors.New("TOS exact relay observation does not meet operator-domain threshold")
	}
	return nil
}

func tosProviderCorroboratedOutcome(outcome agentrelay.TerminalOutcome) agentrelay.TerminalOutcome {
	switch outcome {
	case agentrelay.OutcomeFinalizedSuccess:
		return agentrelay.OutcomeCorroboratedSuccess
	case agentrelay.OutcomeFinalizedExpired:
		return agentrelay.OutcomeCorroboratedExpired
	case agentrelay.OutcomeFinalizedAbsent:
		return agentrelay.OutcomeCorroboratedAbsent
	case agentrelay.OutcomeFinalizedInvalidated:
		return agentrelay.OutcomeCorroboratedInvalidated
	default:
		return outcome
	}
}

var _ ExactRelayResolutionSource = (*TOSExactRelayResolutionSource)(nil)
var _ agentrelay.FinalityEvidenceSource = (*TOSExactRelayResolutionSource)(nil)
var _ agentrelay.IndependentFinalityEvidenceSource = (*TOSExactRelayResolutionSource)(nil)

type agentGiftExactRelayCheckpointReader struct {
	reader   *AgentGiftReader
	accounts *AgentGiftFinalizedAgentAccountResolver
	network  agentrelay.NetworkDomain
}

type relayNodeCandidate struct {
	AccountFound               bool   `json:"account_found"`
	CurrentAuthorityDigest     string `json:"current_authority_digest"`
	CurrentControllerEpoch     uint64 `json:"current_controller_epoch"`
	CurrentSequence            uint32 `json:"current_sequence"`
	CurrentLastTransactionTime uint64 `json:"current_last_transaction_time"`
	ExactExternalFound         bool   `json:"exact_external_found"`
	ExactExternalExecuted      bool   `json:"exact_external_executed"`
	ExecutionAbsenceKnown      bool   `json:"execution_absence_known"`
	ExactOutput                bool   `json:"exact_output"`
	DestinationCreditKnown     bool   `json:"destination_credit_known"`
	ExactDestinationCredit     bool   `json:"exact_destination_credit"`
	SourceExecutionReference   string `json:"source_execution_reference"`
	DestinationCreditReference string `json:"destination_credit_reference"`
	ExecutionTime              uint32 `json:"execution_time"`
}

type relayNodeVote struct {
	CheckpointID string             `json:"checkpoint_id"`
	Candidate    relayNodeCandidate `json:"candidate"`
}

func (reader *agentGiftExactRelayCheckpointReader) ObserveExactAgentNativeSend(ctx context.Context,
	record agentrelay.Record) (tosExactRelayObservation, error) {
	return reader.observeExactAgentNativeSendRequest(ctx, record.ExecutionRequest())
}

// observeExactAgentNativeSendRequest is shared by the Provider's
// query-before-retry resolver and the client's independently configured
// finality verifier.  The latter never needs access to Provider journal state:
// every chain predicate is derived from the immutable execution envelope.
func (reader *agentGiftExactRelayCheckpointReader) observeExactAgentNativeSendRequest(ctx context.Context,
	request agentrelay.RelayExecutionRequest) (tosExactRelayObservation, error) {
	var zero tosExactRelayObservation
	if reader == nil || reader.reader == nil || reader.reader.chain == nil || reader.accounts == nil || ctx == nil {
		return zero, errors.New("Agent Gift exact relay reader is unavailable")
	}
	quoted := request.QuoteRequest.Body
	if quoted.Network != reader.network || quoted.TransactionProfileURI != AgentAccountNativeSendRelayProfileURI ||
		quoted.TransactionProfileDigest != AgentAccountNativeSendRelayProfileDigest() ||
		request.AuthorizedAction.ActionKind != "payment.direct" || quoted.Mode == agentrelay.ModeSponsorOnly {
		return zero, errors.New("unsupported exact Agent Account relay record")
	}
	parsed, err := agentgift.ParseAgentNativeSendBOC(request.SignedTransactionBytes)
	if err != nil || parsed.SenderAgentAccount != quoted.SourceAccount || uint64(parsed.Seqno) != quoted.SourceSequence ||
		uint64(parsed.ValidUntil) != quoted.TransactionValidUntilUnix || parsed.GlobalID != reader.network.GlobalID {
		return zero, errors.New("exact Agent Account relay BOC conflicts with the journal record")
	}
	payloadDigest, err := agentrelay.SignedTransactionDigest(request.SignedTransactionBytes)
	root, rootErr := cell.FromBOC(request.SignedTransactionBytes)
	transactionReference := ""
	if rootErr == nil {
		transactionReference = fmt.Sprintf("tvm-cell-sha256:%x", root.Hash())
	}
	if err != nil || payloadDigest != quoted.SignedTransactionDigest || rootErr != nil ||
		!bytes.Equal(request.SignedTransactionBytes, root.ToBOCWithFlags(false)) ||
		transactionReference != quoted.SignedTransactionCellHash {
		return zero, errors.New("exact Agent Account relay bytes conflict with the signed descriptor")
	}
	binding, err := reader.accounts.binding(parsed.SenderAgentAccount)
	if err != nil {
		return zero, err
	}
	current, nodes, err := reader.reader.chain.consensus(ctx)
	if err != nil {
		return zero, err
	}
	currentVote, currentNodes, err := quorumRead(ctx, nodes, reader.reader.chain.quorum,
		func(ctx context.Context, node *rpcNode) (relayNodeVote, error) {
			return reader.observeNodeAt(ctx, node, current, binding, parsed, request)
		})
	if err != nil {
		return zero, fmt.Errorf("resolve exact Agent Account relay at finalized checkpoint: %w", err)
	}
	outcome, safe := classifyExactRelayCandidate(currentVote.Candidate, quoted, request, current.observedAt)
	if outcome == "" && !safe {
		return zero, nil
	}
	if safe {
		return tosExactRelayObservation{CheckpointID: currentVote.CheckpointID,
			CheckpointSequence: current.seqno, DepthAnchorCheckpointID: currentVote.CheckpointID,
			DepthAnchorCheckpointSequence: current.seqno, ObservedAtUnix: uint64(current.observedAt.Unix()),
			SafeToRebroadcastExact: true}, nil
	}
	depth := uint64(request.ProviderQuote.Body.RelayFinalityProfile.MinimumConfirmationDepth)
	if depth == 0 || current.seqno < depth {
		return zero, errors.New("TOS relay checkpoint cannot satisfy the selected confirmation depth")
	}
	anchorSequence := current.seqno - depth + 1
	anchor := consensusObservation{seqno: anchorSequence, observedAt: current.observedAt}
	anchorVote, anchorNodes, err := quorumRead(ctx, currentNodes, reader.reader.chain.quorum,
		func(ctx context.Context, node *rpcNode) (relayNodeVote, error) {
			return reader.observeNodeAt(ctx, node, anchor, binding, parsed, request)
		})
	if err != nil {
		return zero, fmt.Errorf("resolve exact Agent Account relay depth anchor: %w", err)
	}
	anchorOutcome, _ := classifyExactRelayCandidate(anchorVote.Candidate, quoted, request, current.observedAt)
	if anchorOutcome != outcome || !sameRelayTerminalCandidate(currentVote.Candidate, anchorVote.Candidate, outcome) {
		return zero, nil
	}
	indexes := intersectRelayNodeIndexes(reader.reader.chain.nodes, currentNodes, anchorNodes)
	observation := tosExactRelayObservation{CheckpointID: currentVote.CheckpointID,
		CheckpointSequence: current.seqno, DepthAnchorCheckpointID: anchorVote.CheckpointID,
		DepthAnchorCheckpointSequence: anchorSequence, ObservedAtUnix: uint64(current.observedAt.Unix()),
		Outcome: outcome, AgreedObserverIndexes: indexes}
	if outcome == agentrelay.OutcomeFinalizedSuccess {
		observation.TransactionReference = transactionReference
		observation.SourceExecutionReference = currentVote.Candidate.SourceExecutionReference
		observation.DestinationCreditReference = currentVote.Candidate.DestinationCreditReference
	}
	return observation, nil
}

func (reader *agentGiftExactRelayCheckpointReader) observeNodeAt(ctx context.Context, node *rpcNode,
	checkpoint consensusObservation, binding AgentAccountAgentBinding, parsed agentgift.ParsedNativeSend,
	request agentrelay.RelayExecutionRequest) (relayNodeVote, error) {
	vote, err := readNativeAccountAt(ctx, node, parsed.SenderAgentAccount, checkpoint.seqno,
		reader.reader.network, agentgift.AgentAccountCodeHash)
	if err != nil {
		return relayNodeVote{}, err
	}
	checkpointID, err := relayCheckpointID(checkpoint.seqno, vote.BlockRoot, vote.BlockFile)
	if err != nil {
		return relayNodeVote{}, err
	}
	candidate := relayNodeCandidate{AccountFound: vote.Found, CurrentLastTransactionTime: vote.TransactionTime}
	if !vote.Found {
		return relayNodeVote{CheckpointID: checkpointID, Candidate: candidate}, nil
	}
	account, err := decodeAgentAccountData(vote.Data, parsed.SenderAgentAccount, vote.Balance,
		reader.network.GlobalID, uint32(checkpoint.observedAt.Unix()))
	if err != nil {
		return relayNodeVote{}, err
	}
	candidate.CurrentControllerEpoch, candidate.CurrentSequence = account.ControllerEpoch, account.Seqno
	candidate.CurrentAuthorityDigest, err = AgentAccountRelayAuthorityDigest(reader.network,
		ResolvedRelayAgentAccount{Account: account, FinalizedTime: uint32(checkpoint.observedAt.Unix()),
			AuthorizedAgentID: binding.AuthorizedAgentID})
	if err != nil {
		return relayNodeVote{}, err
	}
	last := transactionID{Type: "internal.transactionId", LT: vote.LT, Hash: vote.TransactionHash}
	history, err := finalizedRelayTransactionHistory(ctx, node, parsed.SenderAgentAccount, last)
	if err != nil {
		return relayNodeVote{}, err
	}
	execution, err := matchRelayExecution(history, rootHash(request.SignedTransactionBytes),
		parsed.SenderAgentAccount, parsed.DestinationAddress, parsed.AmountAtomic, int64(request.CreatedAtUnix))
	if err != nil {
		return relayNodeVote{}, err
	}
	candidate.ExactExternalFound = execution.Found
	candidate.ExactExternalExecuted = execution.Executed
	candidate.ExecutionAbsenceKnown = execution.AbsenceKnown
	candidate.ExactOutput = execution.ExactOutput
	candidate.SourceExecutionReference = execution.ExecutionReference
	candidate.ExecutionTime = execution.ExecutionTime
	if !execution.Executed || !execution.ExactOutput {
		if execution.Found {
			candidate.DestinationCreditKnown = true
		}
		return relayNodeVote{CheckpointID: checkpointID, Candidate: candidate}, nil
	}
	destinationLast, destinationCheckpoint, err := finalizedRelayAccountLastTransaction(ctx, node,
		parsed.DestinationAddress, checkpoint.seqno)
	if err != nil || destinationCheckpoint != checkpointID {
		return relayNodeVote{}, errors.New("destination account read is not pinned to the relay checkpoint")
	}
	destinationHistory, err := finalizedRelayTransactionHistory(ctx, node, parsed.DestinationAddress, destinationLast)
	if err != nil {
		return relayNodeVote{}, err
	}
	credit, err := matchRelayCredit(destinationHistory, parsed.DestinationAddress, execution.OutputHash,
		parsed.AmountAtomic, int64(execution.ExecutionTime))
	if err != nil {
		return relayNodeVote{}, err
	}
	candidate.DestinationCreditKnown = credit.Known
	candidate.ExactDestinationCredit = credit.Credited
	candidate.DestinationCreditReference = credit.Reference
	return relayNodeVote{CheckpointID: checkpointID, Candidate: candidate}, nil
}

func classifyExactRelayCandidate(candidate relayNodeCandidate, quoted agentrelay.RelayQuoteRequestBody,
	request agentrelay.RelayExecutionRequest, observedAt time.Time) (agentrelay.TerminalOutcome, bool) {
	observed := uint64(observedAt.UTC().Unix())
	reorg := uint64(request.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds)
	if candidate.ExactExternalFound {
		if candidate.ExactExternalExecuted && candidate.ExactOutput && candidate.ExactDestinationCredit {
			if uint64(candidate.ExecutionTime)+reorg <= observed {
				return agentrelay.OutcomeFinalizedSuccess, false
			}
			return "", false
		}
		if !candidate.ExactExternalExecuted || !candidate.ExactOutput ||
			candidate.DestinationCreditKnown && !candidate.ExactDestinationCredit {
			if uint64(candidate.ExecutionTime)+reorg <= observed {
				return agentrelay.OutcomeFinalizedInvalidated, false
			}
		}
		return "", false
	}
	if !candidate.ExecutionAbsenceKnown || !candidate.AccountFound {
		return "", false
	}
	if candidate.CurrentAuthorityDigest != quoted.SourceAccountAuthorityDigest ||
		uint64(candidate.CurrentSequence) > quoted.SourceSequence {
		anchor := candidate.CurrentLastTransactionTime
		if anchor != 0 && anchor+reorg <= observed {
			return agentrelay.OutcomeFinalizedInvalidated, false
		}
		return "", false
	}
	if candidate.CurrentControllerEpoch == 0 || uint64(candidate.CurrentSequence) < quoted.SourceSequence {
		return "", false
	}
	if quoted.TransactionValidUntilUnix+reorg <= observed {
		return agentrelay.OutcomeFinalizedExpired, false
	}
	return "", uint64(candidate.CurrentSequence) == quoted.SourceSequence && observed < request.ExpiresAtUnix &&
		observed < quoted.TransactionValidUntilUnix
}

func sameRelayTerminalCandidate(current, anchor relayNodeCandidate, outcome agentrelay.TerminalOutcome) bool {
	switch outcome {
	case agentrelay.OutcomeFinalizedSuccess:
		return current.ExactExternalFound && anchor.ExactExternalFound && current.ExactExternalExecuted &&
			anchor.ExactExternalExecuted && current.ExactOutput && anchor.ExactOutput &&
			current.ExactDestinationCredit && anchor.ExactDestinationCredit &&
			current.SourceExecutionReference == anchor.SourceExecutionReference &&
			current.DestinationCreditReference == anchor.DestinationCreditReference
	case agentrelay.OutcomeFinalizedInvalidated:
		if current.ExactExternalFound || anchor.ExactExternalFound {
			return current.ExactExternalFound == anchor.ExactExternalFound &&
				current.SourceExecutionReference == anchor.SourceExecutionReference &&
				current.ExactExternalExecuted == anchor.ExactExternalExecuted &&
				current.ExactOutput == anchor.ExactOutput &&
				current.ExactDestinationCredit == anchor.ExactDestinationCredit
		}
		return current.CurrentAuthorityDigest == anchor.CurrentAuthorityDigest &&
			current.CurrentControllerEpoch == anchor.CurrentControllerEpoch &&
			current.CurrentSequence == anchor.CurrentSequence
	case agentrelay.OutcomeFinalizedExpired:
		return !current.ExactExternalFound && !anchor.ExactExternalFound &&
			current.ExecutionAbsenceKnown && anchor.ExecutionAbsenceKnown &&
			current.CurrentAuthorityDigest == anchor.CurrentAuthorityDigest &&
			current.CurrentControllerEpoch == anchor.CurrentControllerEpoch &&
			current.CurrentSequence == anchor.CurrentSequence
	default:
		return false
	}
}

func relayCheckpointID(sequence uint64, root, file string) (string, error) {
	if sequence == 0 || !canonicalSHA256Digest(root) || !canonicalSHA256Digest(file) {
		return "", errors.New("invalid TOS relay checkpoint")
	}
	return fmt.Sprintf("tos-masterchain:%d:%s:%s", sequence, root, file), nil
}

func intersectRelayNodeIndexes(all, left, right []*rpcNode) []int {
	leftSet := make(map[*rpcNode]struct{}, len(left))
	rightSet := make(map[*rpcNode]struct{}, len(right))
	for _, node := range left {
		leftSet[node] = struct{}{}
	}
	for _, node := range right {
		rightSet[node] = struct{}{}
	}
	result := make([]int, 0, len(all))
	for index, node := range all {
		if _, ok := leftSet[node]; !ok {
			continue
		}
		if _, ok := rightSet[node]; ok {
			result = append(result, index)
		}
	}
	return result
}

type relayHistoryEntry struct {
	Transaction tlb.Transaction
	Block       blockID
}

func finalizedRelayTransactionHistory(ctx context.Context, node *rpcNode, account string,
	last transactionID) ([]relayHistoryEntry, error) {
	var values []rawTransaction
	if err := node.client.Call(ctx, "getTransactions", struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{account, maxGiftHistoryTransactions, last.LT, last.Hash}, &values); err != nil {
		return nil, err
	}
	if len(values) == 0 || len(values) > maxGiftHistoryTransactions || values[0].TransactionID != last {
		return nil, errors.New("invalid bounded finalized relay transaction history")
	}
	entries := make([]relayHistoryEntry, 0, len(values))
	var previous *tlb.Transaction
	for _, value := range values {
		if value.Type != "raw.transaction" || value.Data == "" ||
			value.TransactionID.Type != "internal.transactionId" {
			return nil, errors.New("malformed finalized relay transaction")
		}
		hash, err := decodeBase64Hash(value.TransactionID.Hash)
		if err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(value.Data)
		if err != nil {
			return nil, err
		}
		root, err := cell.FromBOC(raw)
		if err != nil || !bytes.Equal(root.Hash(), hash) {
			return nil, errors.New("finalized relay transaction hash mismatch")
		}
		slice, _ := root.BeginParse()
		var transaction tlb.Transaction
		lt, parseErr := strconv.ParseUint(value.TransactionID.LT, 10, 64)
		if slice == nil || tlb.LoadFromCell(&transaction, slice) != nil || parseErr != nil || transaction.LT != lt {
			return nil, errors.New("invalid finalized relay transaction BOC")
		}
		transaction.Hash = append([]byte(nil), hash...)
		if previous != nil && (previous.PrevTxLT != transaction.LT ||
			!bytes.Equal(previous.PrevTxHash, hash)) {
			return nil, errors.New("discontinuous finalized relay transaction history")
		}
		entries = append(entries, relayHistoryEntry{Transaction: transaction, Block: value.BlockID})
		previous = &entries[len(entries)-1].Transaction
	}
	return entries, nil
}

type relayExecutionMatch struct {
	Found              bool
	Executed           bool
	AbsenceKnown       bool
	ExactOutput        bool
	OutputHash         string
	ExecutionTime      uint32
	ExecutionReference string
}

func matchRelayExecution(history []relayHistoryEntry, externalHash []byte, source, destination string,
	amount uint64, createdAtUnix int64) (relayExecutionMatch, error) {
	if len(history) == 0 || len(externalHash) != 32 {
		return relayExecutionMatch{}, errors.New("empty or invalid finalized relay history")
	}
	for _, entry := range history {
		transaction := entry.Transaction
		if transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeExternalIn {
			continue
		}
		message, err := transaction.IO.In.ToCell()
		if err != nil || !bytes.Equal(message.Hash(), externalHash) {
			continue
		}
		description, ordinary := transaction.Description.(tlb.TransactionDescriptionOrdinary)
		compute, vm := description.ComputePhase.Phase.(tlb.ComputePhaseVM)
		if !ordinary || !vm {
			return relayExecutionMatch{}, errors.New("exact relay external message has an invalid transaction description")
		}
		reference := relayTransactionReference(source, transaction)
		result := relayExecutionMatch{Found: true, AbsenceKnown: true,
			ExecutionTime: transaction.Now, ExecutionReference: reference}
		if !compute.Success || description.Aborted {
			return result, nil
		}
		result.Executed = true
		if transaction.IO.Out == nil || transaction.OutMsgCount != 1 {
			return result, nil
		}
		outputs, err := transaction.IO.Out.ToSlice()
		if err != nil || len(outputs) != 1 || outputs[0].MsgType != tlb.MsgTypeInternal {
			return result, nil
		}
		out := outputs[0].AsInternal()
		if out.Body == nil {
			return result, nil
		}
		body, bodyErr := out.Body.BeginParse()
		if out.SrcAddr == nil || out.SrcAddr.StringRaw() != source || out.DstAddr == nil ||
			out.DstAddr.StringRaw() != destination || !out.IHRDisabled || out.Bounce || out.Bounced ||
			out.StateInit != nil || out.ExtraCurrencies != nil && !out.ExtraCurrencies.IsEmpty() ||
			bodyErr != nil || body.BitsLeft() != 0 || body.RefsNum() != 0 ||
			out.Amount.Nano().Sign() <= 0 || !out.Amount.Nano().IsUint64() || out.Amount.Nano().Uint64() != amount {
			return result, nil
		}
		cellValue, err := outputs[0].ToCell()
		if err != nil {
			return result, err
		}
		result.ExactOutput = true
		result.OutputHash = hex.EncodeToString(cellValue.Hash())
		return result, nil
	}
	oldest := history[len(history)-1].Transaction
	return relayExecutionMatch{AbsenceKnown: len(history) < maxGiftHistoryTransactions ||
		oldest.PrevTxLT == 0 || int64(oldest.Now) < createdAtUnix}, nil
}

type relayCreditMatch struct {
	Known     bool
	Credited  bool
	Reference string
}

func matchRelayCredit(history []relayHistoryEntry, destination, outputHash string, amount uint64,
	notBeforeUnix int64) (relayCreditMatch, error) {
	if len(history) == 0 {
		return relayCreditMatch{}, errors.New("empty finalized relay credit history")
	}
	for _, entry := range history {
		transaction := entry.Transaction
		if transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeInternal {
			continue
		}
		message, err := transaction.IO.In.ToCell()
		if err != nil || hex.EncodeToString(message.Hash()) != outputHash {
			continue
		}
		in := transaction.IO.In.AsInternal()
		description, ordinary := transaction.Description.(tlb.TransactionDescriptionOrdinary)
		if !ordinary || in.DstAddr == nil || in.DstAddr.StringRaw() != destination ||
			!in.Amount.Nano().IsUint64() || in.Amount.Nano().Uint64() != amount {
			return relayCreditMatch{}, errors.New("exact relay internal message conflicts with expected credit")
		}
		if description.CreditPhase == nil || !description.CreditPhase.Credit.Coins.Nano().IsUint64() ||
			description.CreditPhase.Credit.Coins.Nano().Uint64() != amount {
			return relayCreditMatch{Known: true}, nil
		}
		reference, err := codec.Digest("tos.agent-relay-destination-credit-reference.v1", struct {
			Destination    string `json:"destination"`
			InputCellHash  string `json:"input_cell_hash"`
			TransactionRef string `json:"transaction_reference"`
			AmountAtomic   string `json:"amount_atomic"`
		}{Destination: destination, InputCellHash: "tvm-cell-sha256:" + outputHash,
			TransactionRef: relayTransactionReference(destination, transaction),
			AmountAtomic:   strconv.FormatUint(amount, 10)})
		if err != nil {
			return relayCreditMatch{}, err
		}
		return relayCreditMatch{Known: true, Credited: true, Reference: reference}, nil
	}
	oldest := history[len(history)-1].Transaction
	return relayCreditMatch{Known: len(history) < maxGiftHistoryTransactions || oldest.PrevTxLT == 0 ||
		int64(oldest.Now) < notBeforeUnix}, nil
}

func finalizedRelayAccountLastTransaction(ctx context.Context, node *rpcNode, account string,
	sequence uint64) (transactionID, string, error) {
	var info accountInformation
	if err := node.client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
	}{account, sequence}, &info); err != nil {
		return transactionID{}, "", err
	}
	if info.BlockID.Type != "tos.blockIdExt" || info.BlockID.Workchain != -1 ||
		info.BlockID.Seqno != sequence || info.LastTransactionID.Type != "internal.transactionId" {
		return transactionID{}, "", errors.New("relay destination response is not checkpoint-finalized")
	}
	root, rootErr := decodeBase64Hash(info.BlockID.RootHash)
	file, fileErr := decodeBase64Hash(info.BlockID.FileHash)
	if rootErr != nil || fileErr != nil {
		return transactionID{}, "", errors.New("relay destination checkpoint hashes are invalid")
	}
	checkpointID, err := relayCheckpointID(sequence, "sha256:"+hex.EncodeToString(root),
		"sha256:"+hex.EncodeToString(file))
	return info.LastTransactionID, checkpointID, err
}

func relayTransactionReference(account string, transaction tlb.Transaction) string {
	return fmt.Sprintf("tos-transaction:%s:%d:%x", account, transaction.LT, transaction.Hash)
}

func rootHash(boc []byte) []byte {
	root, err := cell.FromBOC(boc)
	if err != nil {
		return nil
	}
	return root.Hash()
}
