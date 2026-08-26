package toschain

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sort"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const maxTOSRelayClientEvidenceSnapshotBytes = 64 << 10

type tosRelayClientEvidenceSnapshotV1 struct {
	SchemaVersion        uint16                             `json:"schema_version"`
	Capability           agentrelay.RelayEvidenceCapability `json:"capability"`
	Network              agentrelay.NetworkDomain           `json:"network"`
	Endpoints            []string                           `json:"endpoints"`
	Observers            []TOSRelayObserverBinding          `json:"observers"`
	Quorum               uint16                             `json:"quorum"`
	QueryTimeoutNanos    int64                              `json:"query_timeout_nanos"`
	MaxResponseBytes     int64                              `json:"max_response_bytes"`
	ReadinessMaxAgeNanos int64                              `json:"readiness_max_age_nanos"`
	AccountBindings      []AgentAccountAgentBinding         `json:"account_bindings"`
	CheckpointNamespace  string                             `json:"checkpoint_namespace"`
	SnapshotDigest       string                             `json:"snapshot_digest"`
}

// TOSRelayFinalityVerifier is the client-owned verifier for the currently
// available TOS RPC corroboration profile.  It is deliberately separate from
// the Provider's evidence source: callers construct it with their own pinned
// RPC endpoints, observer provenance, and rollback-detecting checkpoint file.
//
// The current implementation supports relay_exact at trusted-local and
// authorized-single-provider assurance.  It does not claim validator proofs,
// decentralized autonomy, or sponsorship dual-absence verification.
type TOSRelayFinalityVerifier struct {
	reader     exactAgentNativeSendRequestReader
	network    agentrelay.NetworkDomain
	observers  []TOSRelayObserverBinding
	quorum     int
	checkpoint *tosRelayCheckpointFence
	// checkpointBasePath is an owner-pinned storage namespace root. Every
	// network derives a distinct fence filename from its full domain digest so
	// a restarted runtime on network B can recover a frozen network-A action
	// without sharing or overwriting either network's rollback high-water.
	checkpointBasePath string
	now                func() time.Time
}

type exactAgentNativeSendRequestReader interface {
	observeExactAgentNativeSendRequest(context.Context,
		agentrelay.RelayExecutionRequest) (tosExactRelayObservation, error)
}

// NewTOSRelayFinalityVerifier freezes a client-owned TOS RPC configuration.
// checkpointPath is the stable owner-private base path for the client
// verification domain and must not be shared with a Provider resolver. The
// implementation appends a full-network-domain namespace so independent
// network high-waters cannot alias during config rotation or recovery.
func NewTOSRelayFinalityVerifier(reader *AgentGiftReader,
	accounts *AgentGiftFinalizedAgentAccountResolver, network agentrelay.NetworkDomain,
	observers []TOSRelayObserverBinding, checkpointPath string) (*TOSRelayFinalityVerifier, error) {
	if reader == nil || accounts == nil || accounts.reader != reader || accounts.network != network ||
		reader.chain == nil || len(observers) != len(reader.chain.nodes) {
		return nil, errors.New("invalid TOS relay client-verifier configuration")
	}
	for index, observer := range observers {
		digest, err := reader.chain.nodes[index].client.EndpointAuthorityDigest()
		if err != nil || observer.EndpointAuthorityDigest != digest {
			return nil, errors.New("TOS relay client observer is not bound to the configured endpoint")
		}
	}
	chainReader := &agentGiftExactRelayCheckpointReader{reader: reader, accounts: accounts, network: network}
	verifier, err := newTOSRelayFinalityVerifier(chainReader, network, observers, reader.chain.quorum,
		checkpointPath)
	if err == nil {
		verifier.now = reader.chain.now
	}
	return verifier, err
}

func newTOSRelayFinalityVerifier(reader exactAgentNativeSendRequestReader,
	network agentrelay.NetworkDomain, observers []TOSRelayObserverBinding, quorum int,
	checkpointPath string) (*TOSRelayFinalityVerifier, error) {
	if reader == nil || len(observers) < 3 || quorum <= len(observers)/2 || quorum > len(observers) {
		return nil, errors.New("TOS relay client verifier requires a reader and at least three observers")
	}
	if _, err := agentrelay.NetworkDomainDigest(network); err != nil {
		return nil, errors.New("TOS relay client-verifier network is invalid")
	}
	// Reuse the profile constructor to validate sorted identity, endpoint, and
	// operator-domain uniqueness without duplicating a weaker check here.
	if _, err := TOSRelayCheckpointQuorumFinalityProfile(network, observers, 1,
		uint16(quorum), 1, 0, 1); err != nil {
		return nil, errors.New("TOS relay client-verifier observer policy is invalid")
	}
	namespacedCheckpointPath, err := tosRelayClientCheckpointPath(checkpointPath, network)
	if err != nil {
		return nil, err
	}
	checkpoint, err := newTOSRelayCheckpointFence(namespacedCheckpointPath)
	if err != nil {
		return nil, err
	}
	return &TOSRelayFinalityVerifier{reader: reader, network: network,
		observers: append([]TOSRelayObserverBinding(nil), observers...), quorum: quorum,
		checkpoint: checkpoint, checkpointBasePath: checkpointPath, now: time.Now}, nil
}

// FreezeRelayFinalityEvidenceSnapshot returns a deterministic, bounded copy
// of the exact client-owned RPC verification configuration. It contains no
// key material or URL credentials (the Adapter rejects credential-bearing
// endpoints). OpenFox stores these bytes only in its protected attempt
// journal, allowing an admitted attempt to finish after ordinary config
// rotation without weakening the selected predicate.
func (verifier *TOSRelayFinalityVerifier) FreezeRelayFinalityEvidenceSnapshot(ctx context.Context,
	capability agentrelay.RelayEvidenceCapability) ([]byte, error) {
	if verifier == nil || ctx == nil || !verifier.SupportsRelayEvidenceCapability(capability) {
		return nil, errors.New("TOS relay client snapshot capability is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	production, ok := verifier.reader.(*agentGiftExactRelayCheckpointReader)
	if !ok || production.reader == nil || production.reader.chain == nil || production.accounts == nil {
		return nil, errors.New("TOS relay client verifier cannot export its production RPC configuration")
	}
	chain := production.reader.chain
	bindings := make([]AgentAccountAgentBinding, 0, len(production.accounts.bindings))
	for _, binding := range production.accounts.bindings {
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(left, right int) bool {
		return bindings[left].SourceAccount < bindings[right].SourceAccount
	})
	snapshot := tosRelayClientEvidenceSnapshotV1{SchemaVersion: 1, Capability: capability,
		Network: verifier.network, Endpoints: append([]string(nil), chain.endpoints...),
		Observers: append([]TOSRelayObserverBinding(nil), verifier.observers...), Quorum: uint16(chain.quorum),
		QueryTimeoutNanos: int64(chain.queryTimeout), MaxResponseBytes: chain.maxBody,
		ReadinessMaxAgeNanos: int64(chain.readinessAge), AccountBindings: bindings}
	checkpointNamespace, err := tosRelayClientCheckpointNamespace(snapshot.Network)
	if err != nil {
		return nil, errors.New("derive TOS relay client checkpoint namespace")
	}
	snapshot.CheckpointNamespace = checkpointNamespace
	snapshot.SnapshotDigest, err = tosRelayClientEvidenceSnapshotDigest(snapshot)
	if err != nil {
		return nil, errors.New("digest TOS relay client evidence snapshot")
	}
	raw, err := codec.Marshal(snapshot)
	if err != nil || len(raw) == 0 || len(raw) > maxTOSRelayClientEvidenceSnapshotBytes {
		return nil, errors.New("encode bounded TOS relay client evidence snapshot")
	}
	return raw, nil
}

// ValidateRelayFinalityEvidenceSnapshot verifies canonical bytes and proves
// that they reconstruct a verifier for the exact selected capability. It does
// not contact the network or mutate the checkpoint high-water.
func (verifier *TOSRelayFinalityVerifier) ValidateRelayFinalityEvidenceSnapshot(
	capability agentrelay.RelayEvidenceCapability, opaque []byte) error {
	_, err := verifier.verifierFromSnapshot(capability, opaque)
	return err
}

// VerifyRelayFinalityFromSnapshot reconstitutes the old pinned client RPC
// view, then performs the same fresh query and monotonic checkpoint checks as
// the ordinary verifier. The current runtime configuration cannot reinterpret
// an already admitted attempt.
func (verifier *TOSRelayFinalityVerifier) VerifyRelayFinalityFromSnapshot(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, signed agentrelay.SignedRelayFinalityEvidence,
	opaque []byte) error {
	capability := tosRelayEvidenceCapability(execution)
	frozen, err := verifier.verifierFromSnapshot(capability, opaque)
	if err != nil {
		return err
	}
	return frozen.VerifyRelayFinality(ctx, execution, signed)
}

func (verifier *TOSRelayFinalityVerifier) verifierFromSnapshot(
	capability agentrelay.RelayEvidenceCapability, opaque []byte) (*TOSRelayFinalityVerifier, error) {
	if verifier == nil || verifier.checkpoint == nil || len(opaque) == 0 ||
		len(opaque) > maxTOSRelayClientEvidenceSnapshotBytes {
		return nil, errors.New("TOS relay client evidence snapshot is unavailable")
	}
	var snapshot tosRelayClientEvidenceSnapshotV1
	if err := codec.Unmarshal(opaque, &snapshot); err != nil {
		return nil, errors.New("decode TOS relay client evidence snapshot")
	}
	canonical, err := codec.Marshal(snapshot)
	snapshotDigest, digestErr := tosRelayClientEvidenceSnapshotDigest(snapshot)
	checkpointNamespace, namespaceErr := tosRelayClientCheckpointNamespace(snapshot.Network)
	if err != nil || !bytes.Equal(canonical, opaque) || snapshot.SchemaVersion != 1 ||
		digestErr != nil || snapshot.SnapshotDigest != snapshotDigest ||
		!reflect.DeepEqual(snapshot.Capability, capability) || snapshot.Network != capability.Network ||
		namespaceErr != nil || snapshot.CheckpointNamespace != checkpointNamespace ||
		len(snapshot.Endpoints) != len(snapshot.Observers) ||
		len(snapshot.Endpoints) < 3 || len(snapshot.Endpoints) > maxEndpoints ||
		int(snapshot.Quorum) <= len(snapshot.Endpoints)/2 || int(snapshot.Quorum) > len(snapshot.Endpoints) ||
		time.Duration(snapshot.QueryTimeoutNanos) <= 0 ||
		time.Duration(snapshot.QueryTimeoutNanos) > maxQueryTimeout || snapshot.MaxResponseBytes <= 0 ||
		snapshot.MaxResponseBytes > maxResponseBytes || time.Duration(snapshot.ReadinessMaxAgeNanos) <= 0 ||
		time.Duration(snapshot.ReadinessMaxAgeNanos) > maxReadinessAge || len(snapshot.AccountBindings) == 0 {
		return nil, errors.New("TOS relay client evidence snapshot is invalid or substituted")
	}
	pinned := &PinnedNetworkDomain{NetworkID: snapshot.Network.NetworkID, GlobalID: snapshot.Network.GlobalID,
		ZeroStateRootHash: snapshot.Network.ZeroStateRootHash,
		ZeroStateFileHash: snapshot.Network.ZeroStateFileHash, WorkchainID: snapshot.Network.WorkchainID}
	chain, err := New(Config{Network: snapshot.Network.NetworkID, PinnedNetworkDomain: pinned,
		Endpoints: append([]string(nil), snapshot.Endpoints...), Quorum: int(snapshot.Quorum),
		QueryTimeout: time.Duration(snapshot.QueryTimeoutNanos), MaxResponseBytes: snapshot.MaxResponseBytes,
		ReadinessMaxAge: time.Duration(snapshot.ReadinessMaxAgeNanos), Now: verifier.now})
	if err != nil {
		return nil, errors.New("restore TOS relay client RPC snapshot")
	}
	reader, err := NewAgentGiftReader(chain, &nativev1.NetworkDomain{NetworkId: snapshot.Network.NetworkID,
		GenesisRootHash: snapshot.Network.ZeroStateRootHash, GenesisFileHash: snapshot.Network.ZeroStateFileHash})
	if err != nil {
		return nil, err
	}
	accounts, err := NewAgentGiftFinalizedAgentAccountResolver(reader, snapshot.Network,
		append([]AgentAccountAgentBinding(nil), snapshot.AccountBindings...))
	if err != nil {
		return nil, err
	}
	restored, err := NewTOSRelayFinalityVerifier(reader, accounts, snapshot.Network,
		append([]TOSRelayObserverBinding(nil), snapshot.Observers...), verifier.checkpointBasePath)
	if err != nil || !restored.SupportsRelayEvidenceCapability(capability) {
		return nil, errors.New("restored TOS relay client snapshot does not support the exact capability")
	}
	restored.now = verifier.now
	return restored, nil
}

func tosRelayClientEvidenceSnapshotDigest(snapshot tosRelayClientEvidenceSnapshotV1) (string, error) {
	projection := snapshot
	projection.SnapshotDigest = ""
	return codec.Digest("tos.toschain.relay-client-evidence-snapshot.v1", projection)
}

func tosRelayClientCheckpointNamespace(network agentrelay.NetworkDomain) (string, error) {
	return codec.Digest("tos.toschain.relay-client-checkpoint-namespace.v1", network)
}

func tosRelayClientCheckpointPath(basePath string, network agentrelay.NetworkDomain) (string, error) {
	namespace, err := tosRelayClientCheckpointNamespace(network)
	if err != nil {
		return "", errors.New("derive TOS relay client checkpoint path")
	}
	if len(namespace) != len("sha256:")+64 || namespace[:len("sha256:")] != "sha256:" {
		return "", errors.New("invalid TOS relay client checkpoint namespace")
	}
	raw := namespace[len("sha256:"):]
	return basePath + ".network-" + raw, nil
}

func tosRelayEvidenceCapability(execution agentrelay.RelayExecutionRequest) agentrelay.RelayEvidenceCapability {
	body := execution.QuoteRequest.Body
	capability := agentrelay.RelayEvidenceCapability{
		Mode:                             body.Mode,
		AssuranceLevel:                   body.AssuranceLevel,
		Network:                          body.Network,
		TransactionProfileURI:            body.TransactionProfileURI,
		TransactionProfileDigest:         body.TransactionProfileDigest,
		UnderlyingActionKind:             body.UnderlyingActionKind,
		RelayTerminalEvidenceClass:       body.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: body.SponsorshipTerminalEvidenceClass,
		RelayFinalityProfile:             execution.ProviderQuote.Body.RelayFinalityProfile,
		SponsorshipReleaseProfile:        body.SelectedSponsorshipReleaseProfile(),
		SponsorshipTerminalProfile:       execution.ProviderQuote.Body.SponsorshipTerminalProfile,
	}
	if body.Mode != agentrelay.ModeRelayExact &&
		body.AssuranceLevel != agentrelay.AssuranceAutonomousDecentralized {
		capability.AbsenceProofProfileURI = agentrelay.RelayAbsenceTOSRPCProofProfileURI
		capability.AbsenceProofProfileDigest, _ = agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	}
	return capability
}

// SupportsRelayEvidenceCapability is an exact current capability query.  An
// empty action kind is not a wildcard, and a relay-only verifier never makes a
// sponsorship pair ready.
func (verifier *TOSRelayFinalityVerifier) SupportsRelayEvidenceCapability(
	capability agentrelay.RelayEvidenceCapability) bool {
	if verifier == nil || (capability.Mode != agentrelay.ModeRelayExact &&
		capability.Mode != agentrelay.ModeSponsorAndRelay) ||
		(capability.AssuranceLevel != agentrelay.AssuranceTrustedLocal &&
			capability.AssuranceLevel != agentrelay.AssuranceAuthorizedSingleProvider) ||
		capability.Network != verifier.network ||
		capability.TransactionProfileURI != AgentAccountNativeSendRelayProfileURI ||
		capability.TransactionProfileDigest != AgentAccountNativeSendRelayProfileDigest() ||
		capability.UnderlyingActionKind != "payment.direct" ||
		capability.RelayTerminalEvidenceClass != agentrelay.RelayTerminalProviderCorroborated ||
		capability.RelayFinalityProfile == nil {
		return false
	}
	profile := capability.RelayFinalityProfile
	expected, err := TOSRelayCheckpointQuorumFinalityProfile(verifier.network, verifier.observers,
		profile.MinimumConfirmationDepth, profile.MinimumObservers, profile.MinimumOperatorDomains,
		profile.ReorgWindowSeconds, profile.MaximumResolutionSeconds)
	if err != nil || *profile != expected || int(profile.MinimumObservers) < verifier.quorum {
		return false
	}
	if capability.Mode == agentrelay.ModeRelayExact {
		return capability.SponsorshipTerminalEvidenceClass == "" &&
			capability.SponsorshipTerminalProfile == nil &&
			capability.SponsorshipReleaseProfile == (agentrelay.SponsorshipReleaseProfile{}) &&
			capability.AbsenceProofProfileURI == "" && capability.AbsenceProofProfileDigest == ""
	}
	absenceProfileDigest, absenceErr := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	sponsorshipProfile := capability.SponsorshipTerminalProfile
	return absenceErr == nil && capability.AbsenceProofProfileURI == agentrelay.RelayAbsenceTOSRPCProofProfileURI &&
		capability.AbsenceProofProfileDigest == absenceProfileDigest &&
		capability.SponsorshipReleaseProfile.EvidenceClass == agentrelay.SponsorshipReleaseObservedUnproven &&
		capability.SponsorshipReleaseProfile.ProfileURI == agentrelay.RPCCorroborationEvidenceProfileURI &&
		canonicalSHA256Digest(capability.SponsorshipReleaseProfile.ProfileDigest) &&
		capability.SponsorshipTerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated &&
		sponsorshipProfile != nil && sponsorshipProfile.ProfileURI == agentrelay.ClientCorroboratedTerminalProfileURI &&
		canonicalSHA256Digest(sponsorshipProfile.ProfileDigest) &&
		sponsorshipProfile.TerminalEvidenceClass == agentrelay.SponsorshipTerminalClientCorroborated &&
		sponsorshipProfile.MinimumConfirmationDepth > 0 && sponsorshipProfile.MinimumObservers > 0 &&
		sponsorshipProfile.MinimumOperatorDomains > 0 &&
		sponsorshipProfile.MinimumOperatorDomains <= sponsorshipProfile.MinimumObservers
}

// SupportsRelayDualAbsenceEvidence remains false until a client-owned query
// path can verify both the Provider top-up action and the client transaction.
func (*TOSRelayFinalityVerifier) SupportsRelayDualAbsenceEvidence(
	agentrelay.RelayEvidenceCapability) bool {
	return false
}

// The in-process relay verifier has no Provider top-up reader.  Sponsorship
// component absence is therefore supported only by the snapshot-bound tosctl
// proof verifier wired by the calling runtime, not by this relay-only object.
func (*TOSRelayFinalityVerifier) SupportsRelaySponsorshipComponentAbsenceEvidence(
	agentrelay.RelayEvidenceCapability) bool {
	return false
}

// The current in-process verifier can resolve a relay transaction when it is
// the primary outcome, but it cannot consume the released transaction-only
// absence proof payload.  It must not make the combined tuple ready by merely
// recognizing the outer protocol type.
func (verifier *TOSRelayFinalityVerifier) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	// The exact transaction component is independently re-queried through this
	// verifier's pinned quorum. Sponsorship and dual scopes remain delegated to
	// the separately frozen tosctl sponsorship proof verifier.
	return capability.Mode == agentrelay.ModeSponsorAndRelay &&
		verifier.SupportsRelayEvidenceCapability(capability)
}

// VerifyRelayFinality independently re-queries the exact immutable client BOC
// through the client's pinned quorum.  Provider observation digests remain
// authenticated provenance; they are never treated as chain truth.
func (verifier *TOSRelayFinalityVerifier) VerifyRelayFinality(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, signed agentrelay.SignedRelayFinalityEvidence) error {
	if verifier == nil || verifier.reader == nil || verifier.checkpoint == nil || ctx == nil {
		return errors.New("TOS relay client verifier is unavailable")
	}
	if _, err := agentrelay.RelayFinalityEvidenceDigest(signed.Body); err != nil {
		return errors.New("TOS relay evidence body is invalid")
	}
	body := execution.QuoteRequest.Body
	capability := tosRelayEvidenceCapability(execution)
	if !verifier.SupportsRelayEvidenceCapability(capability) {
		return errors.New("TOS relay client verifier does not support the exact signed capability")
	}
	observed, err := verifier.reader.observeExactAgentNativeSendRequest(ctx, execution)
	if err != nil {
		return err
	}
	if observed.SafeToRebroadcastExact || observed.Outcome == "" ||
		observed.CheckpointSequence == 0 || observed.CheckpointID == "" {
		return errors.New("TOS relay client quorum has no terminal observation yet")
	}
	if err := validateTOSRelayObservationForProfile(observed, *capability.RelayFinalityProfile,
		verifier.observers); err != nil {
		return err
	}
	localRelayOutcome := tosProviderCorroboratedOutcome(observed.Outcome)
	expectedOutcome := localRelayOutcome
	hasSponsorshipSuccess := signed.Body.SponsorshipTransactionEvidence != nil
	hasSponsorshipAbsence := len(signed.Body.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(signed.Body.TransactionAbsenceObservations) != 0
	if capability.Mode == agentrelay.ModeSponsorAndRelay {
		switch {
		case localRelayOutcome == agentrelay.OutcomeCorroboratedSuccess && hasSponsorshipSuccess:
			expectedOutcome = agentrelay.OutcomeCorroboratedSuccess
		case localRelayOutcome == agentrelay.OutcomeCorroboratedSuccess && hasSponsorshipAbsence:
			expectedOutcome = agentrelay.OutcomeCorroboratedRelayOnly
		case localRelayOutcome != agentrelay.OutcomeCorroboratedSuccess && hasSponsorshipSuccess && hasTransactionAbsence:
			expectedOutcome = agentrelay.OutcomeCorroboratedSponsorshipOnly
		case localRelayOutcome != agentrelay.OutcomeCorroboratedSuccess && hasSponsorshipAbsence &&
			hasTransactionAbsence:
			expectedOutcome = localRelayOutcome
		default:
			return errors.New("client TOS quorum cannot map the relay observation to a complete sponsorship quadrant")
		}
	}
	if signed.Body.Outcome != expectedOutcome || signed.Body.RelayFinalityProfile == nil ||
		*signed.Body.RelayFinalityProfile != *capability.RelayFinalityProfile {
		return errors.New("client TOS quorum disagrees with the Provider relay terminal claim")
	}
	if localRelayOutcome == agentrelay.OutcomeCorroboratedSuccess {
		if signed.Body.RelayTerminalEvidenceClass != agentrelay.RelayTerminalProviderCorroborated ||
			signed.Body.RelayValidatorAuthenticatedPortableProof ||
			observed.CheckpointSequence < signed.Body.RelayFinalizedCheckpointSequence {
			return errors.New("client TOS quorum disagrees with the Provider relay success predicate")
		}
		if observed.TransactionReference != body.SignedTransactionCellHash ||
			signed.Body.SubmittedTransactionHash != observed.TransactionReference ||
			signed.Body.SourceExecutionReference != observed.SourceExecutionReference ||
			len(signed.Body.DestinationCreditReferences) != 1 ||
			signed.Body.DestinationCreditReferences[0] != observed.DestinationCreditReference {
			return errors.New("client TOS quorum disagrees with relay execution or destination credit")
		}
	} else {
		if signed.Body.SubmittedTransactionHash != "" || signed.Body.SourceExecutionReference != "" ||
			len(signed.Body.DestinationCreditReferences) != 0 {
			return errors.New("negative TOS relay evidence lacks exact transaction-component absence")
		}
		if capability.Mode == agentrelay.ModeRelayExact {
			if err := verifier.checkpoint.checkAndAdvance(observed.CheckpointSequence, observed.CheckpointID); err != nil {
				return err
			}
			return nil
		}
		if !hasTransactionAbsence {
			return errors.New("negative combined TOS relay evidence lacks transaction-component absence")
		}
		conclusion := tosRelayAbsenceConclusion(localRelayOutcome)
		if conclusion == "" {
			return errors.New("client TOS quorum returned an unsupported negative relay outcome")
		}
		for _, reference := range signed.Body.TransactionAbsenceObservations {
			if reference.ObservationKind != agentrelay.AbsenceObservationClientTransaction ||
				reference.Conclusion != conclusion ||
				reference.TerminalProfileURI != capability.RelayFinalityProfile.ProfileURI ||
				reference.TerminalProfileDigest != capability.RelayFinalityProfile.ProfileDigest ||
				reference.TerminalEvidenceClass != capability.RelayFinalityProfile.TerminalEvidenceClass ||
				observed.CheckpointSequence < reference.FinalizedCheckpointSequence {
				return errors.New("client TOS quorum disagrees with transaction-component absence evidence")
			}
		}
	}
	if err := verifier.checkpoint.checkAndAdvance(observed.CheckpointSequence, observed.CheckpointID); err != nil {
		return err
	}
	return nil
}

func tosRelayAbsenceConclusion(outcome agentrelay.TerminalOutcome) agentrelay.RelayAbsenceConclusion {
	switch outcome {
	case agentrelay.OutcomeCorroboratedExpired:
		return agentrelay.AbsenceConclusionExpiredWithoutInclusion
	case agentrelay.OutcomeCorroboratedAbsent:
		return agentrelay.AbsenceConclusionAbsent
	case agentrelay.OutcomeCorroboratedInvalidated:
		return agentrelay.AbsenceConclusionInvalidated
	default:
		return ""
	}
}

var _ agentrelay.RelayFinalityEvidenceVerifier = (*TOSRelayFinalityVerifier)(nil)
