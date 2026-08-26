package agentrelay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// AgentKeyResolver resolves finalized Agent identity authority. The public key
// carried in a signed envelope is never self-authorizing.
type AgentKeyResolver interface {
	// AuthorizeRelayKey resolves the Agent authority in the exact chain domain
	// carried by the signed relay object. A display NetworkID is not an
	// authority boundary: two chains may intentionally or accidentally reuse
	// it while having different genesis state.
	AuthorizeRelayKey(network NetworkDomain, agentID string, publicKey ed25519.PublicKey, at time.Time) error
}

func NetworkDomainDigest(network NetworkDomain) (string, error) {
	if err := validateNetworkDomain(network); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-network-domain.v1", network)
}

func RelayServiceProfileDigest(profile RelayServiceProfile) (string, error) {
	if err := validateRelayServiceProfileShape(profile); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-service-profile.v1", profile)
}

func RelayQuoteRequestDigest(body RelayQuoteRequestBody) (string, error) {
	if err := validateRelayQuoteRequestShape(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-quote-request.v1", body)
}

func ProviderRelayQuoteDigest(body ProviderRelayQuoteBody) (string, error) {
	if err := validateProviderRelayQuoteShape(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-provider-quote.v1", body)
}

func RelayAgreementBindingBytes(binding RelayAgreementBinding) ([]byte, error) {
	if err := validateRelayAgreementBinding(binding); err != nil {
		return nil, err
	}
	return codec.Marshal(binding)
}

func RelayAgreementBindingDigest(binding RelayAgreementBinding) (string, error) {
	if err := validateRelayAgreementBinding(binding); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-agreement-binding.v1", binding)
}

func RelayExecutionRequestDigest(request RelayExecutionRequest) (string, error) {
	// The released execution digest deliberately excludes all admission
	// credentials. It therefore has to be computable before the Action Authority
	// issues AdmissionReceipt; requiring a populated receipt here would make the
	// protocol's admission sequence circular.
	if err := validateRelayExecutionRequestCoreShape(request); err != nil {
		return "", err
	}
	return relayExecutionRequestProjectionDigest(request)
}

func relayExecutionRequestProjectionDigest(request RelayExecutionRequest) (string, error) {
	// Writer fences, AuthorizedAction proofs, and the admission receipt are
	// authorization credentials, not semantic request data. The receipt itself
	// binds this projection, so including it would also create a digest cycle.
	projection := struct {
		SchemaVersion           uint16                             `json:"schema_version"`
		QuoteRequest            SignedRelayQuoteRequest            `json:"quote_request"`
		ProviderQuote           SignedProviderRelayQuote           `json:"provider_quote"`
		SignedTransactionBytes  []byte                             `json:"signed_transaction_bytes"`
		AgreementBodyDigest     string                             `json:"agreement_body_digest"`
		AgreementExpiresAtUnix  uint64                             `json:"agreement_expires_at_unix"`
		RelayObligationID       string                             `json:"relay_obligation_id,omitempty"`
		SponsorshipObligationID string                             `json:"sponsorship_obligation_id,omitempty"`
		FeeObligationIDs        []string                           `json:"fee_obligation_ids"`
		UnderlyingActionRequest []byte                             `json:"underlying_action_request"`
		SemanticFields          []agentcommerce.SemanticFieldValue `json:"semantic_fields"`
		CreatedAtUnix           uint64                             `json:"created_at_unix"`
		ExpiresAtUnix           uint64                             `json:"expires_at_unix"`
	}{SchemaVersion: request.SchemaVersion, QuoteRequest: request.QuoteRequest, ProviderQuote: request.ProviderQuote,
		SignedTransactionBytes: request.SignedTransactionBytes,
		AgreementBodyDigest:    request.AgreementBodyDigest, AgreementExpiresAtUnix: request.AgreementExpiresAtUnix,
		RelayObligationID: request.RelayObligationID, SponsorshipObligationID: request.SponsorshipObligationID,
		FeeObligationIDs: request.FeeObligationIDs, UnderlyingActionRequest: request.UnderlyingActionRequest,
		SemanticFields: request.SemanticFields, CreatedAtUnix: request.CreatedAtUnix, ExpiresAtUnix: request.ExpiresAtUnix}
	return codec.Digest("tos.agent-relay-execution-request.v1", projection)
}

func RelayResolutionDigest(body RelayResolutionBody) (string, error) {
	if err := validateRelayResolutionBody(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-resolution.v1", body)
}

func RelayFinalityEvidenceDigest(body RelayFinalityEvidenceBody) (string, error) {
	if err := validateRelayFinalityEvidenceBody(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-finality-evidence.v1", body)
}

func RelaySponsorshipTransactionEvidenceDigest(evidence RelaySponsorshipTransactionEvidence) (string, error) {
	if err := validateRelaySponsorshipTransactionEvidenceShape(evidence); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-sponsorship-transaction-evidence.v1", evidence)
}

// RelaySponsorshipProofBundleDigest verifies that bundle is exact
// deterministic protocol CBOR and commits those bytes under the domain shared
// by every sponsorship proof producer and verifier. It intentionally hashes
// the attachment rather than a language-specific JSON rendering.
func RelaySponsorshipProofBundleDigest(bundle []byte) (string, error) {
	if len(bundle) == 0 || len(bundle) > MaxRelayProofBundleBytes {
		return "", errors.New("relay sponsorship proof bundle byte length is invalid")
	}
	return codec.DigestCanonical("tos.agent-relay-sponsorship-proof-bundle.v1", bundle)
}

// RelayAbsenceProofBundleDigest accepts only exact Core Deterministic CBOR and
// commits the bounded V1 manifest under the released cross-implementation
// domain. The same function is used for sponsorship-only, transaction-only,
// and dual absence scopes.
func RelayAbsenceProofBundleDigest(bundle []byte) (string, error) {
	if len(bundle) == 0 || len(bundle) > MaxRelayProofBundleBytes {
		return "", errors.New("relay absence proof bundle byte length is invalid")
	}
	// Decode the canonical map once before the typed projection so absence is
	// distinguishable from an explicitly encoded null or empty array. Go slices
	// alone collapse those wire states, but V1 uses field presence to bind the
	// proof scope and forbids an inapplicable component field altogether.
	var fields map[string]interface{}
	if err := codec.Unmarshal(bundle, &fields); err != nil {
		return "", err
	}
	var decoded RelayAbsenceProofBundleV1
	if err := codec.Unmarshal(bundle, &decoded); err != nil {
		return "", err
	}
	if err := validateRelayAbsenceProofBundleFieldPresence(fields, decoded.ProofScope); err != nil {
		return "", err
	}
	if err := validateRelayAbsenceProofBundle(decoded); err != nil {
		return "", err
	}
	return codec.DigestCanonical(RelayAbsenceProofBundleDomainV1, bundle)
}

func validateRelayAbsenceProofBundleFieldPresence(fields map[string]interface{}, scope RelayAbsenceProofScope) error {
	presentNonemptyArray := func(name string) (bool, error) {
		value, present := fields[name]
		if !present {
			return false, nil
		}
		items, ok := value.([]interface{})
		if !ok || len(items) == 0 {
			return false, errors.New("relay absence proof bundle component must be a non-empty array")
		}
		return true, nil
	}
	hasSponsorship, err := presentNonemptyArray("sponsorship_absence_observations")
	if err != nil {
		return err
	}
	hasTransaction, err := presentNonemptyArray("transaction_absence_observations")
	if err != nil {
		return err
	}
	switch scope {
	case RelayAbsenceProofSponsorshipOnly:
		if !hasSponsorship || hasTransaction {
			return errors.New("sponsorship-only proof bundle has invalid component field presence")
		}
	case RelayAbsenceProofTransactionOnly:
		if hasSponsorship || !hasTransaction {
			return errors.New("transaction-only proof bundle has invalid component field presence")
		}
	case RelayAbsenceProofDual:
		if !hasSponsorship || !hasTransaction {
			return errors.New("dual proof bundle has invalid component field presence")
		}
	default:
		return errors.New("relay absence proof bundle scope is unknown")
	}
	return nil
}

func RelaySponsorshipCreditObservationDigest(observation RelaySponsorshipCreditObservation) (string, error) {
	if err := validateRelaySponsorshipCreditObservationShape(observation); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-sponsorship-credit-observation.v1", observation)
}

func SignedTransactionDigest(payload []byte) (string, error) {
	if len(payload) == 0 || len(payload) > MaxSignedTransactionBytes {
		return "", errors.New("signed transaction byte length is invalid")
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func SignRelayQuoteRequest(body RelayQuoteRequestBody, key ed25519.PrivateKey) (SignedRelayQuoteRequest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedRelayQuoteRequest{}, errors.New("relay quote request signing key is invalid")
	}
	if err := validateRelayQuoteRequestShape(body); err != nil {
		return SignedRelayQuoteRequest{}, err
	}
	message, err := signatureMessage("tos.agent-relay-quote-request-signature.v1\x00", body)
	if err != nil {
		return SignedRelayQuoteRequest{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return SignedRelayQuoteRequest{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func SignProviderRelayQuote(body ProviderRelayQuoteBody, key ed25519.PrivateKey) (SignedProviderRelayQuote, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedProviderRelayQuote{}, errors.New("provider relay quote signing key is invalid")
	}
	if err := validateProviderRelayQuoteShape(body); err != nil {
		return SignedProviderRelayQuote{}, err
	}
	message, err := signatureMessage("tos.agent-relay-provider-quote-signature.v1\x00", body)
	if err != nil {
		return SignedProviderRelayQuote{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return SignedProviderRelayQuote{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func SignRelayResolution(body RelayResolutionBody, key ed25519.PrivateKey) (SignedRelayResolution, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedRelayResolution{}, errors.New("relay resolution signing key is invalid")
	}
	if err := validateRelayResolutionBody(body); err != nil {
		return SignedRelayResolution{}, err
	}
	message, err := signatureMessage("tos.agent-relay-resolution-signature.v1\x00", body)
	if err != nil {
		return SignedRelayResolution{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return SignedRelayResolution{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func SignRelayFinalityEvidence(body RelayFinalityEvidenceBody, key ed25519.PrivateKey) (SignedRelayFinalityEvidence, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedRelayFinalityEvidence{}, errors.New("relay evidence signing key is invalid")
	}
	if err := validateRelayFinalityEvidenceBody(body); err != nil {
		return SignedRelayFinalityEvidence{}, err
	}
	message, err := signatureMessage("tos.agent-relay-finality-evidence-signature.v1\x00", body)
	if err != nil {
		return SignedRelayFinalityEvidence{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return SignedRelayFinalityEvidence{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func VerifyRelayResolution(signed SignedRelayResolution, resolver AgentKeyResolver, now time.Time) error {
	if err := validateRelayResolutionBody(signed.Body); err != nil {
		return err
	}
	now = now.UTC()
	nowUnix := now.Unix()
	futureLimitUnix := now.Add(5 * time.Minute).Unix()
	if nowUnix < 0 || futureLimitUnix < 0 || signed.Body.ObservedAtUnix > uint64(futureLimitUnix) ||
		uint64(nowUnix) >= signed.Body.ExpiresAtUnix {
		return errors.New("relay resolution is premature or expired")
	}
	return verifyAgentSignature(signed.Body.Network, signed.Body.ProviderAgentID, signed.PublicKey, signed.Signature,
		"tos.agent-relay-resolution-signature.v1\x00", signed.Body, resolver, now)
}

// VerifyRelayResolutionForExecution verifies the Provider signature and binds
// the signed status to the exact selected service route. A valid Provider
// signature alone is insufficient because the same Provider may concurrently
// serve multiple assurance levels and transactions.
func VerifyRelayResolutionForExecution(signed SignedRelayResolution, request RelayExecutionRequest,
	resolver AgentKeyResolver, now time.Time) error {
	if err := VerifyRelayResolution(signed, resolver, now); err != nil {
		return err
	}
	executionDigest, err := RelayExecutionRequestDigest(request)
	if err != nil {
		return err
	}
	body := signed.Body
	quoted := request.QuoteRequest.Body
	if body.ProviderAgentID != request.ProviderQuote.Body.ProviderAgentID || body.Network != quoted.Network ||
		body.AssuranceLevel != quoted.AssuranceLevel || body.StableActionID != quoted.StableActionID ||
		body.ExactRequestDigest != quoted.ExactRequestDigest || body.RelayExecutionDigest != executionDigest {
		return errors.New("relay resolution conflicts with the exact execution and assurance level")
	}
	if body.SponsorshipStatus == SponsorshipResolutionObservedUnproven &&
		quoted.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven {
		return errors.New("relay resolution weakens the signed sponsorship release evidence class")
	}
	return validateRelayResolutionMode(body, quoted.Mode)
}

func validateRelayResolutionMode(body RelayResolutionBody, mode Mode) error {
	hasSponsorshipIdentity := body.SponsorshipStableActionID != "" ||
		body.SponsorshipExactRequestDigest != "" || body.SponsorshipValidUntilUnix != 0
	hasSponsorship := hasSponsorshipIdentity || body.SponsorshipTransferReference != "" ||
		body.SponsorshipStatus != "" || body.SponsorshipObservationDigest != ""
	if mode == ModeRelayExact {
		if hasSponsorship || body.TerminalOutcome == OutcomeFinalizedSponsorshipOnly ||
			body.TerminalOutcome == OutcomeCorroboratedSponsorshipOnly ||
			body.TerminalOutcome == OutcomeCorroboratedSuccess {
			return errors.New("relay-only resolution carries a sponsorship result")
		}
		return nil
	}
	if mode != ModeSponsorOnly && mode != ModeSponsorAndRelay {
		return errors.New("relay resolution mode is invalid")
	}
	if body.State != agentcommerce.ActionTerminal {
		if mode == ModeSponsorOnly && body.TransactionReference != "" {
			return errors.New("nonterminal sponsor-only resolution carries a transaction reference")
		}
		return nil
	}
	if body.SponsorshipTransferReference == "" {
		relayOnly := mode == ModeSponsorAndRelay &&
			(body.TerminalOutcome == OutcomeFinalizedRelayOnly ||
				body.TerminalOutcome == OutcomeCorroboratedRelayOnly) && body.TransactionReference != ""
		sponsorshipAbsent := safeTerminalAbsenceOutcome(body.TerminalOutcome) && body.TransactionReference == ""
		if !hasSponsorshipIdentity || (!relayOnly && !sponsorshipAbsent) {
			return errors.New("sponsorship resolution lacks a typed terminal result")
		}
		return nil
	}
	switch mode {
	case ModeSponsorOnly:
		if (body.TerminalOutcome != OutcomeFinalizedSponsorshipOnly &&
			body.TerminalOutcome != OutcomeCorroboratedSponsorshipOnly) ||
			body.TransactionReference != body.SponsorshipTransferReference {
			return errors.New("sponsor-only resolution carries a relay outcome")
		}
	case ModeSponsorAndRelay:
		switch body.TerminalOutcome {
		case OutcomeFinalizedSponsorshipOnly, OutcomeCorroboratedSponsorshipOnly:
			if body.TransactionReference != body.SponsorshipTransferReference {
				return errors.New("partial combined resolution changed the sponsorship reference")
			}
		case OutcomeFinalizedSuccess, OutcomeCorroboratedSuccess:
			if body.TransactionReference == "" || body.TransactionReference == body.SponsorshipTransferReference {
				return errors.New("combined success lacks a distinct relayed transaction reference")
			}
		default:
			return errors.New("combined resolution outcome conflicts with its sponsorship side effect")
		}
	}
	return nil
}

func VerifyRelayFinalityEvidence(signed SignedRelayFinalityEvidence, resolver AgentKeyResolver, now time.Time) error {
	if err := validateRelayFinalityEvidenceBody(signed.Body); err != nil {
		return err
	}
	// Chain observation time and Provider signature-authority time are distinct.
	// Evidence may be materialized for the first time after a Provider key
	// rotation, so authorizing the current signature at historical chain time
	// would make a valid durable observation unverifiable.
	nowSeconds := now.UTC().Unix()
	if nowSeconds < 0 || signed.Body.SigningAuthorityAtUnix > uint64(1<<63-1) ||
		(signed.Body.SigningAuthorityAtUnix > uint64(nowSeconds) &&
			signed.Body.SigningAuthorityAtUnix-uint64(nowSeconds) > 5*60) {
		return errors.New("relay finality evidence signing-authority time is invalid")
	}
	authorizedAt := time.Unix(int64(signed.Body.SigningAuthorityAtUnix), 0).UTC()
	return verifyAgentSignature(signed.Body.Network, signed.Body.ProviderAgentID, signed.PublicKey, signed.Signature,
		"tos.agent-relay-finality-evidence-signature.v1\x00", signed.Body, resolver, authorizedAt)
}

// SponsorshipTransactionEvidenceVerifier independently validates the proof
// bundle committed by a Provider-funded top-up. Implementations for local and
// single-provider assurance may resolve ProofBundleDigest from an
// owner-configured local store. The Provider signature is never a substitute
// for this verification.
type SponsorshipTransactionEvidenceVerifier interface {
	VerifySponsorshipTransactionEvidence(context.Context, RelaySponsorshipTransactionEvidence,
		RelaySponsorshipEvidenceContext, FinalityProfile) error
}

// RelaySponsorshipEvidenceContext is the exact expected PaymentRequestV3
// projection. A proof verifier must load the canonical payment request
// committed by AgreementPaymentRequestDigest and call
// VerifySponsorshipPaymentRequestForEvidence before accepting chain proof
// bytes. This prevents replay of an unrelated same-account/same-amount top-up.
type RelaySponsorshipEvidenceContext struct {
	AgreementBodyDigest           string
	AgreementObligationID         string
	PayerAgentID                  string
	PayeeAgentID                  string
	NetworkID                     string
	NetworkDomainDigest           string
	DestinationSourceAccount      string
	Amount                        AssetAmount
	MaximumExpiresAtUnix          uint64
	SponsorshipStableActionID     string
	SponsorshipExactRequestDigest string
}

// PortableSponsorshipTransactionEvidenceVerifier is required by the
// autonomous-decentralized assurance profile. Its implementation must verify a
// portable proof without trusting the relay Provider or a Provider-local
// observation database.
type PortableSponsorshipTransactionEvidenceVerifier interface {
	SponsorshipTransactionEvidenceVerifier
	HasIndependentPortableSponsorshipProofs() bool
}

// RelayFinalityEvidenceVerifier is the client-side verifier for the complete
// Provider evidence envelope. Capability checks are exact and current; a
// verifier for another network, transaction profile, evidence predicate, or
// sponsorship mode cannot make this execution ready.
type RelayFinalityEvidenceVerifier interface {
	VerifyRelayFinality(context.Context, RelayExecutionRequest, SignedRelayFinalityEvidence) error
	SupportsRelayEvidenceCapability(RelayEvidenceCapability) bool
	SupportsRelayDualAbsenceEvidence(RelayEvidenceCapability) bool
	SupportsRelaySponsorshipComponentAbsenceEvidence(RelayEvidenceCapability) bool
	SupportsRelayTransactionComponentAbsenceEvidence(RelayEvidenceCapability) bool
}

// PortableRelayFinalityEvidenceVerifier is required whenever a selected
// predicate claims validator finality (and therefore for every autonomous-
// decentralized execution). It verifies retrievable proof material rather
// than accepting the Provider signature as chain truth.
type PortableRelayFinalityEvidenceVerifier interface {
	RelayFinalityEvidenceVerifier
	HasIndependentPortableRelayFinalityProofs() bool
}

// VerifyRelayFinalityEvidenceForExecution binds signed finality to the exact
// execution and selected assurance profile, then independently verifies the
// nested top-up proof when sponsorship occurred.
func VerifyRelayFinalityEvidenceForExecution(ctx context.Context, signed SignedRelayFinalityEvidence,
	request RelayExecutionRequest, resolver AgentKeyResolver,
	finalityVerifier RelayFinalityEvidenceVerifier,
	sponsorshipVerifier SponsorshipTransactionEvidenceVerifier, now time.Time) error {
	if err := VerifyRelayFinalityEvidence(signed, resolver, now); err != nil {
		return err
	}
	executionDigest, err := RelayExecutionRequestDigest(request)
	if err != nil {
		return err
	}
	body := signed.Body
	quoted := request.QuoteRequest.Body
	if body.ProviderAgentID != request.ProviderQuote.Body.ProviderAgentID || body.Network != quoted.Network ||
		body.AssuranceLevel != quoted.AssuranceLevel || body.StableActionID != quoted.StableActionID ||
		body.ExactRequestDigest != quoted.ExactRequestDigest || body.RelayExecutionDigest != executionDigest ||
		body.SignedTransactionDigest != quoted.SignedTransactionDigest ||
		body.SignedTransactionCellHash != quoted.SignedTransactionCellHash ||
		body.TransactionValidUntilUnix != quoted.TransactionValidUntilUnix ||
		body.SourceAccount != quoted.SourceAccount || body.SourceSequence != quoted.SourceSequence ||
		!equalFinalityProfilePointers(body.RelayFinalityProfile, request.ProviderQuote.Body.RelayFinalityProfile) ||
		!equalFinalityProfilePointers(body.SponsorshipTerminalProfile,
			request.ProviderQuote.Body.SponsorshipTerminalProfile) {
		return errors.New("relay finality evidence conflicts with the exact execution and assurance level")
	}
	releaseProfile := quoted.SelectedSponsorshipReleaseProfile()
	references := append([]RelayAbsenceObservationReference(nil), body.SponsorshipAbsenceObservations...)
	references = append(references, body.TransactionAbsenceObservations...)
	for _, reference := range references {
		if reference.ObservationEvidenceProfileURI != releaseProfile.ProfileURI ||
			reference.ObservationEvidenceProfileDigest != releaseProfile.ProfileDigest {
			return errors.New("relay absence observation profile conflicts with the exact signed release profile")
		}
	}
	if err := validateRelayFinalityEvidenceMode(body, quoted.Mode); err != nil {
		return err
	}
	capability := relayEvidenceCapabilityForExecution(request)
	if finalityVerifier == nil || !finalityVerifier.SupportsRelayEvidenceCapability(capability) {
		return errors.New("client finality verifier is not ready for the exact signed capability")
	}
	if quoted.Mode == ModeSponsorAndRelay && !finalityVerifier.SupportsRelayDualAbsenceEvidence(capability) {
		return errors.New("client finality verifier cannot verify both sponsorship absence domains")
	}
	if quoted.Mode != ModeRelayExact &&
		!finalityVerifier.SupportsRelaySponsorshipComponentAbsenceEvidence(capability) {
		return errors.New("client finality verifier cannot verify component sponsorship absence")
	}
	if quoted.Mode == ModeSponsorAndRelay &&
		!finalityVerifier.SupportsRelayTransactionComponentAbsenceEvidence(capability) {
		return errors.New("client finality verifier cannot verify component transaction absence")
	}
	requiresPortable := quoted.AssuranceLevel == AssuranceAutonomousDecentralized ||
		quoted.RelayTerminalEvidenceClass == RelayTerminalValidatorFinality ||
		quoted.SponsorshipTerminalEvidenceClass == SponsorshipTerminalValidatorFinality
	if requiresPortable {
		portable, ok := finalityVerifier.(PortableRelayFinalityEvidenceVerifier)
		if !ok || !portable.HasIndependentPortableRelayFinalityProofs() {
			return errors.New("selected finality predicate requires independently verifiable portable relay evidence")
		}
	}
	if err := finalityVerifier.VerifyRelayFinality(ctx, request, signed); err != nil {
		return errors.New("verify relay finality evidence: " + err.Error())
	}
	hasSponsorshipAbsence := len(body.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(body.TransactionAbsenceObservations) != 0
	hasAnyAbsence := hasSponsorshipAbsence || hasTransactionAbsence
	if quoted.Mode == ModeRelayExact {
		if body.SponsorshipTransactionEvidence != nil || hasAnyAbsence ||
			body.SponsorshipStableActionID != "" || body.SponsorshipExactRequestDigest != "" ||
			body.SponsorshipValidUntilUnix != 0 || body.SponsorshipTransferReference != "" {
			return errors.New("relay-only finality evidence carries a sponsorship result")
		}
		return nil
	}
	if body.SponsorshipTransactionEvidence == nil {
		validSponsorOnlyAbsence := quoted.Mode == ModeSponsorOnly && hasSponsorshipAbsence &&
			!hasTransactionAbsence && safeTerminalAbsenceOutcome(body.Outcome)
		validCombinedDual := quoted.Mode == ModeSponsorAndRelay && hasSponsorshipAbsence &&
			hasTransactionAbsence && safeTerminalAbsenceOutcome(body.Outcome)
		validRelayOnly := quoted.Mode == ModeSponsorAndRelay && hasSponsorshipAbsence &&
			!hasTransactionAbsence && (body.Outcome == OutcomeFinalizedRelayOnly ||
			body.Outcome == OutcomeCorroboratedRelayOnly)
		if !validSponsorOnlyAbsence && !validCombinedDual && !validRelayOnly {
			return errors.New("sponsorship execution lacks transaction or typed absence evidence")
		}
		return nil
	}
	if sponsorshipVerifier == nil {
		return errors.New("independent sponsorship transaction evidence verifier is required")
	}
	evidence := *body.SponsorshipTransactionEvidence
	networkDigest, err := NetworkDomainDigest(quoted.Network)
	if err != nil || request.ProviderQuote.Body.ReservedSponsorship == nil {
		return errors.New("sponsorship execution context is incomplete")
	}
	expected := RelaySponsorshipEvidenceContext{AgreementBodyDigest: request.AgreementBodyDigest,
		AgreementObligationID: request.SponsorshipObligationID,
		PayerAgentID:          quoted.ProviderAgentID, PayeeAgentID: quoted.RequesterAgentID,
		NetworkID: quoted.Network.NetworkID, NetworkDomainDigest: networkDigest,
		DestinationSourceAccount: quoted.SourceAccount, Amount: *request.ProviderQuote.Body.ReservedSponsorship,
		MaximumExpiresAtUnix: request.ExpiresAtUnix, SponsorshipStableActionID: evidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: evidence.SponsorshipExactRequestDigest}
	if err := VerifySponsorshipPaymentRequestForEvidence(evidence.AgreementPaymentRequest, evidence, expected); err != nil {
		return err
	}
	if quoted.AssuranceLevel == AssuranceAutonomousDecentralized {
		portable, ok := sponsorshipVerifier.(PortableSponsorshipTransactionEvidenceVerifier)
		if evidence.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality ||
			!evidence.ValidatorAuthenticatedPortableProof || !ok ||
			!portable.HasIndependentPortableSponsorshipProofs() || evidence.PortableProofLocator == "" {
			return errors.New("autonomous sponsorship requires independently verifiable portable proof evidence")
		}
	} else if quoted.SponsorshipReleaseEvidenceClass == SponsorshipReleaseObservedUnproven {
		if evidence.TerminalEvidenceClass != SponsorshipTerminalClientCorroborated ||
			evidence.ValidatorAuthenticatedPortableProof ||
			request.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
			request.ProviderQuote.Body.SponsorshipTerminalProfile.ProfileURI != ClientCorroboratedTerminalProfileURI {
			return errors.New("lower-assurance RPC sponsorship requires explicitly corroborated terminal evidence")
		}
	} else if evidence.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality ||
		!evidence.ValidatorAuthenticatedPortableProof {
		return errors.New("validator-finality sponsorship profile requires validator-authenticated evidence")
	}
	if request.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		return errors.New("sponsorship execution lacks its signed terminal profile")
	}
	if err := sponsorshipVerifier.VerifySponsorshipTransactionEvidence(ctx, evidence, expected,
		*request.ProviderQuote.Body.SponsorshipTerminalProfile); err != nil {
		return errors.New("verify sponsorship transaction evidence: " + err.Error())
	}
	return nil
}

func relayEvidenceCapabilityForExecution(request RelayExecutionRequest) RelayEvidenceCapability {
	quoted := request.QuoteRequest.Body
	capability := RelayEvidenceCapability{Mode: quoted.Mode, AssuranceLevel: quoted.AssuranceLevel,
		Network: quoted.Network, TransactionProfileURI: quoted.TransactionProfileURI,
		TransactionProfileDigest:         quoted.TransactionProfileDigest,
		UnderlyingActionKind:             quoted.UnderlyingActionKind,
		RelayTerminalEvidenceClass:       quoted.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: quoted.SponsorshipTerminalEvidenceClass,
		SponsorshipReleaseProfile:        quoted.SelectedSponsorshipReleaseProfile()}
	if quoted.Mode != ModeRelayExact && quoted.AssuranceLevel != AssuranceAutonomousDecentralized {
		capability.AbsenceProofProfileURI = RelayAbsenceTOSRPCProofProfileURI
		capability.AbsenceProofProfileDigest, _ = RelayAbsenceTOSRPCProofProfileDigest()
	}
	if request.ProviderQuote.Body.RelayFinalityProfile != nil {
		profile := *request.ProviderQuote.Body.RelayFinalityProfile
		capability.RelayFinalityProfile = &profile
	}
	if request.ProviderQuote.Body.SponsorshipTerminalProfile != nil {
		profile := *request.ProviderQuote.Body.SponsorshipTerminalProfile
		capability.SponsorshipTerminalProfile = &profile
	}
	return capability
}

func equalFinalityProfilePointers(left, right *FinalityProfile) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validateRelayFinalityEvidenceMode(body RelayFinalityEvidenceBody, mode Mode) error {
	hasEvidence := body.SponsorshipTransactionEvidence != nil
	hasSponsorshipAbsence := len(body.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(body.TransactionAbsenceObservations) != 0
	hasAbsence := hasSponsorshipAbsence || hasTransactionAbsence
	hasSponsorshipIdentity := body.SponsorshipStableActionID != "" ||
		body.SponsorshipExactRequestDigest != "" || body.SponsorshipValidUntilUnix != 0
	if mode == ModeRelayExact {
		if body.RelayFinalityProfile == nil || body.SponsorshipTerminalProfile != nil ||
			hasEvidence || hasAbsence || hasSponsorshipIdentity || body.SponsorshipTransferReference != "" ||
			body.Outcome == OutcomeFinalizedSponsorshipOnly ||
			body.Outcome == OutcomeCorroboratedSponsorshipOnly {
			return errors.New("relay-only terminal evidence carries a sponsorship result")
		}
		return nil
	}
	if mode != ModeSponsorOnly && mode != ModeSponsorAndRelay {
		return errors.New("relay terminal evidence mode is invalid")
	}
	if body.SponsorshipTerminalProfile == nil ||
		(mode == ModeSponsorOnly && body.RelayFinalityProfile != nil) ||
		(mode == ModeSponsorAndRelay && body.RelayFinalityProfile == nil) {
		return errors.New("relay terminal evidence profile set conflicts with the selected mode")
	}
	if !hasEvidence {
		sponsorOnlyNegative := mode == ModeSponsorOnly && hasSponsorshipAbsence && !hasTransactionAbsence &&
			safeTerminalAbsenceOutcome(body.Outcome) && body.SubmittedTransactionHash == ""
		combinedNegative := mode == ModeSponsorAndRelay && hasSponsorshipAbsence && hasTransactionAbsence &&
			safeTerminalAbsenceOutcome(body.Outcome) && body.SubmittedTransactionHash == ""
		relayOnly := mode == ModeSponsorAndRelay && hasSponsorshipAbsence && !hasTransactionAbsence &&
			(body.Outcome == OutcomeFinalizedRelayOnly || body.Outcome == OutcomeCorroboratedRelayOnly) &&
			body.SubmittedTransactionHash != "" && body.SourceExecutionReference != ""
		if !hasAbsence || !hasSponsorshipIdentity || body.SponsorshipTransferReference != "" ||
			(!sponsorOnlyNegative && !combinedNegative && !relayOnly) {
			return errors.New("sponsorship execution lacks exact transaction or absence evidence")
		}
		return nil
	}
	if hasSponsorshipAbsence || body.SponsorshipTransferReference == "" {
		return errors.New("sponsorship transaction evidence conflicts with absence or transfer identity")
	}
	if mode == ModeSponsorOnly {
		if (body.Outcome != OutcomeFinalizedSponsorshipOnly &&
			body.Outcome != OutcomeCorroboratedSponsorshipOnly) ||
			body.SubmittedTransactionHash != "" || body.SourceExecutionReference != "" || hasTransactionAbsence {
			return errors.New("sponsor-only terminal evidence carries a relay result")
		}
		return nil
	}
	switch body.Outcome {
	case OutcomeFinalizedSponsorshipOnly, OutcomeCorroboratedSponsorshipOnly:
		if body.SubmittedTransactionHash != "" || body.SourceExecutionReference != "" {
			return errors.New("partial combined terminal evidence carries relay execution")
		}
	case OutcomeFinalizedSuccess, OutcomeCorroboratedSuccess:
		if body.SubmittedTransactionHash == "" || body.SourceExecutionReference == "" {
			return errors.New("combined terminal success lacks relay execution")
		}
	default:
		return errors.New("combined terminal outcome conflicts with its sponsorship side effect")
	}
	return nil
}

// VerifySponsorshipPaymentRequestForEvidence performs the deterministic part
// of sponsorship proof verification over the embedded canonical
// AgreementPaymentRequestV3.
func VerifySponsorshipPaymentRequestForEvidence(payment agentcommerce.AgreementPaymentRequest,
	evidence RelaySponsorshipTransactionEvidence, expected RelaySponsorshipEvidenceContext) error {
	if payment.SchemaVersion != 3 {
		return errors.New("sponsorship evidence requires AgreementPaymentRequestV3")
	}
	paymentDigest, err := agentcommerce.AgreementPaymentRequestDigest(payment)
	if err != nil || paymentDigest != evidence.AgreementPaymentRequestDigest {
		return errors.New("sponsorship payment request digest mismatch")
	}
	canonical, _, err := agentcommerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		return errors.New("sponsorship payment request is invalid")
	}
	exactDigest, err := agentcommerce.ExactRequestDigest(canonical)
	if err != nil || payment.StableActionID != evidence.SponsorshipStableActionID ||
		exactDigest != evidence.SponsorshipExactRequestDigest || payment.StableActionID != expected.SponsorshipStableActionID ||
		exactDigest != expected.SponsorshipExactRequestDigest || payment.AgreementBodyDigest != expected.AgreementBodyDigest ||
		payment.AgreementObligationID != expected.AgreementObligationID || payment.PayerAgentID != expected.PayerAgentID ||
		payment.AgentID != expected.PayerAgentID ||
		payment.PayeeAgentID != expected.PayeeAgentID || payment.NetworkID != expected.NetworkID ||
		payment.NetworkDomainDigest != expected.NetworkDomainDigest || string(payment.Destination) != expected.DestinationSourceAccount ||
		payment.SettlementAdapterURI != DirectPaymentAdapterURI ||
		payment.ExpiresAtUnix != evidence.ProviderSponsorValidUntilUnix || payment.ExpiresAtUnix > expected.MaximumExpiresAtUnix ||
		payment.Amount.AssetNamespace != expected.Amount.Asset.AssetNamespace ||
		payment.Amount.AssetIdentifier != expected.Amount.Asset.AssetIdentifier || payment.Amount.Unit != expected.Amount.Asset.Unit ||
		payment.Amount.AmountAtomic != expected.Amount.AmountAtomic {
		return errors.New("sponsorship payment request conflicts with the exact Agreement, obligation, route, or amount")
	}
	return nil
}

func signatureMessage(domain string, body any) ([]byte, error) {
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write([]byte(domain))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hasher.Write(length[:])
	hasher.Write(canonical)
	return hasher.Sum(nil), nil
}

func verifyAgentSignature(network NetworkDomain, agentID, encodedKey, encodedSignature, domain string, body any,
	resolver AgentKeyResolver, at time.Time) error {
	if resolver == nil {
		return errors.New("relay Agent authority resolver is required")
	}
	public, err := parsePublicKey(encodedKey)
	if err != nil || resolver.AuthorizeRelayKey(network, agentID, public, at.UTC()) != nil {
		return errors.New("relay signing key is not authorized")
	}
	signature, err := parseSignature(encodedSignature)
	if err != nil {
		return err
	}
	message, err := signatureMessage(domain, body)
	if err != nil || !ed25519.Verify(public, message, signature) {
		return errors.New("relay signature is invalid")
	}
	return nil
}

func parsePublicKey(value string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("relay public key scheme is invalid")
	}
	encoded := strings.TrimPrefix(value, "ed25519:")
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize || hex.EncodeToString(decoded) != encoded {
		return nil, errors.New("relay public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func parseSignature(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("relay signature scheme is invalid")
	}
	encoded := strings.TrimPrefix(value, "ed25519:")
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("relay signature is invalid")
	}
	return decoded, nil
}

// CompileRelayAgreementBinding creates the one non-circular projection used
// by every relay-related Agreement obligation.
func CompileRelayAgreementBinding(request SignedRelayQuoteRequest, quote SignedProviderRelayQuote) (RelayAgreementBinding, error) {
	requestDigest, err := RelayQuoteRequestDigest(request.Body)
	if err != nil {
		return RelayAgreementBinding{}, err
	}
	quoteDigest, err := ProviderRelayQuoteDigest(quote.Body)
	if err != nil || quote.Body.QuoteRequestDigest != requestDigest || quote.Body.Mode != request.Body.Mode ||
		quote.Body.AssuranceLevel != request.Body.AssuranceLevel ||
		quote.Body.RelayTerminalEvidenceClass != request.Body.RelayTerminalEvidenceClass ||
		quote.Body.SponsorshipTerminalEvidenceClass != request.Body.SponsorshipTerminalEvidenceClass ||
		quote.Body.SponsorshipReleaseEvidenceClass != request.Body.SponsorshipReleaseEvidenceClass ||
		quote.Body.SponsorshipReleaseProfileURI != request.Body.SponsorshipReleaseProfileURI ||
		quote.Body.SponsorshipReleaseProfileDigest != request.Body.SponsorshipReleaseProfileDigest ||
		!profilePointerMatchesSelection(quote.Body.RelayFinalityProfile, request.Body.RelayFinalityProfileURI,
			request.Body.RelayFinalityProfileDigest) ||
		!profilePointerMatchesSelection(quote.Body.SponsorshipTerminalProfile,
			request.Body.SponsorshipTerminalProfileURI, request.Body.SponsorshipTerminalProfileDigest) {
		return RelayAgreementBinding{}, errors.New("provider quote does not bind the quote request")
	}
	return RelayAgreementBinding{SchemaVersion: 1, QuoteRequestDigest: requestDigest, ProviderQuoteDigest: quoteDigest,
		ServiceProfileDigest: quote.Body.ServiceProfileDigest, Mode: request.Body.Mode,
		AssuranceLevel:                   request.Body.AssuranceLevel,
		SponsorshipReleaseEvidenceClass:  request.Body.SponsorshipReleaseEvidenceClass,
		SponsorshipReleaseProfileURI:     request.Body.SponsorshipReleaseProfileURI,
		SponsorshipReleaseProfileDigest:  request.Body.SponsorshipReleaseProfileDigest,
		RelayTerminalEvidenceClass:       request.Body.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: request.Body.SponsorshipTerminalEvidenceClass,
		RelayFinalityProfileURI:          request.Body.RelayFinalityProfileURI,
		RelayFinalityProfileDigest:       request.Body.RelayFinalityProfileDigest,
		SponsorshipTerminalProfileURI:    request.Body.SponsorshipTerminalProfileURI,
		SponsorshipTerminalProfileDigest: request.Body.SponsorshipTerminalProfileDigest,
		RequesterAgentID:                 request.Body.RequesterAgentID, ProviderAgentID: request.Body.ProviderAgentID,
		StableActionID: request.Body.StableActionID, ExactRequestDigest: request.Body.ExactRequestDigest,
		SignedTransactionDigest: request.Body.SignedTransactionDigest}, nil
}
