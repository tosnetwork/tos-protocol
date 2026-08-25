package agentcommerce

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// AgreementAuthorityKeyResolver resolves a purpose-limited key for the exact
// non-Agent subject frozen in an Agreement predicate.
type AgreementAuthorityKeyResolver interface {
	AuthorizeAgreementAuthorityKey(AgreementAuthoritySubject, ed25519.PublicKey, time.Time) error
}

// AuthoritySignatureEvidence converts one signed typed statement into the
// complete non-Agent authority predicate group selected by the Agreement.
func AuthoritySignatureEvidence(body AgentAgreementBody, acceptance SignedAgreementAcceptance) (AgreementAuthorizationEvidence, error) {
	if err := ValidateAgreementBody(body); err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	digest, err := AgreementBodyDigest(body)
	if err != nil || acceptance.Body.AgreementID != body.AgreementID || acceptance.Body.AgreementVersion != body.Version ||
		acceptance.Body.AgreementBodyDigest != digest {
		return AgreementAuthorizationEvidence{}, errors.New("typed authority acceptance does not target this Agreement")
	}
	var predicates []AgreementAuthorizationPredicate
	for _, predicate := range body.AuthorizationPredicates {
		if predicate.AuthoritySubject == acceptance.Body.AcceptingSubject && predicate.EvidenceProfileURI == EvidenceProfileAuthoritySignature {
			predicates = append(predicates, predicate)
		}
	}
	if len(predicates) == 0 || len(predicates) != len(acceptance.Body.PredicateIDs) {
		return AgreementAuthorizationEvidence{}, errors.New("typed authority acceptance does not cover one complete predicate group")
	}
	for index, predicate := range predicates {
		if predicate.EvidenceProfileVersion != 1 || predicate.EvidenceProfileDigest != AuthoritySignatureProfileDigest() ||
			predicate.PredicateID != acceptance.Body.PredicateIDs[index] ||
			predicate.EvidenceTargetProjectionDigest != acceptance.Body.EvidenceTargetProjectionDigests[index] {
			return AgreementAuthorizationEvidence{}, errors.New("typed authority acceptance predicate group is inconsistent")
		}
	}
	canonical, err := codec.Marshal(acceptance)
	if err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	return AgreementAuthorizationEvidence{AgreementID: body.AgreementID, AgreementVersion: body.Version,
		AgreementBodyDigest: digest, AuthoritySubject: acceptance.Body.AcceptingSubject,
		PredicateIDs: append([]string(nil), acceptance.Body.PredicateIDs...), EvidenceProfileURI: EvidenceProfileAuthoritySignature,
		EvidenceProfileVersion: 1, EvidenceProfileDigest: AuthoritySignatureProfileDigest(),
		EvidenceTargetProjectionDigests: append([]string(nil), acceptance.Body.EvidenceTargetProjectionDigests...),
		EvidenceContentType:             AuthorityAcceptanceContentType, Evidence: canonical}, nil
}

type AuthoritySignatureEvidenceVerifier struct{ Resolver AgreementAuthorityKeyResolver }

func (verifier AuthoritySignatureEvidenceVerifier) VerifyAgreementEvidence(evidence AgreementAuthorizationEvidence, now time.Time) error {
	if verifier.Resolver == nil || evidence.EvidenceProfileURI != EvidenceProfileAuthoritySignature || evidence.EvidenceProfileVersion != 1 ||
		evidence.EvidenceProfileDigest != AuthoritySignatureProfileDigest() || evidence.EvidenceContentType != AuthorityAcceptanceContentType {
		return errors.New("unsupported Agreement authority evidence profile")
	}
	acceptance, err := DecodeSignedAgreementAcceptance(evidence.Evidence)
	if err != nil || acceptance.Body.AgreementID != evidence.AgreementID || acceptance.Body.AgreementVersion != evidence.AgreementVersion ||
		acceptance.Body.AgreementBodyDigest != evidence.AgreementBodyDigest || acceptance.Body.AcceptingSubject != evidence.AuthoritySubject ||
		!equalStrings(acceptance.Body.PredicateIDs, evidence.PredicateIDs) ||
		!equalStrings(acceptance.Body.EvidenceTargetProjectionDigests, evidence.EvidenceTargetProjectionDigests) ||
		!now.UTC().Before(time.Unix(int64(acceptance.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("authority acceptance does not match evidence")
	}
	publicKey, err := parseEd25519PublicKey(acceptance.PublicKey)
	if err != nil {
		return err
	}
	if err := verifier.Resolver.AuthorizeAgreementAuthorityKey(evidence.AuthoritySubject, publicKey, now); err != nil {
		return err
	}
	signature, err := parseEd25519Signature(acceptance.Signature)
	if err != nil {
		return err
	}
	canonical, err := codec.Marshal(acceptance.Body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, framedSHA256("tos.agreement-acceptance-signature.v1\x00", canonical), signature) {
		return errors.New("Agreement authority acceptance signature is invalid")
	}
	return nil
}

// PaidDemandQuoteBindingBody is the generic Agreement side of the optional
// TOS Accepted-Quote profile. Native Quote details remain in the chain profile;
// these commitments prevent their evidence being reused for another Agreement.
type PaidDemandQuoteBindingBody struct {
	SchemaVersion                       uint16   `json:"schema_version"`
	NetworkContext                      string   `json:"network_context"`
	AgreementBodyDigest                 string   `json:"agreement_body_digest"`
	AgreementObligationIDs              []string `json:"agreement_obligation_ids"`
	AgreementAuthorizationPredicateIDs  []string `json:"agreement_authorization_predicate_ids"`
	AgreementAuthorizationTargetDigests []string `json:"agreement_authorization_target_digests"`
	EvidenceProfileURI                  string   `json:"evidence_profile_uri"`
	EvidenceProfileVersion              uint32   `json:"evidence_profile_version"`
	EvidenceProfileDigest               string   `json:"evidence_profile_digest"`
	DemandMutationDigest                string   `json:"demand_mutation_digest"`
	ProviderOfferID                     string   `json:"provider_offer_id"`
	ProviderAgentID                     string   `json:"provider_agent_id"`
	BuyerAgentID                        string   `json:"buyer_agent_id"`
	BuyerWallet                         string   `json:"buyer_wallet"`
	ProviderWallet                      string   `json:"provider_wallet"`
	NativeQuoteTermsProjectionDigest    string   `json:"native_quote_terms_projection_digest"`
	AcceptByUnix                        uint64   `json:"accept_by_unix"`
}

type ProviderProofContext struct {
	SchemaVersion                    uint16 `json:"schema_version"`
	NetworkContext                   string `json:"network_context"`
	ProviderAgentID                  string `json:"provider_agent_id"`
	Purpose                          string `json:"purpose"`
	PublicKey                        string `json:"public_key"`
	AgentGeneration                  uint64 `json:"agent_generation"`
	ControllerPolicyDigest           string `json:"controller_policy_digest"`
	DelegationDigest                 string `json:"delegation_digest"`
	ScopeBoundsDigest                string `json:"scope_bounds_digest"`
	OwnerMandateDigest               string `json:"owner_mandate_digest"`
	IssuanceAuthorityReferenceDigest string `json:"issuance_authority_reference_digest"`
	ValidFromUnix                    uint64 `json:"valid_from_unix"`
	ExpiresAtUnix                    uint64 `json:"expires_at_unix"`
}

type SignedProviderOffer struct {
	Binding   PaidDemandQuoteBindingBody `json:"binding"`
	Context   ProviderProofContext       `json:"context"`
	Signature string                     `json:"signature"`
}

type ProviderOfferKeyResolver interface {
	AuthorizeProviderOfferKey(ProviderProofContext, PaidDemandQuoteBindingBody, ed25519.PublicKey, time.Time) error
}

func SignProviderOffer(binding PaidDemandQuoteBindingBody, context ProviderProofContext, privateKey ed25519.PrivateKey) (SignedProviderOffer, error) {
	if err := validateProviderProofContext(binding, context); err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return SignedProviderOffer{}, errors.New("Provider Offer signing input is invalid")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if context.PublicKey != "ed25519:"+hex.EncodeToString(publicKey) {
		return SignedProviderOffer{}, errors.New("Provider Offer proof key mismatch")
	}
	payload, err := providerOfferSignaturePayload(binding, context)
	if err != nil {
		return SignedProviderOffer{}, err
	}
	return SignedProviderOffer{Binding: binding, Context: context,
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}, nil
}

func VerifyProviderOffer(offer SignedProviderOffer, resolver ProviderOfferKeyResolver, now time.Time) error {
	if resolver == nil || validateProviderProofContext(offer.Binding, offer.Context) != nil ||
		!now.UTC().Before(time.Unix(int64(offer.Context.ExpiresAtUnix), 0).UTC()) {
		return errors.New("Provider Offer proof is invalid or expired")
	}
	publicKey, err := parseEd25519PublicKey(offer.Context.PublicKey)
	if err != nil {
		return err
	}
	if err := resolver.AuthorizeProviderOfferKey(offer.Context, offer.Binding, publicKey, now); err != nil {
		return err
	}
	signature, err := parseEd25519Signature(offer.Signature)
	if err != nil {
		return err
	}
	payload, err := providerOfferSignaturePayload(offer.Binding, offer.Context)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("Provider Offer signature is invalid")
	}
	return nil
}

func ProviderOfferDigest(offer SignedProviderOffer) (string, error) {
	if validateProviderProofContext(offer.Binding, offer.Context) != nil {
		return "", errors.New("Provider Offer is invalid")
	}
	if _, err := parseEd25519Signature(offer.Signature); err != nil {
		return "", err
	}
	return codec.Digest("tos.paid-demand-provider-offer.v1", offer)
}

func validateProviderProofContext(binding PaidDemandQuoteBindingBody, context ProviderProofContext) error {
	if _, err := parseEd25519PublicKey(context.PublicKey); err != nil {
		return errors.New("Provider proof context public key is invalid")
	}
	if ValidatePaidDemandQuoteBinding(binding) != nil || context.SchemaVersion != 1 || context.NetworkContext != binding.NetworkContext ||
		context.ProviderAgentID != binding.ProviderAgentID || context.Purpose != "provider-offer.sign" ||
		context.AgentGeneration == 0 ||
		!canonicalDigestPattern.MatchString(context.ControllerPolicyDigest) || !canonicalDigestPattern.MatchString(context.DelegationDigest) ||
		!canonicalDigestPattern.MatchString(context.ScopeBoundsDigest) || !canonicalDigestPattern.MatchString(context.OwnerMandateDigest) ||
		!canonicalDigestPattern.MatchString(context.IssuanceAuthorityReferenceDigest) || context.ValidFromUnix == 0 ||
		context.ExpiresAtUnix < binding.AcceptByUnix || context.ExpiresAtUnix <= context.ValidFromUnix {
		return errors.New("Provider proof context is invalid or does not cover Quote acceptance")
	}
	return nil
}

func providerOfferSignaturePayload(binding PaidDemandQuoteBindingBody, context ProviderProofContext) ([]byte, error) {
	bindingDigest, err := PaidDemandQuoteBindingDigest(binding)
	if err != nil {
		return nil, err
	}
	contextDigest, err := codec.Digest("tos.paid-demand-provider-proof-context.v1", context)
	if err != nil {
		return nil, err
	}
	canonical, err := codec.Marshal(struct {
		BindingDigest string `json:"binding_digest"`
		ContextDigest string `json:"context_digest"`
	}{bindingDigest, contextDigest})
	if err != nil {
		return nil, err
	}
	return framedSHA256("tos.paid-demand-provider-offer-signature.v1\x00", canonical), nil
}

var canonicalTVMCellDigestPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)

func ValidatePaidDemandQuoteBinding(body PaidDemandQuoteBindingBody) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.NetworkContext, 256) || !canonicalDigestPattern.MatchString(body.AgreementBodyDigest) ||
		validateSortedStrings(body.AgreementObligationIDs, MaxAgreementObligations, 128) != nil || len(body.AgreementObligationIDs) == 0 ||
		validateSortedStrings(body.AgreementAuthorizationPredicateIDs, MaxAgreementPredicates, 128) != nil || len(body.AgreementAuthorizationPredicateIDs) == 0 ||
		len(body.AgreementAuthorizationPredicateIDs) != len(body.AgreementAuthorizationTargetDigests) ||
		body.EvidenceProfileURI != EvidenceProfilePaidDemandQuote || body.EvidenceProfileVersion != 1 || body.EvidenceProfileDigest != PaidDemandQuoteProfileDigest() ||
		!canonicalDigestPattern.MatchString(body.DemandMutationDigest) || !boundedIdentifier(body.ProviderOfferID, 256) ||
		!boundedIdentifier(body.ProviderAgentID, 256) || !boundedIdentifier(body.BuyerAgentID, 256) ||
		!boundedIdentifier(body.BuyerWallet, 256) || !boundedIdentifier(body.ProviderWallet, 256) ||
		!canonicalTVMCellDigestPattern.MatchString(body.NativeQuoteTermsProjectionDigest) || body.AcceptByUnix == 0 {
		return errors.New("Paid Demand Quote binding is invalid")
	}
	for _, target := range body.AgreementAuthorizationTargetDigests {
		if !canonicalDigestPattern.MatchString(target) {
			return errors.New("Paid Demand Quote binding target is invalid")
		}
	}
	return nil
}

// ValidatePaidDemandAgreementBinding proves the complete one-way projection:
// canonical Agreement -> binding -> native Quote. The native terms projection
// explicitly excludes the binding extension, avoiding a commitment cycle.
func ValidatePaidDemandAgreementBinding(agreement AgentAgreementBody, body PaidDemandQuoteBindingBody) error {
	if err := ValidateAgreementBody(agreement); err != nil || ValidatePaidDemandQuoteBinding(body) != nil {
		return errors.New("Paid Demand Agreement or binding is invalid")
	}
	digest, err := AgreementBodyDigest(agreement)
	if err != nil || body.AgreementBodyDigest != digest || body.NetworkContext != agreement.NetworkContext ||
		body.AcceptByUnix > agreement.ExpiresAtUnix {
		return errors.New("Paid Demand binding targets another Agreement or validity window")
	}
	boundObligations := make(map[string]bool, len(body.AgreementObligationIDs))
	for _, id := range body.AgreementObligationIDs {
		boundObligations[id] = true
	}
	for id := range boundObligations {
		found := false
		for _, obligation := range agreement.Obligations {
			found = found || obligation.ObligationID == id
		}
		if !found {
			return errors.New("Paid Demand binding names an absent Agreement obligation")
		}
	}
	boundPredicates := make(map[string]int, len(body.AgreementAuthorizationPredicateIDs))
	for index, id := range body.AgreementAuthorizationPredicateIDs {
		boundPredicates[id] = index
	}
	providerFound, buyerFound := false, false
	for _, predicate := range agreement.AuthorizationPredicates {
		index, included := boundPredicates[predicate.PredicateID]
		if predicate.EvidenceProfileURI == EvidenceProfilePaidDemandQuote && !included {
			return errors.New("Paid Demand binding omits a profile predicate")
		}
		if !included {
			continue
		}
		if predicate.EvidenceProfileURI != EvidenceProfilePaidDemandQuote || predicate.EvidenceProfileVersion != 1 ||
			predicate.EvidenceProfileDigest != PaidDemandQuoteProfileDigest() ||
			predicate.EvidenceTargetProjectionDigest != body.AgreementAuthorizationTargetDigests[index] ||
			predicate.ExpiresAtUnix < body.AcceptByUnix {
			return errors.New("Paid Demand binding predicate profile, target, or validity mismatch")
		}
		scoped := false
		for _, id := range predicate.ObligationIDs {
			scoped = scoped || boundObligations[id]
		}
		if !scoped {
			return errors.New("Paid Demand predicate has no bound obligation scope")
		}
		subject := predicate.AuthoritySubject
		providerFound = providerFound || subject.SubjectKind == "agent" && subject.SubjectIdentifier == body.ProviderAgentID
		buyerFound = buyerFound || subject.SubjectKind == "wallet" && subject.SubjectIdentifier == body.BuyerWallet &&
			subject.RepresentedAgentID == body.BuyerAgentID
	}
	if !providerFound || !buyerFound {
		return errors.New("Paid Demand binding lacks exact Provider or represented buyer-wallet authority")
	}
	return nil
}

func PaidDemandQuoteBindingDigest(body PaidDemandQuoteBindingBody) (string, error) {
	if err := ValidatePaidDemandQuoteBinding(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.paid-demand-quote-binding-body.v1", body)
}

type PaidDemandQuoteEvidence struct {
	Binding           PaidDemandQuoteBindingBody `json:"binding"`
	EvidenceKind      string                     `json:"evidence_kind"`
	NativeEvidence    []byte                     `json:"native_evidence"`
	FinalizedAtUnix   uint64                     `json:"finalized_at_unix"`
	FinalityReference string                     `json:"finality_reference"`
}

func PaidDemandEvidenceFromBinding(agreement AgentAgreementBody, subject AgreementAuthoritySubject,
	binding PaidDemandQuoteBindingBody, evidenceKind string, nativeEvidence []byte, finalizedAt uint64, finalityReference string) (AgreementAuthorizationEvidence, error) {
	if err := ValidateAgreementBody(agreement); err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	agreementDigest, err := AgreementBodyDigest(agreement)
	if err != nil || ValidatePaidDemandAgreementBinding(agreement, binding) != nil || binding.AgreementBodyDigest != agreementDigest ||
		len(nativeEvidence) == 0 || len(nativeEvidence) > MaxAgreementEvidenceBytes || finalizedAt == 0 || !boundedIdentifier(finalityReference, 512) {
		return AgreementAuthorizationEvidence{}, errors.New("Paid Demand evidence is not bound to the exact Agreement")
	}
	contentType := ""
	switch evidenceKind {
	case "buyer_accept":
		contentType = PaidDemandBuyerAcceptContentType
		if subject.SubjectKind != "wallet" || subject.SubjectIdentifier != binding.BuyerWallet || subject.RepresentedAgentID != binding.BuyerAgentID {
			return AgreementAuthorizationEvidence{}, errors.New("Paid Demand buyer evidence subject mismatch")
		}
	case "provider_offer":
		contentType = PaidDemandProviderOfferContentType
		if subject.SubjectKind != "agent" || subject.SubjectIdentifier != binding.ProviderAgentID {
			return AgreementAuthorizationEvidence{}, errors.New("Paid Demand Provider evidence subject mismatch")
		}
	default:
		return AgreementAuthorizationEvidence{}, errors.New("unknown Paid Demand evidence kind")
	}
	var predicateIDs, targets []string
	for _, predicate := range agreement.AuthorizationPredicates {
		if predicate.AuthoritySubject == subject && predicate.EvidenceProfileURI == EvidenceProfilePaidDemandQuote {
			predicateIDs = append(predicateIDs, predicate.PredicateID)
			targets = append(targets, predicate.EvidenceTargetProjectionDigest)
		}
	}
	if len(predicateIDs) == 0 || !orderedSubsetPairs(predicateIDs, targets, binding.AgreementAuthorizationPredicateIDs, binding.AgreementAuthorizationTargetDigests) {
		return AgreementAuthorizationEvidence{}, errors.New("Paid Demand predicate group is absent from Quote binding")
	}
	payload := PaidDemandQuoteEvidence{Binding: binding, EvidenceKind: evidenceKind, NativeEvidence: nativeEvidence,
		FinalizedAtUnix: finalizedAt, FinalityReference: finalityReference}
	canonical, err := codec.Marshal(payload)
	if err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	return AgreementAuthorizationEvidence{AgreementID: agreement.AgreementID, AgreementVersion: agreement.Version, AgreementBodyDigest: agreementDigest,
		AuthoritySubject: subject, PredicateIDs: predicateIDs, EvidenceProfileURI: EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1,
		EvidenceProfileDigest: PaidDemandQuoteProfileDigest(), EvidenceTargetProjectionDigests: targets, EvidenceContentType: contentType, Evidence: canonical}, nil
}

func orderedSubsetPairs(ids, targets, allIDs, allTargets []string) bool {
	index := 0
	for offset, id := range allIDs {
		if index < len(ids) && id == ids[index] && allTargets[offset] == targets[index] {
			index++
		}
	}
	return index == len(ids)
}

type PaidDemandNativeEvidenceVerifier interface {
	VerifyPaidDemandNativeEvidence(PaidDemandQuoteBindingBody, string, []byte, uint64, string, time.Time) error
}

type PaidDemandQuoteEvidenceVerifier struct {
	Native PaidDemandNativeEvidenceVerifier
}

func (verifier PaidDemandQuoteEvidenceVerifier) VerifyAgreementEvidence(evidence AgreementAuthorizationEvidence, now time.Time) error {
	if verifier.Native == nil || evidence.EvidenceProfileURI != EvidenceProfilePaidDemandQuote || evidence.EvidenceProfileVersion != 1 ||
		evidence.EvidenceProfileDigest != PaidDemandQuoteProfileDigest() {
		return errors.New("unsupported Paid Demand Quote evidence profile")
	}
	var payload PaidDemandQuoteEvidence
	if err := codec.Unmarshal(evidence.Evidence, &payload); err != nil || ValidatePaidDemandQuoteBinding(payload.Binding) != nil ||
		payload.Binding.AgreementBodyDigest != evidence.AgreementBodyDigest || payload.Binding.EvidenceProfileDigest != evidence.EvidenceProfileDigest ||
		!orderedSubsetPairs(evidence.PredicateIDs, evidence.EvidenceTargetProjectionDigests,
			payload.Binding.AgreementAuthorizationPredicateIDs, payload.Binding.AgreementAuthorizationTargetDigests) || payload.FinalizedAtUnix == 0 {
		return errors.New("Paid Demand Quote evidence binding mismatch")
	}
	expectedType := PaidDemandBuyerAcceptContentType
	if payload.EvidenceKind == "provider_offer" {
		expectedType = PaidDemandProviderOfferContentType
	} else if payload.EvidenceKind != "buyer_accept" {
		return errors.New("unknown Paid Demand Quote evidence kind")
	}
	if evidence.EvidenceContentType != expectedType {
		return errors.New("Paid Demand Quote evidence content type mismatch")
	}
	return verifier.Native.VerifyPaidDemandNativeEvidence(payload.Binding, payload.EvidenceKind, payload.NativeEvidence,
		payload.FinalizedAtUnix, payload.FinalityReference, now)
}
