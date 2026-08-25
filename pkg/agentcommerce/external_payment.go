package agentcommerce

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const ExternalPaymentEvidenceProfileV1 = "tos.payment.external-attested.v1"

// ExternalPaymentAttestationBody is a narrow evidence class for an external
// settlement adapter. It is not authority to initiate payment: it can only
// attest that one exact, already-authorized AgreementPaymentRequest reached a
// final transfer reference under an owner-pinned adapter authority.
type ExternalPaymentAttestationBody struct {
	SchemaVersion          uint16 `json:"schema_version"`
	AdapterURI             string `json:"adapter_uri"`
	AttestorID             string `json:"attestor_id"`
	PaymentRequestDigest   string `json:"payment_request_digest"`
	StableActionID         string `json:"stable_action_id"`
	ExactTransferReference string `json:"exact_transfer_reference"`
	FinalityReference      string `json:"finality_reference"`
	ResolvedAtUnix         uint64 `json:"resolved_at_unix"`
	ExpiresAtUnix          uint64 `json:"expires_at_unix"`
}

type SignedExternalPaymentAttestation struct {
	Body      ExternalPaymentAttestationBody `json:"body"`
	PublicKey string                         `json:"public_key"`
	Signature string                         `json:"signature"`
}

type ExternalPaymentAttestorResolver interface {
	AuthorizeExternalPaymentAttestor(attestorID, adapterURI string, publicKey ed25519.PublicKey, at time.Time) error
}

func ExternalPaymentAttestationDigest(body ExternalPaymentAttestationBody) (string, error) {
	if err := validateExternalPaymentAttestation(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.external-payment-attestation-body.v1", body)
}

func SignExternalPaymentAttestation(body ExternalPaymentAttestationBody,
	key ed25519.PrivateKey) (SignedExternalPaymentAttestation, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedExternalPaymentAttestation{}, errors.New("external payment attestor key is invalid")
	}
	digest, err := ExternalPaymentAttestationDigest(body)
	if err != nil {
		return SignedExternalPaymentAttestation{}, err
	}
	message := sha256.Sum256([]byte("TOS-EXTERNAL-PAYMENT-ATTESTATION-V1\x00" + digest))
	public := key.Public().(ed25519.PublicKey)
	return SignedExternalPaymentAttestation{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message[:]))}, nil
}

func VerifyExternalPaymentAttestation(attestation SignedExternalPaymentAttestation,
	resolver ExternalPaymentAttestorResolver, now time.Time) error {
	if resolver == nil || now.Unix() < 0 || uint64(now.Unix()) >= attestation.Body.ExpiresAtUnix ||
		attestation.Body.ResolvedAtUnix > uint64(now.Unix()) {
		return errors.New("external payment attestation is expired or has no authority")
	}
	public, err := parseEd25519PublicKey(attestation.PublicKey)
	if err != nil {
		return err
	}
	if err := resolver.AuthorizeExternalPaymentAttestor(attestation.Body.AttestorID, attestation.Body.AdapterURI, public, now); err != nil {
		return err
	}
	signature, err := parseEd25519Signature(attestation.Signature)
	if err != nil {
		return err
	}
	digest, err := ExternalPaymentAttestationDigest(attestation.Body)
	if err != nil {
		return err
	}
	message := sha256.Sum256([]byte("TOS-EXTERNAL-PAYMENT-ATTESTATION-V1\x00" + digest))
	if !ed25519.Verify(public, message[:], signature) {
		return errors.New("external payment attestation signature is invalid")
	}
	return nil
}

func ExternalPaymentEvidence(request AgreementPaymentRequest, attestation SignedExternalPaymentAttestation,
	resolver ExternalPaymentAttestorResolver, now time.Time) (AgreementPaymentEvidence, error) {
	requestDigest, err := AgreementPaymentRequestDigest(request)
	if err != nil || VerifyExternalPaymentAttestation(attestation, resolver, now) != nil ||
		attestation.Body.PaymentRequestDigest != requestDigest || attestation.Body.StableActionID != request.StableActionID ||
		attestation.Body.AdapterURI != request.SettlementAdapterURI {
		return AgreementPaymentEvidence{}, errors.New("external payment attestation does not bind the exact payment request")
	}
	canonical, err := codec.Marshal(attestation)
	if err != nil {
		return AgreementPaymentEvidence{}, err
	}
	return AgreementPaymentEvidence{PaymentRequestDigest: requestDigest, StableActionID: request.StableActionID,
		ExactTransferReference: attestation.Body.ExactTransferReference, AdapterEvidenceProfile: ExternalPaymentEvidenceProfileV1,
		ResolvedState: "finalized", ResolvedAtUnix: attestation.Body.ResolvedAtUnix,
		FinalityReference: attestation.Body.FinalityReference, Evidence: canonical}, nil
}

type ExternalPaymentEvidenceVerifier struct {
	Resolver ExternalPaymentAttestorResolver
}

func (verifier ExternalPaymentEvidenceVerifier) VerifyPaymentEvidence(request AgreementPaymentRequest,
	evidence AgreementPaymentEvidence, now time.Time) error {
	if evidence.AdapterEvidenceProfile != ExternalPaymentEvidenceProfileV1 {
		return errors.New("external payment evidence profile is incorrect")
	}
	var attestation SignedExternalPaymentAttestation
	if err := codec.Unmarshal(evidence.Evidence, &attestation); err != nil {
		return err
	}
	rebuilt, err := ExternalPaymentEvidence(request, attestation, verifier.Resolver, now)
	if err != nil || rebuilt.PaymentRequestDigest != evidence.PaymentRequestDigest || rebuilt.StableActionID != evidence.StableActionID ||
		rebuilt.ExactTransferReference != evidence.ExactTransferReference || rebuilt.ResolvedAtUnix != evidence.ResolvedAtUnix ||
		rebuilt.FinalityReference != evidence.FinalityReference {
		return errors.New("external payment evidence conflicts with its signed attestation")
	}
	return nil
}

func validateExternalPaymentAttestation(body ExternalPaymentAttestationBody) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.AdapterURI, 256) || !boundedIdentifier(body.AttestorID, 256) ||
		!canonicalDigestPattern.MatchString(body.PaymentRequestDigest) || !canonicalDigestPattern.MatchString(body.StableActionID) ||
		!boundedIdentifier(body.ExactTransferReference, 1024) || !boundedIdentifier(body.FinalityReference, 1024) ||
		body.ResolvedAtUnix == 0 || body.ExpiresAtUnix <= body.ResolvedAtUnix || body.ExpiresAtUnix-body.ResolvedAtUnix > uint64((90*24*time.Hour)/time.Second) {
		return errors.New("external payment attestation body is invalid")
	}
	return nil
}
