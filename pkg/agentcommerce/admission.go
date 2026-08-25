package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const MaxAdmissionLifetime = 10 * time.Minute

type OperationAdmissionChallengeBody struct {
	SchemaVersion        uint16 `json:"schema_version"`
	ProfileURI           string `json:"profile_uri"`
	CarrierID            string `json:"carrier_id"`
	ActorID              string `json:"actor_id"`
	OperationKind        string `json:"operation_kind"`
	Audience             string `json:"audience"`
	DeclaredBytes        uint64 `json:"declared_bytes"`
	ResourceVectorDigest string `json:"resource_vector_digest"`
	ChallengeNonce       string `json:"challenge_nonce"`
	DifficultyBits       uint8  `json:"difficulty_bits"`
	IssuedAtUnix         uint64 `json:"issued_at_unix"`
	ExpiresAtUnix        uint64 `json:"expires_at_unix"`
}

type SignedOperationAdmissionChallenge struct {
	Body      OperationAdmissionChallengeBody `json:"body"`
	PublicKey string                          `json:"public_key"`
	Signature string                          `json:"signature"`
}

type OperationAdmissionProof struct {
	SchemaVersion   uint16                            `json:"schema_version"`
	Challenge       SignedOperationAdmissionChallenge `json:"challenge"`
	ChallengeDigest string                            `json:"challenge_digest"`
	Counter         uint64                            `json:"counter"`
}

func NewOperationAdmissionChallenge(body OperationAdmissionChallengeBody, key ed25519.PrivateKey) (SignedOperationAdmissionChallenge, error) {
	if body.ChallengeNonce == "" {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return SignedOperationAdmissionChallenge{}, err
		}
		body.ChallengeNonce = base64.RawURLEncoding.EncodeToString(nonce)
	}
	if err := validateAdmissionChallenge(body, time.Unix(int64(body.IssuedAtUnix), 0).UTC()); err != nil || len(key) != ed25519.PrivateKeySize {
		return SignedOperationAdmissionChallenge{}, errors.New("operation admission challenge is invalid")
	}
	message, err := admissionSignatureMessage(body)
	if err != nil {
		return SignedOperationAdmissionChallenge{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return SignedOperationAdmissionChallenge{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func OperationAdmissionChallengeDigest(body OperationAdmissionChallengeBody) (string, error) {
	return codec.Digest("tos.operation-admission-challenge.v1", body)
}

func SolveOperationAdmission(challenge SignedOperationAdmissionChallenge, maximumAttempts uint64) (OperationAdmissionProof, error) {
	digest, err := OperationAdmissionChallengeDigest(challenge.Body)
	if err != nil || maximumAttempts == 0 {
		return OperationAdmissionProof{}, errors.New("operation admission solve request is invalid")
	}
	for counter := uint64(0); counter < maximumAttempts; counter++ {
		if admissionWorkValid(digest, counter, challenge.Body.DifficultyBits) {
			return OperationAdmissionProof{SchemaVersion: 1, Challenge: challenge, ChallengeDigest: digest, Counter: counter}, nil
		}
	}
	return OperationAdmissionProof{}, errors.New("operation admission work bound exhausted")
}

func VerifyOperationAdmission(proof OperationAdmissionProof, expectedCarrierPublicKey ed25519.PublicKey,
	actorID, operationKind, audience string, declaredBytes uint64, resourceVectorDigest string, now time.Time) error {
	if proof.SchemaVersion != 1 || len(expectedCarrierPublicKey) != ed25519.PublicKeySize {
		return errors.New("operation admission proof is invalid")
	}
	body := proof.Challenge.Body
	if err := validateAdmissionChallenge(body, now.UTC()); err != nil || body.ActorID != actorID || body.OperationKind != operationKind ||
		body.Audience != audience || body.DeclaredBytes != declaredBytes || body.ResourceVectorDigest != resourceVectorDigest {
		return errors.New("operation admission proof does not bind the exact operation")
	}
	public, err := parseEd25519PublicKey(proof.Challenge.PublicKey)
	if err != nil || !expectedCarrierPublicKey.Equal(public) {
		return errors.New("operation admission challenge has the wrong Carrier key")
	}
	signature, err := parseEd25519Signature(proof.Challenge.Signature)
	message, messageErr := admissionSignatureMessage(body)
	if err != nil || messageErr != nil || !ed25519.Verify(public, message, signature) {
		return errors.New("operation admission challenge signature is invalid")
	}
	digest, err := OperationAdmissionChallengeDigest(body)
	if err != nil || digest != proof.ChallengeDigest || !admissionWorkValid(digest, proof.Counter, body.DifficultyBits) {
		return errors.New("operation admission proof of work is invalid")
	}
	return nil
}

func validateAdmissionChallenge(body OperationAdmissionChallengeBody, now time.Time) error {
	if body.SchemaVersion != 1 || body.ProfileURI != "tos.operation-admission.hashcash.v1" || !boundedIdentifier(body.CarrierID, 256) ||
		!boundedIdentifier(body.ActorID, 256) || !canonicalLowerToken(body.OperationKind) || !boundedIdentifier(body.Audience, 256) ||
		body.DeclaredBytes == 0 || body.DeclaredBytes > MaxActionRequestBytes || !canonicalDigestPattern.MatchString(body.ResourceVectorDigest) ||
		body.DifficultyBits > 24 || body.IssuedAtUnix == 0 || body.ExpiresAtUnix <= body.IssuedAtUnix {
		return errors.New("operation admission challenge fields are invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(body.ChallengeNonce)
	if err != nil || len(nonce) != 32 {
		return errors.New("operation admission challenge nonce is invalid")
	}
	issued := time.Unix(int64(body.IssuedAtUnix), 0).UTC()
	expires := time.Unix(int64(body.ExpiresAtUnix), 0).UTC()
	if expires.Sub(issued) > MaxAdmissionLifetime || issued.After(now.UTC().Add(MaxIntentClockSkew)) || !now.UTC().Before(expires) {
		return errors.New("operation admission challenge time bounds are invalid")
	}
	return nil
}

func admissionWorkValid(challengeDigest string, counter uint64, difficulty uint8) bool {
	if !canonicalDigestPattern.MatchString(challengeDigest) {
		return false
	}
	decoded, err := hex.DecodeString(challengeDigest[len("sha256:"):])
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	hasher := sha256.New()
	hasher.Write([]byte("tos.operation-admission-work.v1\x00"))
	hasher.Write(decoded)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], counter)
	hasher.Write(encoded[:])
	work := hasher.Sum(nil)
	remaining := int(difficulty)
	for _, value := range work {
		if remaining <= 0 {
			return true
		}
		zeros := bits.LeadingZeros8(value)
		if remaining <= 8 {
			return zeros >= remaining
		}
		if zeros != 8 {
			return false
		}
		remaining -= 8
	}
	return remaining <= 0
}

func admissionSignatureMessage(body OperationAdmissionChallengeBody) ([]byte, error) {
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(append([]byte("tos.operation-admission-challenge-signature.v1\x00"), canonical...))
	return hash[:], nil
}

func AdmissionResourceVectorDigest(operationKind string, declaredBytes uint64, units map[string]uint64) (string, error) {
	if !canonicalLowerToken(operationKind) || declaredBytes == 0 || len(units) > 32 {
		return "", errors.New("operation resource vector is invalid")
	}
	for name := range units {
		if !canonicalLowerToken(name) {
			return "", fmt.Errorf("operation resource unit %q is invalid", name)
		}
	}
	return codec.Digest("tos.operation-admission-resource-vector.v1", struct {
		OperationKind string            `json:"operation_kind"`
		DeclaredBytes uint64            `json:"declared_bytes"`
		Units         map[string]uint64 `json:"units"`
	}{operationKind, declaredBytes, units})
}
