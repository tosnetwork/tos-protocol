package agentcommerce

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxHandoffLifetime       = 24 * time.Hour
	MaxHandoffPlaintextBytes = 1 << 30
	MaxHandoffFiles          = 4096
)

type PrivateHandoffChallengeBody struct {
	SchemaVersion               uint16   `json:"schema_version"`
	HandoffID                   string   `json:"handoff_id"`
	AgreementBodyDigest         string   `json:"agreement_body_digest"`
	ObligationID                string   `json:"obligation_id"`
	SenderAgentID               string   `json:"sender_agent_id"`
	ReceiverAgentID             string   `json:"receiver_agent_id"`
	Direction                   string   `json:"direction"`
	PurposeDigest               string   `json:"purpose_digest"`
	IngressProfileURI           string   `json:"ingress_profile_uri"`
	IngressInstanceID           string   `json:"ingress_instance_id"`
	ReceiverEncryptionPublicKey string   `json:"receiver_encryption_public_key"`
	MaximumPlaintextBytes       uint64   `json:"maximum_plaintext_bytes"`
	MaximumCiphertextBytes      uint64   `json:"maximum_ciphertext_bytes"`
	MaximumFiles                uint32   `json:"maximum_files"`
	AcceptedMediaTypes          []string `json:"accepted_media_types"`
	RetentionPolicyDigest       string   `json:"retention_policy_digest"`
	IssuedAtUnix                uint64   `json:"issued_at_unix"`
	ExpiresAtUnix               uint64   `json:"expires_at_unix"`
	DeleteNotAfterUnix          uint64   `json:"delete_not_after_unix"`
}

type SignedPrivateHandoffChallenge struct {
	Body      PrivateHandoffChallengeBody `json:"body"`
	PublicKey string                      `json:"public_key"`
	Signature string                      `json:"signature"`
}

type PrivateContentManifest struct {
	ContentDigest         string   `json:"content_digest"`
	MediaType             string   `json:"media_type"`
	FileCount             uint32   `json:"file_count"`
	CanonicalPaths        []string `json:"canonical_paths"`
	PlaintextBytes        uint64   `json:"plaintext_bytes"`
	MaximumExpandedBytes  uint64   `json:"maximum_expanded_bytes"`
	CompressionProfileURI string   `json:"compression_profile_uri"`
}

type PrivateHandoffAuthorizationBody struct {
	SchemaVersion            uint16                 `json:"schema_version"`
	ChallengeDigest          string                 `json:"challenge_digest"`
	SenderDisclosureActionID string                 `json:"sender_disclosure_action_id"`
	Manifest                 PrivateContentManifest `json:"manifest"`
	SenderEphemeralPublicKey string                 `json:"sender_ephemeral_public_key"`
	Nonce                    string                 `json:"nonce"`
	CiphertextDigest         string                 `json:"ciphertext_digest"`
	CiphertextBytes          uint64                 `json:"ciphertext_bytes"`
	AssociatedDataDigest     string                 `json:"associated_data_digest"`
	PossessionProof          string                 `json:"possession_proof"`
	ExpiresAtUnix            uint64                 `json:"expires_at_unix"`
}

type SignedPrivateHandoffAuthorization struct {
	Body      PrivateHandoffAuthorizationBody `json:"body"`
	PublicKey string                          `json:"public_key"`
	Signature string                          `json:"signature"`
}

type AcceptedPrivateContentRecord struct {
	SchemaVersion            uint16 `json:"schema_version"`
	HandoffID                string `json:"handoff_id"`
	ChallengeDigest          string `json:"challenge_digest"`
	AuthorizationDigest      string `json:"authorization_digest"`
	UploadActionID           string `json:"upload_action_id"`
	SenderDisclosureActionID string `json:"sender_disclosure_action_id"`
	ContentDigest            string `json:"content_digest"`
	ContentManifestDigest    string `json:"content_manifest_digest"`
	PlaintextBytes           uint64 `json:"plaintext_bytes"`
	ImmutableObjectDigest    string `json:"immutable_object_digest"`
	RetentionPolicyDigest    string `json:"retention_policy_digest"`
	AcceptedAtUnix           uint64 `json:"accepted_at_unix"`
	DeleteNotAfterUnix       uint64 `json:"delete_not_after_unix"`
}

type SignedPrivateHandoffAcknowledgement struct {
	Record          AcceptedPrivateContentRecord `json:"record"`
	ReceiverAgentID string                       `json:"receiver_agent_id"`
	PublicKey       string                       `json:"public_key"`
	Signature       string                       `json:"signature"`
}

type HandoffAuthorityResolver interface {
	AuthorizeHandoffKey(agentID string, publicKey ed25519.PublicKey, at time.Time) error
}

func GenerateHandoffEncryptionKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func SignPrivateHandoffChallenge(body PrivateHandoffChallengeBody, key ed25519.PrivateKey) (SignedPrivateHandoffChallenge, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedPrivateHandoffChallenge{}, errors.New("handoff challenge signing key is invalid")
	}
	if err := validateHandoffChallenge(body, time.Unix(int64(body.IssuedAtUnix), 0).UTC()); err != nil {
		return SignedPrivateHandoffChallenge{}, err
	}
	message, err := handoffSignatureMessage("tos.private-handoff-challenge-signature.v1", body)
	if err != nil {
		return SignedPrivateHandoffChallenge{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return SignedPrivateHandoffChallenge{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func VerifyPrivateHandoffChallenge(challenge SignedPrivateHandoffChallenge, resolver HandoffAuthorityResolver, now time.Time) error {
	if err := validateHandoffChallenge(challenge.Body, now.UTC()); err != nil {
		return err
	}
	key, err := parseEd25519PublicKey(challenge.PublicKey)
	if err != nil || resolver == nil {
		return errors.New("handoff challenge authority is unavailable")
	}
	if err := resolver.AuthorizeHandoffKey(challenge.Body.ReceiverAgentID, key, now.UTC()); err != nil {
		return fmt.Errorf("handoff receiver key is not authorized: %w", err)
	}
	signature, err := parseEd25519Signature(challenge.Signature)
	if err != nil {
		return err
	}
	message, err := handoffSignatureMessage("tos.private-handoff-challenge-signature.v1", challenge.Body)
	if err != nil || !ed25519.Verify(key, message, signature) {
		return errors.New("handoff challenge signature is invalid")
	}
	return nil
}

func ValidatePrivateHandoffChallenge(body PrivateHandoffChallengeBody, now time.Time) error {
	return validateHandoffChallenge(body, now)
}

func PrivateHandoffChallengeDigest(body PrivateHandoffChallengeBody) (string, error) {
	return codec.Digest("tos.private-handoff-challenge.v1", body)
}

func SealPrivateContent(challenge SignedPrivateHandoffChallenge, manifest PrivateContentManifest, plaintext []byte,
	stableActionID string, senderKey ed25519.PrivateKey) ([]byte, SignedPrivateHandoffAuthorization, error) {
	if len(senderKey) != ed25519.PrivateKeySize || !canonicalDigestPattern.MatchString(stableActionID) {
		return nil, SignedPrivateHandoffAuthorization{}, errors.New("private handoff sender authorization is invalid")
	}
	if err := validateManifest(manifest, challenge.Body); err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	if uint64(len(plaintext)) != manifest.PlaintextBytes {
		return nil, SignedPrivateHandoffAuthorization{}, errors.New("private handoff plaintext size differs from manifest")
	}
	plainDigest := sha256.Sum256(plaintext)
	if manifest.ContentDigest != "sha256:"+hex.EncodeToString(plainDigest[:]) {
		return nil, SignedPrivateHandoffAuthorization{}, errors.New("private handoff plaintext digest differs from manifest")
	}
	receiverPublicRaw, err := base64.RawURLEncoding.DecodeString(challenge.Body.ReceiverEncryptionPublicKey)
	if err != nil || len(receiverPublicRaw) != 32 {
		return nil, SignedPrivateHandoffAuthorization{}, errors.New("receiver X25519 key is invalid")
	}
	receiverPublic, err := ecdh.X25519().NewPublicKey(receiverPublicRaw)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	ephemeral, err := GenerateHandoffEncryptionKey()
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	shared, err := ephemeral.ECDH(receiverPublic)
	if err != nil || allZero(shared) {
		return nil, SignedPrivateHandoffAuthorization{}, errors.New("private handoff key agreement failed")
	}
	challengeDigest, err := PrivateHandoffChallengeDigest(challenge.Body)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	aad, aadDigest, err := privateHandoffAAD(challenge.Body, manifest, stableActionID)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	key, err := deriveHandoffKey(shared, challengeDigest, stableActionID)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	if uint64(len(ciphertext)) > challenge.Body.MaximumCiphertextBytes {
		return nil, SignedPrivateHandoffAuthorization{}, errors.New("private handoff ciphertext exceeds receiver bound")
	}
	cipherDigest := sha256.Sum256(ciphertext)
	proofKey, err := hkdf.Key(sha256.New, shared, []byte(challengeDigest), "tos.private-handoff-possession.v1", 32)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	proof := sha256.Sum256(append(append(proofKey, aad...), cipherDigest[:]...))
	body := PrivateHandoffAuthorizationBody{SchemaVersion: 1, ChallengeDigest: challengeDigest, SenderDisclosureActionID: stableActionID,
		Manifest: manifest, SenderEphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), CiphertextDigest: "sha256:" + hex.EncodeToString(cipherDigest[:]),
		CiphertextBytes: uint64(len(ciphertext)), AssociatedDataDigest: aadDigest,
		PossessionProof: "sha256:" + hex.EncodeToString(proof[:]), ExpiresAtUnix: challenge.Body.ExpiresAtUnix}
	message, err := handoffSignatureMessage("tos.private-handoff-authorization-signature.v1", body)
	if err != nil {
		return nil, SignedPrivateHandoffAuthorization{}, err
	}
	public := senderKey.Public().(ed25519.PublicKey)
	authorization := SignedPrivateHandoffAuthorization{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(senderKey, message))}
	return ciphertext, authorization, nil
}

func OpenPrivateContent(challenge SignedPrivateHandoffChallenge, authorization SignedPrivateHandoffAuthorization,
	ciphertext []byte, receiverKey *ecdh.PrivateKey, resolver HandoffAuthorityResolver, now time.Time) ([]byte, error) {
	if receiverKey == nil || resolver == nil {
		return nil, errors.New("private handoff receiver is unavailable")
	}
	if err := VerifyPrivateHandoffChallenge(challenge, resolver, now); err != nil {
		return nil, err
	}
	challengeDigest, _ := PrivateHandoffChallengeDigest(challenge.Body)
	if authorization.Body.SchemaVersion != 1 || authorization.Body.ChallengeDigest != challengeDigest ||
		authorization.Body.ExpiresAtUnix != challenge.Body.ExpiresAtUnix || uint64(len(ciphertext)) != authorization.Body.CiphertextBytes ||
		uint64(len(ciphertext)) > challenge.Body.MaximumCiphertextBytes || !canonicalDigestPattern.MatchString(authorization.Body.SenderDisclosureActionID) {
		return nil, errors.New("private handoff authorization does not bind the challenge or bytes")
	}
	if err := validateManifest(authorization.Body.Manifest, challenge.Body); err != nil {
		return nil, err
	}
	cipherDigest := sha256.Sum256(ciphertext)
	if authorization.Body.CiphertextDigest != "sha256:"+hex.EncodeToString(cipherDigest[:]) {
		return nil, errors.New("private handoff ciphertext digest is invalid")
	}
	senderKey, err := parseEd25519PublicKey(authorization.PublicKey)
	if err != nil || resolver.AuthorizeHandoffKey(challenge.Body.SenderAgentID, senderKey, now.UTC()) != nil {
		return nil, errors.New("private handoff sender key is not authorized")
	}
	signature, err := parseEd25519Signature(authorization.Signature)
	message, messageErr := handoffSignatureMessage("tos.private-handoff-authorization-signature.v1", authorization.Body)
	if err != nil || messageErr != nil || !ed25519.Verify(senderKey, message, signature) {
		return nil, errors.New("private handoff sender signature is invalid")
	}
	ephemeralRaw, err := base64.RawURLEncoding.DecodeString(authorization.Body.SenderEphemeralPublicKey)
	if err != nil || len(ephemeralRaw) != 32 {
		return nil, errors.New("sender ephemeral X25519 key is invalid")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralRaw)
	if err != nil {
		return nil, err
	}
	shared, err := receiverKey.ECDH(ephemeral)
	if err != nil || allZero(shared) {
		return nil, errors.New("private handoff key agreement failed")
	}
	aad, aadDigest, err := privateHandoffAAD(challenge.Body, authorization.Body.Manifest, authorization.Body.SenderDisclosureActionID)
	if err != nil || aadDigest != authorization.Body.AssociatedDataDigest {
		return nil, errors.New("private handoff associated data is invalid")
	}
	proofKey, err := hkdf.Key(sha256.New, shared, []byte(challengeDigest), "tos.private-handoff-possession.v1", 32)
	if err != nil {
		return nil, err
	}
	proof := sha256.Sum256(append(append(proofKey, aad...), cipherDigest[:]...))
	if authorization.Body.PossessionProof != "sha256:"+hex.EncodeToString(proof[:]) {
		return nil, errors.New("private handoff possession proof is invalid")
	}
	key, err := deriveHandoffKey(shared, challengeDigest, authorization.Body.SenderDisclosureActionID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(authorization.Body.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errors.New("private handoff nonce is invalid")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("private handoff authentication failed")
	}
	plainDigest := sha256.Sum256(plaintext)
	if uint64(len(plaintext)) != authorization.Body.Manifest.PlaintextBytes ||
		authorization.Body.Manifest.ContentDigest != "sha256:"+hex.EncodeToString(plainDigest[:]) {
		return nil, errors.New("private handoff plaintext differs from manifest")
	}
	return plaintext, nil
}

func PrivateHandoffAuthorizationDigest(body PrivateHandoffAuthorizationBody) (string, error) {
	return codec.Digest("tos.private-handoff-authorization.v1", body)
}

func SignPrivateHandoffAcknowledgement(record AcceptedPrivateContentRecord, receiverAgentID string,
	key ed25519.PrivateKey) (SignedPrivateHandoffAcknowledgement, error) {
	if err := validateAcceptedPrivateContent(record); err != nil || !boundedIdentifier(receiverAgentID, 256) || len(key) != ed25519.PrivateKeySize {
		return SignedPrivateHandoffAcknowledgement{}, errors.New("private handoff acknowledgement is invalid")
	}
	message, err := handoffSignatureMessage("tos.private-handoff-acknowledgement-signature.v1", struct {
		Record          AcceptedPrivateContentRecord `json:"record"`
		ReceiverAgentID string                       `json:"receiver_agent_id"`
	}{record, receiverAgentID})
	if err != nil {
		return SignedPrivateHandoffAcknowledgement{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return SignedPrivateHandoffAcknowledgement{Record: record, ReceiverAgentID: receiverAgentID,
		PublicKey: "ed25519:" + hex.EncodeToString(public), Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}

func VerifyPrivateHandoffAcknowledgement(ack SignedPrivateHandoffAcknowledgement,
	resolver HandoffAuthorityResolver, now time.Time) error {
	if err := validateAcceptedPrivateContent(ack.Record); err != nil || resolver == nil {
		return errors.New("private handoff acknowledgement is invalid")
	}
	key, err := parseEd25519PublicKey(ack.PublicKey)
	if err != nil || resolver.AuthorizeHandoffKey(ack.ReceiverAgentID, key, now.UTC()) != nil {
		return errors.New("private handoff acknowledgement key is not authorized")
	}
	signature, err := parseEd25519Signature(ack.Signature)
	message, messageErr := handoffSignatureMessage("tos.private-handoff-acknowledgement-signature.v1", struct {
		Record          AcceptedPrivateContentRecord `json:"record"`
		ReceiverAgentID string                       `json:"receiver_agent_id"`
	}{ack.Record, ack.ReceiverAgentID})
	if err != nil || messageErr != nil || !ed25519.Verify(key, message, signature) {
		return errors.New("private handoff acknowledgement signature is invalid")
	}
	return nil
}

func PrivateHandoffAcknowledgementDigest(ack SignedPrivateHandoffAcknowledgement) (string, error) {
	return codec.Digest("tos.private-handoff-acknowledgement.v1", ack)
}

func ValidateAcceptedPrivateContent(record AcceptedPrivateContentRecord) error {
	return validateAcceptedPrivateContent(record)
}

func validateAcceptedPrivateContent(record AcceptedPrivateContentRecord) error {
	if record.SchemaVersion != 1 || !boundedIdentifier(record.HandoffID, 256) || !canonicalDigestPattern.MatchString(record.ChallengeDigest) ||
		!canonicalDigestPattern.MatchString(record.AuthorizationDigest) || !canonicalDigestPattern.MatchString(record.UploadActionID) ||
		!canonicalDigestPattern.MatchString(record.SenderDisclosureActionID) ||
		!canonicalDigestPattern.MatchString(record.ContentDigest) || !canonicalDigestPattern.MatchString(record.ContentManifestDigest) ||
		record.PlaintextBytes == 0 || record.PlaintextBytes > MaxHandoffPlaintextBytes ||
		!canonicalDigestPattern.MatchString(record.ImmutableObjectDigest) || record.ImmutableObjectDigest != record.ContentDigest ||
		!canonicalDigestPattern.MatchString(record.RetentionPolicyDigest) || record.AcceptedAtUnix == 0 || record.DeleteNotAfterUnix < record.AcceptedAtUnix {
		return errors.New("accepted private content record is invalid")
	}
	return nil
}

func validateHandoffChallenge(body PrivateHandoffChallengeBody, now time.Time) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.HandoffID, 256) || !canonicalDigestPattern.MatchString(body.AgreementBodyDigest) ||
		!boundedIdentifier(body.ObligationID, 256) || !boundedIdentifier(body.SenderAgentID, 256) || !boundedIdentifier(body.ReceiverAgentID, 256) ||
		body.SenderAgentID == body.ReceiverAgentID || !canonicalLowerToken(body.Direction) || !canonicalDigestPattern.MatchString(body.PurposeDigest) ||
		!boundedIdentifier(body.IngressProfileURI, 256) || !boundedIdentifier(body.IngressInstanceID, 256) ||
		body.MaximumPlaintextBytes == 0 || body.MaximumPlaintextBytes > MaxHandoffPlaintextBytes ||
		body.MaximumCiphertextBytes < body.MaximumPlaintextBytes+16 || body.MaximumCiphertextBytes > MaxHandoffPlaintextBytes+16 ||
		body.MaximumFiles == 0 || body.MaximumFiles > MaxHandoffFiles || body.IssuedAtUnix == 0 || body.ExpiresAtUnix <= body.IssuedAtUnix ||
		body.DeleteNotAfterUnix < body.ExpiresAtUnix || body.DeleteNotAfterUnix > body.IssuedAtUnix+uint64((90*24*time.Hour)/time.Second) {
		return errors.New("private handoff challenge is invalid")
	}
	issued := time.Unix(int64(body.IssuedAtUnix), 0).UTC()
	expires := time.Unix(int64(body.ExpiresAtUnix), 0).UTC()
	if expires.Sub(issued) > MaxHandoffLifetime || issued.After(now.UTC().Add(MaxIntentClockSkew)) || !now.UTC().Before(expires) ||
		!canonicalDigestPattern.MatchString(body.RetentionPolicyDigest) {
		return errors.New("private handoff challenge time or retention bounds are invalid")
	}
	key, err := base64.RawURLEncoding.DecodeString(body.ReceiverEncryptionPublicKey)
	if err != nil || len(key) != 32 || allZero(key) {
		return errors.New("private handoff receiver encryption key is invalid")
	}
	if len(body.AcceptedMediaTypes) == 0 || len(body.AcceptedMediaTypes) > 64 || !sort.StringsAreSorted(body.AcceptedMediaTypes) {
		return errors.New("private handoff media types are invalid")
	}
	for index, media := range body.AcceptedMediaTypes {
		if !boundedIdentifier(media, 256) || index > 0 && media == body.AcceptedMediaTypes[index-1] {
			return errors.New("private handoff media types are invalid")
		}
	}
	return nil
}

func validateManifest(manifest PrivateContentManifest, challenge PrivateHandoffChallengeBody) error {
	if !canonicalDigestPattern.MatchString(manifest.ContentDigest) || !boundedIdentifier(manifest.MediaType, 256) ||
		manifest.FileCount == 0 || manifest.FileCount > challenge.MaximumFiles || uint32(len(manifest.CanonicalPaths)) != manifest.FileCount ||
		manifest.PlaintextBytes == 0 || manifest.PlaintextBytes > challenge.MaximumPlaintextBytes ||
		manifest.MaximumExpandedBytes < manifest.PlaintextBytes || manifest.MaximumExpandedBytes > challenge.MaximumPlaintextBytes ||
		!boundedIdentifier(manifest.CompressionProfileURI, 256) || !sort.StringsAreSorted(manifest.CanonicalPaths) {
		return errors.New("private content manifest is invalid")
	}
	mediaAccepted := false
	for _, media := range challenge.AcceptedMediaTypes {
		mediaAccepted = mediaAccepted || media == manifest.MediaType
	}
	if !mediaAccepted {
		return errors.New("private content media type was not accepted by receiver")
	}
	for index, path := range manifest.CanonicalPaths {
		if !canonicalHandoffPath(path) || index > 0 && path == manifest.CanonicalPaths[index-1] {
			return errors.New("private content paths are invalid")
		}
	}
	return nil
}

func canonicalHandoffPath(path string) bool {
	if len(path) == 0 || len(path) > 1024 || path[0] == '/' || path[len(path)-1] == '/' {
		return false
	}
	componentLength := 0
	for _, character := range []byte(path) {
		if character == 0 || character == '\\' || character < 0x20 {
			return false
		}
		if character == '/' {
			if componentLength == 0 {
				return false
			}
			componentLength = 0
		} else {
			componentLength++
		}
	}
	for _, component := range splitPath(path) {
		if component == "." || component == ".." {
			return false
		}
	}
	return componentLength > 0
}

func splitPath(path string) []string {
	var result []string
	start := 0
	for index := 0; index <= len(path); index++ {
		if index == len(path) || path[index] == '/' {
			result = append(result, path[start:index])
			start = index + 1
		}
	}
	return result
}

func privateHandoffAAD(challenge PrivateHandoffChallengeBody, manifest PrivateContentManifest, stableActionID string) ([]byte, string, error) {
	value := struct {
		Challenge      PrivateHandoffChallengeBody `json:"challenge"`
		Manifest       PrivateContentManifest      `json:"manifest"`
		StableActionID string                      `json:"stable_action_id"`
	}{challenge, manifest, stableActionID}
	aad, err := codec.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(aad)
	return aad, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func deriveHandoffKey(shared []byte, challengeDigest, stableActionID string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, []byte(challengeDigest), "tos.private-handoff-aes-256-gcm.v1\x00"+stableActionID, 32)
}

func handoffSignatureMessage(domain string, body any) ([]byte, error) {
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write([]byte(domain))
	hasher.Write([]byte{0})
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hasher.Write(length[:])
	hasher.Write(canonical)
	return hasher.Sum(nil), nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
