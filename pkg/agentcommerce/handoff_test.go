package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type handoffTestResolver map[string]ed25519.PublicKey

func (resolver handoffTestResolver) AuthorizeHandoffKey(agentID string, key ed25519.PublicKey, _ time.Time) error {
	if !ed25519.PublicKey(resolver[agentID]).Equal(key) {
		return errors.New("not authorized")
	}
	return nil
}

func TestPrivateHandoffBindsAgreementSenderReceiverAndCiphertext(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	receiverEncryption, err := GenerateHandoffEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	receiverPublic, receiverSigning, _ := ed25519.GenerateKey(rand.Reader)
	senderPublic, senderSigning, _ := ed25519.GenerateKey(rand.Reader)
	digest := func(value string) string {
		hash := sha256.Sum256([]byte(value))
		return "sha256:" + hex.EncodeToString(hash[:])
	}
	challenge, err := SignPrivateHandoffChallenge(PrivateHandoffChallengeBody{SchemaVersion: 1,
		HandoffID: "handoff:test", AgreementBodyDigest: digest("agreement"), ObligationID: "obligation:input",
		SenderAgentID: "agent:sender", ReceiverAgentID: "agent:receiver", Direction: "input", PurposeDigest: digest("purpose"),
		IngressProfileURI: "tos.private-ingress.v1", IngressInstanceID: "ingress:receiver-selected",
		ReceiverEncryptionPublicKey: base64.RawURLEncoding.EncodeToString(receiverEncryption.PublicKey().Bytes()),
		MaximumPlaintextBytes:       1024, MaximumCiphertextBytes: 1040, MaximumFiles: 2,
		AcceptedMediaTypes: []string{"application/octet-stream"}, RetentionPolicyDigest: digest("retention"),
		IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		DeleteNotAfterUnix: uint64(now.Add(24 * time.Hour).Unix())}, receiverSigning)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("private source bytes")
	plainHash := sha256.Sum256(plaintext)
	manifest := PrivateContentManifest{ContentDigest: "sha256:" + hex.EncodeToString(plainHash[:]), MediaType: "application/octet-stream",
		FileCount: 1, CanonicalPaths: []string{"source.bin"}, PlaintextBytes: uint64(len(plaintext)),
		MaximumExpandedBytes: uint64(len(plaintext)), CompressionProfileURI: "tos.compression.none.v1"}
	actionID := digest("content-upload-action")
	ciphertext, authorization, err := SealPrivateContent(challenge, manifest, plaintext, actionID, senderSigning)
	if err != nil {
		t.Fatal(err)
	}
	resolver := handoffTestResolver{"agent:receiver": receiverPublic, "agent:sender": senderPublic}
	opened, err := OpenPrivateContent(challenge, authorization, ciphertext, receiverEncryption, resolver, now)
	if err != nil || string(opened) != string(plaintext) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 1
	if _, err := OpenPrivateContent(challenge, authorization, tampered, receiverEncryption, resolver, now); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	changed := authorization
	changed.Body.Manifest.CanonicalPaths = []string{"other.bin"}
	if _, err := OpenPrivateContent(challenge, changed, ciphertext, receiverEncryption, resolver, now); err == nil {
		t.Fatal("changed manifest was accepted")
	}
}
