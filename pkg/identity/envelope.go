// Package identity implements small, domain-separated signed envelopes for
// off-chain protocol messages. Wallet owner keys must never be loaded here.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	Version         = 1
	MaxPayloadBytes = 1 << 20
	MaxClockSkew    = 2 * time.Minute
)

type Envelope struct {
	Version   uint8  `json:"version"`
	Domain    string `json:"domain"`
	KeyID     string `json:"keyId"`
	IssuedAt  int64  `json:"issuedAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Nonce     string `json:"nonce"`
	Payload   []byte `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(privateKey ed25519.PrivateKey, domain, keyID string, payload []byte, issuedAt, expiresAt time.Time) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid Ed25519 private key")
	}
	env := Envelope{
		Version:   Version,
		Domain:    domain,
		KeyID:     keyID,
		IssuedAt:  issuedAt.UnixMilli(),
		ExpiresAt: expiresAt.UnixMilli(),
		Payload:   append([]byte(nil), payload...),
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate nonce: %w", err)
	}
	env.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	if err := env.validateStructure(); err != nil {
		return Envelope{}, err
	}
	message := env.signingMessage()
	env.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	return env, nil
}

func (e Envelope) Verify(publicKey ed25519.PublicKey, expectedDomain string, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if err := e.validateStructure(); err != nil {
		return err
	}
	if e.Domain != expectedDomain {
		return errors.New("signature domain mismatch")
	}
	issuedAt := time.UnixMilli(e.IssuedAt)
	expiresAt := time.UnixMilli(e.ExpiresAt)
	if issuedAt.After(now.Add(MaxClockSkew)) {
		return errors.New("envelope issued in the future")
	}
	if !expiresAt.After(now) {
		return errors.New("envelope expired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid signature encoding")
	}
	if !ed25519.Verify(publicKey, e.signingMessage(), signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

func (e Envelope) validateStructure() error {
	if e.Version != Version {
		return fmt.Errorf("unsupported envelope version %d", e.Version)
	}
	if e.Domain == "" || len(e.Domain) > 128 || e.KeyID == "" || len(e.KeyID) > 512 {
		return errors.New("invalid domain or keyId")
	}
	if len(e.Payload) > MaxPayloadBytes {
		return errors.New("payload too large")
	}
	if e.ExpiresAt <= e.IssuedAt {
		return errors.New("invalid validity interval")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(e.Nonce)
	if err != nil || len(nonce) != 16 {
		return errors.New("invalid nonce")
	}
	return nil
}

func (e Envelope) signingMessage() []byte {
	var out bytes.Buffer
	out.WriteString("TOS-SIGNED-ENVELOPE")
	out.WriteByte(0)
	out.WriteByte(e.Version)
	writeField(&out, []byte(e.Domain))
	writeField(&out, []byte(e.KeyID))
	_ = binary.Write(&out, binary.BigEndian, e.IssuedAt)
	_ = binary.Write(&out, binary.BigEndian, e.ExpiresAt)
	writeField(&out, []byte(e.Nonce))
	payloadHash := sha256.Sum256(e.Payload)
	out.Write(payloadHash[:])
	return out.Bytes()
}

func writeField(out *bytes.Buffer, value []byte) {
	_ = binary.Write(out, binary.BigEndian, uint32(len(value)))
	out.Write(value)
}
