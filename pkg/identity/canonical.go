package identity

import (
	"crypto/ed25519"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

// SignCanonical serializes value with the protocol deterministic CBOR codec
// before signing. The caller supplies a message-specific tos.* domain.
func SignCanonical(privateKey ed25519.PrivateKey, domain, keyID string, value interface{}, issuedAt, expiresAt time.Time) (Envelope, error) {
	payload, err := codec.Marshal(value)
	if err != nil {
		return Envelope{}, err
	}
	return Sign(privateKey, domain, keyID, payload, issuedAt, expiresAt)
}

// VerifyCanonical verifies the envelope and decodes only canonical CBOR into
// output.
func (e Envelope) VerifyCanonical(publicKey ed25519.PublicKey, expectedDomain string, now time.Time, output interface{}) error {
	if err := e.Verify(publicKey, expectedDomain, now); err != nil {
		return err
	}
	return codec.Unmarshal(e.Payload, output)
}
