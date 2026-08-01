package identity

import (
	"errors"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

// DecodeEnvelopeJSON strictly decodes an operator-loaded signed envelope and
// validates its complete structural fingerprint. Signature authority is still
// verified later against the current manifest or chain key.
func DecodeEnvelopeJSON(data []byte, expectedDomain string) (Envelope, error) {
	var envelope Envelope
	if err := jsonstrict.Decode(data, &envelope); err != nil {
		return Envelope{}, errors.New("invalid signed envelope JSON")
	}
	if envelope.Domain != expectedDomain {
		return Envelope{}, errors.New("signed envelope domain mismatch")
	}
	if _, err := envelope.Fingerprint(); err != nil {
		return Envelope{}, err
	}
	envelope.Payload = append([]byte(nil), envelope.Payload...)
	return envelope, nil
}
