package agentcommerce

import (
	"bytes"
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// MessengerEffectRequestV1 is the exact request a Messenger side-effect sink
// admits. Business context remains in the semantic identity; this body binds
// the actual recipients, event kind, media type, and bytes that leave the
// process so a coordinator cannot authorize one message and transmit another.
type MessengerEffectRequestV1 struct {
	SchemaVersion     uint16   `json:"schema_version"`
	RecipientAgentIDs []string `json:"recipient_agent_ids"`
	EventKind         string   `json:"event_kind"`
	ContentType       string   `json:"content_type"`
	Payload           []byte   `json:"payload"`
}

func CanonicalMessengerEffectRequest(request MessengerEffectRequestV1) ([]byte, error) {
	if err := ValidateMessengerEffectRequest(request); err != nil {
		return nil, err
	}
	return codec.Marshal(request)
}

func DecodeMessengerEffectRequest(canonical []byte) (MessengerEffectRequestV1, error) {
	var request MessengerEffectRequestV1
	if err := codec.Unmarshal(canonical, &request); err != nil {
		return request, err
	}
	if err := ValidateMessengerEffectRequest(request); err != nil {
		return request, err
	}
	reencoded, err := codec.Marshal(request)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return request, errors.New("Messenger effect request is not canonical")
	}
	return request, nil
}

func ValidateMessengerEffectRequest(request MessengerEffectRequestV1) error {
	if request.SchemaVersion != 1 || len(request.RecipientAgentIDs) != 1 ||
		!sort.StringsAreSorted(request.RecipientAgentIDs) || !boundedIdentifier(request.RecipientAgentIDs[0], 256) ||
		len(request.ContentType) == 0 || len(request.ContentType) > 256 || !utf8.ValidString(request.ContentType) ||
		len(request.Payload) == 0 || len(request.Payload) > 128<<10 {
		return errors.New("Messenger effect request is invalid")
	}
	switch request.EventKind {
	case "text":
		if !utf8.Valid(request.Payload) {
			return errors.New("Messenger text effect is not UTF-8")
		}
	case "intent.application", "agreement.propose", "agreement.accept", "agreement.evidence", "agreement.withdraw", "agreement.delivery",
		"agreement.provider-offer", "commerce.profile-event", "operation.outcome":
	default:
		return errors.New("Messenger effect event kind is not economic-safe")
	}
	return nil
}
