package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	AgentOperationSchemaV1            uint16 = 1
	AgentOperationEnvelopeDomain             = "tos.agent-operation-envelope.v1"
	AgentOperationBodyDomain                 = "tos.agent-operation-body.v1"
	AgentOperationSignatureDomain            = "tos.agent-operation-signature.v1"
	AgentIntentPayloadProfileURI             = "tos.service.agent-intent-payload.v1"
	OperationOutcomePayloadProfileURI        = "tos.operation-outcome.event.v1"
	AgentOperationIDDomain                   = "tos.agent-operation-id.v1"
	MaxAgentOperationEnvelopeBytes           = 1 << 20
	MaxAgentOperationPayloadBytes            = 64 << 20
	MaxAgentOperationPredecessors            = 32
	MaxAgentOperationExtensions              = 32
	MaxAgentOperationExtensionBytes          = 64 << 10
	MaxAgentOperationClockSkew               = 5 * time.Minute
)

type AgentOperationExtensionV1 struct {
	Profile ProfileRefV1 `json:"profile"`
	Value   []byte       `json:"value"`
}

type AgentOperationBodyV1 struct {
	SchemaVersion        uint16                      `json:"schema_version"`
	NetworkID            string                      `json:"network_id"`
	OpcodeNamespace      string                      `json:"opcode_namespace"`
	OpcodeName           string                      `json:"opcode_name"`
	OpcodeVersion        uint64                      `json:"opcode_version"`
	OperationID          string                      `json:"operation_id"`
	ActorAgentID         string                      `json:"actor_agent_id"`
	AuthorizationRef     ProfileRefV1                `json:"authorization_ref"`
	AudienceDescriptor   string                      `json:"audience_descriptor"`
	ObjectID             string                      `json:"object_id,omitempty"`
	OrderingDomain       string                      `json:"ordering_domain"`
	Sequence             uint64                      `json:"sequence,omitempty"`
	Epoch                uint64                      `json:"epoch,omitempty"`
	PredecessorDigests   []string                    `json:"predecessor_digests,omitempty"`
	CreatedAtUnix        uint64                      `json:"created_at_unix"`
	NotBeforeUnix        uint64                      `json:"not_before_unix,omitempty"`
	ExpiresAtUnix        uint64                      `json:"expires_at_unix,omitempty"`
	PayloadProfile       ProfileRefV1                `json:"payload_profile"`
	PayloadDigest        string                      `json:"payload_digest"`
	PayloadSize          uint64                      `json:"payload_size"`
	PublicMetadataDigest string                      `json:"public_metadata_digest,omitempty"`
	AdmissionDescriptor  []byte                      `json:"admission_descriptor,omitempty"`
	Extensions           []AgentOperationExtensionV1 `json:"extensions,omitempty"`
}

type AgentOperationAuthorizationV1 struct {
	AuthoritySubject         string       `json:"authority_subject"`
	AuthorizationProfile     ProfileRefV1 `json:"authorization_profile"`
	PublicKey                string       `json:"public_key"`
	Signature                string       `json:"signature"`
	HistoricalAuthorityProof []byte       `json:"historical_authority_proof"`
}

type AgentOperationEnvelopeV1 struct {
	Body          AgentOperationBodyV1          `json:"body"`
	Authorization AgentOperationAuthorizationV1 `json:"authorization"`
}

type AgentOperationAuthorityResolver interface {
	AuthorizeAgentOperationKey(agentID string, profile ProfileRefV1, publicKey ed25519.PublicKey,
		at time.Time, historicalProof []byte) error
}

func AgentOperationPayloadDigest(profile ProfileRefV1, payload []byte) (string, error) {
	if ValidateProfileRefV1(profile) != nil || len(payload) == 0 || len(payload) > MaxAgentOperationPayloadBytes {
		return "", errors.New("Agent operation payload is invalid")
	}
	return codec.Digest("tos.agent-operation-payload.v1", struct {
		Profile ProfileRefV1 `json:"profile"`
		Payload []byte       `json:"payload"`
	}{Profile: profile, Payload: payload})
}

func AgentOperationBodyDigestV1(body AgentOperationBodyV1) (string, error) {
	if err := ValidateAgentOperationBodyV1(body); err != nil {
		return "", err
	}
	return codec.Digest(AgentOperationBodyDomain, body)
}

// DeriveAgentOperationIDV1 derives the assertion identity from the complete
// operation body except for the identity field itself. This prevents callers
// from assigning aliases to otherwise identical signed assertions.
func DeriveAgentOperationIDV1(body AgentOperationBodyV1) (string, error) {
	projection := body
	projection.OperationID = ""
	if projection.SchemaVersion != AgentOperationSchemaV1 || projection.NetworkID == "" ||
		projection.ActorAgentID == "" || projection.PayloadDigest == "" {
		return "", errors.New("Agent operation ID projection is incomplete")
	}
	return codec.Digest(AgentOperationIDDomain, projection)
}

func validateDerivedOperationIDV1(body AgentOperationBodyV1) error {
	if body.PayloadProfile.ProfileURI != OperationOutcomePayloadProfileURI {
		return nil
	}
	derived, err := DeriveAgentOperationIDV1(body)
	if err != nil || body.OperationID != derived {
		return errors.New("operation outcome operation ID is not verifier-derived")
	}
	return nil
}

func AgentOperationEnvelopeDigestV1(envelope AgentOperationEnvelopeV1) (string, error) {
	if err := validateAgentOperationEnvelopeShapeV1(envelope); err != nil {
		return "", err
	}
	return codec.Digest(AgentOperationEnvelopeDomain, envelope)
}

func SignAgentOperationV1(body AgentOperationBodyV1, authoritySubject string, key ed25519.PrivateKey,
	historicalProof []byte) (AgentOperationEnvelopeV1, error) {
	if err := ValidateAgentOperationBodyV1(body); err != nil || authoritySubject != body.ActorAgentID ||
		len(key) != ed25519.PrivateKeySize || len(historicalProof) == 0 || len(historicalProof) > 64<<10 {
		return AgentOperationEnvelopeV1{}, errors.New("Agent operation signing request is invalid")
	}
	if err := validateDerivedOperationIDV1(body); err != nil {
		return AgentOperationEnvelopeV1{}, err
	}
	message, err := agentOperationSignatureMessage(body)
	if err != nil {
		return AgentOperationEnvelopeV1{}, err
	}
	publicKey := key.Public().(ed25519.PublicKey)
	result := AgentOperationEnvelopeV1{Body: body, Authorization: AgentOperationAuthorizationV1{
		AuthoritySubject: authoritySubject, AuthorizationProfile: body.AuthorizationRef,
		PublicKey:                "ed25519:" + hex.EncodeToString(publicKey),
		Signature:                "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message)),
		HistoricalAuthorityProof: append([]byte(nil), historicalProof...)}}
	if err := validateAgentOperationEnvelopeShapeV1(result); err != nil {
		return AgentOperationEnvelopeV1{}, err
	}
	return result, nil
}

func VerifyAgentOperationV1(envelope AgentOperationEnvelopeV1, payload []byte,
	resolver AgentOperationAuthorityResolver, now time.Time) error {
	if err := validateAgentOperationEnvelopeShapeV1(envelope); err != nil || resolver == nil {
		return errors.New("Agent operation envelope is invalid")
	}
	body := envelope.Body
	if err := validateDerivedOperationIDV1(body); err != nil {
		return err
	}
	nowUnix := now.UTC().Unix()
	if nowUnix < 0 {
		return errors.New("Agent operation verification time is invalid")
	}
	current := uint64(nowUnix)
	skew := uint64(MaxAgentOperationClockSkew / time.Second)
	if body.CreatedAtUnix > current+skew || body.NotBeforeUnix > current+skew ||
		body.ExpiresAtUnix != 0 && current >= body.ExpiresAtUnix {
		return errors.New("Agent operation is outside its validity interval")
	}
	digest, err := AgentOperationPayloadDigest(body.PayloadProfile, payload)
	if err != nil || digest != body.PayloadDigest || uint64(len(payload)) != body.PayloadSize {
		return errors.New("Agent operation payload does not match its signed descriptor")
	}
	publicKey, err := parseAgentOperationPublicKey(envelope.Authorization.PublicKey)
	if err != nil {
		return err
	}
	signature, err := parseAgentOperationSignature(envelope.Authorization.Signature)
	if err != nil {
		return err
	}
	message, err := agentOperationSignatureMessage(body)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		return errors.New("Agent operation signature does not verify")
	}
	return resolver.AuthorizeAgentOperationKey(body.ActorAgentID, body.AuthorizationRef, publicKey,
		time.Unix(int64(body.CreatedAtUnix), 0).UTC(), envelope.Authorization.HistoricalAuthorityProof)
}

func ValidateAgentOperationBodyV1(body AgentOperationBodyV1) error {
	if body.SchemaVersion != AgentOperationSchemaV1 || !operationToken(body.NetworkID, 256) ||
		!operationToken(body.OpcodeNamespace, 64) || !operationToken(body.OpcodeName, 64) || body.OpcodeVersion == 0 ||
		!operationToken(body.OperationID, 256) || !operationToken(body.ActorAgentID, 256) ||
		ValidateProfileRefV1(body.AuthorizationRef) != nil || !operationToken(body.AudienceDescriptor, 512) ||
		!operationToken(body.OrderingDomain, 256) || body.CreatedAtUnix == 0 || body.CreatedAtUnix > math.MaxInt64 ||
		body.NotBeforeUnix > math.MaxInt64 || body.ExpiresAtUnix > math.MaxInt64 ||
		(body.NotBeforeUnix != 0 && body.ExpiresAtUnix != 0 && body.ExpiresAtUnix <= body.NotBeforeUnix) ||
		ValidateProfileRefV1(body.PayloadProfile) != nil || !digest32(body.PayloadDigest) || body.PayloadSize == 0 ||
		body.PayloadSize > MaxAgentOperationPayloadBytes || len(body.PredecessorDigests) > MaxAgentOperationPredecessors ||
		len(body.Extensions) > MaxAgentOperationExtensions || len(body.AdmissionDescriptor) > MaxAgentOperationExtensionBytes {
		return errors.New("Agent operation body is invalid")
	}
	if body.ObjectID != "" && !operationToken(body.ObjectID, 256) || body.PublicMetadataDigest != "" && !digest32(body.PublicMetadataDigest) {
		return errors.New("Agent operation optional identity is invalid")
	}
	if !sort.StringsAreSorted(body.PredecessorDigests) {
		return errors.New("Agent operation predecessors are not canonical")
	}
	for index, digest := range body.PredecessorDigests {
		if !digest32(digest) || index > 0 && digest == body.PredecessorDigests[index-1] {
			return errors.New("Agent operation predecessor is invalid")
		}
	}
	previous := []byte(nil)
	for _, extension := range body.Extensions {
		if ValidateProfileRefV1(extension.Profile) != nil || len(extension.Value) == 0 || len(extension.Value) > MaxAgentOperationExtensionBytes {
			return errors.New("Agent operation extension is invalid")
		}
		canonical, err := codec.Marshal(extension)
		if err != nil || previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return errors.New("Agent operation extensions are not canonical")
		}
		previous = canonical
	}
	return nil
}

func validateAgentOperationEnvelopeShapeV1(envelope AgentOperationEnvelopeV1) error {
	if err := ValidateAgentOperationBodyV1(envelope.Body); err != nil ||
		envelope.Authorization.AuthoritySubject != envelope.Body.ActorAgentID ||
		envelope.Authorization.AuthorizationProfile != envelope.Body.AuthorizationRef ||
		len(envelope.Authorization.HistoricalAuthorityProof) == 0 || len(envelope.Authorization.HistoricalAuthorityProof) > 64<<10 {
		return errors.New("Agent operation authorization binding is invalid")
	}
	canonical, err := codec.Marshal(envelope)
	if err != nil || len(canonical) > MaxAgentOperationEnvelopeBytes {
		return errors.New("Agent operation envelope exceeds its canonical bound")
	}
	return nil
}

func agentOperationSignatureMessage(body AgentOperationBodyV1) ([]byte, error) {
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	domain := []byte(AgentOperationSignatureDomain)
	message := make([]byte, 0, 24+len(domain)+len(canonical))
	message = append(message, []byte("TOS-AGENT-OPERATION\x00")...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(domain)))
	message = append(message, size[:]...)
	message = append(message, domain...)
	binary.BigEndian.PutUint32(size[:], uint32(len(canonical)))
	message = append(message, size[:]...)
	message = append(message, canonical...)
	return message, nil
}

func parseAgentOperationPublicKey(value string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("Agent operation public key encoding is invalid")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("Agent operation public key encoding is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func parseAgentOperationSignature(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("Agent operation signature encoding is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("Agent operation signature encoding is invalid")
	}
	return decoded, nil
}

func operationToken(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func digest32(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
