package agentcommerce

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	OutcomeEvidenceCipherSuiteV1 = "aes-256-gcm"
	OutcomeEvidenceNonceBytesV1  = 12
	OutcomeHidingRandomnessBytes = 16
)

type OutcomeEncryptedEvidenceMetadataV1 struct {
	ObjectDigest          string `json:"object_digest"`
	AudiencePolicyDigest  string `json:"audience_policy_digest"`
	RetentionPolicyDigest string `json:"retention_policy_digest"`
	EvidenceRole          string `json:"evidence_role"`
	CanonicalSize         uint64 `json:"canonical_size"`
}

type OutcomeEncryptedEvidenceV1 struct {
	SchemaVersion        uint16                             `json:"schema_version"`
	CipherSuite          string                             `json:"cipher_suite"`
	KeyReferenceDigest   string                             `json:"key_reference_digest"`
	Nonce                []byte                             `json:"nonce"`
	AssociatedData       OutcomeEncryptedEvidenceMetadataV1 `json:"associated_data"`
	AssociatedDataDigest string                             `json:"associated_data_digest"`
	Ciphertext           []byte                             `json:"ciphertext"`
}

// outcomeEncryptedEvidenceAADV1 is the complete authenticated context for an
// encrypted evidence object. Keep the key reference inside the AEAD boundary:
// it selects the decryption authority and therefore must not be replaceable
// independently of the ciphertext.
type outcomeEncryptedEvidenceAADV1 struct {
	SchemaVersion      uint16                             `json:"schema_version"`
	CipherSuite        string                             `json:"cipher_suite"`
	KeyReferenceDigest string                             `json:"key_reference_digest"`
	Metadata           OutcomeEncryptedEvidenceMetadataV1 `json:"metadata"`
}

type OutcomeDisclosureFieldV1 struct {
	FieldPath   string `json:"field_path"`
	Treatment   string `json:"treatment"`
	ValueDigest string `json:"value_digest"`
}

type OutcomeDisclosureProjectionV1 struct {
	SchemaVersion              uint16                     `json:"schema_version"`
	SourceAssertionRefs        []OutcomeAssertionRefV1    `json:"source_assertion_refs"`
	SourceDisclosurePolicyRoot string                     `json:"source_disclosure_policy_root"`
	SourceAudienceEpochRoot    string                     `json:"source_audience_epoch_root"`
	ProjectionProfileURI       string                     `json:"projection_profile_uri"`
	Fields                     []OutcomeDisclosureFieldV1 `json:"fields"`
	DerivationProfileURI       string                     `json:"derivation_profile_uri"`
	CompositionBudgetID        string                     `json:"composition_budget_id"`
	AudiencePolicyDigest       string                     `json:"audience_policy_digest"`
	PurposeDigest              string                     `json:"purpose_digest"`
	ExpiresAtUnix              uint64                     `json:"expires_at_unix"`
	RetentionPolicyDigest      string                     `json:"retention_policy_digest"`
	ProjectionIssuerID         string                     `json:"projection_issuer_id"`
}

func OutcomeHidingCommitmentV1(contextDigest string, randomness, value []byte) (string, error) {
	if !digest32(contextDigest) || len(randomness) < OutcomeHidingRandomnessBytes || len(randomness) > 64 || len(value) == 0 || len(value) > MaxOutcomeEvidenceObjectBytes {
		return "", errors.New("outcome hiding commitment input is invalid")
	}
	canonical, err := codec.Marshal(struct {
		ContextDigest string `json:"context_digest"`
		Randomness    []byte `json:"randomness"`
		Value         []byte `json:"value"`
	}{contextDigest, append([]byte(nil), randomness...), append([]byte(nil), value...)})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(append([]byte("tos.outcome.hiding-commitment.v1\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func SealOutcomeEncryptedEvidenceV1(key []byte, keyReferenceDigest string, metadata OutcomeEncryptedEvidenceMetadataV1,
	plaintext []byte) (OutcomeEncryptedEvidenceV1, error) {
	return sealOutcomeEncryptedEvidenceV1(rand.Reader, key, keyReferenceDigest, metadata, plaintext)
}

func sealOutcomeEncryptedEvidenceV1(random io.Reader, key []byte, keyReferenceDigest string,
	metadata OutcomeEncryptedEvidenceMetadataV1, plaintext []byte) (OutcomeEncryptedEvidenceV1, error) {
	if random == nil || len(key) != 32 || !digest32(keyReferenceDigest) || validateOutcomeEncryptedEvidenceMetadataV1(metadata) != nil ||
		len(plaintext) == 0 || uint64(len(plaintext)) != metadata.CanonicalSize || len(plaintext) > MaxOutcomeEvidenceObjectBytes {
		return OutcomeEncryptedEvidenceV1{}, errors.New("outcome evidence encryption request is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return OutcomeEncryptedEvidenceV1{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return OutcomeEncryptedEvidenceV1{}, err
	}
	nonce := make([]byte, OutcomeEvidenceNonceBytesV1)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return OutcomeEncryptedEvidenceV1{}, err
	}
	authenticatedContext := outcomeEncryptedEvidenceAADV1{SchemaVersion: 1, CipherSuite: OutcomeEvidenceCipherSuiteV1,
		KeyReferenceDigest: keyReferenceDigest, Metadata: metadata}
	associatedData, err := codec.Marshal(authenticatedContext)
	if err != nil {
		return OutcomeEncryptedEvidenceV1{}, err
	}
	associatedDigest, err := codec.Digest("tos.outcome.encrypted-evidence-associated-data.v1", authenticatedContext)
	if err != nil {
		return OutcomeEncryptedEvidenceV1{}, err
	}
	result := OutcomeEncryptedEvidenceV1{SchemaVersion: 1, CipherSuite: OutcomeEvidenceCipherSuiteV1,
		KeyReferenceDigest: keyReferenceDigest, Nonce: nonce, AssociatedData: metadata, AssociatedDataDigest: associatedDigest,
		Ciphertext: aead.Seal(nil, nonce, plaintext, associatedData)}
	if err := ValidateOutcomeEncryptedEvidenceV1(result); err != nil {
		return OutcomeEncryptedEvidenceV1{}, err
	}
	return result, nil
}

func OpenOutcomeEncryptedEvidenceV1(key []byte, envelope OutcomeEncryptedEvidenceV1) ([]byte, error) {
	if len(key) != 32 || ValidateOutcomeEncryptedEvidenceV1(envelope) != nil {
		return nil, errors.New("outcome evidence decryption request is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	associatedData, err := codec.Marshal(outcomeEncryptedEvidenceAADV1{SchemaVersion: envelope.SchemaVersion,
		CipherSuite: envelope.CipherSuite, KeyReferenceDigest: envelope.KeyReferenceDigest, Metadata: envelope.AssociatedData})
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associatedData)
	if err != nil || uint64(len(plaintext)) != envelope.AssociatedData.CanonicalSize {
		return nil, errors.New("outcome evidence authentication failed")
	}
	return plaintext, nil
}

func ValidateOutcomeEncryptedEvidenceV1(value OutcomeEncryptedEvidenceV1) error {
	if value.SchemaVersion != 1 || value.CipherSuite != OutcomeEvidenceCipherSuiteV1 || !digest32(value.KeyReferenceDigest) ||
		len(value.Nonce) != OutcomeEvidenceNonceBytesV1 || validateOutcomeEncryptedEvidenceMetadataV1(value.AssociatedData) != nil ||
		!digest32(value.AssociatedDataDigest) || len(value.Ciphertext) != int(value.AssociatedData.CanonicalSize)+16 ||
		len(value.Ciphertext) > MaxOutcomeEvidenceObjectBytes+16 {
		return errors.New("encrypted outcome evidence is invalid")
	}
	digest, err := codec.Digest("tos.outcome.encrypted-evidence-associated-data.v1", outcomeEncryptedEvidenceAADV1{
		SchemaVersion: value.SchemaVersion, CipherSuite: value.CipherSuite,
		KeyReferenceDigest: value.KeyReferenceDigest, Metadata: value.AssociatedData})
	if err != nil || digest != value.AssociatedDataDigest {
		return errors.New("encrypted outcome evidence associated-data digest mismatch")
	}
	return nil
}

func validateOutcomeEncryptedEvidenceMetadataV1(value OutcomeEncryptedEvidenceMetadataV1) error {
	if !digest32(value.ObjectDigest) || !digest32(value.AudiencePolicyDigest) || !digest32(value.RetentionPolicyDigest) ||
		!outcomeToken(value.EvidenceRole, 128) || value.CanonicalSize == 0 || value.CanonicalSize > MaxOutcomeEvidenceObjectBytes {
		return errors.New("outcome evidence encryption metadata is invalid")
	}
	return nil
}

func ValidateOutcomeDisclosureProjectionV1(value OutcomeDisclosureProjectionV1) error {
	if value.SchemaVersion != 1 || len(value.SourceAssertionRefs) == 0 || len(value.SourceAssertionRefs) > 32 ||
		!digest32(value.SourceDisclosurePolicyRoot) || !digest32(value.SourceAudienceEpochRoot) ||
		!outcomeToken(value.ProjectionProfileURI, MaxProfileURIBytes) || len(value.Fields) == 0 || len(value.Fields) > 128 ||
		!outcomeToken(value.DerivationProfileURI, MaxProfileURIBytes) || !outcomeToken(value.CompositionBudgetID, 256) ||
		!digest32(value.AudiencePolicyDigest) || !digest32(value.PurposeDigest) || value.ExpiresAtUnix == 0 ||
		!digest32(value.RetentionPolicyDigest) || !outcomeToken(value.ProjectionIssuerID, 256) {
		return errors.New("outcome disclosure projection is invalid")
	}
	if err := validateCanonicalOutcomeSlice(value.SourceAssertionRefs, func(ref OutcomeAssertionRefV1) error {
		if !outcomeToken(ref.NetworkID, 256) || !outcomeToken(ref.ActorAgentID, 256) || !digest32(ref.OperationID) || !digest32(ref.OperationEnvelopeDigest) {
			return errors.New("projection source assertion is invalid")
		}
		return nil
	}); err != nil {
		return err
	}
	return validateCanonicalOutcomeSlice(value.Fields, func(field OutcomeDisclosureFieldV1) error {
		if !outcomeToken(field.FieldPath, 256) || !oneOf(field.Treatment, "disclosed", "omitted", "bucketed") || !digest32(field.ValueDigest) {
			return errors.New("projection field is invalid")
		}
		return nil
	})
}
