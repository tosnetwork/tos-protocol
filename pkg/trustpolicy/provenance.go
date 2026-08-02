package trustpolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
)

const (
	ArtifactProvenanceDomain  = "tos.artifact-provenance.v1"
	ArtifactProvenanceVersion = "0.1.0"
	MaxProvenanceMaterials    = 64
	MaxArtifactBytesHard      = int64(1 << 40)
)

type ProvenanceStatement struct {
	Version        string   `json:"version"`
	ArtifactDigest string   `json:"artifactDigest"`
	Subject        string   `json:"subject"`
	BuilderID      string   `json:"builderId"`
	SourceDigest   string   `json:"sourceDigest"`
	Materials      []string `json:"materials,omitempty"`
}

type ProvenanceTrust struct {
	PublicKey       ed25519.PublicKey
	BuilderID       string
	AllowedSubjects []string
}

type ProvenanceVerifier struct {
	issuers map[string]ProvenanceTrust
}

func NewProvenanceVerifier(issuers map[string]ProvenanceTrust) (*ProvenanceVerifier, error) {
	if len(issuers) == 0 || len(issuers) > 32 {
		return nil, errors.New("invalid provenance trust policy")
	}
	cloned := make(map[string]ProvenanceTrust, len(issuers))
	for keyID, trust := range issuers {
		if !validBoundedID(keyID, 512) || len(trust.PublicKey) != ed25519.PublicKeySize ||
			!validBoundedID(trust.BuilderID, 512) || len(trust.AllowedSubjects) == 0 ||
			len(trust.AllowedSubjects) > 128 {
			return nil, errors.New("invalid provenance trust policy")
		}
		copyTrust := ProvenanceTrust{
			PublicKey:       append(ed25519.PublicKey(nil), trust.PublicKey...),
			BuilderID:       trust.BuilderID,
			AllowedSubjects: append([]string(nil), trust.AllowedSubjects...),
		}
		seenSubjects := make(map[string]struct{}, len(copyTrust.AllowedSubjects))
		for _, subject := range copyTrust.AllowedSubjects {
			if !validBoundedID(subject, 512) {
				return nil, errors.New("invalid provenance trust policy")
			}
			if _, duplicate := seenSubjects[subject]; duplicate {
				return nil, errors.New("invalid provenance trust policy")
			}
			seenSubjects[subject] = struct{}{}
		}
		cloned[keyID] = copyTrust
	}
	return &ProvenanceVerifier{issuers: cloned}, nil
}

func (v *ProvenanceVerifier) VerifyEnvelope(envelope identity.Envelope, expectedDigest string, now time.Time) (ProvenanceStatement, error) {
	if v == nil || !validDigest(expectedDigest) || now.IsZero() {
		return ProvenanceStatement{}, errors.New("artifact provenance rejected")
	}
	trust, ok := v.issuers[envelope.KeyID]
	if !ok {
		return ProvenanceStatement{}, errors.New("artifact provenance rejected")
	}
	var statement ProvenanceStatement
	if envelope.VerifyCanonical(trust.PublicKey, ArtifactProvenanceDomain, now.UTC(), &statement) != nil ||
		statement.Version != ArtifactProvenanceVersion || statement.ArtifactDigest != expectedDigest ||
		statement.BuilderID != trust.BuilderID || !containsExact(trust.AllowedSubjects, statement.Subject) ||
		!validDigest(statement.SourceDigest) || len(statement.Materials) > MaxProvenanceMaterials {
		return ProvenanceStatement{}, errors.New("artifact provenance rejected")
	}
	seen := make(map[string]struct{}, len(statement.Materials))
	for _, digest := range statement.Materials {
		if !validDigest(digest) {
			return ProvenanceStatement{}, errors.New("artifact provenance rejected")
		}
		if _, duplicate := seen[digest]; duplicate {
			return ProvenanceStatement{}, errors.New("artifact provenance rejected")
		}
		seen[digest] = struct{}{}
	}
	return statement, nil
}

// VerifyArtifact hashes at most maximum bytes and requires EOF, so a prefix
// cannot be accepted as the complete artifact.
func VerifyArtifact(reader io.Reader, maximum int64, expectedDigest string) error {
	if reader == nil || maximum <= 0 || maximum > MaxArtifactBytesHard || !validDigest(expectedDigest) {
		return errors.New("artifact rejected")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(reader, maximum+1))
	if err != nil || written > maximum || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		return errors.New("artifact rejected")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && strings.ToLower(value) == value
}

func validBoundedID(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == '\x7f' {
			return false
		}
	}
	return true
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
