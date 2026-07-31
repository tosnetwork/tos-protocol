package protocol

import (
	"errors"
	"fmt"
	"sort"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

const (
	// RequestIntentDomain separates the public, profile-specific request
	// commitment from private Worker request digests and signed envelopes.
	RequestIntentDomain   = "tos.request-intent.v1"
	MaxRequestIntentBytes = codec.MaxCanonicalBytes
)

type requestIntentCommitment struct {
	Version           string   `json:"version"`
	ProfileID         string   `json:"profileId"`
	ProfileVersion    string   `json:"profileVersion"`
	ProfileExtensions []string `json:"profileExtensions,omitempty"`
	Operation         string   `json:"operation"`
	Payload           []byte   `json:"payload"`
}

// RequestIntentDigest commits exact profile intent bytes to the negotiated
// profile version and operation. Profile implementations remain responsible
// for decoding and semantically validating those bytes before execution.
func RequestIntentDigest(
	profileID string,
	profileVersion string,
	profileExtensions []string,
	operation string,
	payload []byte,
) (string, error) {
	if !serviceIDPattern.MatchString(profileID) {
		return "", errors.New("invalid request intent profile ID")
	}
	if _, err := parseVersionSet([]string{profileVersion}); err != nil {
		return "", fmt.Errorf("invalid request intent profile version: %w", err)
	}
	extensions, err := parseExtensionSet(profileExtensions)
	if err != nil {
		return "", fmt.Errorf("invalid request intent profile extensions: %w", err)
	}
	canonicalExtensions := make([]string, 0, len(extensions))
	for extension := range extensions {
		canonicalExtensions = append(canonicalExtensions, extension)
	}
	sort.Strings(canonicalExtensions)
	if err := boundedString("request intent operation", operation, 1, 128); err != nil {
		return "", err
	}
	if len(payload) > MaxRequestIntentBytes {
		return "", errors.New("request intent exceeds byte limit")
	}
	payload = append([]byte{}, payload...)
	return codec.Digest(RequestIntentDomain, requestIntentCommitment{
		Version: BaseEnvelopeVersion, ProfileID: profileID,
		ProfileVersion: profileVersion, ProfileExtensions: canonicalExtensions,
		Operation: operation,
		Payload:   payload,
	})
}
