package paiddemand

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const ExecutionManifestProfileV1 = "tos.execution-manifest.generic.v1"

// ExecutionManifestV1 is a business-neutral bridge from an accepted generic
// Agreement to a native Quote. It says which obligations and immutable input
// set the selected executor is expected to satisfy; profession-specific terms
// remain in the Agreement and opaque plan bytes.
type ExecutionManifestV1 struct {
	SchemaVersion                 uint16   `json:"schema_version"`
	AgreementBodyDigest           string   `json:"agreement_body_digest"`
	WorkObligationIDs             []string `json:"work_obligation_ids"`
	ExecutionProfileURI           string   `json:"execution_profile_uri"`
	PlanContentType               string   `json:"plan_content_type"`
	Plan                          []byte   `json:"plan"`
	AcceptedInputSetDigestOrZero  string   `json:"accepted_input_set_digest_or_zero"`
	DeliverablePolicyDigestOrZero string   `json:"deliverable_policy_digest_or_zero"`
}

func ValidateExecutionManifest(manifest ExecutionManifestV1) error {
	if manifest.SchemaVersion != 1 || !canonicalSHA256(manifest.AgreementBodyDigest) ||
		len(manifest.WorkObligationIDs) == 0 || len(manifest.WorkObligationIDs) > 256 ||
		!boundedManifestText(manifest.ExecutionProfileURI, 256) || !boundedManifestText(manifest.PlanContentType, 256) ||
		len(manifest.Plan) == 0 || len(manifest.Plan) > 1<<20 ||
		!canonicalSHA256(manifest.AcceptedInputSetDigestOrZero) ||
		!canonicalSHA256(manifest.DeliverablePolicyDigestOrZero) ||
		!sort.StringsAreSorted(manifest.WorkObligationIDs) {
		return errors.New("invalid generic execution manifest")
	}
	for index, id := range manifest.WorkObligationIDs {
		if !boundedManifestText(id, 256) || index > 0 && manifest.WorkObligationIDs[index-1] == id {
			return errors.New("execution manifest obligation IDs are invalid or duplicated")
		}
	}
	return nil
}

func CanonicalExecutionManifest(manifest ExecutionManifestV1) ([]byte, string, error) {
	if err := ValidateExecutionManifest(manifest); err != nil {
		return nil, "", err
	}
	canonical, err := codec.Marshal(manifest)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func DecodeCanonicalExecutionManifest(canonical []byte) (ExecutionManifestV1, error) {
	var manifest ExecutionManifestV1
	if len(canonical) == 0 || len(canonical) > 1<<20 || codec.Unmarshal(canonical, &manifest) != nil ||
		ValidateExecutionManifest(manifest) != nil {
		return ExecutionManifestV1{}, errors.New("invalid generic execution manifest encoding")
	}
	reencoded, _, err := CanonicalExecutionManifest(manifest)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return ExecutionManifestV1{}, errors.New("execution manifest encoding is not canonical")
	}
	return manifest, nil
}

func canonicalSHA256(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value[7:])
	return err == nil && len(raw) == 32
}

func boundedManifestText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}
