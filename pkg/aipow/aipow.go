// Package aipow implements the v0 AIPoW (Artificial Intelligence Proof of Work)
// capability-class vocabulary defined by atos-spec's
// docs/AIPOW_WORK_ATTRIBUTION.md: the class registry, per-class
// normalization from receipt usage, and the strict validation verifiers
// apply. A measurement that cannot be normalized under the vocabulary's
// rules is reported under the default class, never approximated under a
// specific one; a malformed attribution is rejected, never repaired.
package aipow

import (
	"fmt"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

// RateCardVersion is the vocabulary revision this package implements.
const RateCardVersion = "v0"

// Capability classes of vocabulary v0.
const (
	ClassTextGeneration          = "text-generation"
	ClassEmbedding               = "embedding"
	ClassImageGeneration         = "image-generation"
	ClassSpeechRecognition       = "speech-recognition"
	ClassSpeechSynthesis         = "speech-synthesis"
	ClassStorageByteHour         = "storage-byte-hour"
	ClassVerificationReplication = "verification-replication"
	// ClassDefault carries the settled amount in nanoTOS as its work
	// units — the interim fallback with no independent measurement.
	ClassDefault = "default"
)

// classUnits is the closed v0 registry: class -> normalized billing unit.
var classUnits = map[string]string{
	ClassTextGeneration:          "kilo-output-tokens",
	ClassEmbedding:               "call",
	ClassImageGeneration:         "image",
	ClassSpeechRecognition:       "audio-second",
	ClassSpeechSynthesis:         "audio-second",
	ClassStorageByteHour:         "byte-hour",
	ClassVerificationReplication: "replicated-call",
	ClassDefault:                 "settled-nanotos",
}

// UnitFor returns the normalized billing unit of a v0 class.
func UnitFor(class string) (string, bool) {
	unit, ok := classUnits[class]
	return unit, ok
}

// textGenerationUnits normalizes output tokens to kilo-output-tokens:
// floor(tokens / 1000), with any nonzero output below 1000 reporting 1.
func textGenerationUnits(outputTokens uint64) uint64 {
	if outputTokens == 0 {
		return 0
	}
	if outputTokens < 1000 {
		return 1
	}
	return outputTokens / 1000
}

// AttributionFromUsage derives the fill for a receipt this authority is
// about to sign. Usage carrying output tokens is measured
// text generation; anything else falls to the default class carrying the
// settled network charge (in atomic nanoTOS). Evidence is whatever the
// caller can substantiate for this receipt — for ordinary settled
// consumer work through the managed flow that is OBSERVED; nothing here
// upgrades it.
func AttributionFromUsage(
	usage *atostosv1.Usage,
	settledAtomicNano uint64,
	evidence atostosv1.AipowEvidenceLevel,
) *atostosv1.AipowWorkAttribution {
	attribution := &atostosv1.AipowWorkAttribution{
		RateCardVersion: RateCardVersion,
		EvidenceLevel:   evidence,
	}
	if usage != nil && usage.OutputTokens > 0 {
		attribution.CapabilityClass = ClassTextGeneration
		attribution.Unit = classUnits[ClassTextGeneration]
		attribution.WorkUnits = textGenerationUnits(usage.OutputTokens)
		return attribution
	}
	attribution.CapabilityClass = ClassDefault
	attribution.Unit = classUnits[ClassDefault]
	attribution.WorkUnits = settledAtomicNano
	return attribution
}

func validateCommitment(label string, digest *atostosv1.Digest) error {
	if digest == nil {
		// Absent commitments are allowed in v0: they are populated once
		// chain identity bindings exist for the parties.
		return nil
	}
	if digest.Algorithm != "sha256" {
		return fmt.Errorf("%s commitment algorithm must be sha256, got %q", label, digest.Algorithm)
	}
	if len(digest.Value) != 32 {
		return fmt.Errorf("%s commitment must be 32 bytes, got %d", label, len(digest.Value))
	}
	return nil
}

// Validate applies the vocabulary's strict verifier rules. A nil
// attribution is valid (the field is optional); a present-but-malformed
// one is an error the caller must treat as a rejection, never a repair.
func Validate(attribution *atostosv1.AipowWorkAttribution) error {
	if attribution == nil {
		return nil
	}
	if attribution.RateCardVersion != RateCardVersion {
		return fmt.Errorf(
			"unknown rate card version %q (this verifier implements %q)",
			attribution.RateCardVersion, RateCardVersion,
		)
	}
	unit, known := classUnits[attribution.CapabilityClass]
	if !known {
		return fmt.Errorf("unknown capability class %q for rate card %s",
			attribution.CapabilityClass, RateCardVersion)
	}
	if attribution.Unit != unit {
		return fmt.Errorf("class %q requires unit %q, got %q",
			attribution.CapabilityClass, unit, attribution.Unit)
	}
	if attribution.WorkUnits == 0 && attribution.CapabilityClass != ClassDefault {
		// Zero measured work under a specific class is meaningless; only
		// the default class may carry zero (zero-charge settlements).
		return fmt.Errorf("class %q attribution with zero work units", attribution.CapabilityClass)
	}
	if attribution.EvidenceLevel == atostosv1.AipowEvidenceLevel_AIPOW_EVIDENCE_LEVEL_UNSPECIFIED ||
		attribution.EvidenceLevel > atostosv1.AipowEvidenceLevel_AIPOW_EVIDENCE_LEVEL_REPLICATED {
		return fmt.Errorf("invalid evidence level %d", attribution.EvidenceLevel)
	}
	if err := validateCommitment("earner", attribution.EarnerIdentityCommitment); err != nil {
		return err
	}
	if err := validateCommitment("payer", attribution.PayerIdentityCommitment); err != nil {
		return err
	}
	return nil
}
