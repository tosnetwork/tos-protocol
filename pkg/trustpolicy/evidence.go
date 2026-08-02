package trustpolicy

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const EvidenceEnvelopeDomain = "tos.evidence-bundle.v1"

type EvidenceIssuer struct {
	PublicKey    ed25519.PublicKey
	Issuer       string
	AllowedTypes []string
	MaximumLevel protocol.EvidenceLevel
}

type EvidenceRequirement struct {
	Type         string
	Subject      string
	MinimumLevel protocol.EvidenceLevel
}

type EvidenceVerifier struct {
	issuers map[string]EvidenceIssuer
}

func NewEvidenceVerifier(issuers map[string]EvidenceIssuer) (*EvidenceVerifier, error) {
	if len(issuers) == 0 || len(issuers) > 32 {
		return nil, errors.New("invalid evidence trust policy")
	}
	cloned := make(map[string]EvidenceIssuer, len(issuers))
	for keyID, issuer := range issuers {
		if !validBoundedID(keyID, 512) || len(issuer.PublicKey) != ed25519.PublicKeySize ||
			!validBoundedID(issuer.Issuer, 512) || len(issuer.AllowedTypes) == 0 ||
			len(issuer.AllowedTypes) > protocol.MaxEvidenceClaims || !issuer.MaximumLevel.Valid() {
			return nil, errors.New("invalid evidence trust policy")
		}
		copyIssuer := EvidenceIssuer{
			PublicKey: append(ed25519.PublicKey(nil), issuer.PublicKey...), Issuer: issuer.Issuer,
			AllowedTypes: append([]string(nil), issuer.AllowedTypes...), MaximumLevel: issuer.MaximumLevel,
		}
		seenTypes := make(map[string]struct{}, len(copyIssuer.AllowedTypes))
		for _, claimType := range copyIssuer.AllowedTypes {
			if !protocol.IsValidEvidenceType(claimType) {
				return nil, errors.New("invalid evidence trust policy")
			}
			if _, duplicate := seenTypes[claimType]; duplicate {
				return nil, errors.New("invalid evidence trust policy")
			}
			seenTypes[claimType] = struct{}{}
		}
		cloned[keyID] = copyIssuer
	}
	return &EvidenceVerifier{issuers: cloned}, nil
}

func (v *EvidenceVerifier) Verify(envelope identity.Envelope, requirements []EvidenceRequirement, now time.Time) (protocol.EvidenceBundle, error) {
	if v == nil || now.IsZero() || len(requirements) > protocol.MaxEvidenceClaims {
		return protocol.EvidenceBundle{}, errors.New("evidence rejected")
	}
	issuer, ok := v.issuers[envelope.KeyID]
	if !ok {
		return protocol.EvidenceBundle{}, errors.New("evidence rejected")
	}
	var bundle protocol.EvidenceBundle
	if envelope.VerifyCanonical(issuer.PublicKey, EvidenceEnvelopeDomain, now.UTC(), &bundle) != nil || bundle.Validate(now.UTC()) != nil {
		return protocol.EvidenceBundle{}, errors.New("evidence rejected")
	}
	for _, claim := range bundle.Claims {
		if claim.Issuer != issuer.Issuer || !containsExact(issuer.AllowedTypes, claim.Type) ||
			evidenceRank(claim.Level) > evidenceRank(issuer.MaximumLevel) {
			return protocol.EvidenceBundle{}, errors.New("evidence rejected")
		}
	}
	requirementKeys := make(map[string]struct{}, len(requirements))
	for _, requirement := range requirements {
		if !requirement.MinimumLevel.Valid() || !protocol.IsValidEvidenceType(requirement.Type) || !validBoundedID(requirement.Subject, 512) {
			return protocol.EvidenceBundle{}, errors.New("evidence rejected")
		}
		requirementKey := requirement.Type + "\x00" + requirement.Subject
		if _, duplicate := requirementKeys[requirementKey]; duplicate {
			return protocol.EvidenceBundle{}, errors.New("evidence rejected")
		}
		requirementKeys[requirementKey] = struct{}{}
		matched := false
		for _, claim := range bundle.Claims {
			if claim.Type == requirement.Type && claim.Subject == requirement.Subject &&
				evidenceRank(claim.Level) >= evidenceRank(requirement.MinimumLevel) {
				matched = true
				break
			}
		}
		if !matched {
			return protocol.EvidenceBundle{}, errors.New("evidence rejected")
		}
	}
	return bundle, nil
}

func evidenceRank(level protocol.EvidenceLevel) int {
	switch level {
	case protocol.EvidenceDeclared:
		return 1
	case protocol.EvidenceObserved:
		return 2
	case protocol.EvidenceBenchmarked:
		return 3
	case protocol.EvidenceAudited:
		return 4
	case protocol.EvidenceAttested:
		return 5
	case protocol.EvidenceReplicated:
		return 6
	case protocol.EvidenceProven:
		return 7
	default:
		return 0
	}
}
