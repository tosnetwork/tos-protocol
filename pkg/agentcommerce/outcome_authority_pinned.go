package agentcommerce

import (
	"errors"
	"reflect"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// PinnedOutcomeEvidenceAuthorityV1 is the smallest production verifier for
// deployments that distribute historical authority checkpoints through an
// authenticated configuration channel. Pins are immutable by digest; key or
// delegation rotation appends a new pin and must retain old pins for replay.
type PinnedOutcomeEvidenceAuthorityV1 struct {
	TimeProofsByDigest     map[string]AuthorityTimeProofV1
	QualificationsByDigest map[string]IssuerQualificationProofV1
}

func NewPinnedOutcomeEvidenceAuthorityV1(timeProofs []AuthorityTimeProofV1,
	qualifications []IssuerQualificationProofV1) (*PinnedOutcomeEvidenceAuthorityV1, error) {
	verifier := &PinnedOutcomeEvidenceAuthorityV1{TimeProofsByDigest: make(map[string]AuthorityTimeProofV1, len(timeProofs)),
		QualificationsByDigest: make(map[string]IssuerQualificationProofV1, len(qualifications))}
	for _, proof := range timeProofs {
		if ValidateAuthorityTimeProofV1(proof) != nil {
			return nil, errors.New("pinned authority-time proof is invalid")
		}
		key := proof.ProofDigest
		if prior, found := verifier.TimeProofsByDigest[key]; found && !reflect.DeepEqual(prior, proof) {
			return nil, errors.New("authority-time pin conflicts")
		}
		verifier.TimeProofsByDigest[key] = proof
	}
	for _, proof := range qualifications {
		if ValidateIssuerQualificationProofV1(proof) != nil {
			return nil, errors.New("pinned issuer qualification is invalid")
		}
		key, err := OutcomeIssuerQualificationIdentityV1(proof)
		if err != nil {
			return nil, err
		}
		if prior, found := verifier.QualificationsByDigest[key]; found && !reflect.DeepEqual(prior, proof) {
			return nil, errors.New("issuer qualification pin conflicts")
		}
		verifier.QualificationsByDigest[key] = proof
	}
	return verifier, nil
}

func OutcomeIssuerQualificationIdentityV1(proof IssuerQualificationProofV1) (string, error) {
	if ValidateIssuerQualificationProofV1(proof) != nil {
		return "", errors.New("issuer qualification is invalid")
	}
	return outcomeQualificationKey(proof.IssuerAgentID, proof.ScopeProfileURI, proof.SubjectScopeDigest, proof.AuthorityTimeProofDigest), nil
}

func OutcomeSubjectScopeDigestV1(subjectDescriptor string) (string, error) {
	if !outcomeToken(subjectDescriptor, 4096) {
		return "", errors.New("outcome subject descriptor is invalid")
	}
	return codec.Digest("tos.operation-outcome.subject-scope.v1", struct {
		SubjectDescriptor string `json:"subject_descriptor"`
	}{subjectDescriptor})
}

func outcomeQualificationKey(issuer, profile, subject, authorityTime string) string {
	return issuer + "\x00" + profile + "\x00" + subject + "\x00" + authorityTime
}

func (verifier *PinnedOutcomeEvidenceAuthorityV1) VerifyOutcomeAuthorityTime(proof AuthorityTimeProofV1,
	_ OutcomeEvidenceItemV1, now time.Time) error {
	if verifier == nil || now.IsZero() || proof.IntervalEndUnix > uint64(now.UTC().Unix()) {
		return errors.New("pinned authority-time verifier is unavailable or proof is from the future")
	}
	pinned, found := verifier.TimeProofsByDigest[proof.ProofDigest]
	if !found || !reflect.DeepEqual(pinned, proof) {
		return errors.New("authority-time proof is not in the authenticated pin set")
	}
	return nil
}

func (verifier *PinnedOutcomeEvidenceAuthorityV1) VerifyOutcomeIssuerQualification(proof IssuerQualificationProofV1,
	item OutcomeEvidenceItemV1, authorityTime AuthorityTimeProofV1, _ time.Time) error {
	if verifier == nil || proof.AuthorityTimeProofDigest != item.AuthorityTimeProofDigest || proof.ScopeProfileURI != item.EvidenceProfileURI ||
		proof.IssuerAgentID != item.IssuerDescriptor || authorityTime.IntervalEndUnix < proof.ValidFromUnix || authorityTime.IntervalEndUnix >= proof.ValidUntilUnix {
		return errors.New("issuer qualification does not cover the evidence")
	}
	subjectScope, err := OutcomeSubjectScopeDigestV1(item.SubjectDescriptor)
	if err != nil || subjectScope != proof.SubjectScopeDigest {
		return errors.New("issuer qualification subject scope mismatch")
	}
	key := outcomeQualificationKey(proof.IssuerAgentID, proof.ScopeProfileURI, proof.SubjectScopeDigest, proof.AuthorityTimeProofDigest)
	pinned, found := verifier.QualificationsByDigest[key]
	if !found || !reflect.DeepEqual(pinned, proof) {
		return errors.New("issuer qualification is not in the authenticated pin set")
	}
	return nil
}

var _ OutcomeEvidenceAuthorityVerifierV1 = (*PinnedOutcomeEvidenceAuthorityV1)(nil)
