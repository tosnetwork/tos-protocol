package agentguarantor

import (
	"errors"
)

// ImmutableEvidenceResolver retrieves an exact content-addressed object from
// an owner-selected, policy-constrained store. It must not interpret retrieval
// hints supplied by an untrusted protocol object.
type ImmutableEvidenceResolver interface {
	ResolveImmutableGuarantorEvidence(ImmutableEvidenceDescriptorV1) ([]byte, error)
}

func resolveImmutableEvidenceV1(resolver AuthorityKeyResolver, descriptor ImmutableEvidenceDescriptorV1,
	required bool) ([]byte, error) {
	contentResolver, ok := resolver.(ImmutableEvidenceResolver)
	if !ok || contentResolver == nil {
		if required {
			return nil, errors.New("independently enforced compact proof has no immutable evidence resolver")
		}
		return nil, nil
	}
	wire, err := contentResolver.ResolveImmutableGuarantorEvidence(descriptor)
	if err != nil || uint64(len(wire)) != descriptor.ContentSize {
		return nil, errors.New("compact proof immutable evidence retrieval failed")
	}
	return wire, nil
}
