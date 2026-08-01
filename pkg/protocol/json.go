package protocol

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

// DecodeServiceDescriptorJSON applies the same strict duplicate/unknown-field
// policy used by public ingress and validates the complete descriptor at the
// supplied startup time. It is intended for operator-loaded deployment files.
func DecodeServiceDescriptorJSON(data []byte, now time.Time) (ServiceDescriptor, error) {
	if now.IsZero() {
		return ServiceDescriptor{}, errors.New("descriptor validation time is required")
	}
	var descriptor ServiceDescriptor
	if err := jsonstrict.Decode(data, &descriptor); err != nil {
		return ServiceDescriptor{}, errors.New("invalid service descriptor JSON")
	}
	if err := descriptor.Validate(now.UTC()); err != nil {
		return ServiceDescriptor{}, err
	}
	return descriptor, nil
}
