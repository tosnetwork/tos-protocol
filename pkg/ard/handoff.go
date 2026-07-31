package ard

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const TOSServiceDescriptorMediaType = "application/vnd.tos.service+json"

// ServiceHandoff preserves the ARD publisher identity while handing a client
// to the separately authenticated TOS descriptor. It does not turn ARD
// publisher verification into TOS controller authorization.
type ServiceHandoff struct {
	ARDIdentifier      string
	Publisher          string
	DescriptorURL      string
	EmbeddedDescriptor *protocol.ServiceDescriptor
}

func ParseServiceHandoff(entry Entry, now time.Time) (ServiceHandoff, error) {
	if err := entry.Validate(DefaultLimits()); err != nil {
		return ServiceHandoff{}, err
	}
	if entry.Type != TOSServiceDescriptorMediaType {
		return ServiceHandoff{}, fmt.Errorf("ARD entry type must be %q", TOSServiceDescriptorMediaType)
	}
	publisher, err := Publisher(entry.Identifier)
	if err != nil {
		return ServiceHandoff{}, err
	}
	handoff := ServiceHandoff{ARDIdentifier: entry.Identifier, Publisher: publisher}
	if entry.URL != "" {
		parsed, err := url.ParseRequestURI(entry.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
			parsed.User != nil || parsed.Fragment != "" {
			return ServiceHandoff{}, errors.New("public TOS descriptor handoff requires an absolute HTTPS URL")
		}
		handoff.DescriptorURL = entry.URL
		return handoff, nil
	}
	var descriptor protocol.ServiceDescriptor
	if err := jsonstrict.Decode(entry.Data, &descriptor); err != nil {
		return ServiceHandoff{}, fmt.Errorf("decode embedded TOS descriptor: %w", err)
	}
	if err := handoff.VerifyDescriptor(descriptor, now); err != nil {
		return ServiceHandoff{}, err
	}
	handoff.EmbeddedDescriptor = &descriptor
	return handoff, nil
}

// VerifyDescriptor validates the operational descriptor and its explicit
// back-reference. Controller signatures and chain authority are verified by
// the TOS client after this structural handoff.
func (h ServiceHandoff) VerifyDescriptor(descriptor protocol.ServiceDescriptor, now time.Time) error {
	if h.ARDIdentifier == "" || h.Publisher == "" {
		return errors.New("incomplete ARD handoff")
	}
	if err := descriptor.Validate(now); err != nil {
		return fmt.Errorf("invalid TOS descriptor: %w", err)
	}
	if descriptor.ARDIdentifier != h.ARDIdentifier {
		return errors.New("TOS descriptor does not bind the ARD identifier")
	}
	return nil
}
