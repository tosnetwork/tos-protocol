package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

// DurableExecutionAuthorization is the bounded semantic context required to
// reconstruct a paid execution after process restart. It is not authority by
// itself: Edge Core must load it from the same durable payment record whose
// request, payment, and execution bindings it rechecks before use.
type DurableExecutionAuthorization struct {
	Quote                protocol.Quote
	PaymentAuthorization protocol.PaymentAuthorization
	ProfileVersion       string
	ProfileExtensions    []string
}

// DurableExecutionAuthorization returns a defensive copy of the exact
// quote/payment context that produced this opaque authorization.
func (a AuthorizedPayment) DurableExecutionAuthorization() (
	DurableExecutionAuthorization,
	error,
) {
	if !a.valid {
		return DurableExecutionAuthorization{}, errors.New(
			"invalid authorized payment",
		)
	}
	return cloneDurableExecutionAuthorization(
		DurableExecutionAuthorization{
			Quote: a.quote, PaymentAuthorization: a.authorization,
			ProfileVersion: a.profileVersion,
			ProfileExtensions: append(
				[]string(nil), a.profileExtensions...,
			),
		},
	), nil
}

// ReceiptInvocationMaterial validates the stored semantic context at its
// original quote issue time and returns the same immutable execution binding
// used by a live AuthorizedPayment. It deliberately performs no chain or
// signature recovery; callers must first establish that this exact value came
// from their trusted durable payment record.
func (d DurableExecutionAuthorization) ReceiptInvocationMaterial() (
	ReceiptInvocationMaterial,
	error,
) {
	d = cloneDurableExecutionAuthorization(d)
	if d.Quote.IssuedAt.IsZero() {
		return ReceiptInvocationMaterial{}, errors.New(
			"durable execution authorization has no quote issue time",
		)
	}
	if err := d.Quote.Validate(d.Quote.IssuedAt); err != nil {
		return ReceiptInvocationMaterial{}, fmt.Errorf(
			"validate durable execution quote: %w", err,
		)
	}
	if err := d.PaymentAuthorization.Validate(
		d.Quote,
		d.Quote.IssuedAt,
	); err != nil {
		return ReceiptInvocationMaterial{}, fmt.Errorf(
			"validate durable payment authorization: %w", err,
		)
	}
	negotiated, err := protocol.NegotiateProfile(
		protocol.ProfileRequest{
			ID:                d.Quote.ProfileID,
			SupportedVersions: []string{d.ProfileVersion},
			SupportedExtensions: append(
				[]string(nil), d.ProfileExtensions...,
			),
		},
		protocol.ProfileOffer{
			ID:       d.Quote.ProfileID,
			Versions: []string{d.ProfileVersion},
			CriticalExtensions: append(
				[]string(nil), d.ProfileExtensions...,
			),
		},
	)
	if err != nil {
		return ReceiptInvocationMaterial{}, fmt.Errorf(
			"validate durable execution profile: %w", err,
		)
	}
	if negotiated.Version != d.ProfileVersion ||
		!slices.Equal(negotiated.Extensions, d.ProfileExtensions) {
		return ReceiptInvocationMaterial{}, errors.New(
			"durable execution profile is not canonical",
		)
	}
	return ReceiptInvocationMaterial{
		Network: d.Quote.Network, ServiceID: d.Quote.ServiceID,
		ProfileID: d.Quote.ProfileID, ProfileVersion: negotiated.Version,
		ProfileExtensions: append([]string(nil), negotiated.Extensions...),
		SessionID:         d.Quote.SessionID, Operation: d.Quote.Operation,
		RequestID: d.Quote.RequestID, IntentDigest: d.Quote.IntentDigest,
		AuthorizationID: d.PaymentAuthorization.AuthorizationID,
		QuoteID:         d.Quote.QuoteID, PriceNanoTOS: d.Quote.PriceNanoTOS,
		MaxInputBytes:    d.Quote.MaxInputBytes,
		MaxOutputBytes:   d.Quote.MaxOutputBytes,
		Deadline:         d.Quote.Deadline.UTC(),
		ServiceRevision:  d.Quote.ServiceRevision,
		ResourceRevision: d.Quote.ResourceRevision,
	}, nil
}

// IssueDurableReceipt signs and verifies a receipt against execution context
// recovered from trusted local durable state. The caller remains responsible
// for matching this context to the current request, payment, and execution
// records before invoking key custody.
func (m *VerifiedManifest) IssueDurableReceipt(
	ctx context.Context,
	durable DurableExecutionAuthorization,
	draft ReceiptDraft,
	signer ReceiptSigner,
	issuedAt time.Time,
	expiresAt time.Time,
) (VerifiedReceipt, error) {
	material, err := durable.ReceiptInvocationMaterial()
	if err != nil {
		return VerifiedReceipt{}, err
	}
	if m == nil || m.runtimeKeys == nil ||
		material.Network != m.manifest.Network ||
		material.ServiceID != m.manifest.ServiceID {
		return VerifiedReceipt{}, errors.New(
			"durable execution authorization does not match manifest authority",
		)
	}
	payment := AuthorizedPayment{
		valid: true,
		quote: durable.Quote, authorization: durable.PaymentAuthorization,
		network: material.Network, serviceID: material.ServiceID,
		profileVersion: material.ProfileVersion,
		profileExtensions: append(
			[]string(nil), material.ProfileExtensions...,
		),
	}
	return m.IssueReceipt(
		ctx,
		payment,
		draft,
		signer,
		issuedAt,
		expiresAt,
	)
}

func cloneDurableExecutionAuthorization(
	value DurableExecutionAuthorization,
) DurableExecutionAuthorization {
	value.Quote.ResourceLimits = append(
		[]protocol.ResourceLimit(nil), value.Quote.ResourceLimits...,
	)
	value.ProfileExtensions = append(
		[]string(nil), value.ProfileExtensions...,
	)
	return value
}
