package authorization

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/nilcheck"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

// ReceiptInvocationMaterial is immutable quote/payment scope used by Edge
// Core to correlate a validated private Worker result. It remains available
// after payment authorization expiry because execution may finish later.
type ReceiptInvocationMaterial struct {
	Network           string
	ServiceID         string
	ProfileID         string
	ProfileVersion    string
	ProfileExtensions []string
	SessionID         string
	Operation         string
	RequestID         string
	IntentDigest      string
	AuthorizationID   string
	QuoteID           string
	PriceNanoTOS      uint64
	MaxInputBytes     uint64
	MaxOutputBytes    uint64
	Deadline          time.Time
	ServiceRevision   string
	ResourceRevision  string
}

// ReceiptDraft contains only execution outcome fields. All authority,
// correlation, and revision fields are copied from AuthorizedPayment.
type ReceiptDraft struct {
	ReceiptID      string
	Status         string
	Usage          []protocol.UsageItem
	ChargedNanoTOS uint64
	ResultDigest   string
	CompletedAt    time.Time
}

// ReceiptSigner is a purpose-specific key-custody boundary. A production
// implementation may call a local sidecar, HSM, or operating-system keystore;
// the private key never needs to enter Edge Core or the Worker process.
type ReceiptSigner interface {
	SignReceipt(
		context.Context,
		[]byte,
		time.Time,
		time.Time,
	) (identity.Envelope, error)
}

func (a AuthorizedPayment) ReceiptInvocationMaterial() (
	ReceiptInvocationMaterial,
	error,
) {
	if !a.valid {
		return ReceiptInvocationMaterial{}, errors.New(
			"invalid authorized payment",
		)
	}
	return ReceiptInvocationMaterial{
		Network: a.network, ServiceID: a.serviceID,
		ProfileID: a.quote.ProfileID, ProfileVersion: a.profileVersion,
		ProfileExtensions: append([]string(nil), a.profileExtensions...),
		SessionID:         a.quote.SessionID, Operation: a.quote.Operation,
		RequestID: a.quote.RequestID, IntentDigest: a.quote.IntentDigest,
		AuthorizationID:  a.authorization.AuthorizationID,
		QuoteID:          a.quote.QuoteID,
		PriceNanoTOS:     a.quote.PriceNanoTOS,
		MaxInputBytes:    a.quote.MaxInputBytes,
		MaxOutputBytes:   a.quote.MaxOutputBytes,
		Deadline:         a.quote.Deadline.UTC(),
		ServiceRevision:  a.quote.ServiceRevision,
		ResourceRevision: a.quote.ResourceRevision,
	}, nil
}

// IssueReceipt constructs an exact payment-bound receipt, delegates only its
// canonical payload to key custody, and immediately re-verifies the returned
// envelope against the current manifest before producing opaque output.
func (m *VerifiedManifest) IssueReceipt(
	ctx context.Context,
	payment AuthorizedPayment,
	draft ReceiptDraft,
	signer ReceiptSigner,
	issuedAt time.Time,
	expiresAt time.Time,
) (VerifiedReceipt, error) {
	if ctx == nil {
		return VerifiedReceipt{}, errors.New("nil receipt signing context")
	}
	if nilcheck.IsNil(signer) {
		return VerifiedReceipt{}, errors.New("nil receipt signer")
	}
	issuedAt, err := validateNow(issuedAt)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	issuedAt = issuedAt.UTC()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(issuedAt) ||
		expiresAt.Sub(issuedAt) > identity.MaxLifetime {
		return VerifiedReceipt{}, errors.New(
			"invalid receipt signing lifetime",
		)
	}
	receipt, err := payment.prepareReceipt(draft)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	payload, err := codec.Marshal(receipt)
	if err != nil {
		return VerifiedReceipt{}, fmt.Errorf(
			"encode canonical receipt: %w",
			err,
		)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedReceipt{}, fmt.Errorf(
			"receipt signing canceled: %w",
			err,
		)
	}
	envelope, err := callReceiptSigner(
		signer,
		ctx,
		append([]byte(nil), payload...),
		issuedAt,
		expiresAt,
	)
	if err != nil {
		return VerifiedReceipt{}, fmt.Errorf("sign receipt: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedReceipt{}, fmt.Errorf(
			"receipt signing canceled: %w",
			err,
		)
	}
	if envelope.IssuedAt != issuedAt.UnixMilli() ||
		envelope.ExpiresAt != expiresAt.UnixMilli() ||
		!bytes.Equal(envelope.Payload, payload) {
		return VerifiedReceipt{}, errors.New(
			"receipt signer changed payload or validity",
		)
	}
	verified, err := m.VerifyReceipt(envelope, payment, issuedAt)
	if err != nil {
		return VerifiedReceipt{}, fmt.Errorf(
			"verify issued receipt: %w",
			err,
		)
	}
	return verified, nil
}

func callReceiptSigner(
	signer ReceiptSigner,
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (envelope identity.Envelope, err error) {
	defer func() {
		if recover() != nil {
			envelope = identity.Envelope{}
			err = errors.New("receipt signer panicked")
		}
	}()
	return signer.SignReceipt(ctx, payload, issuedAt, expiresAt)
}

func (a AuthorizedPayment) prepareReceipt(
	draft ReceiptDraft,
) (protocol.Receipt, error) {
	if !a.valid {
		return protocol.Receipt{}, errors.New("invalid authorized payment")
	}
	if draft.Status != "succeeded" && draft.ResultDigest != "" {
		return protocol.Receipt{}, errors.New(
			"non-successful receipt cannot contain a result digest",
		)
	}
	if draft.ChargedNanoTOS > a.quote.PriceNanoTOS {
		return protocol.Receipt{}, errors.New(
			"receipt charge exceeds quoted price",
		)
	}
	var usage []protocol.UsageItem
	if draft.Usage != nil {
		usage = append(
			make([]protocol.UsageItem, 0, len(draft.Usage)),
			draft.Usage...,
		)
	}
	receipt := protocol.Receipt{
		Version:   protocol.BaseEnvelopeVersion,
		ReceiptID: draft.ReceiptID, RequestID: a.quote.RequestID,
		QuoteID:          a.quote.QuoteID,
		AuthorizationID:  a.authorization.AuthorizationID,
		ServiceID:        a.quote.ServiceID,
		Status:           draft.Status,
		Usage:            usage,
		ChargedNanoTOS:   draft.ChargedNanoTOS,
		ResultDigest:     draft.ResultDigest,
		ServiceRevision:  a.quote.ServiceRevision,
		ResourceRevision: a.quote.ResourceRevision,
		CompletedAt:      draft.CompletedAt.UTC(),
	}
	if err := receipt.Validate(a.quote, a.authorization); err != nil {
		return protocol.Receipt{}, fmt.Errorf(
			"validate prepared receipt: %w",
			err,
		)
	}
	return receipt, nil
}
