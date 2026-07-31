package authorization

import (
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

// ReceiptBinding is the immutable request/payment scope that Edge Core
// repeats immediately before durable terminal application.
type ReceiptBinding struct {
	Network         string
	ServiceID       string
	SessionID       string
	Operation       string
	RequestID       string
	IntentDigest    string
	AuthorizationID string
	QuoteID         string
}

type ReceiptApplicationMaterial struct {
	Binding          ReceiptBinding
	ReceiptID        string
	RuntimeKeyID     string
	Status           string
	Usage            []protocol.UsageItem
	ChargedNanoTOS   uint64
	ResultDigest     string
	ServiceRevision  string
	ResourceRevision string
	CompletedAt      time.Time
	EnvelopeDigest   string
	Envelope         identity.Envelope
}

// VerifiedReceipt is opaque output from current manifest/runtime-role,
// signature, canonical-payload, quote, and payment binding verification.
type VerifiedReceipt struct {
	valid          bool
	binding        ReceiptBinding
	receipt        protocol.Receipt
	envelope       identity.Envelope
	runtimeKeyID   string
	envelopeDigest string
	validUntil     time.Time
	verifiedAt     time.Time
}

// VerifyReceipt verifies a runtime-signed terminal statement against the
// original opaque payment authorization. It does not persist the receipt or
// transition request state.
func (m *VerifiedManifest) VerifyReceipt(
	envelope identity.Envelope,
	payment AuthorizedPayment,
	now time.Time,
) (VerifiedReceipt, error) {
	if m == nil || m.runtimeKeys == nil {
		return VerifiedReceipt{}, errors.New("invalid verified manifest")
	}
	if !payment.valid {
		return VerifiedReceipt{}, errors.New("invalid authorized payment")
	}
	if payment.network != m.manifest.Network ||
		payment.serviceID != m.manifest.ServiceID {
		return VerifiedReceipt{}, errors.New(
			"receipt payment does not match manifest authority",
		)
	}
	verified, err := m.verifyRuntimeEnvelope(
		envelope,
		protocol.ReceiptDomain,
		protocol.RuntimeRoleReceipt,
		now,
	)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	var receipt protocol.Receipt
	if err := codec.Unmarshal(verified.envelope.Payload, &receipt); err != nil {
		return VerifiedReceipt{}, fmt.Errorf(
			"decode canonical receipt: %w",
			err,
		)
	}
	if err := receipt.Validate(
		payment.quote,
		payment.authorization,
	); err != nil {
		return VerifiedReceipt{}, fmt.Errorf("validate receipt: %w", err)
	}
	digest, err := verified.envelope.Fingerprint()
	if err != nil {
		return VerifiedReceipt{}, fmt.Errorf("fingerprint receipt: %w", err)
	}
	return VerifiedReceipt{
		valid: true,
		binding: ReceiptBinding{
			Network: m.manifest.Network, ServiceID: m.manifest.ServiceID,
			SessionID:       payment.quote.SessionID,
			Operation:       payment.quote.Operation,
			RequestID:       payment.quote.RequestID,
			IntentDigest:    payment.quote.IntentDigest,
			AuthorizationID: payment.authorization.AuthorizationID,
			QuoteID:         payment.quote.QuoteID,
		},
		receipt: receipt, envelope: cloneEnvelope(verified.envelope),
		runtimeKeyID:   verified.key.KeyID,
		envelopeDigest: digest,
		validUntil:     verified.validUntil,
		verifiedAt:     verified.verifiedAt,
	}, nil
}

// ApplicationMaterial rejects copied, expired, or altered verified receipts
// and returns defensive copies for journal application.
func (r VerifiedReceipt) ApplicationMaterial(
	binding ReceiptBinding,
	now time.Time,
) (ReceiptApplicationMaterial, error) {
	if !r.valid {
		return ReceiptApplicationMaterial{}, errors.New(
			"invalid verified receipt",
		)
	}
	now, err := validateNow(now)
	if err != nil {
		return ReceiptApplicationMaterial{}, err
	}
	if binding != r.binding {
		return ReceiptApplicationMaterial{}, errors.New(
			"verified receipt application binding mismatch",
		)
	}
	if now.Before(r.verifiedAt.Add(-identity.MaxClockSkew)) ||
		!r.validUntil.After(now) {
		return ReceiptApplicationMaterial{}, errors.New(
			"verified receipt is no longer current",
		)
	}
	var usage []protocol.UsageItem
	if r.receipt.Usage != nil {
		usage = append(
			make([]protocol.UsageItem, 0, len(r.receipt.Usage)),
			r.receipt.Usage...,
		)
	}
	return ReceiptApplicationMaterial{
		Binding: binding, ReceiptID: r.receipt.ReceiptID,
		RuntimeKeyID: r.runtimeKeyID, Status: r.receipt.Status,
		Usage: usage, ChargedNanoTOS: r.receipt.ChargedNanoTOS,
		ResultDigest:     r.receipt.ResultDigest,
		ServiceRevision:  r.receipt.ServiceRevision,
		ResourceRevision: r.receipt.ResourceRevision,
		CompletedAt:      r.receipt.CompletedAt.UTC(),
		EnvelopeDigest:   r.envelopeDigest,
		Envelope:         cloneEnvelope(r.envelope),
	}, nil
}
