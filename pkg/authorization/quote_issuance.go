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

// QuoteDraft contains only request, price, destination, and resource fields.
// Manifest and session authority fields are always derived from verified
// values and cannot be supplied by an ingress handler.
type QuoteDraft struct {
	QuoteID          string
	RequestID        string
	Operation        string
	IntentDigest     string
	ResourceRevision string
	Payee            string
	Settlement       string
	PriceNanoTOS     uint64
	MaxInputBytes    uint64
	MaxOutputBytes   uint64
	ResourceLimits   []protocol.ResourceLimit
	Deadline         time.Time
	ExpiresAt        time.Time
}

// QuoteSigner is the purpose-specific custody boundary for the runtime quote
// role. Implementations may use a local sidecar, HSM, or OS keystore.
type QuoteSigner interface {
	SignQuote(
		context.Context,
		[]byte,
		time.Time,
		time.Time,
	) (identity.Envelope, error)
}

// IssueQuote derives an exact session- and manifest-bound quote, delegates
// only canonical bytes to key custody, and verifies the returned signature
// under the current manifest before returning opaque quote authority.
func (m *VerifiedManifest) IssueQuote(
	ctx context.Context,
	session *VerifiedSessionGrant,
	draft QuoteDraft,
	signer QuoteSigner,
	issuedAt time.Time,
) (*VerifiedQuote, error) {
	if ctx == nil {
		return nil, errors.New("nil quote signing context")
	}
	if nilcheck.IsNil(signer) {
		return nil, errors.New("nil quote signer")
	}
	if m == nil || m.runtimeKeys == nil {
		return nil, errors.New("invalid verified manifest")
	}
	if session == nil || session.grantDigest == "" {
		return nil, errors.New("invalid verified session grant")
	}
	issuedAt, err := validateNow(issuedAt)
	if err != nil {
		return nil, err
	}
	issuedAt = issuedAt.UTC()
	if session.network != m.manifest.Network ||
		session.grant.ServiceID != m.manifest.ServiceID ||
		session.grant.ManifestRevision != m.manifest.Revision ||
		!session.validUntil.After(issuedAt) {
		return nil, errors.New("session is not current for this manifest")
	}
	if !containsString(session.grant.Operations, draft.Operation) {
		return nil, errors.New("quote operation is outside the session scope")
	}
	quote := protocol.Quote{
		Version: protocol.BaseEnvelopeVersion,
		QuoteID: draft.QuoteID, RequestID: draft.RequestID,
		SessionID: session.grant.SessionID,
		ServiceID: m.manifest.ServiceID, ProfileID: session.grant.ProfileID,
		Operation: draft.Operation, IntentDigest: draft.IntentDigest,
		ServiceRevision:  m.manifest.Revision,
		ResourceRevision: draft.ResourceRevision,
		Network:          m.manifest.Network,
		Payee:            draft.Payee, Settlement: draft.Settlement,
		PriceNanoTOS:   draft.PriceNanoTOS,
		MaxInputBytes:  draft.MaxInputBytes,
		MaxOutputBytes: draft.MaxOutputBytes,
		ResourceLimits: append(
			[]protocol.ResourceLimit(nil), draft.ResourceLimits...,
		),
		IssuedAt: issuedAt, Deadline: draft.Deadline.UTC(),
		ExpiresAt: draft.ExpiresAt.UTC(),
	}
	if quote.ExpiresAt.After(session.validUntil) {
		return nil, errors.New("quote validity exceeds the verified session")
	}
	if err := quote.Validate(issuedAt); err != nil {
		return nil, fmt.Errorf("validate prepared quote: %w", err)
	}
	payload, err := codec.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("encode canonical quote: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("quote signing canceled: %w", err)
	}
	envelope, err := callQuoteSigner(
		signer,
		ctx, append([]byte(nil), payload...), issuedAt, quote.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("sign quote: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("quote signing canceled: %w", err)
	}
	if envelope.IssuedAt != issuedAt.UnixMilli() ||
		envelope.ExpiresAt != quote.ExpiresAt.UnixMilli() ||
		!bytes.Equal(envelope.Payload, payload) {
		return nil, errors.New("quote signer changed payload or validity")
	}
	verified, err := m.VerifyQuote(envelope, issuedAt)
	if err != nil {
		return nil, fmt.Errorf("verify issued quote: %w", err)
	}
	return verified, nil
}

func callQuoteSigner(
	signer QuoteSigner,
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (envelope identity.Envelope, err error) {
	defer func() {
		if recover() != nil {
			envelope = identity.Envelope{}
			err = errors.New("quote signer panicked")
		}
	}()
	return signer.SignQuote(ctx, payload, issuedAt, expiresAt)
}
