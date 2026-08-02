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

// SessionDraft contains deployment-authentication policy. Service, manifest,
// and runtime revision values are derived from the already verified manifest.
type SessionDraft struct {
	SessionID         string
	ProfileID         string
	ProfileVersion    string
	ProfileExtensions []string
	Client            string
	RuntimeKeyID      string
	Operations        []string
	MaxRequests       uint64
	MaxNanoTOS        uint64
	ExpiresAt         time.Time
}

// SessionSigner is a purpose-specific authenticate-role custody boundary.
type SessionSigner interface {
	SignSession(context.Context, []byte, time.Time, time.Time) (identity.Envelope, error)
}

// IssueSessionGrant builds a bounded manifest-derived grant, delegates only
// canonical bytes to the authenticate signer, and re-verifies its result.
func (m *VerifiedManifest) IssueSessionGrant(
	ctx context.Context,
	draft SessionDraft,
	signer SessionSigner,
	issuedAt time.Time,
) (*VerifiedSessionGrant, identity.Envelope, error) {
	if ctx == nil || nilcheck.IsNil(signer) || m == nil || m.runtimeKeys == nil {
		return nil, identity.Envelope{}, errors.New("invalid session issuance dependencies")
	}
	issuedAt, err := validateNow(issuedAt)
	if err != nil {
		return nil, identity.Envelope{}, err
	}
	issuedAt = issuedAt.UTC()
	grant := protocol.SessionGrant{
		Version: protocol.BaseEnvelopeVersion, SessionID: draft.SessionID,
		ServiceID: m.manifest.ServiceID, ProfileID: draft.ProfileID,
		ProfileVersion:    draft.ProfileVersion,
		ProfileExtensions: append([]string(nil), draft.ProfileExtensions...),
		Client:            draft.Client, RuntimeKeyID: draft.RuntimeKeyID,
		ManifestRevision: m.manifest.Revision,
		Operations:       append([]string(nil), draft.Operations...),
		MaxRequests:      draft.MaxRequests, MaxNanoTOS: draft.MaxNanoTOS,
		IssuedAt: issuedAt, ExpiresAt: draft.ExpiresAt.UTC(),
	}
	if err := grant.Validate(issuedAt); err != nil {
		return nil, identity.Envelope{}, fmt.Errorf("validate prepared session: %w", err)
	}
	payload, err := codec.Marshal(grant)
	if err != nil {
		return nil, identity.Envelope{}, fmt.Errorf("encode canonical session: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, identity.Envelope{}, err
	}
	envelope, err := callSessionSigner(
		signer, ctx, append([]byte(nil), payload...), issuedAt, grant.ExpiresAt,
	)
	if err != nil {
		return nil, identity.Envelope{}, fmt.Errorf("sign session: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, identity.Envelope{}, err
	}
	if envelope.IssuedAt != issuedAt.UnixMilli() ||
		envelope.ExpiresAt != grant.ExpiresAt.UnixMilli() ||
		!bytes.Equal(envelope.Payload, payload) {
		return nil, identity.Envelope{}, errors.New("session signer changed payload or validity")
	}
	verified, err := m.VerifySessionGrant(envelope, issuedAt)
	if err != nil {
		return nil, identity.Envelope{}, fmt.Errorf("verify issued session: %w", err)
	}
	return verified, cloneEnvelope(envelope), nil
}

func callSessionSigner(
	signer SessionSigner,
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (envelope identity.Envelope, err error) {
	defer func() {
		if recover() != nil {
			envelope = identity.Envelope{}
			err = errors.New("session signer panicked")
		}
	}()
	return signer.SignSession(ctx, payload, issuedAt, expiresAt)
}
