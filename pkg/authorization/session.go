package authorization

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/nilcheck"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

// ClientKeyReference identifies a client or delegated session key in an
// authoritative key source. MinimumMasterSeqno prevents state rollback when
// the source is chain-backed.
type ClientKeyReference struct {
	Network            string
	ServiceID          string
	KeyID              string
	MinimumMasterSeqno uint64
}

// ClientKeySnapshot is a bounded, fresh client-key result. Principal is the
// authenticated client/payment identity represented by the key. Revocations
// name delegations issued by this key; key revocation is separate.
type ClientKeySnapshot struct {
	Network              string
	ServiceID            string
	KeyID                string
	Principal            string
	PublicKey            ed25519.PublicKey
	Revoked              bool
	RevokedDelegationIDs []string
	NotBefore            time.Time
	NotAfter             time.Time
	ObservedMasterSeqno  uint64
	ObservedAt           time.Time
}

// ClientKeyResolver may use chain state, an authenticated session-opening
// exchange, or an explicitly approved local trust policy. Discovery metadata
// alone must not implement this interface.
type ClientKeyResolver interface {
	ResolveClientKey(context.Context, ClientKeyReference) (ClientKeySnapshot, error)
}

// SessionPayloadValidator must bind the canonical payload to both its request
// identity and the exact cumulative amount that admission will reserve.
type SessionPayloadValidator func(
	canonicalCBOR []byte,
	binding AdmissionBinding,
	chargeNanoTOS uint64,
) error

// VerifiedSessionGrant is produced only after the current manifest runtime
// key and the complete canonical session value have been verified.
type VerifiedSessionGrant struct {
	grant                 protocol.SessionGrant
	grantDigest           string
	network               string
	verifiedAt            time.Time
	validUntil            time.Time
	maxKeyAge             time.Duration
	maxRevokedDelegations int
}

// UsageBudget is one cumulative session or delegation limit that Edge Core
// must claim atomically with the request and nonce.
type UsageBudget struct {
	Kind        string
	ID          string
	GrantDigest string
	MaxActions  uint64
	MaxNanoTOS  uint64
}

// SessionAdmissionMaterial is returned only from an opaque
// AuthorizedSessionEnvelope after all bindings are rechecked.
type SessionAdmissionMaterial struct {
	Envelope         identity.Envelope
	ClientID         string
	SessionExpiresAt time.Time
	ChargeNanoTOS    uint64
	Budgets          []UsageBudget
}

// AuthorizedSessionEnvelope is eligible for atomic journal/session-budget
// admission. It is not executable authority until Edge Core has successfully
// persisted that admission.
type AuthorizedSessionEnvelope struct {
	valid           bool
	envelope        identity.Envelope
	network         string
	serviceID       string
	authority       string
	clientID        string
	clientPrincipal string
	binding         AdmissionBinding
	budgets         []UsageBudget
	charge          uint64
	sessionEnd      time.Time
	validUntil      time.Time
	verifiedAt      time.Time
}

func (m *VerifiedManifest) VerifySessionGrant(
	envelope identity.Envelope,
	now time.Time,
) (*VerifiedSessionGrant, error) {
	verified, err := m.verifyRuntimeEnvelope(
		envelope,
		protocol.SessionGrantDomain,
		protocol.RuntimeRoleAuthenticate,
		now,
	)
	if err != nil {
		return nil, err
	}
	var grant protocol.SessionGrant
	if err := codec.Unmarshal(verified.envelope.Payload, &grant); err != nil {
		return nil, fmt.Errorf("decode canonical session grant: %w", err)
	}
	if err := grant.Validate(verified.verifiedAt); err != nil {
		return nil, fmt.Errorf("validate session grant: %w", err)
	}
	if grant.ServiceID != m.manifest.ServiceID ||
		grant.RuntimeKeyID != verified.key.KeyID ||
		grant.ManifestRevision != m.manifest.Revision {
		return nil, errors.New("session grant does not match current manifest authority")
	}
	if !manifestSupportsSessionProfile(
		m.manifest, grant.ProfileID, grant.ProfileVersion,
		grant.ProfileExtensions,
	) {
		return nil, errors.New("session grant selects an undeclared manifest profile or extension")
	}
	envelopeIssuedAt := time.UnixMilli(verified.envelope.IssuedAt)
	envelopeExpiresAt := time.UnixMilli(verified.envelope.ExpiresAt)
	if envelopeIssuedAt.After(envelopeTime(grant.IssuedAt)) ||
		envelopeExpiresAt.Before(envelopeTime(grant.ExpiresAt)) {
		return nil, errors.New("session grant exceeds its authenticated runtime envelope")
	}
	grantDigest, err := verified.envelope.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("fingerprint session grant: %w", err)
	}
	return &VerifiedSessionGrant{
		grant: cloneSessionGrant(grant), grantDigest: grantDigest,
		network: m.manifest.Network, verifiedAt: verified.verifiedAt,
		validUntil: earliest(verified.validUntil, grant.ExpiresAt),
		maxKeyAge:  m.maxKeyAge, maxRevokedDelegations: m.maxRevocations,
	}, nil
}

// AuthorizeClientEnvelope verifies a direct session client or a complete
// root-to-leaf delegation chain. requiredScope is checked on every
// delegation, while binding.Operation is checked against the session grant.
// chargeNanoTOS is the amount all cumulative budgets will reserve atomically.
func (s *VerifiedSessionGrant) AuthorizeClientEnvelope(
	ctx context.Context,
	resolver ClientKeyResolver,
	minimumMasterSeqno uint64,
	delegations []identity.Envelope,
	envelope identity.Envelope,
	expectedDomain, requiredScope string,
	now time.Time,
	binding AdmissionBinding,
	chargeNanoTOS uint64,
	validatePayload SessionPayloadValidator,
) (AuthorizedSessionEnvelope, error) {
	if s == nil || s.grantDigest == "" {
		return AuthorizedSessionEnvelope{}, errors.New("invalid verified session grant")
	}
	if ctx == nil {
		return AuthorizedSessionEnvelope{}, errors.New("nil client-key context")
	}
	if nilcheck.IsNil(resolver) {
		return AuthorizedSessionEnvelope{}, errors.New("nil client-key resolver")
	}
	if err := ctx.Err(); err != nil {
		return AuthorizedSessionEnvelope{}, err
	}
	if validatePayload == nil {
		return AuthorizedSessionEnvelope{}, errors.New("nil semantic payload validator")
	}
	if err := binding.validate(); err != nil {
		return AuthorizedSessionEnvelope{}, err
	}
	now, err := validateNow(now)
	if err != nil {
		return AuthorizedSessionEnvelope{}, err
	}
	if binding.SessionID != s.grant.SessionID ||
		!containsString(s.grant.Operations, binding.Operation) {
		return AuthorizedSessionEnvelope{}, errors.New("request is outside session operation scope")
	}
	if !s.validUntil.After(now) {
		return AuthorizedSessionEnvelope{}, errors.New("verified session is no longer current")
	}
	if len(delegations) > protocol.MaxDelegationDepth+1 {
		return AuthorizedSessionEnvelope{}, errors.New("delegation chain exceeds protocol maximum")
	}
	if len(delegations) != 0 && !serviceIDPattern.MatchString(requiredScope) {
		return AuthorizedSessionEnvelope{}, errors.New("invalid required delegation scope")
	}

	keyCache := make(map[string]ClientKeySnapshot, len(delegations)+1)
	resolve := func(keyID string) (ClientKeySnapshot, error) {
		if cached, ok := keyCache[keyID]; ok {
			return cached, nil
		}
		snapshot, err := safeResolveClientKey(resolver, ctx, ClientKeyReference{
			Network: s.network, ServiceID: s.grant.ServiceID,
			KeyID: keyID, MinimumMasterSeqno: minimumMasterSeqno,
		})
		if err != nil {
			return ClientKeySnapshot{}, fmt.Errorf("resolve client key %q: %w", keyID, err)
		}
		if err := ctx.Err(); err != nil {
			return ClientKeySnapshot{}, err
		}
		if err := snapshot.validate(
			s.network, s.grant.ServiceID, keyID,
			minimumMasterSeqno, s.maxKeyAge,
			s.maxRevokedDelegations, now,
		); err != nil {
			return ClientKeySnapshot{}, err
		}
		snapshot.PublicKey = append(ed25519.PublicKey(nil), snapshot.PublicKey...)
		snapshot.RevokedDelegationIDs = append(
			[]string(nil), snapshot.RevokedDelegationIDs...,
		)
		keyCache[keyID] = snapshot
		return snapshot, nil
	}

	budgets := []UsageBudget{{
		Kind: "session", ID: s.grant.SessionID,
		GrantDigest: s.grantDigest, MaxActions: s.grant.MaxRequests,
		MaxNanoTOS: s.grant.MaxNanoTOS,
	}}
	currentSigner := s.grant.Client
	rootSigner, err := resolve(currentSigner)
	if err != nil {
		return AuthorizedSessionEnvelope{}, err
	}
	clientPrincipal := rootSigner.Principal
	seenSigners := map[string]struct{}{currentSigner: {}}
	seenDelegations := make(map[string]struct{}, len(delegations))
	validUntil := s.validUntil
	var parent protocol.Delegation
	for index, delegationEnvelope := range delegations {
		signer, err := resolve(currentSigner)
		if err != nil {
			return AuthorizedSessionEnvelope{}, err
		}
		delegationEnvelope = cloneEnvelope(delegationEnvelope)
		if delegationEnvelope.KeyID != currentSigner {
			return AuthorizedSessionEnvelope{}, errors.New("delegation signer binding mismatch")
		}
		var delegation protocol.Delegation
		if err := delegationEnvelope.VerifyCanonical(
			signer.PublicKey, protocol.DelegationDomain, now, &delegation,
		); err != nil {
			return AuthorizedSessionEnvelope{}, fmt.Errorf(
				"verify delegation[%d]: %w", index, err,
			)
		}
		if err := delegation.Validate(now); err != nil {
			return AuthorizedSessionEnvelope{}, fmt.Errorf(
				"validate delegation[%d]: %w", index, err,
			)
		}
		if delegation.Issuer != currentSigner ||
			delegation.SessionID != s.grant.SessionID ||
			delegation.Audience != s.grant.ServiceID ||
			!containsString(delegation.Scopes, requiredScope) {
			return AuthorizedSessionEnvelope{}, errors.New("delegation authority or scope mismatch")
		}
		if _, duplicate := seenDelegations[delegation.DelegationID]; duplicate {
			return AuthorizedSessionEnvelope{}, errors.New("duplicate delegation ID in chain")
		}
		seenDelegations[delegation.DelegationID] = struct{}{}
		if _, cycle := seenSigners[delegation.Subject]; cycle {
			return AuthorizedSessionEnvelope{}, errors.New("delegation signer cycle")
		}
		seenSigners[delegation.Subject] = struct{}{}
		if containsString(signer.RevokedDelegationIDs, delegation.DelegationID) {
			return AuthorizedSessionEnvelope{}, errors.New("delegation is revoked")
		}
		if index == 0 {
			if delegation.Depth != 0 || delegation.ParentID != "" {
				return AuthorizedSessionEnvelope{}, errors.New("delegation chain has no valid root")
			}
			if delegation.MaxActions > s.grant.MaxRequests ||
				delegation.MaxNanoTOS > s.grant.MaxNanoTOS {
				return AuthorizedSessionEnvelope{}, errors.New("root delegation expands session limits")
			}
		} else if err := delegation.ValidateChildOf(parent, now); err != nil {
			return AuthorizedSessionEnvelope{}, fmt.Errorf(
				"validate delegation[%d] parent: %w", index, err,
			)
		}
		envelopeIssuedAt := time.UnixMilli(delegationEnvelope.IssuedAt)
		envelopeExpiresAt := time.UnixMilli(delegationEnvelope.ExpiresAt)
		if envelopeIssuedAt.After(envelopeTime(delegation.NotBefore)) ||
			envelopeExpiresAt.Before(envelopeTime(delegation.ExpiresAt)) ||
			envelopeIssuedAt.Before(envelopeTime(signer.NotBefore)) ||
			envelopeExpiresAt.After(envelopeTime(signer.NotAfter)) ||
			delegation.NotBefore.Before(s.grant.IssuedAt) ||
			delegation.ExpiresAt.After(s.grant.ExpiresAt) {
			return AuthorizedSessionEnvelope{}, errors.New("delegation validity exceeds its authority")
		}
		digest, err := delegationEnvelope.Fingerprint()
		if err != nil {
			return AuthorizedSessionEnvelope{}, fmt.Errorf(
				"fingerprint delegation[%d]: %w", index, err,
			)
		}
		budgets = append(budgets, UsageBudget{
			Kind: "delegation", ID: delegation.DelegationID,
			GrantDigest: digest, MaxActions: delegation.MaxActions,
			MaxNanoTOS: delegation.MaxNanoTOS,
		})
		validUntil = earliest(
			validUntil, delegation.ExpiresAt,
			time.UnixMilli(delegationEnvelope.ExpiresAt),
			signer.NotAfter, signer.ObservedAt.Add(s.maxKeyAge),
		)
		currentSigner = delegation.Subject
		parent = delegation
	}

	signer, err := resolve(currentSigner)
	if err != nil {
		return AuthorizedSessionEnvelope{}, err
	}
	envelope = cloneEnvelope(envelope)
	if envelope.KeyID != currentSigner {
		return AuthorizedSessionEnvelope{}, errors.New("client envelope signer binding mismatch")
	}
	if err := envelope.Verify(signer.PublicKey, expectedDomain, now); err != nil {
		return AuthorizedSessionEnvelope{}, fmt.Errorf("verify client envelope: %w", err)
	}
	envelopeIssuedAt := time.UnixMilli(envelope.IssuedAt)
	envelopeExpiresAt := time.UnixMilli(envelope.ExpiresAt)
	if envelopeIssuedAt.Before(envelopeTime(s.grant.IssuedAt)) ||
		envelopeExpiresAt.After(envelopeTime(s.grant.ExpiresAt)) ||
		envelopeIssuedAt.Before(envelopeTime(signer.NotBefore)) ||
		envelopeExpiresAt.After(envelopeTime(signer.NotAfter)) {
		return AuthorizedSessionEnvelope{}, errors.New("client envelope exceeds session or key validity")
	}
	var canonicalPayload interface{}
	if err := codec.Unmarshal(envelope.Payload, &canonicalPayload); err != nil {
		return AuthorizedSessionEnvelope{}, fmt.Errorf("decode canonical client payload: %w", err)
	}
	if err := validatePayload(
		append([]byte(nil), envelope.Payload...),
		binding,
		chargeNanoTOS,
	); err != nil {
		return AuthorizedSessionEnvelope{}, fmt.Errorf("validate client payload: %w", err)
	}
	for _, budget := range budgets {
		if chargeNanoTOS > budget.MaxNanoTOS {
			return AuthorizedSessionEnvelope{}, errors.New("request charge exceeds an authority budget")
		}
	}
	validUntil = earliest(
		validUntil, envelopeExpiresAt,
		signer.NotAfter, signer.ObservedAt.Add(s.maxKeyAge),
	)
	return AuthorizedSessionEnvelope{
		valid: true, envelope: envelope,
		network: s.network, serviceID: s.grant.ServiceID,
		authority: currentSigner, clientID: s.grant.Client,
		clientPrincipal: clientPrincipal,
		binding:         binding, budgets: cloneUsageBudgets(budgets),
		charge: chargeNanoTOS, sessionEnd: s.grant.ExpiresAt,
		validUntil: validUntil, verifiedAt: now,
	}, nil
}

func (a AuthorizedSessionEnvelope) AdmissionMaterial(
	network, serviceID, authority string,
	binding AdmissionBinding,
	chargeNanoTOS uint64,
	now time.Time,
) (SessionAdmissionMaterial, error) {
	if !a.valid {
		return SessionAdmissionMaterial{}, errors.New("invalid authorized session envelope")
	}
	now, err := validateNow(now)
	if err != nil {
		return SessionAdmissionMaterial{}, err
	}
	if network != a.network || serviceID != a.serviceID ||
		authority != a.authority || binding != a.binding ||
		chargeNanoTOS != a.charge {
		return SessionAdmissionMaterial{}, errors.New("authorized session envelope scope mismatch")
	}
	if now.Before(a.verifiedAt.Add(-identity.MaxClockSkew)) ||
		!a.validUntil.After(now) {
		return SessionAdmissionMaterial{}, errors.New("authorized session envelope is no longer admissible")
	}
	return SessionAdmissionMaterial{
		Envelope: cloneEnvelope(a.envelope), ClientID: a.clientID,
		SessionExpiresAt: a.sessionEnd.UTC(), ChargeNanoTOS: a.charge,
		Budgets: cloneUsageBudgets(a.budgets),
	}, nil
}

func (s ClientKeySnapshot) validate(
	network, serviceID, keyID string,
	minimumMasterSeqno uint64,
	maxAge time.Duration,
	maxRevocations int,
	now time.Time,
) error {
	if s.Network != network || s.ServiceID != serviceID || s.KeyID != keyID {
		return errors.New("resolved client key does not match reference")
	}
	if err := bounded("client principal", s.Principal, 1, 512); err != nil {
		return err
	}
	if s.Revoked {
		return errors.New("client key is revoked")
	}
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid client Ed25519 public key")
	}
	if s.ObservedMasterSeqno < minimumMasterSeqno {
		return errors.New("resolved client key is older than caller high-water mark")
	}
	if s.ObservedAt.IsZero() ||
		s.ObservedAt.After(now.Add(identity.MaxClockSkew)) ||
		!s.ObservedAt.Add(maxAge).After(now) {
		return errors.New("client key snapshot is stale or from the future")
	}
	if s.NotBefore.IsZero() || s.NotAfter.IsZero() ||
		!s.NotAfter.After(s.NotBefore) ||
		now.Before(s.NotBefore) || !s.NotAfter.After(now) {
		return errors.New("client key is outside its validity window")
	}
	if len(s.RevokedDelegationIDs) > maxRevocations {
		return errors.New("revoked delegation list exceeds policy")
	}
	seen := make(map[string]struct{}, len(s.RevokedDelegationIDs))
	for _, delegationID := range s.RevokedDelegationIDs {
		if err := bounded("revoked delegation ID", delegationID, 8, 128); err != nil {
			return err
		}
		if _, duplicate := seen[delegationID]; duplicate {
			return errors.New("duplicate revoked delegation ID")
		}
		seen[delegationID] = struct{}{}
	}
	return nil
}

func manifestSupportsSessionProfile(
	manifest protocol.ServiceManifest,
	profileID, profileVersion string,
	profileExtensions []string,
) bool {
	profileFound := false
	for _, profile := range manifest.Profiles {
		if profile.ID == profileID && profile.Version == profileVersion {
			profileFound = true
			break
		}
	}
	if !profileFound {
		return false
	}
	declared := make(map[string]struct{}, len(manifest.Extensions))
	for _, extension := range manifest.Extensions {
		declared[extension.ID] = struct{}{}
	}
	for _, extension := range profileExtensions {
		if _, exists := declared[extension]; !exists {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func cloneSessionGrant(grant protocol.SessionGrant) protocol.SessionGrant {
	grant.Operations = append([]string(nil), grant.Operations...)
	grant.ProfileExtensions = append([]string(nil), grant.ProfileExtensions...)
	return grant
}

func cloneUsageBudgets(values []UsageBudget) []UsageBudget {
	return append([]UsageBudget(nil), values...)
}
