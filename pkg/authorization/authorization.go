// Package authorization verifies controller-signed service manifests and
// runtime envelopes against a fresh chain or local-policy authority snapshot.
// It does not resolve transport identity, observe payment, or execute work.
package authorization

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/nilcheck"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	DefaultMaxAuthorityAge       = 5 * time.Minute
	DefaultMaxRevokedRuntimeKeys = 1_024

	maxAuthorityAge       = time.Hour
	maxRevokedRuntimeKeys = 4_096
)

var (
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	serviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,127}$`)
)

// Reference identifies the chain or local-policy service authority to
// resolve. Address is the service registration address, not a transport URL.
type Reference struct {
	Network            string
	Address            string
	ServiceID          string
	MinimumMasterSeqno uint64
}

// AuthoritySnapshot is the bounded result of resolving current service
// authority. ManifestDigest is the tos.manifest.v1 canonical value digest.
type AuthoritySnapshot struct {
	Active               bool
	Network              string
	ServiceID            string
	Controller           string
	ControllerPublicKey  ed25519.PublicKey
	ManifestDigest       string
	RevokedRuntimeKeyIDs []string
	ObservedMasterSeqno  uint64
	ObservedAt           time.Time
}

// Resolver may be backed by the TOS chain or an explicitly approved local
// trust policy. Transport discovery alone must not implement this interface.
type Resolver interface {
	ResolveAuthority(context.Context, Reference) (AuthoritySnapshot, error)
}

type Policy struct {
	MaxAuthorityAge       time.Duration
	MaxRevokedRuntimeKeys int
}

func DefaultPolicy() Policy {
	return Policy{
		MaxAuthorityAge:       DefaultMaxAuthorityAge,
		MaxRevokedRuntimeKeys: DefaultMaxRevokedRuntimeKeys,
	}
}

type Verifier struct {
	policy Policy
}

func NewVerifier(policy Policy) (*Verifier, error) {
	if policy.MaxAuthorityAge <= 0 || policy.MaxAuthorityAge > maxAuthorityAge ||
		policy.MaxRevokedRuntimeKeys <= 0 ||
		policy.MaxRevokedRuntimeKeys > maxRevokedRuntimeKeys {
		return nil, errors.New("invalid authorization policy")
	}
	return &Verifier{policy: policy}, nil
}

// VerifiedManifest contains only state produced by successful controller,
// canonical-payload, current-digest, freshness, and revocation validation.
// Its fields are deliberately private.
type VerifiedManifest struct {
	manifest         protocol.ServiceManifest
	runtimeKeys      map[string]protocol.RuntimeKey
	revoked          map[string]struct{}
	authorityFreshTo time.Time
	maxKeyAge        time.Duration
	maxRevocations   int
}

// PayloadValidator performs message-specific semantic checks after the
// verifier has established canonical CBOR and runtime authority. The callback
// must bind request/session/operation identifiers and profile policy.
type PayloadValidator func(canonicalCBOR []byte) error

// AdmissionBinding is the request identity that semantic validation must
// extract from the canonical payload. Edge Core rechecks it before journal
// admission so an authorization result cannot be reused for another request.
type AdmissionBinding struct {
	SessionID    string
	Operation    string
	RequestID    string
	IntentDigest string
}

// AuthorizedEnvelope is an unforgeable-in-package result consumed by Edge
// Core. A zero value is invalid.
type AuthorizedEnvelope struct {
	valid      bool
	envelope   identity.Envelope
	network    string
	serviceID  string
	authority  string
	binding    AdmissionBinding
	validUntil time.Time
	verifiedAt time.Time
}

func (v *Verifier) ResolveAndVerifyManifest(
	ctx context.Context,
	resolver Resolver,
	reference Reference,
	envelope identity.Envelope,
	now time.Time,
) (*VerifiedManifest, error) {
	if v == nil {
		return nil, errors.New("nil authorization verifier")
	}
	if ctx == nil {
		return nil, errors.New("nil authorization context")
	}
	if nilcheck.IsNil(resolver) {
		return nil, errors.New("nil authority resolver")
	}
	if err := reference.validate(); err != nil {
		return nil, err
	}
	snapshot, err := safeResolveAuthority(resolver, ctx, reference)
	if err != nil {
		return nil, fmt.Errorf("resolve service authority: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if snapshot.Network != reference.Network ||
		snapshot.ServiceID != reference.ServiceID {
		return nil, errors.New("resolved authority does not match reference")
	}
	if snapshot.ObservedMasterSeqno < reference.MinimumMasterSeqno {
		return nil, errors.New("resolved authority is older than caller high-water mark")
	}
	return v.VerifyManifest(snapshot, envelope, now)
}

func (v *Verifier) VerifyManifest(
	snapshot AuthoritySnapshot,
	envelope identity.Envelope,
	now time.Time,
) (*VerifiedManifest, error) {
	if v == nil {
		return nil, errors.New("nil authorization verifier")
	}
	now, err := validateNow(now)
	if err != nil {
		return nil, err
	}
	if err := snapshot.validate(v.policy, now); err != nil {
		return nil, err
	}
	controllerPublicKey := append(ed25519.PublicKey(nil), snapshot.ControllerPublicKey...)
	envelope = cloneEnvelope(envelope)
	if envelope.KeyID != snapshot.Controller {
		return nil, errors.New("manifest signer does not match current controller")
	}
	var manifest protocol.ServiceManifest
	if err := envelope.VerifyCanonical(
		controllerPublicKey,
		protocol.ServiceManifestDomain,
		now,
		&manifest,
	); err != nil {
		return nil, fmt.Errorf("verify controller manifest: %w", err)
	}
	if err := manifest.Validate(now); err != nil {
		return nil, fmt.Errorf("validate service manifest: %w", err)
	}
	if manifest.Network != snapshot.Network ||
		manifest.ServiceID != snapshot.ServiceID ||
		manifest.Controller != snapshot.Controller {
		return nil, errors.New("manifest does not match current service authority")
	}
	manifestDigest, err := codec.Digest(protocol.ServiceManifestDomain, manifest)
	if err != nil {
		return nil, fmt.Errorf("digest service manifest: %w", err)
	}
	if manifestDigest != snapshot.ManifestDigest {
		return nil, errors.New("manifest is not the current registered revision")
	}
	envelopeIssuedAt := time.UnixMilli(envelope.IssuedAt)
	envelopeExpiresAt := time.UnixMilli(envelope.ExpiresAt)
	if envelopeIssuedAt.After(envelopeTime(manifest.IssuedAt)) ||
		envelopeExpiresAt.Before(envelopeTime(manifest.ExpiresAt)) {
		return nil, errors.New("controller envelope does not cover manifest validity")
	}

	runtimeKeys := make(map[string]protocol.RuntimeKey, len(manifest.RuntimeKeys))
	for _, key := range manifest.RuntimeKeys {
		runtimeKeys[key.KeyID] = key
	}
	revoked := make(map[string]struct{}, len(snapshot.RevokedRuntimeKeyIDs))
	for _, keyID := range snapshot.RevokedRuntimeKeyIDs {
		revoked[keyID] = struct{}{}
	}
	return &VerifiedManifest{
		manifest:         manifest,
		runtimeKeys:      runtimeKeys,
		revoked:          revoked,
		authorityFreshTo: snapshot.ObservedAt.Add(v.policy.MaxAuthorityAge).UTC(),
		maxKeyAge:        v.policy.MaxAuthorityAge,
		maxRevocations:   v.policy.MaxRevokedRuntimeKeys,
	}, nil
}

func (m *VerifiedManifest) AuthorizeRuntimeEnvelope(
	envelope identity.Envelope,
	expectedDomain, requiredRole string,
	now time.Time,
	binding AdmissionBinding,
	validatePayload PayloadValidator,
) (AuthorizedEnvelope, error) {
	if m == nil || m.runtimeKeys == nil {
		return AuthorizedEnvelope{}, errors.New("invalid verified manifest")
	}
	if validatePayload == nil {
		return AuthorizedEnvelope{}, errors.New("nil semantic payload validator")
	}
	if err := binding.validate(); err != nil {
		return AuthorizedEnvelope{}, err
	}
	verified, err := m.verifyRuntimeEnvelope(
		envelope, expectedDomain, requiredRole, now,
	)
	if err != nil {
		return AuthorizedEnvelope{}, err
	}
	if err := validatePayload(
		append([]byte(nil), verified.envelope.Payload...),
	); err != nil {
		return AuthorizedEnvelope{}, fmt.Errorf("validate runtime payload: %w", err)
	}
	return AuthorizedEnvelope{
		valid: true, envelope: verified.envelope,
		network: m.manifest.Network, serviceID: m.manifest.ServiceID,
		authority: verified.key.KeyID, binding: binding,
		validUntil: verified.validUntil, verifiedAt: verified.verifiedAt,
	}, nil
}

type runtimeVerification struct {
	envelope   identity.Envelope
	key        protocol.RuntimeKey
	verifiedAt time.Time
	validUntil time.Time
}

func (m *VerifiedManifest) verifyRuntimeEnvelope(
	envelope identity.Envelope,
	expectedDomain, requiredRole string,
	now time.Time,
) (runtimeVerification, error) {
	if m == nil || m.runtimeKeys == nil {
		return runtimeVerification{}, errors.New("invalid verified manifest")
	}
	now, err := validateNow(now)
	if err != nil {
		return runtimeVerification{}, err
	}
	if !m.manifest.ExpiresAt.After(now) ||
		!m.authorityFreshTo.After(now) {
		return runtimeVerification{}, errors.New("verified authority is no longer current")
	}
	envelope = cloneEnvelope(envelope)
	key, ok := m.runtimeKeys[envelope.KeyID]
	if !ok {
		return runtimeVerification{}, errors.New("runtime key is absent from current manifest")
	}
	if _, isRevoked := m.revoked[key.KeyID]; isRevoked {
		return runtimeVerification{}, errors.New("runtime key is revoked")
	}
	if !hasRole(key.Roles, requiredRole) {
		return runtimeVerification{}, errors.New("runtime key lacks required role")
	}
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(key.PublicKey)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		return runtimeVerification{}, errors.New("invalid runtime public key")
	}
	if err := envelope.Verify(
		ed25519.PublicKey(publicKeyBytes), expectedDomain, now,
	); err != nil {
		return runtimeVerification{}, fmt.Errorf("verify runtime envelope: %w", err)
	}
	envelopeIssuedAt := time.UnixMilli(envelope.IssuedAt)
	envelopeExpiresAt := time.UnixMilli(envelope.ExpiresAt)
	if now.Before(key.NotBefore) || !key.NotAfter.After(now) ||
		envelopeIssuedAt.Before(envelopeTime(key.NotBefore)) ||
		envelopeExpiresAt.After(envelopeTime(key.NotAfter)) {
		return runtimeVerification{}, errors.New("runtime envelope is outside key validity")
	}
	var canonicalPayload interface{}
	if err := codec.Unmarshal(envelope.Payload, &canonicalPayload); err != nil {
		return runtimeVerification{}, fmt.Errorf("decode canonical runtime payload: %w", err)
	}
	return runtimeVerification{
		envelope: envelope, key: key, verifiedAt: now,
		validUntil: earliest(
			envelopeExpiresAt, key.NotAfter,
			m.manifest.ExpiresAt, m.authorityFreshTo,
		),
	}, nil
}

// EnvelopeForAdmission validates that the authorization result is still
// current and bound to the Edge Core replay scope. It returns a defensive
// copy of the verified envelope.
func (a AuthorizedEnvelope) EnvelopeForAdmission(
	network, serviceID, authority string,
	binding AdmissionBinding,
	now time.Time,
) (identity.Envelope, error) {
	if !a.valid {
		return identity.Envelope{}, errors.New("invalid authorized envelope")
	}
	now, err := validateNow(now)
	if err != nil {
		return identity.Envelope{}, err
	}
	if network != a.network || serviceID != a.serviceID ||
		authority != a.authority || binding != a.binding {
		return identity.Envelope{}, errors.New("authorized envelope scope mismatch")
	}
	if now.Before(a.verifiedAt.Add(-identity.MaxClockSkew)) ||
		!a.validUntil.After(now) {
		return identity.Envelope{}, errors.New("authorized envelope is no longer admissible")
	}
	return cloneEnvelope(a.envelope), nil
}

func (b AdmissionBinding) validate() error {
	if err := bounded("sessionId", b.SessionID, 8, 128); err != nil {
		return err
	}
	if err := bounded("operation", b.Operation, 1, 128); err != nil {
		return err
	}
	if err := bounded("requestId", b.RequestID, 8, 128); err != nil {
		return err
	}
	if !digestPattern.MatchString(b.IntentDigest) {
		return errors.New("invalid admission intent digest")
	}
	return nil
}

func (r Reference) validate() error {
	for name, value := range map[string]string{
		"network": r.Network, "address": r.Address,
	} {
		if err := bounded(name, value, 1, 512); err != nil {
			return err
		}
	}
	if !serviceIDPattern.MatchString(r.ServiceID) {
		return errors.New("invalid authorization serviceId")
	}
	return nil
}

func (s AuthoritySnapshot) validate(policy Policy, now time.Time) error {
	if !s.Active {
		return errors.New("service authority is inactive")
	}
	for name, value := range map[string]string{
		"network": s.Network, "controller": s.Controller,
	} {
		if err := bounded(name, value, 1, 512); err != nil {
			return err
		}
	}
	if !serviceIDPattern.MatchString(s.ServiceID) {
		return errors.New("invalid authority serviceId")
	}
	if len(s.ControllerPublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid controller public key")
	}
	if !digestPattern.MatchString(s.ManifestDigest) {
		return errors.New("invalid registered manifest digest")
	}
	if s.ObservedAt.IsZero() ||
		s.ObservedAt.After(now.Add(identity.MaxClockSkew)) ||
		!s.ObservedAt.Add(policy.MaxAuthorityAge).After(now) {
		return errors.New("authority snapshot is stale or from the future")
	}
	if len(s.RevokedRuntimeKeyIDs) > policy.MaxRevokedRuntimeKeys {
		return errors.New("revoked runtime key list exceeds policy")
	}
	seen := make(map[string]struct{}, len(s.RevokedRuntimeKeyIDs))
	for _, keyID := range s.RevokedRuntimeKeyIDs {
		if err := bounded("revoked runtime keyId", keyID, 1, 512); err != nil {
			return err
		}
		if _, duplicate := seen[keyID]; duplicate {
			return errors.New("duplicate revoked runtime keyId")
		}
		seen[keyID] = struct{}{}
	}
	return nil
}

func validateNow(now time.Time) (time.Time, error) {
	if now.IsZero() || now.Year() < 1970 || now.Year() > 9999 {
		return time.Time{}, errors.New("invalid authorization time")
	}
	return now.UTC(), nil
}

func bounded(name, value string, minimum, maximum int) error {
	if len(value) < minimum || len(value) > maximum ||
		strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s has invalid length or content", name)
	}
	return nil
}

func hasRole(roles []string, expected string) bool {
	if expected == "" {
		return false
	}
	for _, role := range roles {
		if role == expected {
			return true
		}
	}
	return false
}

func earliest(values ...time.Time) time.Time {
	output := values[0]
	for _, value := range values[1:] {
		if value.Before(output) {
			output = value
		}
	}
	return output.UTC()
}

func envelopeTime(value time.Time) time.Time {
	return time.UnixMilli(value.UnixMilli()).UTC()
}

func cloneEnvelope(envelope identity.Envelope) identity.Envelope {
	envelope.Payload = append([]byte(nil), envelope.Payload...)
	return envelope
}
