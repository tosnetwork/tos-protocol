package atosrpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/identitycommitment"
	"github.com/tosnetwork/tos-protocol/pkg/revocationcommitment"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

// principalBindingRecord is bucketPrincipalBindings' stored value: the bound
// agent_id plus the exact NetworkReference produced when the binding was
// anchored. Storing the ref at write time (rather than recomputing one on
// every read) is required for correctness: a digest that omitted agent_id
// would make Commit's (kind, id, digest) idempotency collapse two different
// agent_id bindings for the same principal onto the same reference.
type principalBindingRecord struct {
	AgentID                string `json:"agent_id"`
	RefNetwork             string `json:"ref_network"`
	RefReference           string `json:"ref_reference"`
	RefFinalized           bool   `json:"ref_finalized,omitempty"`
	RefFinalizedCheckpoint uint64 `json:"ref_finalized_checkpoint,omitempty"`
	CommitmentDigest       string `json:"commitment_digest,omitempty"`
	CreatedUnixMillis      int64  `json:"created_unix_millis"`
	UpdatedUnixMillis      int64  `json:"updated_unix_millis"`
}

// SeedIdentity installs a bootstrap identity fact. It is intended for service
// startup from already verified configuration; public clients cannot mutate
// identity through a read-only resolution RPC.
func (s *Server) SeedIdentity(identity *atostosv1.AgentIdentity) error {
	if identity == nil || requiredIdentifier("agent_id", identity.AgentId) != nil || strings.TrimSpace(identity.CanonicalUri) == "" {
		return invalid("INVALID_ARGUMENT", "valid agent identity is required")
	}
	copyIdentity := cloneMessage(identity)
	digest, err := identitycommitment.IdentityDigest(copyIdentity)
	if err != nil {
		return err
	}
	if copyIdentity.IdentityRef == nil {
		ref, err := s.authority.Commit(context.Background(), "identity", copyIdentity.AgentId, digest)
		if err != nil {
			return err
		}
		copyIdentity.IdentityRef = &ref
	}
	if copyIdentity.UpdatedUnixMillis == 0 {
		copyIdentity.UpdatedUnixMillis = s.now().UnixMilli()
	}
	return s.store.update(func(tx *bolt.Tx) error {
		// If this agent_id was already seeded under a DIFFERENT
		// canonical_uri, that old mapping must be removed -- otherwise it
		// keeps resolving to this agent_id forever (bucketIdentityURIs has
		// no other cleanup path) and permanently blocks any future attempt
		// to seed a different agent_id under that now-stale URI.
		var previous atostosv1.AgentIdentity
		previousFound, err := s.store.getProto(tx, bucketIdentities, copyIdentity.AgentId, &previous)
		if err != nil {
			return err
		}
		if previousFound && previous.CanonicalUri != "" && previous.CanonicalUri != copyIdentity.CanonicalUri {
			if err := tx.Bucket(bucketIdentityURIs).Delete([]byte(previous.CanonicalUri)); err != nil {
				return err
			}
		}
		if err := s.store.putProto(tx, bucketIdentities, copyIdentity.AgentId, copyIdentity); err != nil {
			return err
		}
		if err := tx.Bucket(bucketIdentityDigests).Put([]byte(copyIdentity.AgentId), []byte(digest)); err != nil {
			return err
		}
		return tx.Bucket(bucketIdentityURIs).Put([]byte(copyIdentity.CanonicalUri), []byte(copyIdentity.AgentId))
	})
}

// IdentitySeedCurrent distinguishes a v2 canonical seed from a legacy local
// projection whose visible identity fields happen to be equal. It is used
// only by trusted startup enrollment so legacy anchors are upgraded exactly
// once instead of being silently retained forever.
func (s *Server) IdentitySeedCurrent(identity *atostosv1.AgentIdentity) (bool, error) {
	digest, err := identitycommitment.IdentityDigest(identity)
	if err != nil {
		return false, err
	}
	current := false
	err = s.store.view(func(tx *bolt.Tx) error {
		stored := tx.Bucket(bucketIdentityDigests).Get([]byte(identity.AgentId))
		current = string(stored) == digest
		return nil
	})
	return current, err
}

// bindPrincipal is a test-only helper that binds without going through
// CreatePrincipalBinding's RPC/idempotency surface OR its
// verifiedTOSController check (self-asserted/cross-network rejection) --
// unexported so nothing outside this package's own tests can reach a path
// that bypasses those invariants. Production binding creation MUST use the
// CreatePrincipalBinding RPC below; this method remains only because
// existing tests construct bindings directly against an in-process *Server.
func (s *Server) bindPrincipal(principalID, agentID string) error {
	if requiredIdentifier("principal_id", principalID) != nil || requiredIdentifier("agent_id", agentID) != nil {
		return invalid("INVALID_ARGUMENT", "valid principal and agent IDs are required")
	}
	return s.store.update(func(tx *bolt.Tx) error {
		var identity atostosv1.AgentIdentity
		found, err := s.store.getProto(tx, bucketIdentities, agentID, &identity)
		if err != nil {
			return err
		}
		if !found {
			return notFound("NOT_FOUND", "agent identity not found")
		}
		digest, err := identitycommitment.BindingDigest(principalID, agentID)
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(context.Background(), "principal-binding", principalID, digest)
		if err != nil {
			return err
		}
		now := s.now().UnixMilli()
		record := principalBindingRecord{
			AgentID: agentID, RefNetwork: ref.Network, RefReference: ref.Reference,
			CreatedUnixMillis: now, UpdatedUnixMillis: now,
		}
		if err := s.store.putJSON(tx, bucketPrincipalBindings, principalID, record); err != nil {
			return err
		}
		return tx.Bucket(bucketPrincipalRevocations).Delete([]byte(principalID))
	})
}

func (s *Server) ResolveAgentIdentity(
	ctx context.Context,
	req *connect.Request[atostosv1.ResolveAgentIdentityRequest],
) (*connect.Response[atostosv1.ResolveAgentIdentityResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if req.Msg.AgentId == "" && req.Msg.CanonicalUri == "" {
		return nil, invalid("INVALID_ARGUMENT", "agent_id or canonical_uri is required")
	}
	response := &atostosv1.ResolveAgentIdentityResponse{}
	err := s.store.view(func(tx *bolt.Tx) error {
		agentID := req.Msg.AgentId
		if agentID == "" {
			encoded := tx.Bucket(bucketIdentityURIs).Get([]byte(req.Msg.CanonicalUri))
			if encoded == nil {
				return nil
			}
			agentID = string(encoded)
		}
		identity := new(atostosv1.AgentIdentity)
		found, err := s.store.getProto(tx, bucketIdentities, agentID, identity)
		if err != nil {
			return err
		}
		if found {
			response.Identity = identity
			response.Found = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !response.Found && req.Msg.ExpectedIdentity != nil && req.Msg.ExpectedIdentityRef != nil && s.authority.Supports(TrustModeVerified) {
		expected := cloneMessage(req.Msg.ExpectedIdentity)
		if expected.AgentId != req.Msg.AgentId || (req.Msg.CanonicalUri != "" && expected.CanonicalUri != req.Msg.CanonicalUri) {
			return nil, conflict("IDENTITY_MISMATCH", "expected identity lookup tuple mismatch")
		}
		expected.IdentityRef = cloneMessage(req.Msg.ExpectedIdentityRef)
		if _, err := verifiedTOSController(expected, s.authority.Network()); err != nil {
			return nil, failedPrecondition("IDENTITY_MISMATCH", err.Error())
		}
		expected.IdentityRef = nil
		expected.UpdatedUnixMillis = 0
		// PublicAttributes are intentionally excluded from identity.v2. Never
		// echo caller-supplied, unauthenticated metadata from an empty-replica
		// recovery response.
		expected.PublicAttributes = nil
		digest, digestErr := identitycommitment.IdentityDigest(expected)
		resolver, ok := s.authority.(CommitmentResolver)
		if digestErr != nil || !ok {
			return nil, unavailable("NETWORK_UNAVAILABLE", "identity commitment resolver unavailable")
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "identity", expected.AgentId, digest, req.Msg.ExpectedIdentityRef)
		if resolveErr != nil || live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 || live.Network != req.Msg.ExpectedIdentityRef.Network || live.Reference != req.Msg.ExpectedIdentityRef.Reference {
			return nil, unavailable("NETWORK_UNAVAILABLE", "identity finality unavailable")
		}
		expected.IdentityRef = live
		response.Identity, response.Found = expected, true
	}
	if response.Found && response.Identity != nil && response.Identity.IdentityRef != nil && req.Msg.ExpectedIdentityRef != nil && s.authority.Supports(TrustModeVerified) {
		expected := cloneMessage(response.Identity)
		ref := cloneMessage(expected.IdentityRef)
		expected.IdentityRef = nil
		expected.UpdatedUnixMillis = 0
		digest, digestErr := identitycommitment.IdentityDigest(expected)
		resolver, ok := s.authority.(CommitmentResolver)
		if digestErr != nil || !ok {
			return nil, unavailable("NETWORK_UNAVAILABLE", "identity commitment resolver unavailable")
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "identity", expected.AgentId, digest, ref)
		if resolveErr != nil || live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 {
			return nil, unavailable("NETWORK_UNAVAILABLE", "identity finality unavailable")
		}
		response.Identity.IdentityRef = live
	}
	return connect.NewResponse(response), nil
}

func (s *Server) ResolvePrincipalBinding(
	ctx context.Context,
	req *connect.Request[atostosv1.ResolvePrincipalBindingRequest],
) (*connect.Response[atostosv1.ResolvePrincipalBindingResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("principal_id", req.Msg.PrincipalId); err != nil {
		return nil, err
	}
	response := &atostosv1.ResolvePrincipalBindingResponse{PrincipalId: req.Msg.PrincipalId}
	var commitmentDigest string
	err := s.store.view(func(tx *bolt.Tx) error {
		var record principalBindingRecord
		found, err := s.store.getJSON(tx, bucketPrincipalBindings, req.Msg.PrincipalId, &record)
		if err != nil {
			return err
		}
		if !found {
			var revocation principalBindingRevocation
			revoked, err := s.store.getJSON(tx, bucketPrincipalRevocations, req.Msg.PrincipalId, &revocation)
			if err != nil {
				return err
			}
			if revoked {
				response.Status = atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_REVOKED
				response.RevocationReasonCode = revocation.ReasonCode
			}
			return nil
		}
		identity := new(atostosv1.AgentIdentity)
		identityFound, err := s.store.getProto(tx, bucketIdentities, record.AgentID, identity)
		if err != nil {
			return err
		}
		if !identityFound {
			return nil
		}
		response.Identity = identity
		response.Bound = true
		response.Status = atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_ACTIVE
		response.BindingRef = &NetworkReference{
			Network: record.RefNetwork, Reference: record.RefReference,
			Finalized: record.RefFinalized, FinalizedCheckpoint: record.RefFinalizedCheckpoint,
		}
		commitmentDigest = record.CommitmentDigest
		if commitmentDigest == "" {
			commitmentDigest = legacyPrincipalBindingDigestTx(tx, req.Msg.PrincipalId, record)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !response.Bound && req.Msg.ExpectedAgentId != "" && req.Msg.ExpectedBindingRef != nil && s.authority.Supports(TrustModeVerified) {
		resolver, ok := s.authority.(CommitmentResolver)
		if !ok {
			return nil, unavailable("NETWORK_UNAVAILABLE", "principal binding resolver is unavailable")
		}
		digest, digestErr := identitycommitment.BindingDigest(req.Msg.PrincipalId, req.Msg.ExpectedAgentId)
		if digestErr != nil {
			return nil, digestErr
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "principal-binding", req.Msg.PrincipalId, digest, req.Msg.ExpectedBindingRef)
		if resolveErr != nil || live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 || live.Network != req.Msg.ExpectedBindingRef.Network || live.Reference != req.Msg.ExpectedBindingRef.Reference {
			return nil, unavailable("NETWORK_UNAVAILABLE", "principal binding finality unavailable")
		}
		revoked, revocationErr := resolvePrincipalBindingRevocation(ctx, s.authority, req.Msg.PrincipalId, req.Msg.ExpectedAgentId, digest)
		if revocationErr != nil {
			return nil, unavailable("NETWORK_UNAVAILABLE", "principal binding current state unavailable")
		}
		if revoked {
			response.Status = atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_REVOKED
			return connect.NewResponse(response), nil
		}
		response.Identity = &atostosv1.AgentIdentity{AgentId: req.Msg.ExpectedAgentId}
		response.Bound = true
		response.Status = atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_ACTIVE
		response.BindingRef = live
		return connect.NewResponse(response), nil
	}
	if response.Bound && response.Identity != nil && response.BindingRef != nil && s.authority.Supports(TrustModeVerified) {
		resolver, ok := s.authority.(CommitmentResolver)
		if !ok {
			return nil, unavailable("NETWORK_UNAVAILABLE", "principal binding resolver is unavailable")
		}
		if commitmentDigest == "" {
			return nil, unavailable("NETWORK_UNAVAILABLE", "principal binding commitment identity is unavailable")
		}
		// Legacy projections predate durable finality fields. Recover those
		// commitments by deterministic tuple, then require the authority result
		// to match the exact reference retained by the old projection.
		var expected *NetworkReference
		if response.BindingRef.Finalized && response.BindingRef.FinalizedCheckpoint != 0 {
			expected = response.BindingRef
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "principal-binding", req.Msg.PrincipalId, commitmentDigest, expected)
		if resolveErr != nil || live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 || live.Network != response.BindingRef.Network || live.Reference != response.BindingRef.Reference {
			return nil, unavailable("NETWORK_UNAVAILABLE", "principal binding finality is unavailable")
		}
		response.BindingRef = live
		revoked, revocationErr := resolvePrincipalBindingRevocation(ctx, s.authority, req.Msg.PrincipalId, response.Identity.AgentId, commitmentDigest)
		if revocationErr != nil {
			return nil, unavailable("NETWORK_UNAVAILABLE", "principal binding current state unavailable")
		}
		if revoked {
			response.Bound = false
			response.Status = atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_REVOKED
		}
	}
	return connect.NewResponse(response), nil
}

// CreatePrincipalBinding anchors a durable, idempotent binding from
// principal_id to an already-existing agent_id. agent_id MUST independently
// resolve (via bucketIdentities, the same fact ResolveAgentIdentity reads)
// before any binding is anchored -- a caller cannot bind to an identity that
// does not exist. Re-issuing the same (principal_id, agent_id) with a fresh
// idempotency_key is a harmless no-op (created=false, same binding_ref);
// naming a DIFFERENT agent_id for a principal that already has an active
// binding is a conflict -- RevokePrincipalBinding must run first.
func (s *Server) CreatePrincipalBinding(
	ctx context.Context,
	req *connect.Request[atostosv1.CreatePrincipalBindingRequest],
) (*connect.Response[atostosv1.CreatePrincipalBindingResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := requiredIdentifier("principal_id", req.Msg.PrincipalId); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("agent_id", req.Msg.AgentId); err != nil {
		return nil, err
	}
	response := new(atostosv1.CreatePrincipalBindingResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("CreatePrincipalBinding", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		identity := new(atostosv1.AgentIdentity)
		identityFound, err := s.store.getProto(tx, bucketIdentities, req.Msg.AgentId, identity)
		if err != nil {
			return err
		}
		if !identityFound {
			return notFound("NOT_FOUND", "agent identity does not exist; it must be established before it can be bound")
		}
		var existing principalBindingRecord
		existingFound, err := s.store.getJSON(tx, bucketPrincipalBindings, req.Msg.PrincipalId, &existing)
		if err != nil {
			return err
		}
		if existingFound {
			if existing.AgentID != req.Msg.AgentId {
				return conflict("ALREADY_EXISTS", "principal is already bound to a different TOS Agent Identity; revoke the existing binding first")
			}
			// An idempotent replay of an ALREADY-anchored binding must not
			// re-run verifiedTOSController against the identity's CURRENT
			// state: a lost-response retry under a fresh idempotency_key is
			// documented as a safe no-op regardless of what happened to the
			// identity's assurance/network since the original successful
			// bind -- the existing binding remains valid until explicitly
			// revoked (see RevokePrincipalBinding's own doc comment), and
			// ResolvePrincipalBinding would still report it ACTIVE. Gating
			// a mere replay on current identity state would make this RPC
			// disagree with ResolvePrincipalBinding about the same fact.
			response.PrincipalId = req.Msg.PrincipalId
			response.Identity = identity
			response.BindingRef = &NetworkReference{Network: existing.RefNetwork, Reference: existing.RefReference}
			response.Created = false
			return nil
		}
		if _, err := verifiedTOSController(identity, s.authority.Network()); err != nil {
			// A distinct stable code from economic.go's PRINCIPAL_NOT_BOUND
			// (which means "no binding exists at all") and
			// PROVIDER_IDENTITY_UNAVAILABLE (which economic.go uses
			// specifically for the counterparty side of an economic
			// transaction) -- CreatePrincipalBinding's principal_id can be
			// either a consumer or a provider account (they share one
			// namespace), so reusing either existing code here would let a
			// client that switches on reason_code misroute this failure.
			return failedPrecondition("AGENT_IDENTITY_NOT_VERIFIED", "agent identity is not independently anchored on this server's configured network: "+err.Error())
		}
		digest, err := identitycommitment.BindingDigest(req.Msg.PrincipalId, req.Msg.AgentId)
		if err != nil {
			return err
		}
		// Binding v2 deliberately has no mutable generation field. Consequently
		// a tuple that has ever been revoked is a permanent tombstone: reusing
		// it would make the old canonical revocation indistinguishable from a
		// revocation of the purported new binding. Check the live authority, not
		// merely the local revocation bucket, before publishing another binding.
		if s.authority.Supports(TrustModeVerified) {
			revoked, resolveErr := resolvePrincipalBindingRevocation(ctx, s.authority, req.Msg.PrincipalId, req.Msg.AgentId, digest)
			if resolveErr != nil {
				return unavailable("NETWORK_UNAVAILABLE", "principal binding revocation state is unavailable")
			}
			if revoked {
				return conflict("BINDING_TUPLE_REVOKED", "principal and agent binding tuple was previously revoked and cannot be reused")
			}
		}
		ref, err := s.authority.Commit(ctx, "principal-binding", req.Msg.PrincipalId, digest)
		if err != nil {
			return unavailable("UNAVAILABLE", "principal binding authority is unavailable")
		}
		now := s.now().UnixMilli()
		record := principalBindingRecord{
			AgentID: req.Msg.AgentId, RefNetwork: ref.Network, RefReference: ref.Reference,
			RefFinalized: ref.Finalized, RefFinalizedCheckpoint: ref.FinalizedCheckpoint,
			CommitmentDigest:  digest,
			CreatedUnixMillis: now, UpdatedUnixMillis: now,
		}
		if err := s.store.putJSON(tx, bucketPrincipalBindings, req.Msg.PrincipalId, record); err != nil {
			return err
		}
		response.PrincipalId = req.Msg.PrincipalId
		response.Identity = identity
		response.BindingRef = &ref
		response.Created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func legacyPrincipalBindingDigestTx(tx *bolt.Tx, principalID string, binding principalBindingRecord) string {
	if tx == nil || principalID == "" || binding.AgentID == "" {
		return ""
	}
	cursor := tx.Bucket(bucketIdempotency).Cursor()
	for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
		parts := strings.Split(string(key), "\x00")
		if len(parts) != 3 || parts[1] != "CreatePrincipalBinding" {
			continue
		}
		var record idempotencyRecord
		if err := json.Unmarshal(value, &record); err != nil || len(record.Response) == 0 {
			continue
		}
		response := new(atostosv1.CreatePrincipalBindingResponse)
		if err := proto.Unmarshal(record.Response, response); err != nil || response.PrincipalId != principalID ||
			response.Identity == nil || response.Identity.AgentId != binding.AgentID || response.BindingRef == nil ||
			response.BindingRef.Reference != binding.RefReference {
			continue
		}
		request := &atostosv1.CreatePrincipalBindingRequest{Context: &atostosv1.RequestContext{CallerId: parts[0], IdempotencyKey: parts[2]}, PrincipalId: principalID, AgentId: binding.AgentID}
		digest, err := protoDigest("ATOS-TOS-PRINCIPAL-BINDING-V1", withoutTransportContext(request))
		if err == nil {
			return digest
		}
	}
	return ""
}

// RevokePrincipalBinding ends a principal's current binding.
// Revoked=false distinguishes "this principal was never bound" from a
// transport/authority failure, mirroring RevokeExecutionSigner's
// idempotent-no-op convention. A principal that WAS bound and already has a
// revocation on record (whether from this exact call or an earlier one --
// e.g. a lost-response retry under a fresh idempotency_key, the same safe
// retry pattern CreatePrincipalBinding documents) also reports Revoked=true
// with the original revocation_ref, matching what ResolvePrincipalBinding
// already reports as PRINCIPAL_BINDING_STATUS_REVOKED for the same
// principal -- this RPC must not disagree with that fact merely because a
// retry no longer finds an active binding to delete.
func (s *Server) RevokePrincipalBinding(
	ctx context.Context,
	req *connect.Request[atostosv1.RevokePrincipalBindingRequest],
) (*connect.Response[atostosv1.RevokePrincipalBindingResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := requiredIdentifier("principal_id", req.Msg.PrincipalId); err != nil {
		return nil, err
	}
	response := new(atostosv1.RevokePrincipalBindingResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("RevokePrincipalBinding", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		var existing principalBindingRecord
		existingFound, err := s.store.getJSON(tx, bucketPrincipalBindings, req.Msg.PrincipalId, &existing)
		if err != nil {
			return err
		}
		if !existingFound {
			var revocation principalBindingRevocation
			alreadyRevoked, err := s.store.getJSON(tx, bucketPrincipalRevocations, req.Msg.PrincipalId, &revocation)
			if err != nil {
				return err
			}
			if alreadyRevoked {
				response.Revoked = true
				response.RevocationRef = &NetworkReference{Network: revocation.RefNetwork, Reference: revocation.RefReference}
				return nil
			}
			response.Revoked = false
			return nil
		}
		bindingDigest := existing.CommitmentDigest
		if bindingDigest == "" {
			bindingDigest, err = identitycommitment.BindingDigest(req.Msg.PrincipalId, existing.AgentID)
			if err != nil {
				return err
			}
		}
		digest, err := revocationcommitment.BindingDigest(req.Msg.PrincipalId, existing.AgentID, bindingDigest)
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "principal-binding-revocation", req.Msg.PrincipalId, digest)
		if err != nil {
			return unavailable("UNAVAILABLE", "principal binding revocation authority is unavailable")
		}
		if err := tx.Bucket(bucketPrincipalBindings).Delete([]byte(req.Msg.PrincipalId)); err != nil {
			return err
		}
		revokedAt := s.now().UnixMilli()
		if s.authority.Supports(TrustModeVerified) {
			observed, observeErr := resolveCommitmentObservation(ctx, s.authority, "principal-binding-revocation", req.Msg.PrincipalId, digest, &ref)
			if observeErr != nil || observed.ObservedUnixMillis <= 0 {
				return unavailable("NETWORK_UNAVAILABLE", "principal binding revocation finality time is unavailable")
			}
			revokedAt = observed.ObservedUnixMillis
		}
		revocation := principalBindingRevocation{
			ReasonCode: req.Msg.ReasonCode, RefNetwork: ref.Network, RefReference: ref.Reference,
			RevokedUnixMillis: revokedAt,
		}
		if err := s.store.putJSON(tx, bucketPrincipalRevocations, req.Msg.PrincipalId, revocation); err != nil {
			return err
		}
		response.Revoked = true
		response.RevocationRef = &ref
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func resolvePrincipalBindingRevocation(ctx context.Context, authority Authority, principalID, agentID, bindingDigest string) (bool, error) {
	digest, err := revocationcommitment.BindingDigest(principalID, agentID, bindingDigest)
	if err != nil {
		return false, err
	}
	observed, err := resolveCommitmentObservation(ctx, authority, "principal-binding-revocation", principalID, digest, nil)
	if errors.Is(err, ErrCommitmentNotFound) {
		return false, nil
	}
	if err != nil || observed == nil || observed.ObservedUnixMillis <= 0 {
		return false, errors.New("canonical binding revocation unavailable")
	}
	return true, nil
}
