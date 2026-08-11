package atosrpc

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	bolt "go.etcd.io/bbolt"
)

// principalBindingRecord is bucketPrincipalBindings' stored value: the bound
// agent_id plus the exact NetworkReference produced when the binding was
// anchored. Storing the ref at write time (rather than recomputing one on
// every read) is required for correctness: a digest that omitted agent_id
// would make Commit's (kind, id, digest) idempotency collapse two different
// agent_id bindings for the same principal onto the same reference.
type principalBindingRecord struct {
	AgentID           string `json:"agent_id"`
	RefNetwork        string `json:"ref_network"`
	RefReference      string `json:"ref_reference"`
	CreatedUnixMillis int64  `json:"created_unix_millis"`
	UpdatedUnixMillis int64  `json:"updated_unix_millis"`
}

// SeedIdentity installs a bootstrap identity fact. It is intended for service
// startup from already verified configuration; public clients cannot mutate
// identity through a read-only resolution RPC.
func (s *Server) SeedIdentity(identity *atostosv1.AgentIdentity) error {
	if identity == nil || requiredIdentifier("agent_id", identity.AgentId) != nil || strings.TrimSpace(identity.CanonicalUri) == "" {
		return invalid("INVALID_ARGUMENT", "valid agent identity is required")
	}
	copyIdentity := cloneMessage(identity)
	if copyIdentity.IdentityRef == nil {
		digest, err := protoDigest("ATOS-TOS-IDENTITY-V1", copyIdentity)
		if err != nil {
			return err
		}
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
		if err := s.store.putProto(tx, bucketIdentities, copyIdentity.AgentId, copyIdentity); err != nil {
			return err
		}
		return tx.Bucket(bucketIdentityURIs).Put([]byte(copyIdentity.CanonicalUri), []byte(copyIdentity.AgentId))
	})
}

// BindPrincipal is a test/bootstrap-only helper that binds without going
// through CreatePrincipalBinding's RPC/idempotency surface. Production
// binding creation MUST use the CreatePrincipalBinding RPC below -- this
// method remains only because existing tests construct bindings directly
// against an in-process *Server.
func (s *Server) BindPrincipal(principalID, agentID string) error {
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
		digest, err := protoDigest("ATOS-TOS-PRINCIPAL-BINDING-V1", &atostosv1.CreatePrincipalBindingRequest{
			PrincipalId: principalID, AgentId: agentID,
		})
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
	_ context.Context,
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
	return connect.NewResponse(response), nil
}

func (s *Server) ResolvePrincipalBinding(
	_ context.Context,
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
		response.BindingRef = &NetworkReference{Network: record.RefNetwork, Reference: record.RefReference}
		return nil
	})
	if err != nil {
		return nil, err
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
		if _, err := verifiedTOSController(identity, s.authority.Network()); err != nil {
			return failedPrecondition("PROVIDER_IDENTITY_UNAVAILABLE", "agent identity is not independently anchored on this server's configured network: "+err.Error())
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
			response.PrincipalId = req.Msg.PrincipalId
			response.Identity = identity
			response.BindingRef = &NetworkReference{Network: existing.RefNetwork, Reference: existing.RefReference}
			response.Created = false
			return nil
		}
		digest, err := protoDigest("ATOS-TOS-PRINCIPAL-BINDING-V1", withoutTransportContext(req.Msg))
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "principal-binding", req.Msg.PrincipalId, digest)
		if err != nil {
			return unavailable("UNAVAILABLE", "principal binding authority is unavailable")
		}
		now := s.now().UnixMilli()
		record := principalBindingRecord{
			AgentID: req.Msg.AgentId, RefNetwork: ref.Network, RefReference: ref.Reference,
			CreatedUnixMillis: now, UpdatedUnixMillis: now,
		}
		if err := s.store.putJSON(tx, bucketPrincipalBindings, req.Msg.PrincipalId, record); err != nil {
			return err
		}
		if err := tx.Bucket(bucketPrincipalRevocations).Delete([]byte(req.Msg.PrincipalId)); err != nil {
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

// RevokePrincipalBinding ends a principal's current binding. A missing
// binding is not an error: RevokePrincipalBindingResponse.Revoked=false
// distinguishes "there was nothing to revoke" from a transport/authority
// failure, mirroring RevokeExecutionSigner's idempotent-no-op convention.
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
			response.Revoked = false
			return nil
		}
		digest, err := protoDigest("ATOS-TOS-PRINCIPAL-BINDING-REVOCATION-V1", withoutTransportContext(req.Msg))
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
		revocation := principalBindingRevocation{
			ReasonCode: req.Msg.ReasonCode, RefNetwork: ref.Network, RefReference: ref.Reference,
			RevokedUnixMillis: s.now().UnixMilli(),
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
