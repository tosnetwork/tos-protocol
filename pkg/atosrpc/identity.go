package atosrpc

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	bolt "go.etcd.io/bbolt"
)

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
		return tx.Bucket(bucketPrincipalBindings).Put([]byte(principalID), []byte(agentID))
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
		encoded := tx.Bucket(bucketPrincipalBindings).Get([]byte(req.Msg.PrincipalId))
		if encoded == nil {
			return nil
		}
		identity := new(atostosv1.AgentIdentity)
		found, err := s.store.getProto(tx, bucketIdentities, string(encoded), identity)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		response.Identity = identity
		response.Bound = true
		digest, err := protoDigest("ATOS-TOS-PRINCIPAL-BINDING-V1", req.Msg)
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(context.Background(), "principal-binding", req.Msg.PrincipalId, digest)
		if err != nil {
			return err
		}
		response.BindingRef = &ref
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}
