package atosrpc

import (
	"bytes"
	"context"
	"strings"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	bolt "go.etcd.io/bbolt"
)

func (s *Server) ResolveCapability(
	_ context.Context,
	req *connect.Request[atostosv1.ResolveCapabilityRequest],
) (*connect.Response[atostosv1.ResolveCapabilityResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if req.Msg.CapabilityId == "" && req.Msg.CanonicalUri == "" {
		return nil, invalid("INVALID_ARGUMENT", "capability_id or canonical_uri is required")
	}
	response := &atostosv1.ResolveCapabilityResponse{}
	err := s.store.view(func(tx *bolt.Tx) error {
		capabilityID := req.Msg.CapabilityId
		version := req.Msg.Version
		if capabilityID == "" {
			// Canonical URI lookup is intentionally bounded by the number of
			// committed capabilities; the public registry/indexer owns search.
			cursor := tx.Bucket(bucketCapabilities).Cursor()
			for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
				candidate := new(atostosv1.CapabilityIdentity)
				found, err := s.store.getProto(tx, bucketCapabilities, string(key), candidate)
				if err != nil {
					return err
				}
				if found && candidate.CanonicalUri == req.Msg.CanonicalUri {
					response.Capability, response.Found = candidate, true
					return nil
				}
			}
			return nil
		}
		if version == "" {
			latest := tx.Bucket(bucketCapabilityLatest).Get([]byte(capabilityID))
			if latest == nil {
				return nil
			}
			version = string(latest)
		}
		identity := new(atostosv1.CapabilityIdentity)
		found, err := s.store.getProto(tx, bucketCapabilities, capabilityKey(capabilityID, version), identity)
		if err != nil {
			return err
		}
		if found {
			response.Capability, response.Found = identity, true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) VerifyCapabilityOwnership(
	_ context.Context,
	req *connect.Request[atostosv1.VerifyCapabilityOwnershipRequest],
) (*connect.Response[atostosv1.VerifyCapabilityOwnershipResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("capability_id", req.Msg.CapabilityId); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("provider_id", req.Msg.ProviderId); err != nil {
		return nil, err
	}
	response := &atostosv1.VerifyCapabilityOwnershipResponse{ReasonCode: "NOT_FOUND"}
	err := s.store.view(func(tx *bolt.Tx) error {
		version := req.Msg.Version
		if version == "" {
			latest := tx.Bucket(bucketCapabilityLatest).Get([]byte(req.Msg.CapabilityId))
			if latest == nil {
				return nil
			}
			version = string(latest)
		}
		identity := new(atostosv1.CapabilityIdentity)
		found, err := s.store.getProto(tx, bucketCapabilities, capabilityKey(req.Msg.CapabilityId, version), identity)
		if err != nil || !found {
			return err
		}
		if identity.ProviderId != req.Msg.ProviderId {
			response.ReasonCode = "PROVIDER_MISMATCH"
			return nil
		}
		if req.Msg.ExpectedManifestDigest != nil {
			if identity.ManifestDigest == nil || identity.ManifestDigest.Algorithm != req.Msg.ExpectedManifestDigest.Algorithm ||
				!bytes.Equal(identity.ManifestDigest.Value, req.Msg.ExpectedManifestDigest.Value) {
				response.ReasonCode = "MANIFEST_MISMATCH"
				return nil
			}
		}
		response.Verified = true
		response.ReasonCode = ""
		response.OwnershipRef = cloneMessage(identity.OwnershipRef)
		response.ManifestRef = cloneMessage(identity.ManifestRef)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) CommitCapabilityManifest(
	ctx context.Context,
	req *connect.Request[atostosv1.CommitCapabilityManifestRequest],
) (*connect.Response[atostosv1.CommitCapabilityManifestResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateDigest(req.Msg.ManifestDigest); err != nil {
		return nil, err
	}
	for name, value := range map[string]string{
		"capability_id": req.Msg.CapabilityId, "provider_id": req.Msg.ProviderId,
		"version": req.Msg.Version,
	} {
		if err := requiredIdentifier(name, value); err != nil {
			return nil, err
		}
	}
	response := new(atostosv1.CommitCapabilityManifestResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("CommitCapabilityManifest", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		key := capabilityKey(req.Msg.CapabilityId, req.Msg.Version)
		existing := new(atostosv1.CapabilityIdentity)
		found, err := s.store.getProto(tx, bucketCapabilities, key, existing)
		if err != nil {
			return err
		}
		if found {
			if existing.ProviderId != req.Msg.ProviderId || existing.ManifestDigest == nil ||
				existing.ManifestDigest.Algorithm != req.Msg.ManifestDigest.Algorithm ||
				!bytes.Equal(existing.ManifestDigest.Value, req.Msg.ManifestDigest.Value) {
				return conflict("ALREADY_EXISTS", "capability version is already committed with different ownership or manifest")
			}
			response.Capability = existing
			response.CommitmentRef = cloneMessage(existing.ManifestRef)
			return nil
		}
		activeModes := make([]atostosv1.TrustMode, 0, len(req.Msg.RequestedTrustModes))
		seenModes := make(map[atostosv1.TrustMode]struct{})
		for _, mode := range req.Msg.RequestedTrustModes {
			if mode == atostosv1.TrustMode_TRUST_MODE_UNSPECIFIED {
				return invalid("INVALID_ARGUMENT", "requested_trust_modes must be concrete")
			}
			if _, duplicate := seenModes[mode]; duplicate {
				continue
			}
			seenModes[mode] = struct{}{}
			if s.authority.Supports(mode) {
				activeModes = append(activeModes, mode)
			}
		}
		manifestDigest, err := protoDigest("ATOS-TOS-CAPABILITY-MANIFEST-V1", req.Msg)
		if err != nil {
			return err
		}
		manifestRef, err := s.authority.Commit(ctx, "capability-manifest", req.Msg.CapabilityId+"@"+req.Msg.Version, manifestDigest)
		if err != nil {
			return unavailable("UNAVAILABLE", "capability manifest authority is unavailable")
		}
		ownershipRef, err := s.authority.Commit(ctx, "capability-ownership", req.Msg.CapabilityId+"@"+req.Msg.Version, manifestDigest)
		if err != nil {
			return unavailable("UNAVAILABLE", "capability ownership authority is unavailable")
		}
		identity := &atostosv1.CapabilityIdentity{
			CapabilityId: req.Msg.CapabilityId,
			CanonicalUri: "tos://capability/" + req.Msg.CapabilityId + "@" + req.Msg.Version,
			ProviderId:   req.Msg.ProviderId, Version: req.Msg.Version,
			ManifestDigest: cloneMessage(req.Msg.ManifestDigest),
			ManifestRef:    &manifestRef, OwnershipRef: &ownershipRef,
			ActiveTrustModes: activeModes, UpdatedUnixMillis: s.now().UnixMilli(),
		}
		if route, found := s.router.Resolve(req.Msg.ProviderId, req.Msg.CapabilityId, req.Msg.Version); found {
			identity.Endpoints = []string{"worker://" + route.ServiceID + "/" + route.Operation + "?model=" + route.Model}
		}
		if err := s.store.putProto(tx, bucketCapabilities, key, identity); err != nil {
			return err
		}
		if err := tx.Bucket(bucketCapabilityLatest).Put([]byte(req.Msg.CapabilityId), []byte(req.Msg.Version)); err != nil {
			return err
		}
		// A committed provider capability creates only a self-asserted local
		// identity unless startup configuration supplied stronger assurance.
		providerIdentity := new(atostosv1.AgentIdentity)
		providerFound, err := s.store.getProto(tx, bucketIdentities, req.Msg.ProviderId, providerIdentity)
		if err != nil {
			return err
		}
		if !providerFound {
			providerIdentity = &atostosv1.AgentIdentity{
				AgentId:      req.Msg.ProviderId,
				CanonicalUri: "tos://agent/" + req.Msg.ProviderId,
				Controllers:  []string{req.Msg.ProviderId}, Assurance: "self_asserted",
				UpdatedUnixMillis: s.now().UnixMilli(),
				IdentityRef:       &NetworkReference{Network: s.authority.Network(), Reference: "atosrpc:self-asserted:" + req.Msg.ProviderId},
			}
			if err := s.store.putProto(tx, bucketIdentities, req.Msg.ProviderId, providerIdentity); err != nil {
				return err
			}
			if err := tx.Bucket(bucketIdentityURIs).Put([]byte(providerIdentity.CanonicalUri), []byte(providerIdentity.AgentId)); err != nil {
				return err
			}
		}
		response.Capability = identity
		response.Created = true
		response.CommitmentRef = &manifestRef
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func containsMode(modes []atostosv1.TrustMode, expected atostosv1.TrustMode) bool {
	for _, mode := range modes {
		if mode == expected {
			return true
		}
	}
	return false
}

func capabilityHasEndpoint(identity *atostosv1.CapabilityIdentity, serviceID string) bool {
	for _, endpoint := range identity.Endpoints {
		if strings.Contains(endpoint, serviceID) {
			return true
		}
	}
	return false
}
