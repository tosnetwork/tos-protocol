package atosrpc

import (
	"context"
	"crypto/ed25519"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	bolt "go.etcd.io/bbolt"
)

func (s *Server) CommitQuote(
	ctx context.Context,
	req *connect.Request[atostosv1.CommitQuoteRequest],
) (*connect.Response[atostosv1.CommitQuoteResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Quote == nil {
		return nil, invalid("INVALID_ARGUMENT", "quote commitment is required")
	}
	quote := req.Msg.Quote
	for name, value := range map[string]string{
		"quote_id": quote.QuoteId, "principal_id": quote.PrincipalId,
		"provider_id": quote.ProviderId, "capability_id": quote.CapabilityId,
		"capability_version": quote.CapabilityVersion,
	} {
		if err := requiredIdentifier(name, value); err != nil {
			return nil, err
		}
	}
	if err := validateModeProfile(quote.TrustMode, quote.ProofProfile); err != nil {
		return nil, err
	}
	if err := s.ensureSupported(quote.TrustMode); err != nil {
		return nil, err
	}
	if quote.ExpiresUnixMillis <= s.now().UnixMilli() {
		return nil, invalid("QUOTE_EXPIRED", "quote expiry must be in the future")
	}
	if quote.TotalMax == nil || strings.TrimSpace(quote.TotalMax.Amount) == "" || strings.TrimSpace(quote.TotalMax.Currency) == "" {
		return nil, invalid("INVALID_ARGUMENT", "quote total_max is required")
	}
	if err := validateDigest(quote.TermsDigest); err != nil {
		return nil, err
	}
	response := new(atostosv1.CommitQuoteResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("CommitQuote", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		capability := new(atostosv1.CapabilityIdentity)
		found, err := s.store.getProto(tx, bucketCapabilities, capabilityKey(quote.CapabilityId, quote.CapabilityVersion), capability)
		if err != nil {
			return err
		}
		if !found {
			return failedPrecondition("CAPABILITY_UNAVAILABLE", "capability manifest is not committed")
		}
		if capability.ProviderId != quote.ProviderId {
			return failedPrecondition("CAPABILITY_OWNERSHIP_FAILED", "quote provider does not own capability")
		}
		if !containsMode(capability.ActiveTrustModes, quote.TrustMode) {
			return failedPrecondition("TRUST_MODE_UNAVAILABLE", "quoted trust mode is not active for capability")
		}
		existing := new(atostosv1.QuoteCommitment)
		exists, err := s.store.getProto(tx, bucketQuoteCommitments, quote.QuoteId, existing)
		if err != nil {
			return err
		}
		if exists {
			existingDigest, _ := protoDigest("ATOS-TOS-QUOTE-COMMITMENT-V1", existing.Value)
			requestedDigest, _ := protoDigest("ATOS-TOS-QUOTE-COMMITMENT-V1", quote)
			if existingDigest != requestedDigest {
				return conflict("QUOTE_MISMATCH", "quote ID is already committed to different terms")
			}
			response.Quote = existing
			return nil
		}
		digest, err := protoDigest("ATOS-TOS-QUOTE-COMMITMENT-V1", quote)
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "quote", quote.QuoteId, digest)
		if err != nil {
			return unavailable("NETWORK_UNAVAILABLE", "quote commitment authority is unavailable")
		}
		committed := &atostosv1.QuoteCommitment{
			Value: cloneMessage(quote), CommitmentRef: &ref,
			CommittedUnixMillis: s.now().UnixMilli(),
		}
		if err := s.store.putProto(tx, bucketQuoteCommitments, quote.QuoteId, committed); err != nil {
			return err
		}
		if err := s.putProofTx(tx, &ref, "quote_commitment", quote); err != nil {
			return err
		}
		response.Quote = committed
		response.Created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) GetQuoteCommitment(
	_ context.Context,
	req *connect.Request[atostosv1.GetQuoteCommitmentRequest],
) (*connect.Response[atostosv1.GetQuoteCommitmentResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("quote_id", req.Msg.QuoteId); err != nil {
		return nil, err
	}
	response := new(atostosv1.GetQuoteCommitmentResponse)
	err := s.store.view(func(tx *bolt.Tx) error {
		quote := new(atostosv1.QuoteCommitment)
		found, err := s.store.getProto(tx, bucketQuoteCommitments, req.Msg.QuoteId, quote)
		if err != nil {
			return err
		}
		if found {
			response.Quote, response.Found = quote, true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) AuthorizeExecutionSigner(
	ctx context.Context,
	req *connect.Request[atostosv1.AuthorizeExecutionSignerRequest],
) (*connect.Response[atostosv1.AuthorizeExecutionSignerResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Authorization == nil {
		return nil, invalid("INVALID_ARGUMENT", "execution signer authorization is required")
	}
	value := req.Msg.Authorization
	for name, field := range map[string]string{
		"authorization_id": value.AuthorizationId, "provider_id": value.ProviderId,
		"capability_id": value.CapabilityId, "capability_version": value.CapabilityVersion,
		"execution_signer_id": value.ExecutionSignerId,
	} {
		if err := requiredIdentifier(name, field); err != nil {
			return nil, err
		}
	}
	if strings.ToLower(value.SignatureAlgorithm) != "ed25519" || len(value.SignerPublicKey) != ed25519.PublicKeySize {
		return nil, invalid("INVALID_ARGUMENT", "only Ed25519 execution signers are accepted")
	}
	if value.ValidFromUnixMillis <= 0 || value.ValidUntilUnixMillis <= value.ValidFromUnixMillis ||
		value.ValidUntilUnixMillis <= s.now().UnixMilli() {
		return nil, invalid("INVALID_ARGUMENT", "execution signer validity window is invalid")
	}
	response := new(atostosv1.AuthorizeExecutionSignerResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("AuthorizeExecutionSigner", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		capability := new(atostosv1.CapabilityIdentity)
		found, err := s.store.getProto(tx, bucketCapabilities, capabilityKey(value.CapabilityId, value.CapabilityVersion), capability)
		if err != nil {
			return err
		}
		if !found || capability.ProviderId != value.ProviderId {
			return failedPrecondition("CAPABILITY_OWNERSHIP_FAILED", "signer provider does not own the capability version")
		}
		key := signerKey(value.ProviderId, value.CapabilityId, value.CapabilityVersion, value.ExecutionSignerId)
		digest, err := protoDigest("ATOS-TOS-SIGNER-AUTHORIZATION-V1", value)
		if err != nil {
			return err
		}
		existing := new(atostosv1.ExecutionSignerAuthorization)
		exists, err := s.store.getProto(tx, bucketSignerAuths, key, existing)
		if err != nil {
			return err
		}
		if exists {
			existingDigest, err := protoDigest("ATOS-TOS-SIGNER-AUTHORIZATION-V1", existing.Value)
			if err != nil {
				return err
			}
			if existingDigest != digest {
				return conflict("ALREADY_EXISTS", "execution signer is already authorized differently")
			}
			response.Authorization = existing
			return nil
		}
		// authorization_id must not be silently reused across two different
		// (provider, capability, version, signer_id) keys -- otherwise
		// RevokeExecutionSigner, which resolves an authorization_id to
		// exactly one signer, would be ambiguous about which one it means.
		if ownerKey := tx.Bucket(bucketSignerAuthByAuthID).Get([]byte(value.AuthorizationId)); ownerKey != nil && string(ownerKey) != key {
			return conflict("ALREADY_EXISTS", "authorization_id is already bound to a different execution signer")
		}
		ref, err := s.authority.Commit(ctx, "execution-signer", value.AuthorizationId, digest)
		if err != nil {
			return unavailable("NETWORK_UNAVAILABLE", "signer authorization authority is unavailable")
		}
		authorization := &atostosv1.ExecutionSignerAuthorization{
			Value: cloneMessage(value), AuthorizationRef: &ref,
		}
		if err := s.store.putProto(tx, bucketSignerAuths, key, authorization); err != nil {
			return err
		}
		if err := tx.Bucket(bucketSignerAuthByAuthID).Put([]byte(value.AuthorizationId), []byte(key)); err != nil {
			return err
		}
		if err := s.putProofTx(tx, &ref, "execution_signer_authorization", value); err != nil {
			return err
		}
		response.Authorization = authorization
		response.Created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) RevokeExecutionSigner(
	ctx context.Context,
	req *connect.Request[atostosv1.RevokeExecutionSignerRequest],
) (*connect.Response[atostosv1.RevokeExecutionSignerResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := requiredIdentifier("authorization_id", req.Msg.AuthorizationId); err != nil {
		return nil, err
	}
	response := new(atostosv1.RevokeExecutionSignerResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("RevokeExecutionSigner", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		ownerKey := tx.Bucket(bucketSignerAuthByAuthID).Get([]byte(req.Msg.AuthorizationId))
		if ownerKey == nil {
			return notFound("NOT_FOUND", "execution signer authorization not found")
		}
		key := string(ownerKey)
		authorization := new(atostosv1.ExecutionSignerAuthorization)
		found, err := s.store.getProto(tx, bucketSignerAuths, key, authorization)
		if err != nil {
			return err
		}
		if !found || authorization.Value == nil || authorization.Value.AuthorizationId != req.Msg.AuthorizationId {
			return notFound("NOT_FOUND", "execution signer authorization not found")
		}
		if authorization.Revoked {
			response.Authorization = authorization
			response.Revoked = true
			return nil
		}
		digest, err := protoDigest("ATOS-TOS-SIGNER-REVOCATION-V1", withoutTransportContext(req.Msg))
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "execution-signer-revocation", req.Msg.AuthorizationId, digest)
		if err != nil {
			return unavailable("NETWORK_UNAVAILABLE", "signer revocation authority is unavailable")
		}
		authorization.Revoked = true
		authorization.RevocationRef = &ref
		if err := s.store.putProto(tx, bucketSignerAuths, key, authorization); err != nil {
			return err
		}
		response.Authorization = authorization
		response.Revoked = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) ResolveExecutionSignerAuthorization(
	_ context.Context,
	req *connect.Request[atostosv1.ResolveExecutionSignerAuthorizationRequest],
) (*connect.Response[atostosv1.ResolveExecutionSignerAuthorizationResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	response := &atostosv1.ResolveExecutionSignerAuthorizationResponse{ReasonCode: "NOT_FOUND"}
	err := s.store.view(func(tx *bolt.Tx) error {
		key := signerKey(req.Msg.ProviderId, req.Msg.CapabilityId, req.Msg.CapabilityVersion, req.Msg.ExecutionSignerId)
		authorization := new(atostosv1.ExecutionSignerAuthorization)
		found, err := s.store.getProto(tx, bucketSignerAuths, key, authorization)
		if err != nil || !found {
			return err
		}
		if authorization.Revoked {
			response.Authorization = authorization
			response.ReasonCode = "REVOKED"
			return nil
		}
		at := req.Msg.AtUnixMillis
		if at == 0 {
			at = s.now().UnixMilli()
		}
		if authorization.Value == nil || at < authorization.Value.ValidFromUnixMillis || at >= authorization.Value.ValidUntilUnixMillis {
			response.Authorization = authorization
			response.ReasonCode = "OUTSIDE_VALIDITY_WINDOW"
			return nil
		}
		response.Authorization = authorization
		response.Authorized = true
		response.ReasonCode = ""
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) ensureLocalExecutionSignerTx(tx *bolt.Tx, providerID, capabilityID, version string) (*atostosv1.ExecutionSignerAuthorization, error) {
	key := signerKey(providerID, capabilityID, version, s.signerID)
	authorization := new(atostosv1.ExecutionSignerAuthorization)
	found, err := s.store.getProto(tx, bucketSignerAuths, key, authorization)
	if err != nil {
		return nil, err
	}
	if found {
		return authorization, nil
	}
	now := s.now()
	value := &atostosv1.ExecutionSignerAuthorizationInput{
		AuthorizationId: "auth-" + s.signerID + "-" + capabilityID + "-" + version,
		ProviderId:      providerID, CapabilityId: capabilityID, CapabilityVersion: version,
		ExecutionSignerId: s.signerID, SignerPublicKey: append([]byte(nil), s.publicKey...),
		SignatureAlgorithm:   "ed25519",
		ValidFromUnixMillis:  now.Add(-time.Minute).UnixMilli(),
		ValidUntilUnixMillis: now.Add(365 * 24 * time.Hour).UnixMilli(),
	}
	digest, err := protoDigest("ATOS-TOS-SIGNER-AUTHORIZATION-V1", value)
	if err != nil {
		return nil, err
	}
	ref, err := s.authority.Commit(context.Background(), "execution-signer", value.AuthorizationId, digest)
	if err != nil {
		return nil, err
	}
	authorization = &atostosv1.ExecutionSignerAuthorization{Value: value, AuthorizationRef: &ref}
	if err := s.store.putProto(tx, bucketSignerAuths, key, authorization); err != nil {
		return nil, err
	}
	return authorization, nil
}
