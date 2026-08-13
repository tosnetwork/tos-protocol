package atosrpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/revocationcommitment"
	bolt "go.etcd.io/bbolt"
)

var canonicalMoneyPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)

func (s *Server) CommitQuote(
	ctx context.Context,
	req *connect.Request[atostosv1.CommitQuoteRequest],
) (*connect.Response[atostosv1.CommitQuoteResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Quote == nil {
		return nil, invalid("INVALID_ARGUMENT", "quote commitment is required")
	}
	quote := req.Msg.Quote
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
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
	verified := quote.TrustMode == atostosv1.TrustMode_TRUST_MODE_VERIFIED
	if verified {
		if quote.Version != quotecommitment.Version || quote.Canonicalization != quotecommitment.Canonicalization || quote.NetworkId != s.authority.Network() || quote.Domain != s.config.TrustDomain {
			return nil, invalid("NETWORK_DOMAIN_MISMATCH", "quote version, network, or domain does not match this authority")
		}
		if req.Msg.Context == nil || req.Msg.Context.IdempotencyKey != quote.QuoteId {
			return nil, invalid("INVALID_ARGUMENT", "quote idempotency_key must equal quote_id")
		}
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
	if verified {
		if err := validateVerifiedQuoteMoney(quote); err != nil {
			return nil, err
		}
		if quote.AcceptanceDeadlineUnixMillis <= s.now().UnixMilli() || quote.AcceptanceDeadlineUnixMillis != quote.ExpiresUnixMillis || quote.ExecutionDeadlineUnixMillis <= quote.AcceptanceDeadlineUnixMillis {
			return nil, invalid("INVALID_ARGUMENT", "quote acceptance/expiry/execution deadlines are invalid")
		}
		if err := validateDigest(quote.ManifestDigest); err != nil {
			return nil, err
		}
		if err := validateDigest(quote.DisputePolicyDigest); err != nil {
			return nil, err
		}
		if quote.SettlementBackend != "tos" || quote.SettlementAsset != "TOS" {
			return nil, invalid("INVALID_ARGUMENT", "verified Quote settlement must use the TOS backend and TOS provider asset")
		}
		if err := requiredIdentifier("underlying_service_quote_ref", quote.UnderlyingServiceQuoteRef); err != nil {
			return nil, err
		}
		if quote.OwnershipRef == nil || quote.SignerAuthorizationRef == nil || quote.RequesterAgentId == "" || quote.SignerAuthorizationId == "" {
			return nil, invalid("INVALID_ARGUMENT", "quote ownership, requester, and signer authorization facts are required")
		}
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
		if verified && (!bytes.Equal(capability.ManifestDigest.GetValue(), quote.ManifestDigest.GetValue()) || capability.ManifestDigest.GetAlgorithm() != quote.ManifestDigest.GetAlgorithm() || !sameReference(capability.OwnershipRef, quote.OwnershipRef)) {
			return failedPrecondition("MANIFEST_MISMATCH", "quote manifest or ownership reference is not current")
		}
		if verified {
			var requester principalBindingRecord
			bound, err := s.store.getJSON(tx, bucketPrincipalBindings, quote.PrincipalId, &requester)
			if err != nil {
				return err
			}
			if !bound || requester.AgentID != quote.RequesterAgentId || requester.RefNetwork != quote.NetworkId {
				return failedPrecondition("REQUESTER_IDENTITY_UNBOUND", "requester identity is not currently bound on this network")
			}
			var provider principalBindingRecord
			providerBound, err := s.store.getJSON(tx, bucketPrincipalBindings, quote.ProviderId, &provider)
			if err != nil {
				return err
			}
			if !providerBound || provider.RefNetwork != quote.NetworkId {
				return failedPrecondition("PROVIDER_IDENTITY_UNBOUND", "provider identity is not currently bound on this network")
			}
			authKey := tx.Bucket(bucketSignerAuthByAuthID).Get([]byte(quote.SignerAuthorizationId))
			if authKey == nil {
				return failedPrecondition("SIGNER_NOT_AUTHORIZED", "execution signer authorization is missing")
			}
			auth := new(atostosv1.ExecutionSignerAuthorization)
			found, err = s.store.getProto(tx, bucketSignerAuths, string(authKey), auth)
			if err != nil {
				return err
			}
			nowMS := s.now().UnixMilli()
			if !found || auth.Value == nil || auth.Revoked || auth.Value.ProviderId != quote.ProviderId || auth.Value.CapabilityId != quote.CapabilityId || auth.Value.CapabilityVersion != quote.CapabilityVersion || nowMS < auth.Value.ValidFromUnixMillis || nowMS >= auth.Value.ValidUntilUnixMillis || !sameReference(auth.AuthorizationRef, quote.SignerAuthorizationRef) {
				return failedPrecondition("SIGNER_NOT_AUTHORIZED", "execution signer authorization is missing, stale, revoked, or mismatched")
			}
		}
		commitmentDomain := "ATOS-TOS-QUOTE-COMMITMENT-V1"
		existing := new(atostosv1.QuoteCommitment)
		exists, err := s.store.getProto(tx, bucketQuoteCommitments, quote.QuoteId, existing)
		if err != nil {
			return err
		}
		if exists {
			existingDigest, requestedDigest := "", ""
			if verified {
				existingDigest, _ = quotecommitment.Digest(existing.Value)
				requestedDigest, _ = quotecommitment.Digest(quote)
			} else {
				existingDigest, _ = protoDigest(commitmentDomain, existing.Value)
				requestedDigest, _ = protoDigest(commitmentDomain, quote)
			}
			if existingDigest != requestedDigest {
				return conflict("QUOTE_MISMATCH", "quote ID is already committed to different terms")
			}
			response.Quote = existing
			return nil
		}
		var digest string
		if verified {
			digest, err = quotecommitment.Digest(quote)
		} else {
			digest, err = protoDigest(commitmentDomain, quote)
		}
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "quote", quote.QuoteId, digest)
		if err != nil {
			return unavailable("NETWORK_UNAVAILABLE", "quote commitment authority is unavailable")
		}
		if verified && (ref.Network != quote.NetworkId || !ref.Finalized || ref.FinalizedCheckpoint == 0) {
			return unavailable("AUTHORITY_NOT_FINAL", "quote commitment authority did not return matching finalized state")
		}
		committed := &atostosv1.QuoteCommitment{
			Value: cloneMessage(quote), CommitmentRef: &ref,
			CommittedUnixMillis: s.now().UnixMilli(), CommitmentDigest: digestMessageFromString(digest),
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
	if verified {
		digest, digestErr := quotecommitment.Digest(response.Quote.GetValue())
		resolver, ok := s.authority.(CommitmentResolver)
		if digestErr != nil || !ok || response.Quote.GetCommitmentRef() == nil {
			return nil, unavailable("NETWORK_UNAVAILABLE", "verified Quote requires live authority resolution")
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "quote", quote.QuoteId, digest, response.Quote.CommitmentRef)
		if resolveErr != nil || !validLiveQuoteReference(s.authority.Network(), live, response.Quote.CommitmentRef) {
			return nil, unavailable("NETWORK_UNAVAILABLE", "verified Quote finality could not be re-observed")
		}
		response.Quote.CommitmentRef = cloneMessage(live)
		response.Quote.CommitmentDigest = digestMessageFromString(digest)
	}
	return connect.NewResponse(response), nil
}

func sameReference(a, b *NetworkReference) bool {
	return a != nil && b != nil && a.Network == b.Network && a.Reference == b.Reference
}

func digestMessageFromString(value string) *atostosv1.Digest {
	decoded, _ := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return &atostosv1.Digest{Algorithm: "sha256", Value: decoded}
}

func validateVerifiedQuoteMoney(q *atostosv1.QuoteCommitmentInput) error {
	if q.AssetDecimals == 0 || q.AssetDecimals > 18 || q.Subtotal == nil || q.Fees == nil || q.TotalMax == nil {
		return invalid("INVALID_ARGUMENT", "quote money fields and asset_decimals are required")
	}
	asset := q.TotalMax.Currency
	values := []*atostosv1.Money{q.Subtotal, q.Fees, q.TotalMax}
	ints := make([]*big.Int, 0, 3)
	for _, money := range values {
		if money.Currency != asset || !canonicalMoneyPattern.MatchString(money.Amount) {
			return invalid("INVALID_ARGUMENT", "quote money is not canonical or assets differ")
		}
		parts := strings.SplitN(money.Amount, ".", 2)
		if len(parts) != 2 || len(parts[1]) != int(q.AssetDecimals) {
			return invalid("INVALID_ARGUMENT", "quote money must use exactly asset_decimals fractional digits")
		}
		value, ok := new(big.Int).SetString(parts[0]+parts[1], 10)
		if !ok {
			return invalid("INVALID_ARGUMENT", "invalid quote money")
		}
		ints = append(ints, value)
	}
	if new(big.Int).Add(ints[0], ints[1]).Cmp(ints[2]) != 0 {
		return invalid("INVALID_ARGUMENT", "quote subtotal plus fees must equal total_max")
	}
	if ints[1].Sign() != 0 {
		return invalid("INVALID_ARGUMENT", "verified Quote fees must be zero until TaskEscrow supports canonical gateway payout")
	}
	return nil
}

func (s *Server) GetQuoteCommitment(
	ctx context.Context,
	req *connect.Request[atostosv1.GetQuoteCommitmentRequest],
) (*connect.Response[atostosv1.GetQuoteCommitmentResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
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
	if req.Msg.ExpectedQuote != nil {
		if req.Msg.ExpectedQuote.QuoteId != req.Msg.QuoteId {
			return nil, invalid("INVALID_ARGUMENT", "expected quote_id mismatch")
		}
		expectedDigest, digestErr := quotecommitment.Digest(req.Msg.ExpectedQuote)
		if digestErr != nil {
			return nil, invalid("INVALID_ARGUMENT", "expected Quote cannot be canonicalized")
		}
		if response.Found {
			storedDigest, digestErr := quotecommitment.Digest(response.Quote.Value)
			if digestErr != nil || storedDigest != expectedDigest {
				return nil, conflict("QUOTE_MISMATCH", "stored Quote differs from expected canonical value")
			}
		}
	}
	verifiedExpected := req.Msg.ExpectedQuote != nil && req.Msg.ExpectedQuote.TrustMode == atostosv1.TrustMode_TRUST_MODE_VERIFIED
	verifiedStored := response.Found && response.Quote != nil && response.Quote.Value != nil && response.Quote.Value.TrustMode == atostosv1.TrustMode_TRUST_MODE_VERIFIED
	if verifiedExpected || verifiedStored {
		value := req.Msg.ExpectedQuote
		if value == nil {
			value = response.Quote.Value
		}
		digest, digestErr := quotecommitment.Digest(value)
		resolver, ok := s.authority.(CommitmentResolver)
		if digestErr != nil || !ok {
			return nil, unavailable("NETWORK_UNAVAILABLE", "verified Quote requires live authority resolution")
		}
		var known *NetworkReference
		if response.Found {
			known = response.Quote.CommitmentRef
		} else {
			known = req.Msg.ExpectedCommitmentRef
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "quote", req.Msg.QuoteId, digest, known)
		if errors.Is(resolveErr, ErrCommitmentNotFound) {
			return connect.NewResponse(&atostosv1.GetQuoteCommitmentResponse{}), nil
		}
		if resolveErr != nil || !validLiveQuoteReference(s.authority.Network(), live, known) {
			return nil, unavailable("NETWORK_UNAVAILABLE", "verified Quote finality could not be re-observed")
		}
		if !response.Found {
			response.Quote = &atostosv1.QuoteCommitment{Value: cloneMessage(value), CommitmentRef: cloneMessage(live), CommitmentDigest: digestMessageFromString(digest)}
			response.Found = true
		}
		response.Quote.CommitmentRef = cloneMessage(live)
		response.Quote.CommitmentDigest = digestMessageFromString(digest)
	}
	return connect.NewResponse(response), nil
}

func validLiveQuoteReference(network string, live, known *NetworkReference) bool {
	if live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 || live.Network != network || strings.TrimSpace(live.Reference) == "" {
		return false
	}
	return known == nil || (live.Reference == known.Reference && live.FinalizedCheckpoint >= known.FinalizedCheckpoint)
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
		digest, err := revocationcommitment.SignerDigest(req.Msg.AuthorizationId)
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "execution-signer-revocation", req.Msg.AuthorizationId, digest)
		if err != nil {
			return unavailable("NETWORK_UNAVAILABLE", "signer revocation authority is unavailable")
		}
		revokedAt := s.now().UnixMilli()
		if s.authority.Supports(TrustModeVerified) {
			observed, observeErr := resolveCommitmentObservation(ctx, s.authority, "execution-signer-revocation", req.Msg.AuthorizationId, digest, &ref)
			if observeErr != nil || observed.ObservedUnixMillis <= 0 {
				return unavailable("NETWORK_UNAVAILABLE", "signer revocation finality time is unavailable")
			}
			revokedAt = observed.ObservedUnixMillis
		}
		authorization.Revoked = true
		authorization.RevocationRef = &ref
		authorization.RevokedUnixMillis = revokedAt
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
	ctx context.Context,
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
		at := req.Msg.AtUnixMillis
		if at == 0 {
			at = s.now().UnixMilli()
		}
		if authorization.Revoked && (authorization.RevokedUnixMillis == 0 || at >= authorization.RevokedUnixMillis) {
			response.Authorization = authorization
			response.ReasonCode = "REVOKED"
			return nil
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
	if response.Authorization == nil && req.Msg.ExpectedAuthorization != nil && req.Msg.ExpectedAuthorizationRef != nil && s.authority.Supports(TrustModeVerified) {
		expected := req.Msg.ExpectedAuthorization
		if expected.ProviderId != req.Msg.ProviderId || expected.CapabilityId != req.Msg.CapabilityId || expected.CapabilityVersion != req.Msg.CapabilityVersion || expected.ExecutionSignerId != req.Msg.ExecutionSignerId {
			return nil, conflict("SIGNER_MISMATCH", "expected signer authorization tuple mismatch")
		}
		digest, digestErr := protoDigest("ATOS-TOS-SIGNER-AUTHORIZATION-V1", expected)
		resolver, ok := s.authority.(CommitmentResolver)
		if digestErr != nil || !ok {
			return nil, unavailable("NETWORK_UNAVAILABLE", "execution signer resolver unavailable")
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "execution-signer", expected.AuthorizationId, digest, req.Msg.ExpectedAuthorizationRef)
		if resolveErr != nil || live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 || live.Network != req.Msg.ExpectedAuthorizationRef.Network || live.Reference != req.Msg.ExpectedAuthorizationRef.Reference {
			return nil, unavailable("NETWORK_UNAVAILABLE", "execution signer finality unavailable")
		}
		at := req.Msg.AtUnixMillis
		if at == 0 {
			at = s.now().UnixMilli()
		}
		if at < expected.ValidFromUnixMillis || at >= expected.ValidUntilUnixMillis {
			return connect.NewResponse(response), nil
		}
		revoked, revocationRef, revokedAt, revocationErr := resolveSignerRevocation(ctx, s.authority, expected.AuthorizationId)
		if revocationErr != nil {
			return nil, unavailable("NETWORK_UNAVAILABLE", "execution signer revocation state unavailable")
		}
		response.Authorization = &atostosv1.ExecutionSignerAuthorization{Value: cloneMessage(expected), AuthorizationRef: live, Revoked: revoked, RevocationRef: revocationRef, RevokedUnixMillis: revokedAt}
		if revoked && at >= revokedAt {
			response.ReasonCode = "REVOKED"
			return connect.NewResponse(response), nil
		}
		response.Authorized = true
		response.ReasonCode = ""
		return connect.NewResponse(response), nil
	}
	if response.Authorization != nil && response.Authorization.Value != nil && response.Authorization.AuthorizationRef != nil && s.authority.Supports(TrustModeVerified) {
		resolver, ok := s.authority.(CommitmentResolver)
		if !ok {
			return nil, unavailable("NETWORK_UNAVAILABLE", "execution signer resolver unavailable")
		}
		digest, digestErr := protoDigest("ATOS-TOS-SIGNER-AUTHORIZATION-V1", response.Authorization.Value)
		if digestErr != nil {
			return nil, digestErr
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "execution-signer", response.Authorization.Value.AuthorizationId, digest, response.Authorization.AuthorizationRef)
		if resolveErr != nil || live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 {
			return nil, unavailable("NETWORK_UNAVAILABLE", "execution signer finality unavailable")
		}
		response.Authorization.AuthorizationRef = live
		revoked, revocationRef, revokedAt, revocationErr := resolveSignerRevocation(ctx, s.authority, response.Authorization.Value.AuthorizationId)
		if revocationErr != nil {
			return nil, unavailable("NETWORK_UNAVAILABLE", "execution signer revocation state unavailable")
		}
		response.Authorization.Revoked = revoked
		response.Authorization.RevocationRef = revocationRef
		response.Authorization.RevokedUnixMillis = revokedAt
		at := req.Msg.AtUnixMillis
		if at == 0 {
			at = s.now().UnixMilli()
		}
		if revoked && at >= revokedAt {
			response.Authorized = false
			response.ReasonCode = "REVOKED"
		}
	}
	return connect.NewResponse(response), nil
}

func resolveSignerRevocation(ctx context.Context, authority Authority, authorizationID string) (bool, *NetworkReference, int64, error) {
	digest, err := revocationcommitment.SignerDigest(authorizationID)
	if err != nil {
		return false, nil, 0, err
	}
	observed, err := resolveCommitmentObservation(ctx, authority, "execution-signer-revocation", authorizationID, digest, nil)
	if errors.Is(err, ErrCommitmentNotFound) {
		return false, nil, 0, nil
	}
	if err != nil || observed == nil || observed.ObservedUnixMillis <= 0 {
		return false, nil, 0, errors.New("canonical revocation unavailable")
	}
	return true, cloneMessage(observed.Reference), observed.ObservedUnixMillis, nil
}

func resolveCommitmentObservation(ctx context.Context, authority Authority, kind, objectID, digest string, ref *NetworkReference) (*CommitmentObservation, error) {
	resolver, ok := authority.(CommitmentObservationResolver)
	if !ok {
		return nil, errors.New("commitment observation resolver unavailable")
	}
	return resolver.ResolveCommitmentObservation(ctx, kind, objectID, digest, ref)
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
