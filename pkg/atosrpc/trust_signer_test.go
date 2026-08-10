package atosrpc

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

// newTrustSignerTestServer opens a fresh server backed by a temp-dir bbolt
// file and commits one capability manifest for providerID/capabilityID, so
// execution-signer tests have an owning capability to authorize against
// without duplicating CommitCapabilityManifest's own test coverage.
func newTrustSignerTestServer(t *testing.T, now time.Time, providerID, capabilityID string) *Server {
	t.Helper()
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: NewLocalAuthority("tos-local"),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if _, err := server.CommitCapabilityManifest(context.Background(), connect.NewRequest(
		capabilityCommitRequest(now, capabilityID, providerID),
	)); err != nil {
		t.Fatalf("CommitCapabilityManifest: %v", err)
	}
	return server
}

func testSignerPublicKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return pub
}

func authorizeRequest(now time.Time, providerID, capabilityID, authorizationID, signerID string, publicKey []byte) *atostosv1.AuthorizeExecutionSignerRequest {
	return &atostosv1.AuthorizeExecutionSignerRequest{
		Context: &atostosv1.RequestContext{
			RequestId: "request-" + authorizationID, CallerId: "caller-test",
			IdempotencyKey:     "idem-" + authorizationID,
			DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
		},
		Authorization: &atostosv1.ExecutionSignerAuthorizationInput{
			AuthorizationId: authorizationID, ProviderId: providerID,
			CapabilityId: capabilityID, CapabilityVersion: "1.0.0",
			ExecutionSignerId: signerID, SignerPublicKey: publicKey,
			SignatureAlgorithm:   "ed25519",
			ValidFromUnixMillis:  now.Add(-time.Minute).UnixMilli(),
			ValidUntilUnixMillis: now.Add(24 * time.Hour).UnixMilli(),
		},
	}
}

// TestAuthorizeExecutionSigner_GoldenPathThenResolveAuthorized proves the
// basic authorize -> resolve golden path: a freshly authorized signer
// resolves as authorized for the exact capability+version it was
// authorized against.
func TestAuthorizeExecutionSigner_GoldenPathThenResolveAuthorized(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-golden", "cap-golden")
	pub := testSignerPublicKey(t)

	resp, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(
		authorizeRequest(now, "provider-golden", "cap-golden", "auth-golden", "signer-golden", pub),
	))
	if err != nil {
		t.Fatalf("AuthorizeExecutionSigner: %v", err)
	}
	if !resp.Msg.Created || resp.Msg.Authorization == nil || resp.Msg.Authorization.Revoked {
		t.Fatalf("unexpected authorize response: %+v", resp.Msg)
	}

	resolved, err := server.ResolveExecutionSignerAuthorization(context.Background(), connect.NewRequest(
		&atostosv1.ResolveExecutionSignerAuthorizationRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "resolve-golden", CallerId: "caller-test",
				DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			ProviderId: "provider-golden", CapabilityId: "cap-golden", CapabilityVersion: "1.0.0",
			ExecutionSignerId: "signer-golden",
		},
	))
	if err != nil {
		t.Fatalf("ResolveExecutionSignerAuthorization: %v", err)
	}
	if !resolved.Msg.Authorized || resolved.Msg.ReasonCode != "" {
		t.Fatalf("expected authorized with no reason code, got %+v", resolved.Msg)
	}
}

// TestAuthorizeExecutionSigner_SameIdempotencyKeyReplayReturnsByteIdenticalResponse
// proves the shared atomicMutation transport-level idempotency machinery
// (mutation.go, already covered generically for CreateEscrow in
// mutation_test.go) actually covers this RPC too: replaying the exact
// same (caller_id, idempotency_key, request) returns the ORIGINAL cached
// response verbatim -- including Created:true, since that is genuinely
// what the first successful call returned -- without invoking apply(tx)
// (and therefore without a second authority.Commit call) a second time.
func TestAuthorizeExecutionSigner_SameIdempotencyKeyReplayReturnsByteIdenticalResponse(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-replay", "cap-replay")
	pub := testSignerPublicKey(t)
	request := authorizeRequest(now, "provider-replay", "cap-replay", "auth-replay", "signer-replay", pub)

	first, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request))
	if err != nil {
		t.Fatalf("first AuthorizeExecutionSigner: %v", err)
	}
	if !first.Msg.Created {
		t.Fatalf("expected first call to report created=true, got %+v", first.Msg)
	}

	second, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request))
	if err != nil {
		t.Fatalf("replayed AuthorizeExecutionSigner: %v", err)
	}
	if !second.Msg.Created {
		t.Fatalf("expected a same-idempotency-key replay to return the original cached Created:true verbatim, got %+v", second.Msg)
	}
	if second.Msg.Authorization.AuthorizationRef.GetReference() != first.Msg.Authorization.AuthorizationRef.GetReference() {
		t.Fatalf("replay produced a different commitment reference: first=%q second=%q",
			first.Msg.Authorization.AuthorizationRef.GetReference(), second.Msg.Authorization.AuthorizationRef.GetReference())
	}
}

// TestAuthorizeExecutionSigner_DifferentIdempotencyKeySameContentDedupes
// proves the SECOND, business-level dedup layer inside trust.go itself
// (distinct from the transport-level idempotency-key cache exercised
// above): a genuinely different logical call (different idempotency key
// -- e.g. an independent retry after the caller's own idempotency record
// was lost) for the identical (provider, capability, version, signer_id,
// public_key) still resolves to the existing authorization rather than
// creating a duplicate signerKey entry or committing a second
// authority.Commit reference, and correctly reports Created:false since
// nothing new was created by THIS call.
func TestAuthorizeExecutionSigner_DifferentIdempotencyKeySameContentDedupes(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-dedupe", "cap-dedupe")
	pub := testSignerPublicKey(t)

	first := authorizeRequest(now, "provider-dedupe", "cap-dedupe", "auth-dedupe", "signer-dedupe", pub)
	first.Context.IdempotencyKey = "idem-dedupe-1"
	firstResp, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(first))
	if err != nil {
		t.Fatalf("first AuthorizeExecutionSigner: %v", err)
	}
	if !firstResp.Msg.Created {
		t.Fatalf("expected first call to report created=true, got %+v", firstResp.Msg)
	}

	second := authorizeRequest(now, "provider-dedupe", "cap-dedupe", "auth-dedupe", "signer-dedupe", pub)
	second.Context.IdempotencyKey = "idem-dedupe-2"
	secondResp, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(second))
	if err != nil {
		t.Fatalf("second AuthorizeExecutionSigner: %v", err)
	}
	if secondResp.Msg.Created {
		t.Fatalf("expected a different-idempotency-key call with identical signer content to report created=false, got %+v", secondResp.Msg)
	}
	if secondResp.Msg.Authorization.AuthorizationRef.GetReference() != firstResp.Msg.Authorization.AuthorizationRef.GetReference() {
		t.Fatalf("business-level dedup produced a different commitment reference: first=%q second=%q",
			firstResp.Msg.Authorization.AuthorizationRef.GetReference(), secondResp.Msg.Authorization.AuthorizationRef.GetReference())
	}
}

// TestAuthorizeExecutionSigner_SameSignerIDDifferentContentConflicts proves a
// genuinely different authorization body reusing the same (provider,
// capability, version, signer_id) key is rejected as a conflict rather than
// silently overwriting the original -- this is the signer-specific
// business-level idempotency guard in trust.go, layered on top of (and
// distinct from) the shared idempotency-key machinery exercised above. Note
// this exercises a different authorization_id AND a different public key on
// the retry; it does not on its own prove authorization_id reuse is rejected
// -- see TestAuthorizeExecutionSigner_AuthorizationIDReusedAcrossDifferentSignerIDsConflicts
// for that.
func TestAuthorizeExecutionSigner_SameSignerIDDifferentContentConflicts(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-conflict", "cap-conflict")
	firstKey := testSignerPublicKey(t)
	secondKey := testSignerPublicKey(t)

	first := authorizeRequest(now, "provider-conflict", "cap-conflict", "auth-conflict", "signer-conflict", firstKey)
	first.Context.IdempotencyKey = "idem-conflict-1"
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(first)); err != nil {
		t.Fatalf("first AuthorizeExecutionSigner: %v", err)
	}

	// A different idempotency key (a genuinely new logical request) but
	// the same signer_id under the same provider/capability/version, with
	// a different public key -- must conflict, not silently replace the
	// original binding.
	second := authorizeRequest(now, "provider-conflict", "cap-conflict", "auth-conflict-2", "signer-conflict", secondKey)
	second.Context.IdempotencyKey = "idem-conflict-2"
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(second)); err == nil {
		t.Fatal("expected a conflict authorizing the same signer_id with a different public key")
	}
}

// TestAuthorizeExecutionSigner_AuthorizationIDReusedAcrossDifferentSignerIDsConflicts
// proves authorization_id identity is global, not scoped to one signer_id:
// two different signer_ids under the same capability version must not be
// able to share an authorization_id. Before the secondary
// bucketSignerAuthByAuthID index this was silently accepted -- both records
// were written under distinct primary keys -- and RevokeExecutionSigner,
// which resolves by authorization_id alone, would then revoke whichever of
// the two a bucket scan happened to reach first, leaving the other one an
// authorized signer no caller could name or revoke.
func TestAuthorizeExecutionSigner_AuthorizationIDReusedAcrossDifferentSignerIDsConflicts(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-shared-authid", "cap-shared-authid")

	first := authorizeRequest(now, "provider-shared-authid", "cap-shared-authid", "auth-shared", "signer-a", testSignerPublicKey(t))
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(first)); err != nil {
		t.Fatalf("first AuthorizeExecutionSigner: %v", err)
	}

	second := authorizeRequest(now, "provider-shared-authid", "cap-shared-authid", "auth-shared", "signer-b", testSignerPublicKey(t))
	// A distinct idempotency key is essential here: reusing the first
	// request's key (as authorizeRequest's default "idem-"+authorizationID
	// does, since both calls share authorization_id) would make the outer
	// transport-level idempotency-key guard in mutation.go reject this as a
	// same-key-different-content conflict before ever reaching the
	// signer-specific authorization_id check this test means to exercise.
	second.Context.IdempotencyKey = "idem-shared-authid-2"
	if resp, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(second)); err == nil {
		t.Fatalf("expected a conflict authorizing a different signer_id with an already-used authorization_id, got %+v", resp.Msg)
	} else if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("expected ALREADY_EXISTS, got %v", err)
	}

	// The first signer must still be exactly what it was -- unaffected by
	// the rejected second attempt.
	resolved, err := server.ResolveExecutionSignerAuthorization(context.Background(), connect.NewRequest(
		&atostosv1.ResolveExecutionSignerAuthorizationRequest{
			Context:    readContext("resolve-shared-authid"),
			ProviderId: "provider-shared-authid", CapabilityId: "cap-shared-authid",
			CapabilityVersion: "1.0.0", ExecutionSignerId: "signer-a",
		}))
	if err != nil {
		t.Fatalf("ResolveExecutionSignerAuthorization: %v", err)
	}
	if resolved.Msg.ReasonCode != "" || resolved.Msg.Authorization == nil ||
		resolved.Msg.Authorization.Value.ExecutionSignerId != "signer-a" {
		t.Fatalf("original signer-a authorization was disturbed by the rejected conflict: %#v", resolved.Msg)
	}
}

// TestRevokeExecutionSigner_ResolvesCorrectSignerAmongMultiple proves the
// bucketSignerAuthByAuthID-indexed lookup in RevokeExecutionSigner (which
// replaced a full bucket scan matching the first cursor hit) revokes exactly
// the signer named by authorization_id and leaves every other authorized
// signer, including ones registered before and after it, untouched.
func TestRevokeExecutionSigner_ResolvesCorrectSignerAmongMultiple(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-multi-revoke", "cap-multi-revoke")

	for _, spec := range []struct{ authID, signerID string }{
		{"auth-multi-1", "signer-multi-1"},
		{"auth-multi-2", "signer-multi-2"},
		{"auth-multi-3", "signer-multi-3"},
	} {
		request := authorizeRequest(now, "provider-multi-revoke", "cap-multi-revoke", spec.authID, spec.signerID, testSignerPublicKey(t))
		if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request)); err != nil {
			t.Fatalf("AuthorizeExecutionSigner(%s): %v", spec.signerID, err)
		}
	}

	if _, err := server.RevokeExecutionSigner(context.Background(), connect.NewRequest(&atostosv1.RevokeExecutionSignerRequest{
		Context: mutationContext("revoke-multi-2"), AuthorizationId: "auth-multi-2", ReasonCode: "test",
	})); err != nil {
		t.Fatalf("RevokeExecutionSigner: %v", err)
	}

	for _, spec := range []struct {
		signerID    string
		wantRevoked bool
	}{
		{"signer-multi-1", false},
		{"signer-multi-2", true},
		{"signer-multi-3", false},
	} {
		resolved, err := server.ResolveExecutionSignerAuthorization(context.Background(), connect.NewRequest(
			&atostosv1.ResolveExecutionSignerAuthorizationRequest{
				Context:    readContext("resolve-" + spec.signerID),
				ProviderId: "provider-multi-revoke", CapabilityId: "cap-multi-revoke",
				CapabilityVersion: "1.0.0", ExecutionSignerId: spec.signerID,
			}))
		if err != nil {
			t.Fatalf("ResolveExecutionSignerAuthorization(%s): %v", spec.signerID, err)
		}
		revoked := resolved.Msg.ReasonCode == "REVOKED"
		if revoked != spec.wantRevoked {
			t.Fatalf("%s: revoked=%v, want %v (reason_code=%q)", spec.signerID, revoked, spec.wantRevoked, resolved.Msg.ReasonCode)
		}
	}
}

// TestAuthorizeExecutionSigner_RejectsNonOwningProvider proves the
// capability-ownership check is enforced: a caller cannot authorize a
// signer against a capability owned by a different provider.
func TestAuthorizeExecutionSigner_RejectsNonOwningProvider(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-real-owner", "cap-owned")
	pub := testSignerPublicKey(t)
	request := authorizeRequest(now, "provider-impostor", "cap-owned", "auth-impostor", "signer-impostor", pub)
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request)); err == nil {
		t.Fatal("expected an ownership error authorizing against a capability owned by a different provider")
	}
}

// TestResolveExecutionSignerAuthorization_OutsideValidityWindow proves the
// validity-window check in ResolveExecutionSignerAuthorization: a signer
// authorized with a window entirely in the past resolves as not
// authorized with the OUTSIDE_VALIDITY_WINDOW reason code, not as a
// generic not-found.
func TestResolveExecutionSignerAuthorization_OutsideValidityWindow(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-expired", "cap-expired")
	pub := testSignerPublicKey(t)
	request := authorizeRequest(now, "provider-expired", "cap-expired", "auth-expired", "signer-expired", pub)
	request.Authorization.ValidFromUnixMillis = now.Add(-2 * time.Hour).UnixMilli()
	request.Authorization.ValidUntilUnixMillis = now.Add(-time.Hour).UnixMilli()
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request)); err == nil {
		t.Fatal("expected AuthorizeExecutionSigner to reject a validity window already in the past")
	}

	// Authorize with a window that is valid now but will have elapsed by
	// the time we resolve "at" a later instant.
	request.Authorization.ValidFromUnixMillis = now.Add(-time.Minute).UnixMilli()
	request.Authorization.ValidUntilUnixMillis = now.Add(time.Hour).UnixMilli()
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request)); err != nil {
		t.Fatalf("AuthorizeExecutionSigner: %v", err)
	}

	resolved, err := server.ResolveExecutionSignerAuthorization(context.Background(), connect.NewRequest(
		&atostosv1.ResolveExecutionSignerAuthorizationRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "resolve-expired", CallerId: "caller-test",
				DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			ProviderId: "provider-expired", CapabilityId: "cap-expired", CapabilityVersion: "1.0.0",
			ExecutionSignerId: "signer-expired", AtUnixMillis: now.Add(2 * time.Hour).UnixMilli(),
		},
	))
	if err != nil {
		t.Fatalf("ResolveExecutionSignerAuthorization: %v", err)
	}
	if resolved.Msg.Authorized || resolved.Msg.ReasonCode != "OUTSIDE_VALIDITY_WINDOW" {
		t.Fatalf("expected OUTSIDE_VALIDITY_WINDOW, got %+v", resolved.Msg)
	}
}

// TestResolveExecutionSignerAuthorization_UnknownSignerIsNotFound proves
// resolving a signer that was never authorized at all reports the
// original NOT_FOUND reason code (the response's zero-value default),
// distinct from OUTSIDE_VALIDITY_WINDOW and REVOKED.
func TestResolveExecutionSignerAuthorization_UnknownSignerIsNotFound(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-unknown", "cap-unknown")
	resolved, err := server.ResolveExecutionSignerAuthorization(context.Background(), connect.NewRequest(
		&atostosv1.ResolveExecutionSignerAuthorizationRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "resolve-unknown", CallerId: "caller-test",
				DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			ProviderId: "provider-unknown", CapabilityId: "cap-unknown", CapabilityVersion: "1.0.0",
			ExecutionSignerId: "signer-never-authorized",
		},
	))
	if err != nil {
		t.Fatalf("ResolveExecutionSignerAuthorization: %v", err)
	}
	if resolved.Msg.Authorized || resolved.Msg.ReasonCode != "NOT_FOUND" || resolved.Msg.Authorization != nil {
		t.Fatalf("expected NOT_FOUND with no authorization record, got %+v", resolved.Msg)
	}
}

// TestExecutionSignerVersionBinding proves a signer authorized for one
// Capability version is invisible to a resolve call for a different
// version of the same capability+signer_id -- the version-binding
// precedent atos-spec's Quote/binding-freeze rule (§7.1.0) depends on
// carrying through unchanged to execution-signer authorization (§7.2.2).
func TestExecutionSignerVersionBinding(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-versioned", "cap-versioned")
	pub := testSignerPublicKey(t)
	request := authorizeRequest(now, "provider-versioned", "cap-versioned", "auth-versioned", "signer-versioned", pub)
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request)); err != nil {
		t.Fatalf("AuthorizeExecutionSigner: %v", err)
	}

	resolved, err := server.ResolveExecutionSignerAuthorization(context.Background(), connect.NewRequest(
		&atostosv1.ResolveExecutionSignerAuthorizationRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "resolve-versioned", CallerId: "caller-test",
				DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			ProviderId: "provider-versioned", CapabilityId: "cap-versioned", CapabilityVersion: "2.0.0",
			ExecutionSignerId: "signer-versioned",
		},
	))
	if err != nil {
		t.Fatalf("ResolveExecutionSignerAuthorization: %v", err)
	}
	if resolved.Msg.Authorized || resolved.Msg.ReasonCode != "NOT_FOUND" {
		t.Fatalf("expected a different capability_version to be unauthorized/not-found, got %+v", resolved.Msg)
	}
}

// TestRevokeExecutionSigner_GoldenPathThenResolveRevoked proves the
// revoke -> resolve golden path, including the REVOKED reason code
// distinguishing a deliberately revoked signer from one that was simply
// never authorized or whose window elapsed.
func TestRevokeExecutionSigner_GoldenPathThenResolveRevoked(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-revoke", "cap-revoke")
	pub := testSignerPublicKey(t)
	authorize := authorizeRequest(now, "provider-revoke", "cap-revoke", "auth-revoke", "signer-revoke", pub)
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(authorize)); err != nil {
		t.Fatalf("AuthorizeExecutionSigner: %v", err)
	}

	revoked, err := server.RevokeExecutionSigner(context.Background(), connect.NewRequest(
		&atostosv1.RevokeExecutionSignerRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "revoke-revoke", CallerId: "caller-test",
				IdempotencyKey: "idem-revoke-revoke", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			AuthorizationId: "auth-revoke", ReasonCode: "rotation",
		},
	))
	if err != nil {
		t.Fatalf("RevokeExecutionSigner: %v", err)
	}
	if !revoked.Msg.Revoked || !revoked.Msg.Authorization.Revoked {
		t.Fatalf("expected revoked=true, got %+v", revoked.Msg)
	}

	resolved, err := server.ResolveExecutionSignerAuthorization(context.Background(), connect.NewRequest(
		&atostosv1.ResolveExecutionSignerAuthorizationRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "resolve-revoke", CallerId: "caller-test",
				DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			ProviderId: "provider-revoke", CapabilityId: "cap-revoke", CapabilityVersion: "1.0.0",
			ExecutionSignerId: "signer-revoke",
		},
	))
	if err != nil {
		t.Fatalf("ResolveExecutionSignerAuthorization: %v", err)
	}
	if resolved.Msg.Authorized || resolved.Msg.ReasonCode != "REVOKED" {
		t.Fatalf("expected REVOKED, got %+v", resolved.Msg)
	}
}

// TestRevokeExecutionSigner_ReplayOfAlreadyRevokedIsIdempotent proves the
// early-return path in RevokeExecutionSigner (an authorization already
// revoked short-circuits to revoked=true without attempting a second
// authority.Commit) actually reachable and correct -- a second revoke
// call for the same authorization_id (a fresh idempotency key, simulating
// an independent retry that doesn't share the first call's idempotency
// record) must still report revoked=true, not an error.
func TestRevokeExecutionSigner_ReplayOfAlreadyRevokedIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-double-revoke", "cap-double-revoke")
	pub := testSignerPublicKey(t)
	authorize := authorizeRequest(now, "provider-double-revoke", "cap-double-revoke", "auth-double-revoke", "signer-double-revoke", pub)
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(authorize)); err != nil {
		t.Fatalf("AuthorizeExecutionSigner: %v", err)
	}

	revokeOnce := func(idempotencyKey string) (*atostosv1.RevokeExecutionSignerResponse, error) {
		resp, err := server.RevokeExecutionSigner(context.Background(), connect.NewRequest(
			&atostosv1.RevokeExecutionSignerRequest{
				Context: &atostosv1.RequestContext{
					RequestId: "revoke-" + idempotencyKey, CallerId: "caller-test",
					IdempotencyKey: idempotencyKey, DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
				},
				AuthorizationId: "auth-double-revoke",
			},
		))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	first, err := revokeOnce("idem-double-revoke-1")
	if err != nil {
		t.Fatalf("first RevokeExecutionSigner: %v", err)
	}
	if !first.Revoked {
		t.Fatalf("expected first revoke to report revoked=true, got %+v", first)
	}

	second, err := revokeOnce("idem-double-revoke-2")
	if err != nil {
		t.Fatalf("second RevokeExecutionSigner: %v", err)
	}
	if !second.Revoked {
		t.Fatalf("expected replayed revoke of an already-revoked authorization to report revoked=true, got %+v", second)
	}
}

// TestRevokeExecutionSigner_UnknownAuthorizationIsNotFound proves
// revoking an authorization_id that was never authorized returns a
// not-found error rather than silently succeeding.
func TestRevokeExecutionSigner_UnknownAuthorizationIsNotFound(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-no-auth", "cap-no-auth")
	_, err := server.RevokeExecutionSigner(context.Background(), connect.NewRequest(
		&atostosv1.RevokeExecutionSignerRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "revoke-missing", CallerId: "caller-test",
				IdempotencyKey: "idem-missing", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			AuthorizationId: "auth-never-existed",
		},
	))
	if err == nil {
		t.Fatal("expected an error revoking an authorization_id that was never authorized")
	}
}

// TestAuthorizeExecutionSigner_RejectsNonEd25519Algorithm proves the
// signature-algorithm allowlist is enforced at the RPC boundary, not left
// to callers to self-police.
func TestAuthorizeExecutionSigner_RejectsNonEd25519Algorithm(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	server := newTrustSignerTestServer(t, now, "provider-badalg", "cap-badalg")
	request := authorizeRequest(now, "provider-badalg", "cap-badalg", "auth-badalg", "signer-badalg", testSignerPublicKey(t))
	request.Authorization.SignatureAlgorithm = "secp256k1"
	if _, err := server.AuthorizeExecutionSigner(context.Background(), connect.NewRequest(request)); err == nil {
		t.Fatal("expected a non-Ed25519 signature algorithm to be rejected")
	}
}
