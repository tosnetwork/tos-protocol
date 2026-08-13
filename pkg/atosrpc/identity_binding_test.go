package atosrpc

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

// testCanonicalController returns a syntactically valid canonical TOS
// account address (workchain 0, 32 bytes), suitable for
// CreatePrincipalBinding's verifiedTOSController check. seed varies the
// byte value so distinct agent identities don't collide on the same address.
func testCanonicalController(seed byte) string {
	return "0:" + strings.Repeat(fmt.Sprintf("%02x", seed), 32)
}

func newIdentityBindingTestServer(t *testing.T, now time.Time) *Server {
	t.Helper()
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: NewLocalAuthority("tos-local"),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func bindingReqCtx(callerID, idempotencyKey string, now time.Time) *atostosv1.RequestContext {
	return &atostosv1.RequestContext{
		RequestId: "req-" + idempotencyKey, TraceId: "11111111111111111111111111111111",
		CallerId: callerID, IdempotencyKey: idempotencyKey,
		DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
	}
}

func TestCreatePrincipalBinding_RejectsUnresolvedAgentIdentity(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	_, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context:     bindingReqCtx("caller-1", "idem-1", now),
		PrincipalId: "prn_1", AgentId: "agt_does_not_exist",
	}))
	if err == nil {
		t.Fatal("expected error binding to a non-existent agent identity")
	}
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("error code = %v, want NotFound", connect.CodeOf(err))
	}
}

func TestResolveAgentIdentity_FreshReplicaUsesCanonicalExpectedTuple(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	authority := new(verifiedTestAuthority)
	first, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "first.db"), BearerToken: "test-secret", Authority: authority, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	identity := &atostosv1.AgentIdentity{AgentId: "agt_fresh", CanonicalUri: "tos://agent/agt_fresh", Controllers: []string{testCanonicalController(4)}, Assurance: "tos_attested"}
	if err := first.SeedIdentity(identity); err != nil {
		t.Fatal(err)
	}
	stored, err := first.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{Context: bindingReqCtx("verifier", "read-first", now), AgentId: identity.AgentId}))
	if err != nil || !stored.Msg.Found {
		t.Fatalf("seeded identity unavailable: %v", err)
	}
	fresh, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "fresh.db"), BearerToken: "test-secret", Authority: authority, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	callerExpected := cloneMessage(identity)
	callerExpected.PublicAttributes = map[string]string{"admin": "true"}
	resolved, err := fresh.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{Context: bindingReqCtx("verifier", "read-fresh", now), AgentId: identity.AgentId, CanonicalUri: identity.CanonicalUri, ExpectedIdentity: callerExpected, ExpectedIdentityRef: stored.Msg.Identity.IdentityRef}))
	if err != nil || !resolved.Msg.Found || resolved.Msg.Identity.IdentityRef.FinalizedCheckpoint == 0 || resolved.Msg.Identity.Controllers[0] != identity.Controllers[0] {
		t.Fatalf("fresh canonical identity recovery failed: response=%+v err=%v", resolved, err)
	}
	if len(resolved.Msg.Identity.PublicAttributes) != 0 {
		t.Fatalf("empty replica echoed uncommitted public attributes: %v", resolved.Msg.Identity.PublicAttributes)
	}
}

func TestResolvePrincipalBinding_FreshReplicaRejectsCanonicallyRevokedBinding(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000).UTC()
	authority := new(verifiedTestAuthority)
	first, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "first.db"), BearerToken: "test-secret", Authority: authority, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	identity := &atostosv1.AgentIdentity{AgentId: "agt_revoked_fresh", CanonicalUri: "tos://agent/agt_revoked_fresh", Controllers: []string{testCanonicalController(7)}, Assurance: "tos_attested"}
	if err := first.SeedIdentity(identity); err != nil {
		t.Fatal(err)
	}
	created, err := first.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{Context: bindingReqCtx("operator", "bind-revoked-fresh", now), PrincipalId: "prn_revoked_fresh", AgentId: identity.AgentId}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.RevokePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.RevokePrincipalBindingRequest{Context: bindingReqCtx("operator", "revoke-fresh", now), PrincipalId: "prn_revoked_fresh", ReasonCode: "ROTATED"})); err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "fresh.db"), BearerToken: "test-secret", Authority: authority, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	resolved, err := fresh.ResolvePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.ResolvePrincipalBindingRequest{Context: bindingReqCtx("verifier", "resolve-revoked-fresh", now), PrincipalId: "prn_revoked_fresh", ExpectedAgentId: identity.AgentId, ExpectedBindingRef: created.Msg.BindingRef}))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Msg.Bound || resolved.Msg.Status != atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_REVOKED {
		t.Fatalf("fresh replica accepted historical revoked binding: %+v", resolved.Msg)
	}
}

func TestCreatePrincipalBinding_RejectsReuseOfCanonicallyRevokedTuple(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000).UTC()
	authority := new(verifiedTestAuthority)
	server, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "state.db"), BearerToken: "test-secret", Authority: authority, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for i, agentID := range []string{"agt_rebind_a", "agt_rebind_b"} {
		if err := server.SeedIdentity(&atostosv1.AgentIdentity{AgentId: agentID, CanonicalUri: "tos://agent/" + agentID, Controllers: []string{testCanonicalController(byte(20 + i))}, Assurance: "tos_attested"}); err != nil {
			t.Fatal(err)
		}
	}
	create := func(agentID, key string) error {
		_, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{Context: bindingReqCtx("operator", key, now), PrincipalId: "prn_rebind", AgentId: agentID}))
		return err
	}
	revoke := func(key string) {
		t.Helper()
		if _, err := server.RevokePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.RevokePrincipalBindingRequest{Context: bindingReqCtx("operator", key, now), PrincipalId: "prn_rebind", ReasonCode: "ROTATED"})); err != nil {
			t.Fatal(err)
		}
	}
	if err := create("agt_rebind_a", "create-a-1"); err != nil {
		t.Fatal(err)
	}
	revoke("revoke-a-1")
	if err := create("agt_rebind_a", "create-a-2"); err == nil || connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("revoked tuple reuse error=%v, want AlreadyExists", err)
	}
	if err := create("agt_rebind_b", "create-b"); err != nil {
		t.Fatal(err)
	}
	revoke("revoke-b")
	if err := create("agt_rebind_a", "create-a-3"); err == nil || connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("historical tuple reuse after rotation error=%v, want AlreadyExists", err)
	}
}

func TestCreatePrincipalBinding_StaleReplicaRejectsCanonicallyRevokedTuple(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000).UTC()
	authority := new(verifiedTestAuthority)
	first, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "first.db"), BearerToken: "test-secret", Authority: authority, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	stale, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "stale.db"), BearerToken: "test-secret", Authority: authority, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Close()
	identity := &atostosv1.AgentIdentity{AgentId: "agt_stale_rebind", CanonicalUri: "tos://agent/agt_stale_rebind", Controllers: []string{testCanonicalController(31)}, Assurance: "tos_attested"}
	for _, server := range []*Server{first, stale} {
		if err := server.SeedIdentity(identity); err != nil {
			t.Fatal(err)
		}
	}
	create := func(server *Server, key string) error {
		_, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{Context: bindingReqCtx("operator", key, now), PrincipalId: "prn_stale_rebind", AgentId: identity.AgentId}))
		return err
	}
	if err := create(first, "create-first"); err != nil {
		t.Fatal(err)
	}
	if err := create(stale, "create-stale-projection"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.RevokePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.RevokePrincipalBindingRequest{Context: bindingReqCtx("operator", "revoke-first", now), PrincipalId: "prn_stale_rebind", ReasonCode: "ROTATED"})); err != nil {
		t.Fatal(err)
	}
	if err := create(stale, "create-after-revoke"); err == nil || connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("stale replica returned success for canonically revoked tuple: %v", err)
	}
}

// TestCreatePrincipalBinding_RejectsSelfAssertedIdentity proves an identity
// with no independent anchoring (self_asserted, or empty assurance) cannot
// be bound -- a binding to an identity that can never satisfy
// TOSBackedActivationAuthority's ownership checks would be a permanently
// unusable, misleading "active" binding in the operator surface.
func TestCreatePrincipalBinding_RejectsSelfAssertedIdentity(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_self_asserted", CanonicalUri: "tos://agent/agt_self_asserted",
		Controllers: []string{testCanonicalController(9)}, Assurance: "self_asserted",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-1", now), PrincipalId: "prn_1", AgentId: "agt_self_asserted",
	}))
	if err == nil {
		t.Fatal("expected error binding to a self-asserted (unverified) agent identity")
	}
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

// TestCreatePrincipalBinding_RejectsCrossNetworkIdentity proves the fix for
// the missing "network/domain binding that prevents mixing references from
// different TOS networks" invariant: an AgentIdentity anchored on a
// DIFFERENT network than this server's own configured network (e.g. a
// mainnet identity resolved against a devnet gateway) must not be bindable,
// even though it independently resolves and is not self-asserted.
func TestCreatePrincipalBinding_RejectsCrossNetworkIdentity(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now) // Authority.Network() == "tos-local"
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_other_network", CanonicalUri: "tos://agent/agt_other_network",
		Controllers: []string{testCanonicalController(7)}, Assurance: "tos_attested",
		IdentityRef: &atostosv1.NetworkReference{Network: "tos-mainnet", Reference: "tos:external-anchor"},
	}); err != nil {
		t.Fatal(err)
	}
	_, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-1", now), PrincipalId: "prn_1", AgentId: "agt_other_network",
	}))
	if err == nil {
		t.Fatal("expected error binding to an identity anchored on a different TOS network")
	}
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

// TestCreatePrincipalBinding_ReplayDoesNotReverifyCurrentIdentityState
// proves an idempotent replay (same principal+agent, fresh idempotency_key,
// the documented safe lost-response retry pattern) succeeds even if the
// bound identity's CURRENT state would fail verifiedTOSController -- the
// existing binding remains valid until explicitly revoked, and
// ResolvePrincipalBinding would still report it ACTIVE, so this RPC must
// not disagree by re-validating current identity state on a mere replay.
func TestCreatePrincipalBinding_ReplayDoesNotReverifyCurrentIdentityState(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_degrades", CanonicalUri: "tos://agent/agt_degrades", Controllers: []string{testCanonicalController(5)},
		Assurance: "tos_attested",
	}); err != nil {
		t.Fatal(err)
	}
	resp1, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-1", now), PrincipalId: "prn_degrades", AgentId: "agt_degrades",
	}))
	if err != nil {
		t.Fatal(err)
	}

	// The identity's assurance degrades to self_asserted after the bind --
	// it would now fail verifiedTOSController if re-checked.
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_degrades", CanonicalUri: "tos://agent/agt_degrades", Controllers: []string{testCanonicalController(5)},
		Assurance: "self_asserted",
	}); err != nil {
		t.Fatal(err)
	}

	resp2, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-2", now), PrincipalId: "prn_degrades", AgentId: "agt_degrades",
	}))
	if err != nil {
		t.Fatalf("idempotent replay must not re-verify current identity state: %v", err)
	}
	if resp2.Msg.Created {
		t.Fatal("replay must report created=false")
	}
	if resp2.Msg.BindingRef.Reference != resp1.Msg.BindingRef.Reference {
		t.Fatalf("binding_ref changed across replay: %q vs %q", resp1.Msg.BindingRef.Reference, resp2.Msg.BindingRef.Reference)
	}
}

func TestCreatePrincipalBinding_HappyPathThenIdempotentReplay(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_1", CanonicalUri: "tos://agent/agt_1", Controllers: []string{testCanonicalController(1)},
		Assurance: "tos_attested",
	}); err != nil {
		t.Fatal(err)
	}

	resp1, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context:     bindingReqCtx("caller-1", "idem-1", now),
		PrincipalId: "prn_1", AgentId: "agt_1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp1.Msg.Created || resp1.Msg.BindingRef == nil || resp1.Msg.BindingRef.Reference == "" {
		t.Fatalf("unexpected first response: %+v", resp1.Msg)
	}

	// Re-issuing the SAME (principal, agent) under a NEW idempotency_key is a
	// harmless no-op that returns the original ref, not a second commitment.
	resp2, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context:     bindingReqCtx("caller-1", "idem-2", now),
		PrincipalId: "prn_1", AgentId: "agt_1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Msg.Created {
		t.Fatal("re-binding the same principal to the same agent must not report created=true again")
	}
	if resp2.Msg.BindingRef.Reference != resp1.Msg.BindingRef.Reference {
		t.Fatalf("binding_ref changed across idempotent re-bind: %q vs %q", resp1.Msg.BindingRef.Reference, resp2.Msg.BindingRef.Reference)
	}

	resolved, err := server.ResolvePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.ResolvePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "", now), PrincipalId: "prn_1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Msg.Bound || resolved.Msg.Status != atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_ACTIVE {
		t.Fatalf("unexpected resolve after bind: %+v", resolved.Msg)
	}
	if resolved.Msg.BindingRef.Reference != resp1.Msg.BindingRef.Reference {
		t.Fatal("ResolvePrincipalBinding must return the stored binding_ref, not recompute a fresh one")
	}
}

func TestCreatePrincipalBinding_RebindingToDifferentAgentConflicts(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	for i, agentID := range []string{"agt_1", "agt_2"} {
		if err := server.SeedIdentity(&atostosv1.AgentIdentity{
			AgentId: agentID, CanonicalUri: "tos://agent/" + agentID,
			Controllers: []string{testCanonicalController(byte(i + 1))}, Assurance: "tos_attested",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-1", now), PrincipalId: "prn_1", AgentId: "agt_1",
	})); err != nil {
		t.Fatal(err)
	}
	_, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-2", now), PrincipalId: "prn_1", AgentId: "agt_2",
	}))
	if err == nil {
		t.Fatal("expected conflict rebinding an already-bound principal to a different agent identity")
	}
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("error code = %v, want AlreadyExists", connect.CodeOf(err))
	}
}

func TestRevokePrincipalBinding_NoExistingBindingIsNotAnError(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	resp, err := server.RevokePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.RevokePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-1", now), PrincipalId: "prn_never_bound", ReasonCode: "TEST",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Revoked {
		t.Fatal("revoking a principal with no binding must report revoked=false, not error and not true")
	}
}

// TestRevokePrincipalBinding_RetryWithFreshKeyAfterLostResponseReportsRevoked
// proves a caller that revoked successfully, lost the response, and retried
// with a fresh idempotency_key (the same safe lost-response retry pattern
// CreatePrincipalBinding documents) sees Revoked=true with the original
// revocation_ref -- not Revoked=false, which would be indistinguishable
// from "this principal was never bound" and would contradict what
// ResolvePrincipalBinding already reports as PRINCIPAL_BINDING_STATUS_REVOKED
// for the same principal.
func TestRevokePrincipalBinding_RetryWithFreshKeyAfterLostResponseReportsRevoked(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_revoke_retry", CanonicalUri: "tos://agent/agt_revoke_retry", Controllers: []string{testCanonicalController(6)},
		Assurance: "tos_attested",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-bind", now), PrincipalId: "prn_revoke_retry", AgentId: "agt_revoke_retry",
	})); err != nil {
		t.Fatal(err)
	}

	first, err := server.RevokePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.RevokePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-revoke-1", now), PrincipalId: "prn_revoke_retry", ReasonCode: "TEST",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Msg.Revoked || first.Msg.RevocationRef == nil || first.Msg.RevocationRef.Reference == "" {
		t.Fatalf("unexpected first revoke response: %+v", first.Msg)
	}

	// Simulates the response being lost and the caller retrying under a
	// DIFFERENT idempotency_key -- bucketPrincipalBindings is already
	// empty, so this must consult bucketPrincipalRevocations instead of
	// concluding "nothing to revoke."
	retry, err := server.RevokePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.RevokePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-revoke-2", now), PrincipalId: "prn_revoke_retry", ReasonCode: "TEST",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !retry.Msg.Revoked {
		t.Fatal("retry after a lost response must report revoked=true, not indistinguishable from never-bound")
	}
	if retry.Msg.RevocationRef == nil || retry.Msg.RevocationRef.Reference != first.Msg.RevocationRef.Reference {
		t.Fatalf("retry must return the ORIGINAL revocation_ref, got %+v vs first %+v", retry.Msg.RevocationRef, first.Msg.RevocationRef)
	}
}

func TestRevokePrincipalBinding_FullLifecycleThenRebind(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	for i, agentID := range []string{"agt_1", "agt_2"} {
		if err := server.SeedIdentity(&atostosv1.AgentIdentity{
			AgentId: agentID, CanonicalUri: "tos://agent/" + agentID,
			Controllers: []string{testCanonicalController(byte(i + 1))}, Assurance: "tos_attested",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-1", now), PrincipalId: "prn_1", AgentId: "agt_1",
	})); err != nil {
		t.Fatal(err)
	}

	revokeResp, err := server.RevokePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.RevokePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-revoke", now), PrincipalId: "prn_1", ReasonCode: "OWNER_REQUEST",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !revokeResp.Msg.Revoked || revokeResp.Msg.RevocationRef == nil {
		t.Fatalf("unexpected revoke response: %+v", revokeResp.Msg)
	}

	resolvedAfterRevoke, err := server.ResolvePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.ResolvePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "", now), PrincipalId: "prn_1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resolvedAfterRevoke.Msg.Bound {
		t.Fatal("a revoked binding must resolve as not currently bound")
	}
	if resolvedAfterRevoke.Msg.Status != atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_REVOKED {
		t.Fatalf("status = %v, want REVOKED", resolvedAfterRevoke.Msg.Status)
	}
	if resolvedAfterRevoke.Msg.RevocationReasonCode != "OWNER_REQUEST" {
		t.Fatalf("revocation_reason_code = %q, want OWNER_REQUEST", resolvedAfterRevoke.Msg.RevocationReasonCode)
	}

	// A principal whose binding was revoked can be bound again -- to a
	// DIFFERENT agent identity this time -- and the fresh bind must fully
	// supersede the stale revocation record.
	if _, err := server.CreatePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.CreatePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "idem-rebind", now), PrincipalId: "prn_1", AgentId: "agt_2",
	})); err != nil {
		t.Fatal(err)
	}
	resolvedAfterRebind, err := server.ResolvePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.ResolvePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "", now), PrincipalId: "prn_1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resolvedAfterRebind.Msg.Bound || resolvedAfterRebind.Msg.Status != atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_ACTIVE {
		t.Fatalf("unexpected resolve after rebind: %+v", resolvedAfterRebind.Msg)
	}
	if resolvedAfterRebind.Msg.Identity.AgentId != "agt_2" {
		t.Fatalf("rebound identity = %q, want agt_2", resolvedAfterRebind.Msg.Identity.AgentId)
	}
}

func TestResolvePrincipalBinding_NeverBoundIsUnspecifiedNotRevoked(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	resolved, err := server.ResolvePrincipalBinding(context.Background(), connect.NewRequest(&atostosv1.ResolvePrincipalBindingRequest{
		Context: bindingReqCtx("caller-1", "", now), PrincipalId: "prn_never_seen",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Msg.Bound {
		t.Fatal("never-bound principal must not resolve as bound")
	}
	if resolved.Msg.Status != atostosv1.PrincipalBindingStatus_PRINCIPAL_BINDING_STATUS_UNSPECIFIED {
		t.Fatalf("status = %v, want UNSPECIFIED for a principal that was never bound", resolved.Msg.Status)
	}
}

// TestSeedIdentity_ReseedWithNewCanonicalURIRemovesStaleMapping proves that
// re-seeding an existing agent_id under a DIFFERENT canonical_uri cleans up
// the old bucketIdentityURIs mapping -- otherwise the old URI would keep
// resolving to this agent_id forever, and permanently block seeding a
// different agent_id under that now-stale URI.
func TestSeedIdentity_ReseedWithNewCanonicalURIRemovesStaleMapping(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_uri_move", CanonicalUri: "tos://agent/old-uri",
		Controllers: []string{testCanonicalController(8)}, Assurance: "tos_attested",
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_uri_move", CanonicalUri: "tos://agent/new-uri",
		Controllers: []string{testCanonicalController(8)}, Assurance: "tos_attested",
	}); err != nil {
		t.Fatal(err)
	}

	byOldURI, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: bindingReqCtx("caller-1", "", now), CanonicalUri: "tos://agent/old-uri",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if byOldURI.Msg.Found {
		t.Fatal("the old canonical_uri must no longer resolve after re-seeding under a new one")
	}

	byNewURI, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: bindingReqCtx("caller-1", "", now), CanonicalUri: "tos://agent/new-uri",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !byNewURI.Msg.Found || byNewURI.Msg.Identity.AgentId != "agt_uri_move" {
		t.Fatalf("the new canonical_uri must resolve to the re-seeded agent: %+v", byNewURI.Msg)
	}

	// A different agent_id can now legitimately claim the freed-up old URI.
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_uri_move_other", CanonicalUri: "tos://agent/old-uri",
		Controllers: []string{testCanonicalController(9)}, Assurance: "tos_attested",
	}); err != nil {
		t.Fatalf("freed-up canonical_uri must be seedable for a different agent_id: %v", err)
	}
}
