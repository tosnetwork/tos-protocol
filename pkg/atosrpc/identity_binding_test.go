package atosrpc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

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

func TestCreatePrincipalBinding_HappyPathThenIdempotentReplay(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: "agt_1", CanonicalUri: "tos://agent/agt_1", Controllers: []string{"tos:addr:1"},
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
	for _, agentID := range []string{"agt_1", "agt_2"} {
		if err := server.SeedIdentity(&atostosv1.AgentIdentity{
			AgentId: agentID, CanonicalUri: "tos://agent/" + agentID, Controllers: []string{"tos:addr:" + agentID},
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

func TestRevokePrincipalBinding_FullLifecycleThenRebind(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	server := newIdentityBindingTestServer(t, now)
	for _, agentID := range []string{"agt_1", "agt_2"} {
		if err := server.SeedIdentity(&atostosv1.AgentIdentity{
			AgentId: agentID, CanonicalUri: "tos://agent/" + agentID, Controllers: []string{"tos:addr:" + agentID},
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
