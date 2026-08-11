package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/atosrpc"
)

func newTestServer(t *testing.T) *atosrpc.Server {
	t.Helper()
	authority, err := buildAuthority("local", "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := atosrpc.Open(atosrpc.Config{
		StatePath: filepath.Join(t.TempDir(), "state.db"), BearerToken: "test-token-0123456789",
		Authority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server
}

func testRequestContext() *atostosv1.RequestContext {
	return &atostosv1.RequestContext{RequestId: "req-test-1", CallerId: "test-caller"}
}

func writeIdentitySeedFile(t *testing.T, seeds []identitySeed) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identities.json")
	encoded, err := json.Marshal(seeds)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSeedIdentities_EmptyPathIsNoOp(t *testing.T) {
	server := newTestServer(t)
	count, err := seedIdentities(server, "")
	if err != nil || count != 0 {
		t.Fatalf("count=%d err=%v, want 0, nil", count, err)
	}
}

func TestSeedIdentities_GoldenPathIsResolvable(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_golden", CanonicalURI: "tos://agent/agt_seed_golden",
		Controllers: []string{"0:1111111111111111111111111111111111111111111111111111111111111111"},
		Assurance:   "tos_operator_verified",
	}})
	count, err := seedIdentities(server, path)
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want 1, nil", count, err)
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_golden",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.Found || resp.Msg.Identity.Assurance != "tos_operator_verified" {
		t.Fatalf("unexpected resolved identity: %+v", resp.Msg)
	}
}

func TestSeedIdentities_RepeatedSeedIsStable(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_repeat", CanonicalURI: "tos://agent/agt_seed_repeat",
		Controllers: []string{"0:2222222222222222222222222222222222222222222222222222222222222222"},
		Assurance:   "tos_operator_verified",
	}})
	if _, err := seedIdentities(server, path); err != nil {
		t.Fatal(err)
	}
	first, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{Context: testRequestContext(), AgentId: "agt_seed_repeat"}))
	if err != nil {
		t.Fatal(err)
	}
	// Re-running with identical content (e.g. a process restart) must
	// converge on the same chain commitment reference, not mint a new one.
	if _, err := seedIdentities(server, path); err != nil {
		t.Fatal(err)
	}
	second, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{Context: testRequestContext(), AgentId: "agt_seed_repeat"}))
	if err != nil {
		t.Fatal(err)
	}
	if first.Msg.Identity.IdentityRef.Reference != second.Msg.Identity.IdentityRef.Reference {
		t.Fatalf("re-seed produced a different reference: %q vs %q",
			first.Msg.Identity.IdentityRef.Reference, second.Msg.Identity.IdentityRef.Reference)
	}
}

func TestSeedIdentities_RejectsSelfAssertedAssurance(t *testing.T) {
	server := newTestServer(t)
	for _, assurance := range []string{"", "self_asserted", "SELF_ASSERTED"} {
		path := writeIdentitySeedFile(t, []identitySeed{{
			AgentID: "agt_seed_bad", CanonicalURI: "tos://agent/agt_seed_bad",
			Controllers: []string{"0:3333333333333333333333333333333333333333333333333333333333333333"},
			Assurance:   assurance,
		}})
		if _, err := seedIdentities(server, path); err == nil {
			t.Fatalf("assurance %q was accepted", assurance)
		}
	}
}

func TestSeedIdentities_RejectsNoControllers(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_nocontroller", CanonicalURI: "tos://agent/agt_seed_nocontroller",
		Assurance: "tos_operator_verified",
	}})
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("identity with no controllers was accepted")
	}
}

func TestSeedIdentities_MalformedFileRejected(t *testing.T) {
	server := newTestServer(t)
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"not":"an array"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("malformed identity seed file was accepted")
	}
}

func TestPlainHTTPRestrictedToLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8090", "[::1]:8090", "localhost:8090"} {
		if _, useTLS, err := buildServerTLS(address, "", "", ""); err != nil || useTLS {
			t.Fatalf("loopback %q rejected: useTLS=%v err=%v", address, useTLS, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8090", ":8090", "192.0.2.10:8090"} {
		if _, _, err := buildServerTLS(address, "", "", ""); err == nil {
			t.Fatalf("non-loopback plain HTTP %q was accepted", address)
		}
	}
}

func TestTLSCertificateAndKeyMustBePaired(t *testing.T) {
	if _, _, err := buildServerTLS("0.0.0.0:8090", "cert.pem", "", ""); err == nil {
		t.Fatal("certificate without key was accepted")
	}
	if _, _, err := buildServerTLS("0.0.0.0:8090", "", "key.pem", ""); err == nil {
		t.Fatal("key without certificate was accepted")
	}
}

func TestBuildAuthoritySelectsExplicitBackend(t *testing.T) {
	local, err := buildAuthority("local", "")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if local.Network() != "tos-local" || !local.Supports(atosrpc.TrustModeManaged) {
		t.Fatalf("unexpected local Authority: network=%q", local.Network())
	}
	if _, err := buildAuthority("local", "/unused/config.json"); err == nil {
		t.Fatal("local Authority silently ignored a chain config")
	}
	if _, err := buildAuthority("unknown", ""); err == nil {
		t.Fatal("unknown Authority backend was accepted")
	}
	if _, err := buildAuthority("chain", ""); err == nil {
		t.Fatal("chain Authority without config was accepted")
	}
}

func TestBuildAuthorityLoadsStrictChainConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.json")
	config := `{
	  "version":"1",
	  "chain":{
	    "version":"1",
	    "network":"tos-test",
	    "endpoints":[
	      "https://rpc-one.example/jsonRPC",
	      "https://rpc-two.example/jsonRPC",
	      "https://rpc-three.example/jsonRPC"
	    ],
	    "quorum":2,
	    "allowedServiceCodeHashes":["tvm-cell-sha256:1111111111111111111111111111111111111111111111111111111111111111"]
	  },
	  "serviceAddress":"0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "serviceId":"service-test",
	  "publisherSocket":"` + filepath.Join(t.TempDir(), "publisher.sock") + `",
	  "anchorPayer":"0:1111111111111111111111111111111111111111111111111111111111111111",
	  "anchorPayee":"0:2222222222222222222222222222222222222222222222222222222222222222",
	  "anchorAmountNanoTOS":1
	}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	authority, err := buildAuthority("chain", path)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if authority.Network() != "tos-test" || !authority.Supports(atosrpc.TrustModeVerified) ||
		authority.Supports(atosrpc.TrustModeNative) {
		t.Fatalf("unexpected chain Authority mode support: network=%q", authority.Network())
	}
}

func TestBuildEconomicDriverSelectsExplicitBackend(t *testing.T) {
	if driver, err := buildEconomicDriver("disabled", ""); err != nil || driver != nil {
		t.Fatalf("disabled driver rejected: driver=%v err=%v", driver, err)
	}
	if _, err := buildEconomicDriver("disabled", "/unused/config.json"); err == nil {
		t.Fatal("disabled driver silently ignored a config")
	}
	if _, err := buildEconomicDriver("task-escrow", ""); err == nil {
		t.Fatal("task-escrow driver without config was accepted")
	}
	if _, err := buildEconomicDriver("unknown", ""); err == nil {
		t.Fatal("unknown economic driver was accepted")
	}
}

func TestBuildEconomicDriverLoadsStrictTaskEscrowConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "economic.json")
	config := `{
	  "version":"1",
	  "chain":{
	    "version":"1",
	    "network":"tos-test",
	    "endpoints":[
	      "https://rpc-one.example/jsonRPC",
	      "https://rpc-two.example/jsonRPC",
	      "https://rpc-three.example/jsonRPC"
	    ],
	    "quorum":2,
	    "allowedServiceCodeHashes":["tvm-cell-sha256:1111111111111111111111111111111111111111111111111111111111111111"]
	  },
	  "allowedTaskEscrowCodeHashes":["tvm-cell-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
	  "verifierAddress":"0:3333333333333333333333333333333333333333333333333333333333333333",
	  "publisherSocket":"` + filepath.Join(t.TempDir(), "task-escrow-publisher.sock") + `",
	  "fundingOverheadNanoTOS":50
	}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	driver, err := buildEconomicDriver("task-escrow", path)
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	if driver.Network() != "tos-test" {
		t.Fatalf("unexpected economic driver network: %q", driver.Network())
	}
}
