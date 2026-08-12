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

// TestSeedIdentities_SkipsAlreadyMatchingRecordsOnReseed proves an unchanged
// re-run of seedIdentities (e.g. every process restart, which this function
// is designed to tolerate) does not redundantly re-commit records that
// already resolve with identical content -- both an efficiency property
// (avoids a real, potentially costly re-commit under a chain-backed
// Authority) and what shrinks the exposure of a genuine mid-loop Commit
// failure: a retry only re-attempts records that did not already land.
func TestSeedIdentities_SkipsAlreadyMatchingRecordsOnReseed(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_reseed", CanonicalURI: "tos://agent/agt_seed_reseed",
		Controllers: []string{"0:5555555555555555555555555555555555555555555555555555555555555555"},
		Assurance:   "tos_operator_verified",
	}})
	count, err := seedIdentities(server, path)
	if err != nil || count != 1 {
		t.Fatalf("first run: count=%d err=%v, want 1, nil", count, err)
	}
	count, err = seedIdentities(server, path)
	if err != nil || count != 0 {
		t.Fatalf("unchanged re-run: count=%d err=%v, want 0 (nothing newly applied), nil", count, err)
	}
}

// TestSeedIdentities_ReappliesOnContentChange proves the skip above is
// content-aware, not a blanket "agent_id already exists" skip -- an operator
// intentionally rotating a seed record's controller must see it re-applied.
func TestSeedIdentities_ReappliesOnContentChange(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_rotate", CanonicalURI: "tos://agent/agt_seed_rotate",
		Controllers: []string{"0:6666666666666666666666666666666666666666666666666666666666666666"},
		Assurance:   "tos_operator_verified",
	}})
	if count, err := seedIdentities(server, path); err != nil || count != 1 {
		t.Fatalf("first run: count=%d err=%v, want 1, nil", count, err)
	}
	rotatedPath := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_rotate", CanonicalURI: "tos://agent/agt_seed_rotate",
		Controllers: []string{"0:7777777777777777777777777777777777777777777777777777777777777777"},
		Assurance:   "tos_operator_verified",
	}})
	count, err := seedIdentities(server, rotatedPath)
	if err != nil || count != 1 {
		t.Fatalf("rotated re-run: count=%d err=%v, want 1 (re-applied), nil", count, err)
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_rotate",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Identity.Controllers) != 1 || resp.Msg.Identity.Controllers[0] != "0:7777777777777777777777777777777777777777777777777777777777777777" {
		t.Fatalf("controller was not rotated: %+v", resp.Msg.Identity.Controllers)
	}
}

// TestSeedIdentities_RejectsMultipleDistinctControllers proves a record
// whose controllers canonicalize to more than one unique address is
// rejected at seed time, matching CreatePrincipalBinding's own
// uniqueTOSController requirement -- not silently accepted only to fail
// every subsequent bind attempt with no obvious link back to the seed file.
func TestSeedIdentities_RejectsMultipleDistinctControllers(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_multicontroller", CanonicalURI: "tos://agent/agt_seed_multicontroller",
		Controllers: []string{
			"0:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		Assurance: "tos_operator_verified",
	}})
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("expected two distinct controllers to be rejected")
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_multicontroller",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Found {
		t.Fatal("a record with multiple distinct controllers must not have been committed")
	}
}

// TestSeedIdentities_RejectsCanonicalURICollisionAcrossRuns proves the
// canonical_uri collision check also covers identities committed by a
// PRIOR run, not just within the current file -- an edited/reduced seed
// file across restarts must not silently orphan a previously-seeded
// identity's canonical_uri resolution.
func TestSeedIdentities_RejectsCanonicalURICollisionAcrossRuns(t *testing.T) {
	server := newTestServer(t)
	firstPath := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_uri_first", CanonicalURI: "tos://agent/shared-across-runs",
		Controllers: []string{"0:1212121212121212121212121212121212121212121212121212121212121212"},
		Assurance:   "tos_operator_verified",
	}})
	if _, err := seedIdentities(server, firstPath); err != nil {
		t.Fatalf("first run: %v", err)
	}
	secondPath := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_uri_second", CanonicalURI: "tos://agent/shared-across-runs",
		Controllers: []string{"0:3434343434343434343434343434343434343434343434343434343434343434"},
		Assurance:   "tos_operator_verified",
	}})
	if _, err := seedIdentities(server, secondPath); err == nil {
		t.Fatal("expected the second run's canonical_uri collision with the first run's identity to be rejected")
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), CanonicalUri: "tos://agent/shared-across-runs",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.Found || resp.Msg.Identity.AgentId != "agt_seed_uri_first" {
		t.Fatalf("the first run's identity must still own the canonical_uri: %+v", resp.Msg)
	}
}

// TestSeedIdentities_RejectsMalformedController proves a syntactically
// invalid controller address is caught at seed time -- not silently
// accepted only to fail far later, at the first CreatePrincipalBinding
// attempt against that agent_id, with identityAlreadySeeded then masking
// the defect as "already seeded" on every subsequent restart.
func TestSeedIdentities_RejectsMalformedController(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{{
		AgentID: "agt_seed_badcontroller", CanonicalURI: "tos://agent/agt_seed_badcontroller",
		Controllers: []string{"not-a-canonical-address"},
		Assurance:   "tos_operator_verified",
	}})
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("expected a malformed controller address to be rejected")
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_badcontroller",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Found {
		t.Fatal("a record with a malformed controller must not have been committed")
	}
}

// TestSeedIdentities_RejectsCollidingCanonicalURI proves two different
// agent_id records sharing one canonical_uri are rejected outright, instead
// of SeedIdentity's unconditional bucketIdentityURIs.Put silently letting
// the second record's write make the first agent_id unresolvable by URI.
func TestSeedIdentities_RejectsCollidingCanonicalURI(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{
		{
			AgentID: "agt_seed_uri_a", CanonicalURI: "tos://agent/shared",
			Controllers: []string{"0:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
			Assurance:   "tos_operator_verified",
		},
		{
			AgentID: "agt_seed_uri_b", CanonicalURI: "tos://agent/shared",
			Controllers: []string{"0:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			Assurance:   "tos_operator_verified",
		},
	})
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("expected a colliding canonical_uri across two agent_id records to be rejected")
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_uri_a",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Found {
		t.Fatal("a rejected colliding-canonical_uri file must not have applied either record")
	}
}

// TestSeedIdentities_MalformedAgentIDDoesNotLeakPartialApplication proves
// the pre-validation pass catches a malformed-but-non-empty agent_id (which
// SeedIdentity/ResolveAgentIdentity would only reject once actually
// reached) BEFORE any record is applied -- not just an empty one.
func TestSeedIdentities_MalformedAgentIDDoesNotLeakPartialApplication(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{
		{
			AgentID: "agt_seed_ok", CanonicalURI: "tos://agent/agt_seed_ok",
			Controllers: []string{"0:8888888888888888888888888888888888888888888888888888888888888888"},
			Assurance:   "tos_operator_verified",
		},
		{
			AgentID: "bad agent id", CanonicalURI: "tos://agent/bad",
			Controllers: []string{"0:9999999999999999999999999999999999999999999999999999999999999999"},
			Assurance:   "tos_operator_verified",
		},
	})
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("expected the malformed agent_id to reject the whole seed")
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_ok",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Found {
		t.Fatal("the earlier, well-formed record must not have been committed when a later record's agent_id was malformed")
	}
}

// TestSeedIdentities_RejectsDuplicateAgentIDInSameFile proves a seed file
// listing the same agent_id twice is rejected outright, not silently
// applied twice with the later record's content winning unnoticed.
func TestSeedIdentities_RejectsDuplicateAgentIDInSameFile(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{
		{
			AgentID: "agt_seed_dup", CanonicalURI: "tos://agent/agt_seed_dup",
			Controllers: []string{"0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Assurance:   "tos_operator_verified",
		},
		{
			AgentID: "agt_seed_dup", CanonicalURI: "tos://agent/agt_seed_dup",
			Controllers: []string{"0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			Assurance:   "tos_operator_verified",
		},
	})
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("expected a duplicate agent_id within one seed file to be rejected")
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_dup",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Found {
		t.Fatal("a rejected duplicate-agent_id file must not have applied either record")
	}
}

// TestSeedIdentities_ValidatesAllBeforeApplyingAny proves a later record's
// validation failure does not leave earlier, individually-valid records
// already durably committed -- an operator fixing the bad record and
// retrying must see the WHOLE file's intent applied, not a partial mix from
// the failed attempt plus the retry.
func TestSeedIdentities_ValidatesAllBeforeApplyingAny(t *testing.T) {
	server := newTestServer(t)
	path := writeIdentitySeedFile(t, []identitySeed{
		{
			AgentID: "agt_seed_partial_good", CanonicalURI: "tos://agent/agt_seed_partial_good",
			Controllers: []string{"0:4444444444444444444444444444444444444444444444444444444444444444"},
			Assurance:   "tos_operator_verified",
		},
		{
			AgentID: "agt_seed_partial_bad", CanonicalURI: "tos://agent/agt_seed_partial_bad",
			Assurance: "self_asserted",
		},
	})
	if _, err := seedIdentities(server, path); err == nil {
		t.Fatal("expected the file's invalid second record to reject the whole seed")
	}
	resp, err := server.ResolveAgentIdentity(context.Background(), connect.NewRequest(&atostosv1.ResolveAgentIdentityRequest{
		Context: testRequestContext(), AgentId: "agt_seed_partial_good",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Found {
		t.Fatal("the earlier, individually-valid record must not have been committed when a later record failed validation")
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
	  "publisherJournalIdentity":"journal-test",
	  "publisherJournalBinding":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
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
