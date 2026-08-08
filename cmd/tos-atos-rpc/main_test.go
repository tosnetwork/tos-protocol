package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/atosrpc"
)

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
