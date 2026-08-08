package economic

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

func TestTaskEscrowStartupConfigRejectsUnknownJSON(t *testing.T) {
	_, err := DecodeTaskEscrowStartupConfigJSON([]byte(`{
		"version":"1",
		"chain":{},
		"unknown":true
	}`))
	if err == nil {
		t.Fatal("unknown Task Escrow config field was accepted")
	}
}

func TestTaskEscrowStartupConfigBuildsStrictDriver(t *testing.T) {
	config := validTaskEscrowStartupConfig(filepath.Join(t.TempDir(), "publisher.sock"))
	driver, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	if driver.Network() != "tos-test" || !driver.Supports(TrustModeVerified) || driver.Supports(TrustModeNative) {
		t.Fatalf("unexpected economic driver mode support: network=%q", driver.Network())
	}
}

func TestTaskEscrowStartupConfigRejectsMissingCodeAllowlist(t *testing.T) {
	config := validTaskEscrowStartupConfig(filepath.Join(t.TempDir(), "publisher.sock"))
	config.AllowedTaskEscrowCodeHashes = nil
	if _, err := config.Build(); err == nil {
		t.Fatal("Task Escrow driver without reviewed code hashes was accepted")
	}
}

func validTaskEscrowStartupConfig(socket string) TaskEscrowStartupConfig {
	return TaskEscrowStartupConfig{
		Version: TaskEscrowStartupConfigVersion,
		Chain: toschain.StartupConfig{
			Version: toschain.StartupConfigVersion, Network: "tos-test",
			Endpoints: []string{
				"https://rpc-one.example/jsonRPC",
				"https://rpc-two.example/jsonRPC",
				"https://rpc-three.example/jsonRPC",
			},
			Quorum: 2,
			AllowedServiceCodeHashes: []string{
				"tvm-cell-sha256:" + strings.Repeat("1", 64),
			},
		},
		AllowedTaskEscrowCodeHashes: []string{
			"tvm-cell-sha256:" + strings.Repeat("a", 64),
		},
		VerifierAddress:        testVerifier,
		PublisherSocket:        socket,
		FundingOverheadNanoTOS: 50,
	}
}
