package atosrpc

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

func TestChainAuthorityStartupConfigBuildsWithoutPrivateKeys(t *testing.T) {
	config := validChainAuthorityStartupConfig(filepath.Join(t.TempDir(), "publisher.sock"))
	authority, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if authority.Network() != "tos-test" || !authority.Supports(TrustModeManaged) ||
		!authority.Supports(TrustModeVerified) || authority.Supports(TrustModeNative) {
		t.Fatalf("unexpected chain Authority mode support: network=%q", authority.Network())
	}
}

func TestChainAuthorityStartupConfigRejectsUnknownJSON(t *testing.T) {
	_, err := DecodeChainAuthorityStartupConfigJSON([]byte(`{
		"version":"1",
		"chain":{},
		"unknown":true
	}`))
	if err == nil {
		t.Fatal("unknown chain Authority config field was accepted")
	}
}

func TestChainAuthorityStartupConfigRejectsMissingPublisher(t *testing.T) {
	config := validChainAuthorityStartupConfig("")
	if _, err := config.Build(); err == nil {
		t.Fatal("chain Authority without a private publisher socket was accepted")
	}
}

func validChainAuthorityStartupConfig(socket string) ChainAuthorityStartupConfig {
	return ChainAuthorityStartupConfig{
		Version:        ChainAuthorityStartupConfigVersion,
		Chain:          toschainStartupForAuthorityTest(),
		ServiceAddress: "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ServiceID:      "service-test", PublisherSocket: socket,
		AnchorPayer: testChainPayer, AnchorPayee: testChainPayee,
		AnchorAmountNanoTOS: 1,
	}
}

func toschainStartupForAuthorityTest() toschain.StartupConfig {
	return toschain.StartupConfig{
		Version: toschain.StartupConfigVersion,
		Network: "tos-test",
		Endpoints: []string{
			"https://rpc-one.example/jsonRPC",
			"https://rpc-two.example/jsonRPC",
			"https://rpc-three.example/jsonRPC",
		},
		Quorum: 2,
		AllowedServiceCodeHashes: []string{
			fmt.Sprintf("tvm-cell-sha256:%s", strings.Repeat("1", 64)),
		},
	}
}
