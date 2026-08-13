//go:build integration

package toschain

import (
	"context"
	"os"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
)

func TestNativeRegistryCanonicalAbsenceOnLocalnet(t *testing.T) {
	if os.Getenv("TOS_PHASE5B_RPC_URL") == "" {
		t.Skip("Phase 5B localnet is not configured")
	}
	network := nativeprotocol.NetworkDomain{NetworkID: os.Getenv("TOS_PHASE5B_NETWORK_ID"),
		GenesisRootHash: os.Getenv("TOS_PHASE5B_GENESIS_ROOT"), GenesisFileHash: os.Getenv("TOS_PHASE5B_GENESIS_FILE")}
	adapter, err := New(Config{Network: network.NetworkID, Endpoints: []string{
		"http://127.0.0.1:29545/", "http://127.0.0.1:29546/", "http://127.0.0.1:29547/"}, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	head, _, err := adapter.consensus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	address := "0:0ad940d13c4ad418aac2dec32dbc14aa974a1692d10738a29fa74c0d31724993"
	for index, node := range adapter.nodes {
		vote, readErr := readNativeAccountAt(context.Background(), node, address, head.seqno, network,
			"tvm-cell-sha256:efb7b9260383ff66e9f0ca6a9bc2e30979186bd48416d3d61b116ccb65098ba7")
		if readErr != nil {
			t.Fatalf("endpoint %d canonical absence: %v", index, readErr)
		}
		if vote.Found {
			t.Fatalf("endpoint %d reported nonexistent account present", index)
		}
	}
}
