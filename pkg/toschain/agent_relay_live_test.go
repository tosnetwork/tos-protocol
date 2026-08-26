package toschain

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

// TestTOSRelayThreeNodeReadOnlyIntegration is deliberately opt-in and performs
// only getConsensusBlock/getMasterchainInfo reads. The immutable genesis values
// come from owner-supplied environment pins; the test never learns a domain from
// an endpoint and then treats that endpoint-selected value as authority.
//
// Required environment:
//
//	OPENFOX_TOS_RELAY_READONLY_INTEGRATION=1
//	OPENFOX_TOS_RPC_1, OPENFOX_TOS_RPC_2, OPENFOX_TOS_RPC_3
//	OPENFOX_TOS_NETWORK_ID, OPENFOX_TOS_GLOBAL_ID
//	OPENFOX_TOS_ZERO_STATE_ROOT_HASH, OPENFOX_TOS_ZERO_STATE_FILE_HASH
//	OPENFOX_TOS_WORKCHAIN_ID
func TestTOSRelayThreeNodeReadOnlyIntegration(t *testing.T) {
	if os.Getenv("OPENFOX_TOS_RELAY_READONLY_INTEGRATION") != "1" {
		t.Skip("set OPENFOX_TOS_RELAY_READONLY_INTEGRATION=1 for the read-only three-node relay probe")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s is required", name)
		}
		return value
	}
	parseI32 := func(name string) int32 {
		t.Helper()
		value, err := strconv.ParseInt(required(name), 10, 32)
		if err != nil {
			t.Fatalf("%s is not a signed int32: %v", name, err)
		}
		return int32(value)
	}

	network := agentrelay.NetworkDomain{
		NetworkID:         required("OPENFOX_TOS_NETWORK_ID"),
		GlobalID:          parseI32("OPENFOX_TOS_GLOBAL_ID"),
		ZeroStateRootHash: required("OPENFOX_TOS_ZERO_STATE_ROOT_HASH"),
		ZeroStateFileHash: required("OPENFOX_TOS_ZERO_STATE_FILE_HASH"),
		WorkchainID:       parseI32("OPENFOX_TOS_WORKCHAIN_ID"),
	}
	if _, err := agentrelay.NetworkDomainDigest(network); err != nil {
		t.Fatalf("owner-pinned relay network domain is invalid: %v", err)
	}
	adapter, err := New(Config{Network: network.NetworkID, PinnedNetworkDomain: &PinnedNetworkDomain{
		NetworkID: network.NetworkID, GlobalID: network.GlobalID, ZeroStateRootHash: network.ZeroStateRootHash,
		ZeroStateFileHash: network.ZeroStateFileHash, WorkchainID: network.WorkchainID},
		Endpoints: []string{required("OPENFOX_TOS_RPC_1"), required("OPENFOX_TOS_RPC_2"), required("OPENFOX_TOS_RPC_3")},
		Quorum:    2, QueryTimeout: 5 * time.Second, ReadinessMaxAge: DefaultReadinessMaxAge})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	readiness, err := adapter.Readiness(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("three-node relay readiness failed: %v", err)
	}
	if readiness.Network != network.NetworkID || readiness.ObservedMasterSeqno == 0 || readiness.QuorumEndpoints < 2 {
		t.Fatalf("three-node relay readiness returned an invalid snapshot: %+v", readiness)
	}
	if err := adapter.VerifyPinnedRelayGenesis(ctx, network); err != nil {
		t.Fatalf("three-node pinned relay genesis preflight failed: %v", err)
	}
}
