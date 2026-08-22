package buyersdk

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

type capabilityClientFake struct {
	state   *nativev1.NativeStateV1
	err     error
	request *nativev1.ResolveNativeStateRequest
}

func (f *capabilityClientFake) ResolveNativeState(_ context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	f.request = proto.Clone(request).(*nativev1.ResolveNativeStateRequest)
	if f.err != nil {
		return nil, f.err
	}
	return &nativev1.ResolveNativeStateResponse{Found: f.state != nil, State: proto.Clone(f.state).(*nativev1.NativeStateV1)}, nil
}

func capabilityVerifierFixture(t *testing.T) (*CapabilityVerifier, *capabilityClientFake, CapabilityExpectation) {
	t.Helper()
	network := &nativev1.NetworkDomain{NetworkId: "tos-test", GenesisRootHash: "sha256:" + strings.Repeat("a", 64),
		GenesisFileHash: "sha256:" + strings.Repeat("b", 64)}
	expected := CapabilityExpectation{CapabilityID: "cap_" + strings.Repeat("c", 64),
		OwnerAgentID: "agent_" + strings.Repeat("d", 64), Version: "1.0.0",
		ManifestDigest: "sha256:" + strings.Repeat("e", 64)}
	registry := "tvm-cell-sha256:" + strings.Repeat("f", 64)
	client := &capabilityClientFake{state: &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("1", 64),
		Reference: &nativev1.ChainReference{FinalizedCheckpoint: 42, ContractCodeHash: registry,
			TransactionHash: "sha256:" + strings.Repeat("2", 64)},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
			CapabilityId: expected.CapabilityID, OwnerAgentId: expected.OwnerAgentID,
			Versions: []*nativev1.CapabilityVersionV1{{Version: expected.Version, ManifestDigest: expected.ManifestDigest}},
		}}}}
	verifier, err := NewCapabilityVerifier(CapabilityVerifierConfig{NativeClient: client, Network: network,
		RegistryCodeHash: registry, CallerID: "openfox-opportunity", Timeout: 5 * time.Second,
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return verifier, client, expected
}

func TestCapabilityVerifierReturnsExactFinalizedObservation(t *testing.T) {
	verifier, client, expected := capabilityVerifierFixture(t)
	observation, err := verifier.Verify(context.Background(), expected)
	if err != nil || observation.FinalizedCheckpoint != 42 || observation.State.GetCapability().GetCapabilityId() != expected.CapabilityID {
		t.Fatalf("verify: %+v err=%v", observation, err)
	}
	if client.request.GetObjectId() != expected.CapabilityID || client.request.GetContext().GetDeadlineUnixMillis() <= 0 {
		t.Fatalf("wrong finalized request: %+v", client.request)
	}
	observation.State.GetCapability().OwnerAgentId = "mutated"
	if client.state.GetCapability().OwnerAgentId != expected.OwnerAgentID {
		t.Fatal("returned observation aliases resolver state")
	}
}

func TestCapabilityVerifierFailsClosedOnAuthoritySubstitution(t *testing.T) {
	mutations := map[string]func(*nativev1.NativeStateV1, *CapabilityExpectation){
		"network": func(state *nativev1.NativeStateV1, _ *CapabilityExpectation) { state.Network.NetworkId = "other" },
		"registry": func(state *nativev1.NativeStateV1, _ *CapabilityExpectation) {
			state.Reference.ContractCodeHash = "tvm-cell-sha256:" + strings.Repeat("0", 64)
		},
		"owner": func(state *nativev1.NativeStateV1, _ *CapabilityExpectation) {
			state.GetCapability().OwnerAgentId = "agent_" + strings.Repeat("0", 64)
		},
		"tombstone": func(state *nativev1.NativeStateV1, _ *CapabilityExpectation) { state.GetCapability().Tombstoned = true },
		"manifest": func(_ *nativev1.NativeStateV1, expected *CapabilityExpectation) {
			expected.ManifestDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"rollback": func(state *nativev1.NativeStateV1, _ *CapabilityExpectation) { state.Reference.FinalizedCheckpoint = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			verifier, client, expected := capabilityVerifierFixture(t)
			mutate(client.state, &expected)
			if _, err := verifier.Verify(context.Background(), expected); err == nil {
				t.Fatal("authority substitution was accepted")
			}
		})
	}
}

func TestCapabilityVerifierPropagatesResolverFailureAndRejectsWeakConfig(t *testing.T) {
	verifier, client, expected := capabilityVerifierFixture(t)
	client.err = errors.New("quorum unavailable")
	if _, err := verifier.Verify(context.Background(), expected); !errors.Is(err, client.err) {
		t.Fatalf("resolver failure lost: %v", err)
	}
	if _, err := NewCapabilityVerifier(CapabilityVerifierConfig{RegistryCodeHash: "x"}); err == nil {
		t.Fatal("incomplete verifier config was accepted")
	}
}
