package atosrpc

import (
	"reflect"
	"testing"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
)

func TestNativeRegistryProtoMappingPreservesCanonicalFieldNames(t *testing.T) {
	want := nativeprotocol.RegistryAction{
		Version: nativeprotocol.Version,
		Kind:    nativeprotocol.ActionRegisterAgent,
		Network: nativeprotocol.NetworkDomain{
			NetworkID:       "tos-testnet",
			GenesisRootHash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			GenesisFileHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
		AgentID: "agent_3333333333333333333333333333333333333333333333333333333333333333",
	}
	wire, err := nativeToProto[atostosv1.NativeRegistryActionV1](want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protoAs[nativeprotocol.RegistryAction](wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Native mapping lost fields:\nwant=%+v\ngot=%+v", want, got)
	}
}
