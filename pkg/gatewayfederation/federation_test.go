package gatewayfederation

import (
	"context"
	"errors"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"google.golang.org/protobuf/proto"
)

type fakeClient struct {
	search   *nativev1.SearchCapabilitiesResponse
	manifest *nativev1.GetSoftwareWorkManifestResponse
	err      error
}

func (f fakeClient) SearchCapabilities(context.Context, *nativev1.SearchCapabilitiesRequest) (*nativev1.SearchCapabilitiesResponse, error) {
	return f.search, f.err
}
func (f fakeClient) GetSoftwareWorkManifest(context.Context, *nativev1.GetSoftwareWorkManifestRequest) (*nativev1.GetSoftwareWorkManifestResponse, error) {
	return f.manifest, f.err
}

func network() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
}

func candidate(manifest string) *nativev1.CapabilitySearchResultV1 {
	return &nativev1.CapabilitySearchResultV1{CapabilityVersion: "1.0.0", ManifestDigest: manifest,
		Capability: &nativev1.NativeStateV1{Network: network(), TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("33", 32),
			Reference: &nativev1.ChainReference{FinalizedCheckpoint: 5, TransactionHash: "sha256:" + strings.Repeat("44", 32),
				ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32)},
			State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
				CapabilityId: "cap_" + strings.Repeat("66", 32), OwnerAgentId: "agent_" + strings.Repeat("77", 32),
				Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: manifest}}}}}}
}

func federation(t *testing.T) *Federation {
	t.Helper()
	f, err := New(Config{Network: network(), RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32)})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func request() *nativev1.SearchCapabilitiesRequest {
	return &nativev1.SearchCapabilitiesRequest{Context: &nativev1.RequestContext{RequestId: "request"}, PageSize: 10}
}

func TestSearchIsolatesFailureAndPreservesSource(t *testing.T) {
	manifest := "sha256:" + strings.Repeat("88", 32)
	valid := &nativev1.SearchCapabilitiesResponse{Results: []*nativev1.CapabilitySearchResultV1{candidate(manifest)}}
	gateways := []Gateway{{ID: "gateway-b", Client: fakeClient{err: errors.New("offline")}},
		{ID: "gateway-a", Client: fakeClient{search: valid}}}
	results, failures, err := federation(t).Search(context.Background(), gateways, request())
	if err != nil || len(results) != 1 || results[0].GatewayID != "gateway-a" || len(failures) != 1 || failures[0].GatewayID != "gateway-b" {
		t.Fatalf("results=%+v failures=%+v err=%v", results, failures, err)
	}
	if results[0].Result == valid.Results[0] {
		t.Fatal("federation leaked mutable Gateway response")
	}
}

func TestSearchRejectsWholeMalformedGatewayResponse(t *testing.T) {
	manifest := "sha256:" + strings.Repeat("88", 32)
	bad := candidate(manifest)
	bad.CapabilityVersion = "2.0.0"
	gateways := []Gateway{{ID: "bad", Client: fakeClient{search: &nativev1.SearchCapabilitiesResponse{Results: []*nativev1.CapabilitySearchResultV1{bad}}}},
		{ID: "good", Client: fakeClient{search: &nativev1.SearchCapabilitiesResponse{}}}}
	results, failures, err := federation(t).Search(context.Background(), gateways, request())
	if err != nil || len(results) != 0 || len(failures) != 1 || failures[0].GatewayID != "bad" {
		t.Fatalf("results=%+v failures=%+v err=%v", results, failures, err)
	}
}

func TestSearchFailsClosedWhenAllGatewaysFail(t *testing.T) {
	gateways := []Gateway{{ID: "a", Client: fakeClient{err: errors.New("offline")}},
		{ID: "b", Client: fakeClient{err: errors.New("offline")}}}
	if _, failures, err := federation(t).Search(context.Background(), gateways, request()); err == nil || len(failures) != 2 {
		t.Fatalf("failures=%+v err=%v", failures, err)
	}
}

func TestSearchRejectsAggregateOutsideConfiguredBound(t *testing.T) {
	manifest := "sha256:" + strings.Repeat("88", 32)
	response := &nativev1.SearchCapabilitiesResponse{Results: []*nativev1.CapabilitySearchResultV1{candidate(manifest)}}
	f, err := New(Config{Network: network(), RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32), MaxResults: 1})
	if err != nil {
		t.Fatal(err)
	}
	gateways := []Gateway{{ID: "a", Client: fakeClient{search: response}}, {ID: "b", Client: fakeClient{search: response}}}
	if results, _, err := f.Search(context.Background(), gateways, request()); err == nil || len(results) != 0 {
		t.Fatalf("results=%+v err=%v", results, err)
	}
}

func TestFetchManifestFailsOverAndChecksDigest(t *testing.T) {
	raw := []byte{0xa1, 0x61, 0x61, 0x01}
	digest := sha(raw)
	gateways := []Gateway{{ID: "corrupt", Client: fakeClient{manifest: &nativev1.GetSoftwareWorkManifestResponse{
		ManifestDigest: digest, CanonicalCbor: []byte("wrong")}}}, {ID: "exact", Client: fakeClient{manifest: &nativev1.GetSoftwareWorkManifestResponse{
		ManifestDigest: digest, CanonicalCbor: raw}}}}
	request := &nativev1.GetSoftwareWorkManifestRequest{Context: &nativev1.RequestContext{RequestId: "request"}, ManifestDigest: digest}
	got, source, failures, err := federation(t).FetchManifest(context.Background(), gateways, request)
	if err != nil || source != "exact" || len(failures) != 1 || !proto.Equal(&nativev1.GetSoftwareWorkManifestResponse{CanonicalCbor: got},
		&nativev1.GetSoftwareWorkManifestResponse{CanonicalCbor: raw}) {
		t.Fatalf("source=%s failures=%+v err=%v got=%x", source, failures, err, got)
	}
}
