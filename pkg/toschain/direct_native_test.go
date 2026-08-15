package toschain

import (
	"context"
	"errors"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type directNativeResolverFake struct {
	state    *nativev1.NativeStateV1
	found    bool
	err      error
	objectID string
	expected string
}

func (f *directNativeResolverFake) ResolveState(_ context.Context, objectID, expected string) (*nativev1.NativeStateV1, bool, error) {
	f.objectID, f.expected = objectID, expected
	return f.state, f.found, f.err
}

func TestDirectNativeClientResolvesWithoutGateway(t *testing.T) {
	state := &nativev1.NativeStateV1{TvmStateHash: "tvm-cell-sha256:state"}
	resolver := &directNativeResolverFake{state: state, found: true}
	client, err := NewDirectNativeClient(resolver)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	client.now = func() time.Time { return now }
	response, err := client.ResolveNativeState(context.Background(), &nativev1.ResolveNativeStateRequest{
		Context:  &nativev1.RequestContext{RequestId: "request", CallerId: "buyer", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli()},
		ObjectId: "cap_01", ExpectedTvmStateHash: "tvm-cell-sha256:expected",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Found || response.State != state || resolver.objectID != "cap_01" || resolver.expected != "tvm-cell-sha256:expected" {
		t.Fatal("direct Native client changed the authoritative resolution result")
	}
}

func TestDirectNativeClientRejectsInvalidRequests(t *testing.T) {
	resolver := &directNativeResolverFake{}
	client, err := NewDirectNativeClient(resolver)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	client.now = func() time.Time { return now }
	for _, request := range []*nativev1.ResolveNativeStateRequest{
		nil,
		{},
		{Context: &nativev1.RequestContext{RequestId: "request", CallerId: "buyer", DeadlineUnixMillis: now.UnixMilli()}, ObjectId: "cap_01"},
	} {
		if _, err := client.ResolveNativeState(context.Background(), request); err == nil {
			t.Fatal("invalid direct Native request was accepted")
		}
	}
	resolver.err = errors.New("quorum unavailable")
	request := &nativev1.ResolveNativeStateRequest{Context: &nativev1.RequestContext{
		RequestId: "request", CallerId: "buyer", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli()}, ObjectId: "cap_01"}
	if _, err := client.ResolveNativeState(context.Background(), request); !errors.Is(err, resolver.err) {
		t.Fatal("resolver failure was not propagated")
	}
}
