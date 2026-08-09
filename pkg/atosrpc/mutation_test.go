package atosrpc

import (
	"path/filepath"
	"testing"
	"time"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func TestAtomicMutationReplayIgnoresTransportContextAcrossRestart(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "atos-rpc.db")
	openServer := func() *Server {
		t.Helper()
		server, err := Open(Config{
			StatePath: statePath, BearerToken: "test-secret",
			Authority: NewLocalAuthority("tos-local"),
			Now:       func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	request := &atostosv1.CreateEscrowRequest{
		Context: &atostosv1.RequestContext{
			RequestId: "request-first", TraceId: "11111111111111111111111111111111",
			CallerId: "caller-test", IdempotencyKey: "idem-test",
			DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
		},
		QuoteId: "quote-test", PrincipalId: "principal-test",
		ProviderId: "provider-test", CapabilityId: "capability-test",
		TrustMode: atostosv1.TrustMode_TRUST_MODE_MANAGED,
		Reserve:   &atostosv1.NetworkAmount{Asset: "USD", AtomicAmount: "100"},
	}

	applyCalls := 0
	server := openServer()
	first := new(atostosv1.CreateEscrowResponse)
	err := server.atomicMutation("CreateEscrow", request.Context, request, first, func(*bolt.Tx) error {
		applyCalls++
		first.Created = true
		first.Escrow = &atostosv1.Escrow{EscrowId: "escrow-test", QuoteId: request.QuoteId}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a new ATOS process retrying after the first server committed its
	// durable response but the RPC response was lost. Request and trace IDs, and
	// the transport deadline, are expected to change across this retry.
	retry := proto.Clone(request).(*atostosv1.CreateEscrowRequest)
	retry.Context.RequestId = "request-retry"
	retry.Context.TraceId = "22222222222222222222222222222222"
	retry.Context.DeadlineUnixMillis = now.Add(2 * time.Minute).UnixMilli()

	server = openServer()
	defer server.Close()
	second := new(atostosv1.CreateEscrowResponse)
	err = server.atomicMutation("CreateEscrow", retry.Context, retry, second, func(*bolt.Tx) error {
		applyCalls++
		return nil
	})
	if err != nil {
		t.Fatalf("transport-only retry was rejected: %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("idempotent mutation applied %d times, want 1", applyCalls)
	}
	if !second.Created || second.Escrow == nil || second.Escrow.EscrowId != "escrow-test" {
		t.Fatalf("retry did not return the original response: %#v", second)
	}

	// The normalization must not weaken semantic substitution detection.
	conflict := proto.Clone(retry).(*atostosv1.CreateEscrowRequest)
	conflict.ProviderId = "different-provider"
	conflictResponse := new(atostosv1.CreateEscrowResponse)
	if err := server.atomicMutation("CreateEscrow", conflict.Context, conflict, conflictResponse, func(*bolt.Tx) error {
		applyCalls++
		return nil
	}); err == nil {
		t.Fatal("same idempotency key accepted a different business request")
	}
	if applyCalls != 1 {
		t.Fatalf("conflicting request applied mutation; calls=%d", applyCalls)
	}
}

func TestMutationRequestDigestRequiresRequestContext(t *testing.T) {
	if _, err := mutationRequestDigest("CreateEscrow", &atostosv1.CreateEscrowRequest{}); err == nil {
		t.Fatal("mutation request without context was canonicalized")
	}
	if _, err := mutationRequestDigest("CreateEscrow", nil); err == nil {
		t.Fatal("nil mutation request was canonicalized")
	}
}
