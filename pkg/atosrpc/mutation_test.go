package atosrpc

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
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

// TestCommitmentDigestIgnoresTransportContext proves the fix for the five
// call sites that used to hash the whole request (including RequestContext)
// into the digest an Authority.Commit call is keyed on: CreateEscrow,
// ReleaseEscrow, SettleJob, RevokeExecutionSigner, and
// CommitCapabilityManifest. Before the fix, two deliveries of the same
// logical operation that legitimately vary request_id/trace_id/deadline (any
// client retry) computed two different digests, which for a chain-backed
// Authority means two different ActionIDs -- i.e. two distinct on-chain
// commitments for what the caller believes is a single operation. Each case
// below is the exact (kind, proto message) pair as it is actually built at
// its call site.
func TestCommitmentDigestIgnoresTransportContext(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	baseContext := func(requestID string) *atostosv1.RequestContext {
		return &atostosv1.RequestContext{
			RequestId: requestID, TraceId: "trace-" + requestID,
			CallerId: "caller-test", IdempotencyKey: "idem-stable",
			DeadlineUnixMillis: now.Add(time.Duration(len(requestID)) * time.Second).UnixMilli(),
		}
	}
	cases := []struct {
		name string
		kind string
		msg  func(requestID string) proto.Message
	}{
		{
			name: "RevokeExecutionSigner",
			kind: "ATOS-TOS-SIGNER-REVOCATION-V1",
			msg: func(requestID string) proto.Message {
				return &atostosv1.RevokeExecutionSignerRequest{
					Context: baseContext(requestID), AuthorizationId: "auth-1", ReasonCode: "rotation",
				}
			},
		},
		{
			name: "CreateEscrow",
			kind: "ATOS-TOS-ESCROW-V1",
			msg: func(requestID string) proto.Message {
				return &atostosv1.CreateEscrowRequest{
					Context: baseContext(requestID), QuoteId: "quote-1", PrincipalId: "principal-1",
					ProviderId: "provider-1", CapabilityId: "capability-1",
					TrustMode: atostosv1.TrustMode_TRUST_MODE_MANAGED,
					Reserve:   &atostosv1.NetworkAmount{Asset: "USD", AtomicAmount: "100"},
				}
			},
		},
		{
			name: "ReleaseEscrow",
			kind: "ATOS-TOS-ESCROW-RELEASE-V1",
			msg: func(requestID string) proto.Message {
				return &atostosv1.ReleaseEscrowRequest{
					Context: baseContext(requestID), EscrowId: "escrow-1", QuoteId: "quote-1",
					JobId: "job-1", ReasonCode: "expired",
				}
			},
		},
		{
			name: "SettleJob",
			kind: "ATOS-TOS-SETTLEMENT-V1",
			msg: func(requestID string) proto.Message {
				return &atostosv1.SettleJobRequest{
					Context: baseContext(requestID), EscrowId: "escrow-1", QuoteId: "quote-1",
					JobId: "job-1", ReceiptId: "receipt-1",
					RequestedCharge: &atostosv1.NetworkAmount{Asset: "USD", AtomicAmount: "50"},
				}
			},
		},
		{
			name: "CommitCapabilityManifest",
			kind: "ATOS-TOS-CAPABILITY-MANIFEST-V1",
			msg: func(requestID string) proto.Message {
				return &atostosv1.CommitCapabilityManifestRequest{
					Context: baseContext(requestID), CapabilityId: "capability-1", ProviderId: "provider-1",
					Version: "1.0.0", ManifestDigest: digestMessage([]byte("capability-1")),
					RequestedTrustModes: []atostosv1.TrustMode{TrustModeManaged},
				}
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			original, err := protoDigest(testCase.kind, withoutTransportContext(testCase.msg("request-original")))
			if err != nil {
				t.Fatalf("digest original: %v", err)
			}
			retry, err := protoDigest(testCase.kind, withoutTransportContext(testCase.msg("request-retry")))
			if err != nil {
				t.Fatalf("digest retry: %v", err)
			}
			if original != retry {
				t.Fatalf("commitment digest changed across a transport-only retry: original=%q retry=%q", original, retry)
			}
			differentBusiness := &atostosv1.RevokeExecutionSignerRequest{
				Context: baseContext("request-original"), AuthorizationId: "auth-DIFFERENT", ReasonCode: "rotation",
			}
			if testCase.name == "RevokeExecutionSigner" {
				changedDigest, err := protoDigest(testCase.kind, withoutTransportContext(differentBusiness))
				if err != nil {
					t.Fatalf("digest changed business content: %v", err)
				}
				if changedDigest == original {
					t.Fatal("commitment digest did not change when business content changed")
				}
			}
		})
	}
}

// scriptedAuthority wraps a real Authority but fails the first failFirstN
// Commit calls whose kind matches failKind, simulating a caller that never
// received the response to an attempt the underlying network may or may not
// have actually committed. Every Commit call is recorded so tests can assert
// what digest each attempt actually used. Unrelated setup calls (a different
// kind) always pass through so a test can build fixtures before the scripted
// failure is armed.
type scriptedAuthority struct {
	Authority
	mu         sync.Mutex
	calls      []scriptedCommitCall
	failKind   string
	failFirstN int
	failed     int
}

type scriptedCommitCall struct{ Kind, ID, Digest string }

func (a *scriptedAuthority) Commit(ctx context.Context, kind, id, digest string) (NetworkReference, error) {
	a.mu.Lock()
	a.calls = append(a.calls, scriptedCommitCall{Kind: kind, ID: id, Digest: digest})
	shouldFail := kind == a.failKind && a.failed < a.failFirstN
	if shouldFail {
		a.failed++
	}
	a.mu.Unlock()
	if shouldFail {
		return NetworkReference{}, errors.New("simulated: caller never received this attempt's response")
	}
	return a.Authority.Commit(ctx, kind, id, digest)
}

// TestCreateEscrowRetryAfterUncertainAuthorityFailureConverges is the
// end-to-end counterpart to TestCommitmentDigestIgnoresTransportContext: it
// drives CreateEscrow through the real RPC handler, not just the digest
// function, proving a caller that retries with a fresh request_id/trace_id
// after an uncertain first attempt converges on exactly one escrow committed
// through exactly one distinct commitment digest -- the failed attempt and
// the retry must have used the identical digest.
func TestCreateEscrowRetryAfterUncertainAuthorityFailureConverges(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	authority := &scriptedAuthority{Authority: NewLocalAuthority("tos-local"), failKind: "escrow", failFirstN: 1}
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: authority,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer server.Close()
	ctx := context.Background()

	if _, err := server.CommitCapabilityManifest(ctx, connect.NewRequest(
		capabilityCommitRequest(now, "capability-escrow-retry", "provider-escrow-retry"),
	)); err != nil {
		t.Fatalf("CommitCapabilityManifest: %v", err)
	}
	if _, err := server.CommitQuote(ctx, connect.NewRequest(&atostosv1.CommitQuoteRequest{
		Context: mutationContext("commit-quote-escrow-retry"),
		Quote: &atostosv1.QuoteCommitmentInput{
			QuoteId: "quote-escrow-retry", PrincipalId: "principal-escrow-retry",
			ProviderId: "provider-escrow-retry", CapabilityId: "capability-escrow-retry",
			CapabilityVersion: "1.0.0",
			TrustMode:         atostosv1.TrustMode_TRUST_MODE_MANAGED,
			ProofProfile:      atostosv1.ProofProfile_PROOF_PROFILE_NONE,
			TotalMax:          &atostosv1.Money{Amount: "1.00", Currency: "USD"},
			TermsDigest:       &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)},
			ExpiresUnixMillis: now.Add(time.Hour).UnixMilli(),
		},
	})); err != nil {
		t.Fatalf("CommitQuote: %v", err)
	}

	escrowRequest := func(requestID string) *atostosv1.CreateEscrowRequest {
		return &atostosv1.CreateEscrowRequest{
			Context: &atostosv1.RequestContext{
				RequestId: requestID, TraceId: "trace-" + requestID,
				CallerId: "caller-escrow-retry", IdempotencyKey: "idem-escrow-retry",
				DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			QuoteId: "quote-escrow-retry", PrincipalId: "principal-escrow-retry",
			ProviderId: "provider-escrow-retry", CapabilityId: "capability-escrow-retry",
			TrustMode: atostosv1.TrustMode_TRUST_MODE_MANAGED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_NONE,
			Reserve:           &atostosv1.NetworkAmount{Asset: "USD", AtomicAmount: "100"},
			ExpiresUnixMillis: now.Add(time.Hour).UnixMilli(),
		}
	}

	if _, err := server.CreateEscrow(ctx, connect.NewRequest(escrowRequest("request-attempt-1"))); err == nil {
		t.Fatal("expected the scripted first attempt to fail")
	}
	response, err := server.CreateEscrow(ctx, connect.NewRequest(escrowRequest("request-attempt-2")))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !response.Msg.Created || response.Msg.Escrow == nil {
		t.Fatalf("retry did not create the escrow: %#v", response.Msg)
	}

	authority.mu.Lock()
	defer authority.mu.Unlock()
	escrowCalls := make([]scriptedCommitCall, 0, 2)
	for _, call := range authority.calls {
		if call.Kind == "escrow" {
			escrowCalls = append(escrowCalls, call)
		}
	}
	if len(escrowCalls) != 2 {
		t.Fatalf("expected exactly 2 escrow Commit attempts (failed + retry), got %d: %#v", len(escrowCalls), escrowCalls)
	}
	if escrowCalls[0].Digest != escrowCalls[1].Digest || escrowCalls[0].ID != escrowCalls[1].ID {
		t.Fatalf("retry used a different commitment identity than the failed attempt: first=%+v second=%+v",
			escrowCalls[0], escrowCalls[1])
	}

	getResponse, err := server.GetEscrow(ctx, connect.NewRequest(&atostosv1.GetEscrowRequest{
		Context: readContext("get-escrow-retry"), EscrowId: response.Msg.Escrow.EscrowId,
	}))
	if err != nil {
		t.Fatalf("GetEscrow: %v", err)
	}
	if !getResponse.Msg.Found {
		t.Fatal("no escrow was durably recorded after the retry converged")
	}
}
