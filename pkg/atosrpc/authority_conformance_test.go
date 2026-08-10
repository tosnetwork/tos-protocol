package atosrpc

import (
	"context"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

// TestAuthorityCommitIsIdempotentByKindIDDigest proves every Authority
// implementation honors the contract documented on Authority.Commit: calling
// Commit twice with the same (kind, id, digest) -- as a caller does when it
// retries a mutation after never receiving the first attempt's response --
// must return an identical NetworkReference rather than producing a second,
// divergent commitment. Every atosrpc call site that retries a request after
// a local failure depends on this holding for every Authority, present and
// future.
func TestAuthorityCommitIsIdempotentByKindIDDigest(t *testing.T) {
	const (
		kind   = "capability-manifest"
		id     = "cap-idempotence-test@1.0.0"
		digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	)
	authorities := map[string]func(t *testing.T) Authority{
		"local": func(t *testing.T) Authority {
			return NewLocalAuthority("tos-local")
		},
		"chain": func(t *testing.T) Authority {
			now := time.Unix(1_800_000_001, 0).UTC()
			runtime := &testChainAuthorityRuntime{readiness: toschain.ReadinessSnapshot{
				Network: "tos-test", ObservedMasterSeqno: 700,
				ObservedAt: now.Add(-time.Second), QuorumEndpoints: 2,
			}}
			authority, err := newTestChainAuthority(runtime, new(testChainActionPublisher), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = authority.Close() })
			return authority
		},
	}
	for name, construct := range authorities {
		t.Run(name, func(t *testing.T) {
			authority := construct(t)
			first, err := authority.Commit(context.Background(), kind, id, digest)
			if err != nil {
				t.Fatalf("first Commit: %v", err)
			}
			second, err := authority.Commit(context.Background(), kind, id, digest)
			if err != nil {
				t.Fatalf("second Commit (simulated retry): %v", err)
			}
			if first.Network != second.Network || first.Reference != second.Reference {
				t.Fatalf("Commit is not idempotent for a repeated (kind,id,digest): first=%q/%q second=%q/%q",
					first.Network, first.Reference, second.Network, second.Reference)
			}
		})
	}
}

// TestChainAuthorityActionIDExcludesFreshnessWindow proves the chain
// Authority's ActionID -- the identity a compliant ActionPublisher uses to
// recognize a retried publish -- does not change when only the freshness
// window (anchorLifetime, driven by the wall clock at call time) changes
// between two calls carrying the same (kind, id, digest). If it did, every
// retry that happened to land in a different anchorLifetime window would be
// misidentified as a brand new commitment.
func TestChainAuthorityActionIDExcludesFreshnessWindow(t *testing.T) {
	runtime := &testChainAuthorityRuntime{readiness: toschain.ReadinessSnapshot{
		Network: "tos-test", ObservedMasterSeqno: 700, QuorumEndpoints: 2,
	}}
	publisher := new(testChainActionPublisher)
	callTime := time.Unix(1_800_000_001, 0).UTC()
	authority, err := newTestChainAuthority(runtime, publisher, func() time.Time {
		callTime = callTime.Add(time.Minute)
		return callTime
	})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	const (
		kind   = "capability-manifest"
		id     = "cap-freshness-test@1.0.0"
		digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	if _, err := authority.Commit(context.Background(), kind, id, digest); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if _, err := authority.Commit(context.Background(), kind, id, digest); err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	if len(publisher.actions) != 2 {
		t.Fatalf("expected the fake publisher to observe 2 publish attempts, got %d", len(publisher.actions))
	}
	if publisher.actions[0].ActionID != publisher.actions[1].ActionID {
		t.Fatalf("ActionID changed across calls with identical (kind,id,digest) but different call times: %q vs %q",
			publisher.actions[0].ActionID, publisher.actions[1].ActionID)
	}
	if publisher.actions[0].ExpiresUnixMillis == publisher.actions[1].ExpiresUnixMillis {
		t.Fatal("test setup did not actually vary the freshness window between calls")
	}
}
