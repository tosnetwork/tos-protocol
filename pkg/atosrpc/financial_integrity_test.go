package atosrpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"google.golang.org/protobuf/proto"
)

type countingFinancialAuthority struct {
	Authority
	commits int
	fail    bool
}

func (a *countingFinancialAuthority) Commit(ctx context.Context, kind, id, digest string) (NetworkReference, error) {
	a.commits++
	if a.fail {
		return NetworkReference{}, errors.New("injected publish failure")
	}
	return NetworkReference{
		Network: a.Network(), Reference: "tos:localnet:" + id,
		Finalized: true, FinalizedCheckpoint: 77,
	}, nil
}

func testDigest(fill byte) *atostosv1.Digest {
	return &atostosv1.Digest{Algorithm: "sha256", Value: bytesOf(fill, sha256.Size)}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func testManagedFinancialAnchor(t *testing.T, network string) *atostosv1.ManagedFinancialAnchorInput {
	t.Helper()
	value := &atostosv1.ManagedFinancialAnchorInput{
		Version: managedFinancialAnchorVersion, BatchId: "fbat_01",
		BatchSequence: 1, FirstSequence: 1, LastSequence: 2, CommitmentCount: 2,
		PreviousMerkleRoot: testDigest(0), MerkleRoot: testDigest(1),
		ManifestDigest: testDigest(2), SignatureDigest: testDigest(3),
		SigningKeyId: "kms-key-01", Canonicalization: managedFinancialCanonical,
		GatewayId: "gateway.example", NetworkId: network,
	}
	id, err := managedFinancialAnchorID(value)
	if err != nil {
		t.Fatal(err)
	}
	value.AnchorId = id
	return value
}

func testFinancialContext(anchor *atostosv1.ManagedFinancialAnchorInput, request string) *atostosv1.RequestContext {
	return &atostosv1.RequestContext{
		RequestId: request, TraceId: "trace-" + request,
		IdempotencyKey: anchor.AnchorId, CallerId: anchor.GatewayId,
		DeadlineUnixMillis: time.Now().Add(time.Minute).UnixMilli(),
	}
}

func TestManagedFinancialAnchorPublishResolveAndLostResponseRetry(t *testing.T) {
	authority := &countingFinancialAuthority{Authority: NewLocalAuthority("tos-dev-financial")}
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	anchor := testManagedFinancialAnchor(t, authority.Network())
	request := &atostosv1.PublishManagedFinancialAnchorRequest{
		Context: testFinancialContext(anchor, "first"), Anchor: anchor,
	}
	first, err := server.PublishManagedFinancialAnchor(context.Background(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Msg.Finalized || first.Msg.FinalizedCheckpoint != 77 ||
		first.Msg.AnchorRef == nil || !first.Msg.AnchorRef.Finalized {
		t.Fatalf("anchor was not returned with finalized evidence: %#v", first.Msg)
	}

	// Treat the first successful response as lost. A transport retry changes
	// request/trace/deadline but not semantic content and must not republish.
	retry := proto.Clone(request).(*atostosv1.PublishManagedFinancialAnchorRequest)
	retry.Context = testFinancialContext(anchor, "retry")
	second, err := server.PublishManagedFinancialAnchor(context.Background(), connect.NewRequest(retry))
	if err != nil {
		t.Fatal(err)
	}
	if authority.commits != 1 || !proto.Equal(first.Msg, second.Msg) {
		t.Fatalf("lost-response retry diverged: commits=%d equal=%v", authority.commits, proto.Equal(first.Msg, second.Msg))
	}

	resolved, err := server.ResolveManagedFinancialAnchor(context.Background(), connect.NewRequest(
		&atostosv1.ResolveManagedFinancialAnchorRequest{
			Context:  &atostosv1.RequestContext{CallerId: anchor.GatewayId, RequestId: "resolve", DeadlineUnixMillis: time.Now().Add(time.Minute).UnixMilli()},
			AnchorId: anchor.AnchorId, NetworkId: anchor.NetworkId,
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Msg.Found || !resolved.Msg.Finalized ||
		!proto.Equal(resolved.Msg.Anchor, anchor) ||
		resolved.Msg.AnchorRef.Reference != first.Msg.AnchorRef.Reference {
		t.Fatalf("resolved anchor differs: %#v", resolved.Msg)
	}
}

func TestManagedFinancialAnchorRejectsSubstitutionAndFailure(t *testing.T) {
	authority := &countingFinancialAuthority{Authority: NewLocalAuthority("tos-dev-financial")}
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	anchor := testManagedFinancialAnchor(t, authority.Network())

	t.Run("changed root under stable anchor id", func(t *testing.T) {
		changed := proto.Clone(anchor).(*atostosv1.ManagedFinancialAnchorInput)
		changed.MerkleRoot = testDigest(9)
		_, err := server.PublishManagedFinancialAnchor(context.Background(), connect.NewRequest(
			&atostosv1.PublishManagedFinancialAnchorRequest{Context: testFinancialContext(changed, "changed"), Anchor: changed},
		))
		if err == nil {
			t.Fatal("changed root was accepted under the original anchor ID")
		}
	})

	t.Run("wrong network", func(t *testing.T) {
		wrong := proto.Clone(anchor).(*atostosv1.ManagedFinancialAnchorInput)
		wrong.NetworkId = "tos-dev-other"
		id, _ := managedFinancialAnchorID(wrong)
		wrong.AnchorId = id
		_, err := server.PublishManagedFinancialAnchor(context.Background(), connect.NewRequest(
			&atostosv1.PublishManagedFinancialAnchorRequest{Context: testFinancialContext(wrong, "network"), Anchor: wrong},
		))
		if err == nil {
			t.Fatal("wrong network was accepted")
		}
	})

	t.Run("publication failure is not finalized", func(t *testing.T) {
		failedAuthority := &countingFinancialAuthority{Authority: NewLocalAuthority("tos-dev-fail"), fail: true}
		failedServer, openErr := Open(Config{
			StatePath:   filepath.Join(t.TempDir(), "failed.db"),
			BearerToken: "test-secret", Authority: failedAuthority,
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer failedServer.Close()
		failed := testManagedFinancialAnchor(t, failedAuthority.Network())
		_, publishErr := failedServer.PublishManagedFinancialAnchor(context.Background(), connect.NewRequest(
			&atostosv1.PublishManagedFinancialAnchorRequest{Context: testFinancialContext(failed, "failure"), Anchor: failed},
		))
		if publishErr == nil {
			t.Fatal("authority failure was reported as finalized")
		}
		resolved, resolveErr := failedServer.ResolveManagedFinancialAnchor(context.Background(), connect.NewRequest(
			&atostosv1.ResolveManagedFinancialAnchorRequest{
				Context:  &atostosv1.RequestContext{CallerId: failed.GatewayId, RequestId: "resolve-failed", DeadlineUnixMillis: time.Now().Add(time.Minute).UnixMilli()},
				AnchorId: failed.AnchorId, NetworkId: failed.NetworkId,
			},
		))
		if resolveErr != nil || resolved.Msg.Found {
			t.Fatalf("failed publication became durable: response=%#v err=%v", resolved.Msg, resolveErr)
		}
	})
}
