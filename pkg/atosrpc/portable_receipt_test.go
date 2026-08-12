package atosrpc

import (
	"connectrpc.com/connect"
	"context"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/poscommitment"
	"github.com/tosnetwork/tos-protocol/pkg/receiptcommitment"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveExecutionReceiptIsReadOnlyAndRequiresLiveFinality(t *testing.T) {
	a := &verifiedTestAuthority{}
	s, e := Open(Config{StatePath: filepath.Join(t.TempDir(), "state.db"), BearerToken: "x", Authority: a, Now: func() time.Time { return time.Now().UTC() }})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r := &atostosv1.ExecutionReceiptEnvelope{ReceiptId: "r", QuoteId: "q", EscrowId: "e", JobId: "j", PrincipalId: "p", ProviderId: "v", CapabilityId: "c", CapabilityVersion: "1", TrustMode: atostosv1.TrustMode_TRUST_MODE_VERIFIED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1, Result: atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS, SignatureAlgorithm: "ed25519"}
	d, e := receiptcommitment.Digest(r)
	if e != nil {
		t.Fatal(e)
	}
	ref, e := a.Commit(context.Background(), "verified-receipt", r.ReceiptId, d)
	if e != nil {
		t.Fatal(e)
	}
	before := a.commits
	resp, e := s.ResolveExecutionReceipt(context.Background(), connect.NewRequest(&atostosv1.ResolveExecutionReceiptRequest{Context: &atostosv1.RequestContext{RequestId: "resolve_1", CallerId: "principal"}, Receipt: r, ExpectedReceiptRef: &ref}))
	if e != nil {
		t.Fatal(e)
	}
	if !resp.Msg.Found || resp.Msg.ReceiptRef.FinalizedCheckpoint == 0 {
		t.Fatalf("response=%+v", resp.Msg)
	}
	if a.commits != before {
		t.Fatalf("read-only resolver mutated authority: %d -> %d", before, a.commits)
	}
	a.resolveErr = context.DeadlineExceeded
	if _, e := s.ResolveExecutionReceipt(context.Background(), connect.NewRequest(&atostosv1.ResolveExecutionReceiptRequest{Context: &atostosv1.RequestContext{RequestId: "resolve_2", CallerId: "principal"}, Receipt: r})); e == nil {
		t.Fatal("authority outage accepted")
	}
}

func TestResolveProofOfServiceIsReadOnlyWithoutLocalProjection(t *testing.T) {
	a := &verifiedTestAuthority{}
	s, e := Open(Config{StatePath: filepath.Join(t.TempDir(), "state.db"), BearerToken: "x", Authority: a})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v := &atostosv1.ProofOfServiceEvidenceInput{EvidenceId: "pos-r", ReceiptId: "r", ProviderId: "provider", CapabilityId: "cap", CapabilityVersion: "1", EvidenceDigest: &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)}}
	d, e := poscommitment.Digest(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Commit(context.Background(), "proof-of-service", v.EvidenceId, d); e != nil {
		t.Fatal(e)
	}
	before := a.commits
	resp, e := s.ResolveProofOfServiceEvidence(context.Background(), connect.NewRequest(&atostosv1.ResolveProofOfServiceEvidenceRequest{Context: &atostosv1.RequestContext{RequestId: "resolve-pos", CallerId: "principal"}, Evidence: v}))
	if e != nil {
		t.Fatal(e)
	}
	if !resp.Msg.Found || resp.Msg.EvidenceRef.FinalizedCheckpoint == 0 {
		t.Fatalf("response=%+v", resp.Msg)
	}
	if a.commits != before {
		t.Fatal("resolver mutated authority")
	}
}
