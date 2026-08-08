package atosrpc

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func TestCompleteDurableJobBindsCommercialChargesBeforeSigning(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret",
		Authority:   NewLocalAuthority("tos-local"),
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer server.Close()

	const (
		quoteID      = "q-charge-binding"
		escrowID     = "esc-charge-binding"
		jobID        = "job-charge-binding"
		principalID  = "prn-charge-binding"
		providerID   = "agt-charge-binding"
		capabilityID = "cap-charge-binding"
	)
	quote := &atostosv1.QuoteCommitment{Value: &atostosv1.QuoteCommitmentInput{
		QuoteId: quoteID, PrincipalId: principalID, ProviderId: providerID,
		CapabilityId: capabilityID, CapabilityVersion: "1.0.0",
		TrustMode:    atostosv1.TrustMode_TRUST_MODE_MANAGED,
		ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_NONE,
		TotalMax:     &atostosv1.Money{Amount: "1.05", Currency: "USD"},
	}}
	escrow := &atostosv1.Escrow{
		EscrowId: escrowID, QuoteId: quoteID, PrincipalId: principalID,
		ProviderId: providerID, CapabilityId: capabilityID,
		TrustMode:    atostosv1.TrustMode_TRUST_MODE_MANAGED,
		ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_NONE,
		Reserved:     &atostosv1.NetworkAmount{Asset: "USD", AtomicAmount: "105"},
		State:        atostosv1.EscrowState_ESCROW_STATE_RESERVED,
	}
	if err := server.store.update(func(tx *bolt.Tx) error {
		if err := server.store.putProto(tx, bucketQuoteCommitments, quoteID, quote); err != nil {
			return err
		}
		return server.store.putProto(tx, bucketEscrows, escrowID, escrow)
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	record := &atostosv1.JobRecord{
		JobId: jobID, QuoteId: quoteID, EscrowId: escrowID,
		ProviderId: providerID, CapabilityId: capabilityID,
		CapabilityVersion: "1.0.0",
		TrustMode:         atostosv1.TrustMode_TRUST_MODE_MANAGED,
		ProofProfile:      atostosv1.ProofProfile_PROOF_PROFILE_NONE,
		State:             atostosv1.JobState_JOB_STATE_WORKING,
		ProofStatus:       initialExecutionProofStatus(atostosv1.TrustMode_TRUST_MODE_MANAGED),
	}
	stored := &storedExecutionJob{Input: []byte(`{"x":1}`)}
	completion := localrpc.InvocationCompletion{
		Output: []byte(`{"ok":true}`),
		Usage: localrpc.InvocationUsage{
			InputBytes: 7, OutputBytes: 11, ExecutionMillis: 25,
		},
		RequestDigest:   "sha256:test-worker-request",
		ModelRevision:   "test-model-v1",
		RuntimeRevision: "test-runtime-v1",
		CompletedAt:     now,
	}
	if _, err := server.completeDurableJob(jobID, stored, record, completion); err != nil {
		t.Fatalf("completeDurableJob: %v", err)
	}
	if len(stored.CanonicalReceipt) == 0 {
		t.Fatal("canonical receipt was not persisted")
	}
	receipt := new(atostosv1.ExecutionReceiptEnvelope)
	if err := proto.Unmarshal(stored.CanonicalReceipt, receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.PrincipalId != principalID {
		t.Fatalf("principal_id = %q, want %q", receipt.PrincipalId, principalID)
	}
	if receipt.ClientCharge == nil || receipt.ClientCharge.Amount != "1.05" || receipt.ClientCharge.Currency != "USD" {
		t.Fatalf("client charge not bound from Quote: %+v", receipt.ClientCharge)
	}
	if receipt.NetworkCharge == nil || receipt.NetworkCharge.Asset != "USD" || receipt.NetworkCharge.AtomicAmount != "105" {
		t.Fatalf("network charge not bound from Escrow: %+v", receipt.NetworkCharge)
	}
	originalBytes, err := receiptSigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(server.publicKey, originalBytes, receipt.Signature) {
		t.Fatal("server-issued receipt signature does not verify")
	}

	tampered := cloneMessage(receipt)
	tampered.ClientCharge.Amount = "0.01"
	tamperedBytes, err := receiptSigningBytes(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(server.publicKey, tamperedBytes, receipt.Signature) {
		t.Fatal("changing the client charge did not invalidate the receipt signature")
	}
}
