package atosrpc

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	bolt "go.etcd.io/bbolt"
)

type verifiedTestAuthority struct{ closed bool }

func (*verifiedTestAuthority) Network() string { return "tos-test" }
func (*verifiedTestAuthority) Supports(mode TrustMode) bool {
	return mode == TrustModeManaged || mode == TrustModeVerified
}
func (*verifiedTestAuthority) CheckReady(context.Context) error { return nil }
func (*verifiedTestAuthority) Commit(
	_ context.Context, kind, id, digest string,
) (NetworkReference, error) {
	return NetworkReference{Network: "tos-test", Reference: "tos:test:" + kind + ":" + id + ":" + digest, Finalized: true, FinalizedCheckpoint: 42}, nil
}
func (a *verifiedTestAuthority) Close() error { a.closed = true; return nil }

type verifiedTestEconomy struct{ closed bool }

func (*verifiedTestEconomy) Network() string { return "tos-test" }
func (*verifiedTestEconomy) Supports(mode economic.TrustMode) bool {
	return mode == economic.TrustModeVerified
}
func (*verifiedTestEconomy) CheckReady(context.Context) error { return nil }
func (*verifiedTestEconomy) ReserveEscrow(context.Context, economic.ReserveEscrowRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) AcceptEscrow(context.Context, economic.AcceptEscrowRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) CommitResult(context.Context, economic.CommitResultRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) ReleaseEscrow(context.Context, economic.ReleaseEscrowRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) SettleProvider(context.Context, economic.SettleProviderRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) RefundPrincipal(context.Context, economic.RefundPrincipalRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) OpenDispute(context.Context, economic.OpenDisputeRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) ResolveDispute(context.Context, economic.ResolveDisputeRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) ReadEconomicState(context.Context, string) (chain.TaskEscrowState, error) {
	return chain.TaskEscrowState{}, errors.New("not used")
}
func (e *verifiedTestEconomy) Close() error { e.closed = true; return nil }

func TestEconomicDriverRequiresVerifiedAuthority(t *testing.T) {
	_, err := (Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: NewLocalAuthority("tos-local"),
		EconomicDriver: new(verifiedTestEconomy),
	}).withDefaults()
	if err == nil {
		t.Fatal("economic driver was accepted with a Managed-only Authority")
	}
}

func TestCapabilityActivatesVerifiedOnlyForAnchoredProvider(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: new(verifiedTestAuthority),
		EconomicDriver: new(verifiedTestEconomy), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	selfAsserted, err := server.CommitCapabilityManifest(context.Background(), connect.NewRequest(
		capabilityCommitRequest(now, "cap-self", "provider-self"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if !containsMode(selfAsserted.Msg.Capability.ActiveTrustModes, TrustModeManaged) ||
		containsMode(selfAsserted.Msg.Capability.ActiveTrustModes, TrustModeVerified) {
		t.Fatalf("self-asserted provider activated Verified: %v", selfAsserted.Msg.Capability.ActiveTrustModes)
	}

	const providerID = "provider-verified"
	providerController := "0:" + strings.Repeat("22", 32)
	if err := server.SeedIdentity(&atostosv1.AgentIdentity{
		AgentId: providerID, CanonicalUri: "tos://agent/" + providerID,
		Controllers: []string{providerController}, Assurance: "tos_chain_verified",
		IdentityRef: &NetworkReference{Network: "tos-test", Reference: "tos:tx:v1:provider"},
	}); err != nil {
		t.Fatal(err)
	}
	verified, err := server.CommitCapabilityManifest(context.Background(), connect.NewRequest(
		capabilityCommitRequest(now, "cap-verified", providerID),
	))
	if err != nil {
		t.Fatal(err)
	}
	if !containsMode(verified.Msg.Capability.ActiveTrustModes, TrustModeVerified) {
		t.Fatalf("anchored provider did not activate Verified: %v", verified.Msg.Capability.ActiveTrustModes)
	}
}

func TestEconomicPartiesRejectSelfAssertedIdentity(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	server, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: new(verifiedTestAuthority),
		EconomicDriver: new(verifiedTestEconomy), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	principalIdentity := &atostosv1.AgentIdentity{
		AgentId: "agent-principal", CanonicalUri: "tos://agent/agent-principal",
		Controllers: []string{"0:" + strings.Repeat("11", 32)}, Assurance: "tos_chain_verified",
		IdentityRef: &NetworkReference{Network: "tos-test", Reference: "tos:tx:v1:principal"},
	}
	if err := server.SeedIdentity(principalIdentity); err != nil {
		t.Fatal(err)
	}
	if err := server.bindPrincipal("principal-test", principalIdentity.AgentId); err != nil {
		t.Fatal(err)
	}
	if _, err := server.CommitCapabilityManifest(context.Background(), connect.NewRequest(
		capabilityCommitRequest(now, "cap-self", "provider-self"),
	)); err != nil {
		t.Fatal(err)
	}
	err = server.store.view(func(tx *bolt.Tx) error {
		_, _, partyErr := server.economicPartiesTx(tx, "principal-test", "provider-self")
		return partyErr
	})
	if err == nil {
		t.Fatal("self-asserted provider identity was accepted for Verified economics")
	}
}

func capabilityCommitRequest(now time.Time, capabilityID, providerID string) *atostosv1.CommitCapabilityManifestRequest {
	return &atostosv1.CommitCapabilityManifestRequest{
		Context: &atostosv1.RequestContext{
			RequestId: "request-" + capabilityID, CallerId: "caller-test",
			IdempotencyKey:     "idem-" + capabilityID,
			DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
		},
		CapabilityId: capabilityID, ProviderId: providerID, Version: "1.0.0",
		ManifestDigest:      digestMessage([]byte(capabilityID)),
		RequestedTrustModes: []atostosv1.TrustMode{TrustModeManaged, TrustModeVerified},
	}
}

type recordingEconomy struct {
	reserveRequest economic.ReserveEscrowRequest
	settleRequest  economic.SettleProviderRequest
	contract       string
	settlementRef  string
}

func (e *recordingEconomy) Network() string { return "tos-test" }
func (e *recordingEconomy) Supports(mode economic.TrustMode) bool {
	return mode == economic.TrustModeVerified
}
func (e *recordingEconomy) CheckReady(context.Context) error { return nil }
func (e *recordingEconomy) ReserveEscrow(_ context.Context, request economic.ReserveEscrowRequest) (economic.Result, error) {
	e.reserveRequest = request
	return economic.Result{
		ContractReference:   e.contract,
		TransitionReference: "tos:tx:v1:0:" + strings.Repeat("44", 32) + ":1:" + strings.Repeat("55", 32),
		State: chain.TaskEscrowState{
			Network: "tos-test", ContractAddress: strings.TrimPrefix(e.contract, "tos:task-escrow:v1:"),
			Creator: request.Creator, Agent: request.Agent, HasAgent: true,
			Verifier: "0:" + strings.Repeat("33", 32), HasVerifier: true,
			BudgetNanoTOS: request.BudgetNanoTOS, Status: chain.TaskEscrowStatusOpen,
		},
	}, nil
}
func (*recordingEconomy) AcceptEscrow(context.Context, economic.AcceptEscrowRequest) (economic.Result, error) {
	return economic.Result{}, nil
}
func (*recordingEconomy) CommitResult(context.Context, economic.CommitResultRequest) (economic.Result, error) {
	return economic.Result{}, nil
}
func (*recordingEconomy) ReleaseEscrow(context.Context, economic.ReleaseEscrowRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (e *recordingEconomy) SettleProvider(_ context.Context, request economic.SettleProviderRequest) (economic.Result, error) {
	e.settleRequest = request
	return economic.Result{
		ContractReference: e.contract, TransitionReference: e.settlementRef,
		AgentPaidNanoTOS:   request.PayoutNanoTOS,
		CreatorPaidNanoTOS: request.BudgetNanoTOS - request.PayoutNanoTOS,
		State: chain.TaskEscrowState{
			Network: "tos-test", ContractAddress: strings.TrimPrefix(e.contract, "tos:task-escrow:v1:"),
			Status: chain.TaskEscrowStatusSettled,
		},
	}, nil
}
func (*recordingEconomy) RefundPrincipal(context.Context, economic.RefundPrincipalRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*recordingEconomy) OpenDispute(context.Context, economic.OpenDisputeRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*recordingEconomy) ResolveDispute(context.Context, economic.ResolveDisputeRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*recordingEconomy) ReadEconomicState(context.Context, string) (chain.TaskEscrowState, error) {
	return chain.TaskEscrowState{}, errors.New("not used")
}
func (*recordingEconomy) Close() error { return nil }

func TestVerifiedEscrowAndSettlementUseContractEconomicDriver(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	contractAddress := "0:" + strings.Repeat("44", 32)
	economy := &recordingEconomy{
		contract:      "tos:task-escrow:v1:" + contractAddress,
		settlementRef: "tos:tx:v1:0:" + strings.Repeat("44", 32) + ":2:" + strings.Repeat("66", 32),
	}
	server, err := Open(Config{
		StatePath: filepath.Join(t.TempDir(), "atos-rpc.db"), BearerToken: "test-secret",
		Authority: new(verifiedTestAuthority), EconomicDriver: economy,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	const (
		principalID      = "principal-verified"
		principalAgentID = "agent-principal-verified"
		providerID       = "provider-verified-settlement"
		capabilityID     = "cap-verified-settlement"
		quoteID          = "quote-verified-settlement"
		jobID            = "job-verified-settlement"
		receiptID        = "receipt-verified-settlement"
	)
	creator := "0:" + strings.Repeat("11", 32)
	agent := "0:" + strings.Repeat("22", 32)
	for _, identity := range []*atostosv1.AgentIdentity{
		{
			AgentId: principalAgentID, CanonicalUri: "tos://agent/" + principalAgentID,
			Controllers: []string{creator}, Assurance: "tos_chain_verified",
			IdentityRef: &NetworkReference{Network: "tos-test", Reference: "tos:tx:v1:principal"},
		},
		{
			AgentId: providerID, CanonicalUri: "tos://agent/" + providerID,
			Controllers: []string{agent}, Assurance: "tos_chain_verified",
			IdentityRef: &NetworkReference{Network: "tos-test", Reference: "tos:tx:v1:provider"},
		},
	} {
		if err := server.SeedIdentity(identity); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.bindPrincipal(principalID, principalAgentID); err != nil {
		t.Fatal(err)
	}
	quote := &atostosv1.QuoteCommitment{Value: &atostosv1.QuoteCommitmentInput{
		QuoteId: quoteID, PrincipalId: principalID, ProviderId: providerID,
		CapabilityId: capabilityID, CapabilityVersion: "1.0.0",
		TrustMode: TrustModeVerified, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1,
		TotalMax: &atostosv1.Money{Amount: "1.00", Currency: "USD"},
	}}
	if err := server.store.update(func(tx *bolt.Tx) error {
		return server.store.putProto(tx, bucketQuoteCommitments, quoteID, quote)
	}); err != nil {
		t.Fatal(err)
	}

	create, err := server.CreateEscrow(context.Background(), connect.NewRequest(
		&atostosv1.CreateEscrowRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "request-create-verified", CallerId: "caller-test",
				IdempotencyKey: "idem-create-verified", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			QuoteId: quoteID, PrincipalId: principalID, ProviderId: providerID,
			CapabilityId: capabilityID, TrustMode: TrustModeVerified,
			ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1,
			Reserve:      &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"},
			FundingModel: "task_escrow_v1", ExpiresUnixMillis: now.Add(time.Hour).UnixMilli(),
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !create.Msg.Created || create.Msg.Escrow == nil || create.Msg.Escrow.EscrowRef == nil ||
		create.Msg.Escrow.EscrowRef.Reference != economy.contract {
		t.Fatalf("unexpected Verified escrow response: %#v", create.Msg)
	}
	if economy.reserveRequest.Creator != creator || economy.reserveRequest.Agent != agent ||
		economy.reserveRequest.BudgetNanoTOS != 1000 || economy.reserveRequest.PolicyHash == "" ||
		economy.reserveRequest.PermissionHash == "" {
		t.Fatalf("Verified reservation binding was lost: %#v", economy.reserveRequest)
	}

	escrowID := create.Msg.Escrow.EscrowId
	receipt := &atostosv1.ExecutionReceiptEnvelope{
		ReceiptId: receiptID, QuoteId: quoteID, EscrowId: escrowID, JobId: jobID,
		PrincipalId: principalID, ProviderId: providerID, CapabilityId: capabilityID,
		CapabilityVersion: "1.0.0", TrustMode: TrustModeVerified,
		ProofProfile:     atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1,
		OutputCommitment: digestMessage([]byte("verified-output")),
	}
	if err := server.store.update(func(tx *bolt.Tx) error {
		return server.store.putProto(tx, bucketReceipts, receiptID, &atostosv1.CommittedExecutionReceipt{
			Receipt: receipt, VerificationStatus: atostosv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED,
		})
	}); err != nil {
		t.Fatal(err)
	}
	settled, err := server.SettleJob(context.Background(), connect.NewRequest(
		&atostosv1.SettleJobRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "request-settle-verified", CallerId: "caller-test",
				IdempotencyKey: "idem-settle-verified", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			EscrowId: escrowID, QuoteId: quoteID, JobId: jobID, ReceiptId: receiptID,
			RequestedCharge: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "700"},
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !settled.Msg.Created || settled.Msg.Settlement == nil ||
		settled.Msg.Settlement.SettlementRef == nil ||
		settled.Msg.Settlement.SettlementRef.Reference != economy.settlementRef {
		t.Fatalf("unexpected Verified settlement response: %#v", settled.Msg)
	}
	if economy.settleRequest.ContractAddress != contractAddress ||
		economy.settleRequest.BudgetNanoTOS != 1000 ||
		economy.settleRequest.PayoutNanoTOS != 700 ||
		economy.settleRequest.ResultHash == "" || economy.settleRequest.EvidenceHash == "" {
		t.Fatalf("Verified settlement binding was lost: %#v", economy.settleRequest)
	}
}
