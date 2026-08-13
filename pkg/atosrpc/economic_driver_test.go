package atosrpc

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

type verifiedTestAuthority struct {
	mu         sync.Mutex
	closed     bool
	resolveErr error
	refs       map[string]string
	commits    int
}

func (*verifiedTestAuthority) Network() string { return "tos-test" }
func (*verifiedTestAuthority) Supports(mode TrustMode) bool {
	return mode == TrustModeManaged || mode == TrustModeVerified
}
func (*verifiedTestAuthority) CheckReady(context.Context) error { return nil }
func (a *verifiedTestAuthority) Commit(_ context.Context, kind, id, digest string) (NetworkReference, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refs == nil {
		a.refs = make(map[string]string)
	}
	key := kind + "\x00" + id + "\x00" + digest
	reference := "tos:test:" + kind + ":" + id + ":" + digest
	a.refs[key] = reference
	a.commits++
	return NetworkReference{Network: "tos-test", Reference: reference, Finalized: true, FinalizedCheckpoint: 42}, nil
}
func (a *verifiedTestAuthority) Close() error { a.closed = true; return nil }
func (a *verifiedTestAuthority) ResolveCommitment(_ context.Context, kind, id, digest string, ref *NetworkReference) (*NetworkReference, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.resolveErr != nil {
		return nil, a.resolveErr
	}
	reference, ok := a.refs[kind+"\x00"+id+"\x00"+digest]
	if !ok {
		return nil, ErrCommitmentNotFound
	}
	if ref != nil && (ref.Network != "tos-test" || ref.Reference != reference) {
		return nil, ErrCommitmentNotFound
	}
	return &NetworkReference{Network: "tos-test", Reference: reference, Finalized: true, FinalizedCheckpoint: 42}, nil
}
func (a *verifiedTestAuthority) ResolveCommitmentObservation(ctx context.Context, kind, id, digest string, ref *NetworkReference) (*CommitmentObservation, error) {
	live, err := a.ResolveCommitment(ctx, kind, id, digest, ref)
	if err != nil {
		return nil, err
	}
	return &CommitmentObservation{Reference: live, ObservedUnixMillis: 1_700_000_000_000}, nil
}

type verifiedTestEconomy struct{ closed bool }

func (*verifiedTestEconomy) Network() string { return "tos-test" }
func (*verifiedTestEconomy) Supports(mode economic.TrustMode) bool {
	return mode == economic.TrustModeVerified
}
func (*verifiedTestEconomy) CheckReady(context.Context) error { return nil }
func (*verifiedTestEconomy) ReserveEscrow(context.Context, economic.ReserveEscrowRequest) (economic.Result, error) {
	return economic.Result{}, errors.New("not used")
}
func (*verifiedTestEconomy) ResolveEscrow(context.Context, economic.ReserveEscrowRequest) (economic.Result, bool, error) {
	return economic.Result{}, false, nil
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
	reserveRequest       economic.ReserveEscrowRequest
	settleRequest        economic.SettleProviderRequest
	contract             string
	settlementRef        string
	settlementCheckpoint uint64
	settleCalls          int
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
			ObservedMasterSeqno: 42, CodeHash: "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		},
	}, nil
}
func (e *recordingEconomy) ResolveEscrow(_ context.Context, request economic.ReserveEscrowRequest) (economic.Result, bool, error) {
	if request.EscrowID == "" || request.EscrowID != e.reserveRequest.EscrowID {
		return economic.Result{}, false, nil
	}
	status := chain.TaskEscrowStatusOpen
	budget := request.BudgetNanoTOS
	checkpoint := uint64(42)
	transition := ""
	if e.settleCalls > 0 && e.settlementCheckpoint > 0 {
		status = chain.TaskEscrowStatusSettled
		budget = 0
		checkpoint = e.settlementCheckpoint
		transition = e.settlementRef
	}
	return economic.Result{
		ContractReference: e.contract, TransitionReference: transition,
		State: chain.TaskEscrowState{
			Network: "tos-test", ContractAddress: strings.TrimPrefix(e.contract, "tos:task-escrow:v1:"),
			Creator: request.Creator, Agent: request.Agent, HasAgent: true,
			Verifier: "0:" + strings.Repeat("33", 32), HasVerifier: true,
			BudgetNanoTOS: budget, Status: status,
			ObservedMasterSeqno: checkpoint, CodeHash: "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		},
	}, true, nil
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
	e.settleCalls++
	e.settleRequest = request
	return economic.Result{
		ContractReference: e.contract, TransitionReference: e.settlementRef,
		AgentPaidNanoTOS:   request.PayoutNanoTOS,
		CreatorPaidNanoTOS: request.BudgetNanoTOS - request.PayoutNanoTOS,
		State: chain.TaskEscrowState{
			Network: "tos-test", ContractAddress: strings.TrimPrefix(e.contract, "tos:task-escrow:v1:"),
			Status:              chain.TaskEscrowStatusSettled,
			ObservedMasterSeqno: e.settlementCheckpoint, CodeHash: "tvm-cell-sha256:" + strings.Repeat("aa", 32),
		},
	}, nil
}
func (e *recordingEconomy) ResolveSettlement(_ context.Context, request economic.SettleProviderRequest) (economic.Result, error) {
	return economic.Result{
		ContractReference: e.contract, TransitionReference: e.settlementRef,
		AgentPaidNanoTOS: request.PayoutNanoTOS, CreatorPaidNanoTOS: request.BudgetNanoTOS - request.PayoutNanoTOS,
		State: chain.TaskEscrowState{Network: "tos-test", ContractAddress: strings.TrimPrefix(e.contract, "tos:task-escrow:v1:"), Status: chain.TaskEscrowStatusSettled, ObservedMasterSeqno: e.settlementCheckpoint, CodeHash: "tvm-cell-sha256:" + strings.Repeat("aa", 32)},
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
		contract:             "tos:task-escrow:v1:" + contractAddress,
		settlementRef:        "tos:tx:v1:0:" + strings.Repeat("44", 32) + ":2:" + strings.Repeat("66", 32),
		settlementCheckpoint: 43,
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
	expires := now.Add(time.Hour).Truncate(time.Second).UnixMilli()
	quoteValue := &atostosv1.QuoteCommitmentInput{
		QuoteId: quoteID, PrincipalId: principalID, ProviderId: providerID,
		CapabilityId: capabilityID, CapabilityVersion: "1.0.0",
		TrustMode: TrustModeVerified, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1,
		Version: quotecommitment.Version, Canonicalization: quotecommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im",
		RequesterAgentId: principalAgentID, ManifestDigest: digestMessage([]byte("manifest")), OwnershipRef: &NetworkReference{Network: "tos-test", Reference: "ownership"},
		Subtotal: &atostosv1.Money{Amount: "0.000001000", Currency: "TOS"}, Fees: &atostosv1.Money{Amount: "0.000000000", Currency: "TOS"}, TotalMax: &atostosv1.Money{Amount: "0.000001000", Currency: "TOS"}, AssetDecimals: 9,
		TermsDigest: digestMessage([]byte("terms")), DisputePolicyDigest: digestMessage([]byte("dispute")), AcceptanceDeadlineUnixMillis: expires, ExpiresUnixMillis: expires, ExecutionDeadlineUnixMillis: expires,
		SettlementBackend: "tos", SettlementAsset: "TOS", UnderlyingServiceQuoteRef: "service-quote", SignerAuthorizationId: "auth-1", SignerAuthorizationRef: &NetworkReference{Network: "tos-test", Reference: "auth"},
	}
	quoteDigest, err := quotecommitment.Digest(quoteValue)
	if err != nil {
		t.Fatal(err)
	}
	quoteRef, err := server.authority.Commit(context.Background(), "quote", quoteID, quoteDigest)
	if err != nil {
		t.Fatal(err)
	}
	quote := &atostosv1.QuoteCommitment{Value: quoteValue, CommitmentRef: &quoteRef, CommitmentDigest: digestMessageFromString(quoteDigest)}
	if err := server.store.update(func(tx *bolt.Tx) error {
		return server.store.putProto(tx, bucketQuoteCommitments, quoteID, quote)
	}); err != nil {
		t.Fatal(err)
	}

	terms := &atostosv1.VerifiedEscrowTerms{Version: escrowcommitment.Version, Canonicalization: escrowcommitment.Canonicalization, NetworkId: "tos-test", Domain: "atos.im", JobId: jobID, QuoteId: quoteID, QuoteCommitmentDigest: quoteDigest, QuoteCommitmentRef: &quoteRef, PrincipalId: principalID, RequesterAgentId: principalAgentID, ProviderId: providerID, CapabilityId: capabilityID, CapabilityVersion: "1.0.0", ManifestDigest: quoteValue.ManifestDigest, OwnershipRef: quoteValue.OwnershipRef, TrustMode: TrustModeVerified, ProofProfile: quoteValue.ProofProfile, Reserve: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, Subtotal: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"}, Fees: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "0"}, AssetDecimals: 9, SettlementBackend: "tos", SettlementAsset: "TOS", FundingModel: "task_escrow_v1", AcceptanceDeadlineUnixMillis: expires, ExecutionDeadlineUnixMillis: expires, EscrowDeadlineUnixMillis: expires, UnderlyingServiceQuoteRef: "service-quote", DisputePolicyDigest: quoteValue.DisputePolicyDigest, SignerAuthorizationId: "auth-1", SignerAuthorizationRef: quoteValue.SignerAuthorizationRef, TermsDigest: quoteValue.TermsDigest}
	terms.EscrowId = escrowcommitment.EscrowID(terms.NetworkId, terms.Domain, terms.QuoteId, terms.JobId)
	misaligned := proto.Clone(terms).(*atostosv1.VerifiedEscrowTerms)
	misaligned.EscrowDeadlineUnixMillis++
	if _, err := server.CreateEscrow(context.Background(), connect.NewRequest(
		&atostosv1.CreateEscrowRequest{
			Context: &atostosv1.RequestContext{
				RequestId: "request-create-misaligned", CallerId: "caller-test",
				IdempotencyKey: "idem-create-misaligned", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
			},
			QuoteId: quoteID, PrincipalId: principalID, ProviderId: providerID,
			CapabilityId: capabilityID, TrustMode: TrustModeVerified,
			ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1,
			Reserve:      &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "1000"},
			FundingModel: "task_escrow_v1", ExpiresUnixMillis: expires, VerifiedTerms: misaligned,
		},
	)); err == nil {
		t.Fatal("non-second-aligned Verified escrow deadline was accepted")
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
			FundingModel: "task_escrow_v1", ExpiresUnixMillis: expires, VerifiedTerms: terms,
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
	// A verifier replica has an empty bbolt projection. The complete expected
	// tuple and canonical identity controllers must still recover the same
	// escrow through the shared live authority/economy without a mutation.
	fresh, freshErr := Open(Config{StatePath: filepath.Join(t.TempDir(), "fresh-verifier.db"), BearerToken: "test-secret", Authority: server.authority, EconomicDriver: economy, Now: func() time.Time { return now }})
	if freshErr != nil {
		t.Fatal(freshErr)
	}
	defer fresh.Close()
	freshGet, freshErr := fresh.GetEscrow(context.Background(), connect.NewRequest(&atostosv1.GetEscrowRequest{Context: &atostosv1.RequestContext{RequestId: "fresh-empty-projection", CallerId: "independent-verifier", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli()}, EscrowId: terms.EscrowId, QuoteId: quoteID, ExpectedTerms: terms, ExpectedReservationDigest: create.Msg.Escrow.ReservationDigest, ExpectedEscrowRef: create.Msg.Escrow.EscrowRef, ExpectedCreatorAddress: creator, ExpectedAgentAddress: agent}))
	if freshErr != nil || !freshGet.Msg.Found || freshGet.Msg.Escrow == nil || freshGet.Msg.Escrow.EscrowRef.Reference != economy.contract {
		t.Fatalf("fresh protocol replica failed canonical recovery: response=%+v err=%v", freshGet, freshErr)
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
	settleRequest := &atostosv1.SettleJobRequest{
		Context: &atostosv1.RequestContext{
			RequestId: "request-settle-verified", CallerId: "caller-test",
			IdempotencyKey: "idem-settle-verified", DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
		},
		EscrowId: escrowID, QuoteId: quoteID, JobId: jobID, ReceiptId: receiptID,
		RequestedCharge: &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "0"},
		ExpectedTerms:   terms, ExpectedEscrowRef: create.Msg.Escrow.EscrowRef,
		ExpectedReservationDigest: create.Msg.Escrow.ReservationDigest,
	}
	unbound := proto.Clone(settleRequest).(*atostosv1.SettleJobRequest)
	unbound.ExpectedTerms = nil
	unbound.ExpectedEscrowRef = nil
	unbound.ExpectedReservationDigest = ""
	if _, err := server.SettleJob(context.Background(), connect.NewRequest(unbound)); err == nil {
		t.Fatal("Verified settlement without canonical reservation assertions was accepted")
	}
	if economy.settleCalls != 0 {
		t.Fatal("unbound settlement request reached irreversible mutation")
	}
	if err := server.store.update(func(tx *bolt.Tx) error {
		corrupt := proto.Clone(create.Msg.Escrow).(*atostosv1.Escrow)
		corrupt.EscrowRef.Reference = "tos:task-escrow:v1:0:" + strings.Repeat("99", 32)
		return server.store.putProto(tx, bucketEscrows, escrowID, corrupt)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.SettleJob(context.Background(), connect.NewRequest(proto.Clone(settleRequest).(*atostosv1.SettleJobRequest))); err == nil {
		t.Fatal("settlement accepted a local escrow reference that differed from canonical reservation")
	}
	if economy.settleCalls != 0 {
		t.Fatal("canonical reservation mismatch reached irreversible settlement mutation")
	}
	if err := server.store.update(func(tx *bolt.Tx) error {
		return server.store.putProto(tx, bucketEscrows, escrowID, create.Msg.Escrow)
	}); err != nil {
		t.Fatal(err)
	}
	economy.settlementCheckpoint = 0
	if _, err := server.SettleJob(context.Background(), connect.NewRequest(proto.Clone(settleRequest).(*atostosv1.SettleJobRequest))); err == nil {
		t.Fatal("Verified settlement without a finalized checkpoint was accepted")
	}
	if economy.settleCalls != 1 {
		t.Fatalf("zero-checkpoint settlement mutation calls=%d want 1", economy.settleCalls)
	}
	economy.settlementCheckpoint = 43
	settled, err := server.SettleJob(context.Background(), connect.NewRequest(settleRequest))
	if err != nil {
		t.Fatal(err)
	}
	if !settled.Msg.Created || settled.Msg.Settlement == nil ||
		settled.Msg.Settlement.SettlementRef == nil ||
		settled.Msg.Settlement.SettlementRef.Reference != economy.settlementRef ||
		!settled.Msg.Settlement.SettlementRef.Finalized ||
		settled.Msg.Settlement.SettlementRef.FinalizedCheckpoint != 43 {
		t.Fatalf("unexpected Verified settlement response: %#v", settled.Msg)
	}
	if economy.settleRequest.ContractAddress != contractAddress ||
		economy.settleRequest.BudgetNanoTOS != 1000 ||
		economy.settleRequest.PayoutNanoTOS != 0 ||
		economy.settleRequest.ResultHash == "" || economy.settleRequest.EvidenceHash == "" {
		t.Fatalf("Verified settlement binding was lost: %#v", economy.settleRequest)
	}
	if settled.Msg.Settlement.Charged.AtomicAmount != "0" || settled.Msg.Settlement.Refunded.AtomicAmount != "1000" {
		t.Fatalf("zero-charge settlement did not preserve full refund: %#v", settled.Msg.Settlement)
	}
	replay, err := server.SettleJob(context.Background(), connect.NewRequest(proto.Clone(settleRequest).(*atostosv1.SettleJobRequest)))
	if err != nil || replay.Msg.Settlement == nil || replay.Msg.Settlement.SettlementId != settled.Msg.Settlement.SettlementId {
		t.Fatalf("live canonical settlement replay failed: response=%#v err=%v", replay, err)
	}
	if economy.settleCalls != 2 {
		t.Fatalf("settlement replay published another mutation: calls=%d", economy.settleCalls)
	}
}
