package atosrpc

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
)

// fakeThirdPartyWorker is an in-memory stand-in for
// tos.edge.v1.ThirdPartyExecutionService, used to prove the atosrpc-side
// routing/state-machine logic without a real Unix-socket worker process.
type fakeThirdPartyWorker struct {
	mu          sync.Mutex
	invokeCalls int
	healthFunc  func(*edgev1.ThirdPartyHealthRequest) (*edgev1.ThirdPartyHealthResponse, error)
	invokeFunc  func(*edgev1.ThirdPartyInvokeRequest) (*edgev1.ThirdPartyInvokeResponse, error)
	queryFunc   func(*edgev1.ThirdPartyQueryRequest) (*edgev1.ThirdPartyQueryResponse, error)
	cancelFunc  func(*edgev1.ThirdPartyCancelRequest) (*edgev1.ThirdPartyCancelResponse, error)
}

func (f *fakeThirdPartyWorker) Health(_ context.Context, req *edgev1.ThirdPartyHealthRequest) (*edgev1.ThirdPartyHealthResponse, error) {
	if f.healthFunc != nil {
		return f.healthFunc(req)
	}
	return &edgev1.ThirdPartyHealthResponse{Healthy: true}, nil
}

func (f *fakeThirdPartyWorker) Invoke(_ context.Context, req *edgev1.ThirdPartyInvokeRequest) (*edgev1.ThirdPartyInvokeResponse, error) {
	f.mu.Lock()
	f.invokeCalls++
	f.mu.Unlock()
	if f.invokeFunc != nil {
		return f.invokeFunc(req)
	}
	return &edgev1.ThirdPartyInvokeResponse{
		RequestId: req.RequestId, Status: edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_COMPLETED,
		Output: []byte(`{"ok":true}`), CompletedUnixMillis: time.Now().UnixMilli(),
	}, nil
}

func (f *fakeThirdPartyWorker) Query(_ context.Context, req *edgev1.ThirdPartyQueryRequest) (*edgev1.ThirdPartyQueryResponse, error) {
	if f.queryFunc != nil {
		return f.queryFunc(req)
	}
	return &edgev1.ThirdPartyQueryResponse{Found: false}, nil
}

func (f *fakeThirdPartyWorker) Cancel(_ context.Context, req *edgev1.ThirdPartyCancelRequest) (*edgev1.ThirdPartyCancelResponse, error) {
	if f.cancelFunc != nil {
		return f.cancelFunc(req)
	}
	return &edgev1.ThirdPartyCancelResponse{Accepted: true}, nil
}

func (f *fakeThirdPartyWorker) invocations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.invokeCalls
}

func newThirdPartyTestServer(t *testing.T, worker *fakeThirdPartyWorker) *Server {
	t.Helper()
	srv, err := Open(Config{
		StatePath: filepath.Join(t.TempDir(), "atos-rpc.db"), BearerToken: "test-secret",
		Authority: NewLocalAuthority(""), ThirdPartyWorker: worker,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func mutationContext(id string) *atostosv1.RequestContext {
	return &atostosv1.RequestContext{RequestId: id, CallerId: "test-caller", IdempotencyKey: id}
}

func readContext(id string) *atostosv1.RequestContext {
	return &atostosv1.RequestContext{RequestId: id, CallerId: "test-caller"}
}

// thirdPartyQuoteFixture registers a Managed Capability, commits an ATOS
// Quote and reserves an Escrow for it, then requests a third-party
// ServiceExecutionQuote -- the full chain of durable state SubmitJob's
// third-party branch validates against, exercised through the real RPC
// methods rather than poked directly into storage.
type thirdPartyQuoteFixture struct {
	providerID, capabilityID, version string
	quoteID, escrowID, serviceQuoteID string
	binding                           *atostosv1.ThirdPartyBinding
	inputCommitment                   *atostosv1.Digest
	deadline                          int64
}

func setUpThirdPartyQuote(t *testing.T, srv *Server, endpointRef string) thirdPartyQuoteFixture {
	t.Helper()
	ctx := context.Background()
	providerID, capabilityID, version := "agt_provider_1", "cap_http_1", "1.0.0"

	if _, err := srv.CommitCapabilityManifest(ctx, connect.NewRequest(&atostosv1.CommitCapabilityManifestRequest{
		Context: mutationContext("commit-manifest-1"), CapabilityId: capabilityID, ProviderId: providerID, Version: version,
		ManifestDigest:      &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)},
		RequestedTrustModes: []atostosv1.TrustMode{atostosv1.TrustMode_TRUST_MODE_MANAGED},
	})); err != nil {
		t.Fatalf("CommitCapabilityManifest: %v", err)
	}

	deadline := time.Now().Add(time.Hour).UnixMilli()
	inputCommitment := digestMessage([]byte("test"))

	// QuoteExecution happens first (mirroring atos's own QuoteService.Create,
	// which asks tos-protocol for a ServiceExecutionQuote before it builds
	// its own commercial Quote) so ServiceQuoteId is known before CommitQuote
	// records it as UnderlyingServiceQuoteRef.
	binding := &atostosv1.ThirdPartyBinding{
		Transport: atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_HTTP, EndpointRef: endpointRef,
		BindingCommitment: &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)},
	}
	quoteResp, err := srv.QuoteExecution(ctx, connect.NewRequest(&atostosv1.QuoteExecutionRequest{
		Context: readContext("quote-execution-1"), ProviderId: providerID,
		CapabilityId: capabilityID, CapabilityVersion: version,
		InputCommitment: inputCommitment, InputBytes: 4, MaxOutputBytes: 4096,
		ExecutionDeadlineUnixMillis: deadline,
		IntendedTrustMode:           atostosv1.TrustMode_TRUST_MODE_MANAGED,
		IntendedProofProfile:        atostosv1.ProofProfile_PROOF_PROFILE_NONE,
		ThirdPartyBinding:           binding,
	}))
	if err != nil {
		t.Fatalf("QuoteExecution (third-party): %v", err)
	}
	serviceQuoteID := quoteResp.Msg.Quote.ServiceQuoteId

	quoteID := "q_third_party_1"
	if _, err := srv.CommitQuote(ctx, connect.NewRequest(&atostosv1.CommitQuoteRequest{
		Context: mutationContext("commit-quote-1"),
		Quote: &atostosv1.QuoteCommitmentInput{
			QuoteId: quoteID, PrincipalId: "prn_1", ProviderId: providerID,
			CapabilityId: capabilityID, CapabilityVersion: version,
			TrustMode: atostosv1.TrustMode_TRUST_MODE_MANAGED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_NONE,
			TotalMax:                  &atostosv1.Money{Amount: "1.00", Currency: "USD"},
			TermsDigest:               &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)},
			ExpiresUnixMillis:         deadline,
			UnderlyingServiceQuoteRef: serviceQuoteID,
		},
	})); err != nil {
		t.Fatalf("CommitQuote: %v", err)
	}

	escrowResp, err := srv.CreateEscrow(ctx, connect.NewRequest(&atostosv1.CreateEscrowRequest{
		Context: mutationContext("create-escrow-1"), QuoteId: quoteID, PrincipalId: "prn_1",
		ProviderId: providerID, CapabilityId: capabilityID,
		TrustMode: atostosv1.TrustMode_TRUST_MODE_MANAGED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_NONE,
		Reserve:           &atostosv1.NetworkAmount{Asset: "USD", AtomicAmount: "100"},
		ExpiresUnixMillis: deadline,
	}))
	if err != nil {
		t.Fatalf("CreateEscrow: %v", err)
	}

	return thirdPartyQuoteFixture{
		providerID: providerID, capabilityID: capabilityID, version: version,
		quoteID: quoteID, escrowID: escrowResp.Msg.Escrow.EscrowId, serviceQuoteID: quoteResp.Msg.Quote.ServiceQuoteId,
		binding: binding, inputCommitment: inputCommitment, deadline: deadline,
	}
}

func (f thirdPartyQuoteFixture) submitRequest(jobID string, idempotencyKey string) *atostosv1.SubmitJobRequest {
	return &atostosv1.SubmitJobRequest{
		Context: mutationContext(idempotencyKey), JobId: jobID, InvocationId: "inv-" + jobID,
		PrincipalId: "prn_1", ProviderId: f.providerID, CapabilityId: f.capabilityID, CapabilityVersion: f.version,
		QuoteId: f.quoteID, ServiceQuoteId: f.serviceQuoteID, EscrowId: f.escrowID,
		TrustMode: atostosv1.TrustMode_TRUST_MODE_MANAGED, ProofProfile: atostosv1.ProofProfile_PROOF_PROFILE_NONE,
		Input: []byte(`test`), InputCommitment: f.inputCommitment,
		MaxOutputBytes: 4096, ExecutionDeadlineUnixMillis: f.deadline, RetainUntilUnixMillis: f.deadline + 1,
		ThirdPartyBinding: f.binding,
	}
}

func TestSubmitThirdPartyJob_GoldenPathCompletesAndSignsReceipt(t *testing.T) {
	worker := &fakeThirdPartyWorker{}
	srv := newThirdPartyTestServer(t, worker)
	fixture := setUpThirdPartyQuote(t, srv, "https://provider.example.com/invoke")

	resp, err := srv.SubmitJob(context.Background(), connect.NewRequest(fixture.submitRequest("job_1", "submit-job-1")))
	if err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}
	if resp.Msg.State != atostosv1.JobState_JOB_STATE_COMPLETED {
		t.Fatalf("state = %s, want completed", resp.Msg.State)
	}
	if worker.invocations() != 1 {
		t.Fatalf("thirdPartyWorker.Invoke called %d times, want exactly 1", worker.invocations())
	}

	receipt, err := srv.FetchExecutionReceipt(context.Background(), connect.NewRequest(&atostosv1.FetchExecutionReceiptRequest{
		Context: readContext("fetch-receipt-1"), JobId: "job_1",
	}))
	if err != nil {
		t.Fatalf("FetchExecutionReceipt: %v", err)
	}
	if receipt.Msg.ReceiptId == "" || len(receipt.Msg.CanonicalReceipt) == 0 {
		t.Fatal("expected a signed execution receipt after third-party completion")
	}

	result, err := srv.FetchResult(context.Background(), connect.NewRequest(&atostosv1.FetchResultRequest{
		Context: readContext("fetch-result-1"), JobId: "job_1",
	}))
	if err != nil {
		t.Fatalf("FetchResult: %v", err)
	}
	if string(result.Msg.Output) != `{"ok":true}` {
		t.Fatalf("output = %q, want the third-party worker's output", result.Msg.Output)
	}
}

func TestSubmitThirdPartyJob_RetryIsIdempotentAndDoesNotReinvoke(t *testing.T) {
	worker := &fakeThirdPartyWorker{}
	srv := newThirdPartyTestServer(t, worker)
	fixture := setUpThirdPartyQuote(t, srv, "https://provider.example.com/invoke")
	req := fixture.submitRequest("job_2", "submit-job-2")

	first, err := srv.SubmitJob(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("SubmitJob (first): %v", err)
	}
	second, err := srv.SubmitJob(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("SubmitJob (retry): %v", err)
	}
	if first.Msg.State != second.Msg.State || first.Msg.JobId != second.Msg.JobId {
		t.Fatalf("retry produced a different response: %+v vs %+v", first.Msg, second.Msg)
	}
	if worker.invocations() != 1 {
		t.Fatalf("thirdPartyWorker.Invoke called %d times across an idempotent retry, want exactly 1", worker.invocations())
	}
}

func TestSubmitThirdPartyJob_RejectsBindingSubstitution(t *testing.T) {
	worker := &fakeThirdPartyWorker{}
	srv := newThirdPartyTestServer(t, worker)
	fixture := setUpThirdPartyQuote(t, srv, "https://provider.example.com/invoke")

	req := fixture.submitRequest("job_3", "submit-job-3")
	// Submit against a DIFFERENT endpoint than the one that was quoted --
	// this must be rejected before any dispatch, never silently honored.
	req.ThirdPartyBinding = &atostosv1.ThirdPartyBinding{
		Transport:         atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_HTTP,
		EndpointRef:       "https://attacker.example.com/invoke",
		BindingCommitment: fixture.binding.BindingCommitment,
	}

	if _, err := srv.SubmitJob(context.Background(), connect.NewRequest(req)); err == nil {
		t.Fatal("expected SubmitJob to reject a binding that does not match the quoted binding")
	}
	if worker.invocations() != 0 {
		t.Fatalf("thirdPartyWorker.Invoke called %d times for a rejected submission, want 0", worker.invocations())
	}
}

func TestSubmitThirdPartyJob_RecoversAfterTransientInvokeFailure(t *testing.T) {
	worker := &fakeThirdPartyWorker{}
	worker.invokeFunc = func(req *edgev1.ThirdPartyInvokeRequest) (*edgev1.ThirdPartyInvokeResponse, error) {
		return nil, connect.NewError(connect.CodeUnavailable, context.DeadlineExceeded)
	}
	worker.queryFunc = func(req *edgev1.ThirdPartyQueryRequest) (*edgev1.ThirdPartyQueryResponse, error) {
		// The provider never actually admitted the attempt -- an honest "no
		// record", not a fabricated terminal outcome.
		return &edgev1.ThirdPartyQueryResponse{Found: false}, nil
	}
	srv := newThirdPartyTestServer(t, worker)
	fixture := setUpThirdPartyQuote(t, srv, "https://provider.example.com/invoke")

	resp, err := srv.SubmitJob(context.Background(), connect.NewRequest(fixture.submitRequest("job_4", "submit-job-4")))
	if err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}
	if resp.Msg.State != atostosv1.JobState_JOB_STATE_UNCERTAIN {
		t.Fatalf("state = %s, want uncertain after a transient failure with no recovered record", resp.Msg.State)
	}

	// Recovery is read-only (Query), never a blind re-Invoke -- calling
	// SubmitJob again with the same idempotency identity must NOT cause a
	// second dispatch attempt while the outcome is still genuinely unknown.
	replay, err := srv.SubmitJob(context.Background(), connect.NewRequest(fixture.submitRequest("job_4", "submit-job-4")))
	if err != nil {
		t.Fatalf("SubmitJob (replay while uncertain): %v", err)
	}
	if replay.Msg.State != atostosv1.JobState_JOB_STATE_UNCERTAIN {
		t.Fatalf("state = %s, want still uncertain -- a retry must never blindly re-invoke", replay.Msg.State)
	}
	if worker.invocations() != 1 {
		t.Fatalf("thirdPartyWorker.Invoke called %d times, want exactly 1 -- recovery must stay read-only", worker.invocations())
	}

	// Once the provider becomes queryable and reports the job actually
	// completed, GetJob's own recovery-on-read must observe that --
	// completion is discovered via Query, never invented locally.
	worker.queryFunc = func(req *edgev1.ThirdPartyQueryRequest) (*edgev1.ThirdPartyQueryResponse, error) {
		return &edgev1.ThirdPartyQueryResponse{
			Found: true,
			Result: &edgev1.ThirdPartyInvokeResponse{
				RequestId: req.RequestId, Status: edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_COMPLETED,
				Output: []byte(`{"ok":true}`), CompletedUnixMillis: time.Now().UnixMilli(),
			},
		}, nil
	}
	getResp, err := srv.GetJob(context.Background(), connect.NewRequest(&atostosv1.GetJobRequest{
		Context: readContext("get-job-4"), JobId: "job_4",
	}))
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if getResp.Msg.Job.State != atostosv1.JobState_JOB_STATE_COMPLETED {
		t.Fatalf("state = %s, want completed once Query reports the recovered outcome", getResp.Msg.Job.State)
	}
	if worker.invocations() != 1 {
		t.Fatalf("thirdPartyWorker.Invoke called %d times, want still exactly 1 -- GetJob's recovery must stay read-only too", worker.invocations())
	}
}

// TestSubmitThirdPartyJob_RejectsOutputExceedingQuotedMaxOutputBytes proves
// a provider response larger than the Job's own quoted max_output_bytes
// (independent of the worker operator's own, unrelated wire-envelope
// MaxResponseBytes) never reaches completeDurableJob/the signed Receipt/
// settlement -- the fixture quotes 4096 bytes; the fake worker returns
// more.
func TestSubmitThirdPartyJob_RejectsOutputExceedingQuotedMaxOutputBytes(t *testing.T) {
	oversized := make([]byte, 8192)
	worker := &fakeThirdPartyWorker{
		invokeFunc: func(req *edgev1.ThirdPartyInvokeRequest) (*edgev1.ThirdPartyInvokeResponse, error) {
			return &edgev1.ThirdPartyInvokeResponse{
				RequestId: req.RequestId, Status: edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_COMPLETED,
				Output: oversized, CompletedUnixMillis: time.Now().UnixMilli(),
			}, nil
		},
	}
	srv := newThirdPartyTestServer(t, worker)
	fixture := setUpThirdPartyQuote(t, srv, "https://provider.example.com/invoke")

	if _, err := srv.SubmitJob(context.Background(), connect.NewRequest(fixture.submitRequest("job_5", "submit-job-5"))); err == nil {
		t.Fatal("expected SubmitJob to reject output exceeding the quoted max_output_bytes")
	}

	receipt, err := srv.FetchExecutionReceipt(context.Background(), connect.NewRequest(&atostosv1.FetchExecutionReceiptRequest{
		Context: readContext("fetch-receipt-5"), JobId: "job_5",
	}))
	if err == nil && receipt.Msg != nil && len(receipt.Msg.CanonicalReceipt) > 0 {
		t.Fatal("an oversized third-party result must never produce a signed execution receipt")
	}
}

// TestGetProviderStatus_ThirdPartyBinding_PopulatesDeepProbeAndLatency proves
// GetProviderStatusResponse.deep_probe/latency_unix_millis are carried
// through from tos.edge.v1.ThirdPartyExecutionService.Health's own
// deep_probe/latency_millis, so ATOS's HealthService/CertificationService
// can record the same evidence fidelity through this remote path as local
// probing already captures (atos-spec docs/THIRD_PARTY_EXECUTION_PLANE.md
// §3.1).
func TestGetProviderStatus_ThirdPartyBinding_PopulatesDeepProbeAndLatency(t *testing.T) {
	worker := &fakeThirdPartyWorker{
		healthFunc: func(*edgev1.ThirdPartyHealthRequest) (*edgev1.ThirdPartyHealthResponse, error) {
			return &edgev1.ThirdPartyHealthResponse{Healthy: true, DeepProbe: true, LatencyMillis: 42}, nil
		},
	}
	srv := newThirdPartyTestServer(t, worker)

	resp, err := srv.GetProviderStatus(context.Background(), connect.NewRequest(&atostosv1.GetProviderStatusRequest{
		Context: readContext("provider-status-1"), ProviderId: "agt_provider_1", CapabilityId: "cap_http_1",
		ThirdPartyBinding: &atostosv1.ThirdPartyBinding{
			Transport: atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_HTTP, EndpointRef: "https://provider.example.com/invoke",
			BindingCommitment: &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)},
		},
	}))
	if err != nil {
		t.Fatalf("GetProviderStatus: %v", err)
	}
	if !resp.Msg.DeepProbe {
		t.Fatal("deep_probe = false, want true from the worker's Health response")
	}
	if resp.Msg.LatencyUnixMillis != 42 {
		t.Fatalf("latency_unix_millis = %d, want 42", resp.Msg.LatencyUnixMillis)
	}
	if resp.Msg.Readiness != atostosv1.ProviderReadiness_PROVIDER_READINESS_READY {
		t.Fatalf("readiness = %s, want READY", resp.Msg.Readiness)
	}
}

// TestGetProviderStatus_ThirdPartyBinding_PopulatesLatencyOnUnhealthy proves
// latency_unix_millis is still recorded when the probe completes but reports
// unhealthy -- latency is meaningful evidence on a failed probe too, not
// only a successful one.
func TestGetProviderStatus_ThirdPartyBinding_PopulatesLatencyOnUnhealthy(t *testing.T) {
	worker := &fakeThirdPartyWorker{
		healthFunc: func(*edgev1.ThirdPartyHealthRequest) (*edgev1.ThirdPartyHealthResponse, error) {
			return &edgev1.ThirdPartyHealthResponse{Healthy: false, FailureReason: "TOOL_NOT_FOUND", LatencyMillis: 17}, nil
		},
	}
	srv := newThirdPartyTestServer(t, worker)

	resp, err := srv.GetProviderStatus(context.Background(), connect.NewRequest(&atostosv1.GetProviderStatusRequest{
		Context: readContext("provider-status-2"), ProviderId: "agt_provider_1", CapabilityId: "cap_http_1",
		ThirdPartyBinding: &atostosv1.ThirdPartyBinding{
			Transport: atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_HTTP, EndpointRef: "https://provider.example.com/invoke",
			BindingCommitment: &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)},
		},
	}))
	if err != nil {
		t.Fatalf("GetProviderStatus: %v", err)
	}
	if resp.Msg.LatencyUnixMillis != 17 {
		t.Fatalf("latency_unix_millis = %d, want 17 even on an unhealthy probe", resp.Msg.LatencyUnixMillis)
	}
	if resp.Msg.ReasonCode != "TOOL_NOT_FOUND" {
		t.Fatalf("reason_code = %q, want the worker's failure_reason", resp.Msg.ReasonCode)
	}
}

// TestGetProviderStatus_ThirdPartyBinding_ForwardsCapabilityVersion proves
// GetProviderStatusRequest.capability_version reaches the private Worker's
// ThirdPartyHealthRequest.Binding.CapabilityVersion instead of being
// silently dropped as "" -- a worker-operator allowlist entry may be
// version-scoped (atos-spec docs/THIRD_PARTY_EXECUTION_PLANE.md §4), so a
// probe that doesn't say which version it means cannot actually ask "is
// THIS version's binding allowlisted and healthy".
func TestGetProviderStatus_ThirdPartyBinding_ForwardsCapabilityVersion(t *testing.T) {
	worker := &fakeThirdPartyWorker{
		healthFunc: func(req *edgev1.ThirdPartyHealthRequest) (*edgev1.ThirdPartyHealthResponse, error) {
			if req.Binding.CapabilityVersion != "1.2.3" {
				return &edgev1.ThirdPartyHealthResponse{Healthy: false, FailureReason: "VERSION_MISMATCH"}, nil
			}
			return &edgev1.ThirdPartyHealthResponse{Healthy: true}, nil
		},
	}
	srv := newThirdPartyTestServer(t, worker)

	resp, err := srv.GetProviderStatus(context.Background(), connect.NewRequest(&atostosv1.GetProviderStatusRequest{
		Context: readContext("provider-status-3"), ProviderId: "agt_provider_1", CapabilityId: "cap_http_1",
		CapabilityVersion: "1.2.3",
		ThirdPartyBinding: &atostosv1.ThirdPartyBinding{
			Transport: atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_HTTP, EndpointRef: "https://provider.example.com/invoke",
			BindingCommitment: &atostosv1.Digest{Algorithm: "sha256", Value: make([]byte, 32)},
		},
	}))
	if err != nil {
		t.Fatalf("GetProviderStatus: %v", err)
	}
	if resp.Msg.ReasonCode == "VERSION_MISMATCH" {
		t.Fatal("capability_version was dropped before reaching the private Worker's Health request")
	}
	if resp.Msg.Readiness != atostosv1.ProviderReadiness_PROVIDER_READINESS_READY {
		t.Fatalf("readiness = %s, want READY", resp.Msg.Readiness)
	}
}
