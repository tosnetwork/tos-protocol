package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type actionAuthorityResolver struct {
	snapshot authorization.AuthoritySnapshot
}

type fixedPaidActionHTTPAuthorizer struct {
	action authorization.AuthorizedPaidAction
}

func (a fixedPaidActionHTTPAuthorizer) AuthorizePaidAction(
	context.Context,
	*http.Request,
) (authorization.AuthorizedPaidAction, error) {
	return a.action, nil
}

func (r actionAuthorityResolver) ResolveAuthority(
	_ context.Context,
	reference authorization.Reference,
) (authorization.AuthoritySnapshot, error) {
	if reference.Network != r.snapshot.Network ||
		reference.ServiceID != r.snapshot.ServiceID ||
		reference.MinimumMasterSeqno > r.snapshot.ObservedMasterSeqno {
		return authorization.AuthoritySnapshot{}, errors.New(
			"action authority reference mismatch",
		)
	}
	return r.snapshot, nil
}

func TestExecuteRegisteredPaidActionCompletesOnce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, plan, fixture := prepareDispatchRequest(
		t, now, "paid-action-success-0001",
	)
	defer core.Close()
	workerServer := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("action-output"),
	}
	worker := startDispatchWorkerClient(t, workerServer)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate, keyID: "runtime-auth-key",
	}
	resolution, err := core.ExecuteRegisteredPaidAction(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), plan, worker, fixture.manifest, signer,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := resolution.Disposition()
	if err != nil || disposition != ExecutionResolutionSucceeded {
		t.Fatalf("paid action disposition=%q err=%v", disposition, err)
	}
	completed, err := resolution.CompletedInvocation()
	if err != nil || string(completed.Output) != "action-output" ||
		completed.Disposition != journal.ReceiptApplied ||
		workerServer.invokeCalls.Load() != 1 || workerServer.getCalls.Load() != 0 ||
		signer.calls.Load() != 1 {
		t.Fatalf("unexpected paid action completion=%#v err=%v", completed, err)
	}
	workerServer.completedAt.Store(completed.Receipt.CompletedAt.UnixMilli())
	if _, err := core.RecoverRegisteredPaidAction(
		context.Background(), scope, []byte("changed-dispatch-intent"), plan,
		worker, fixture.manifest, signer, time.Minute,
	); err == nil || workerServer.getCalls.Load() != 0 {
		t.Fatalf("changed terminal intent reached Worker: err=%v", err)
	}
	replayed, err := core.RecoverRegisteredPaidAction(
		context.Background(), scope, []byte("dispatch-intent"), plan,
		worker, fixture.manifest, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedCompletion, err := replayed.CompletedInvocation()
	if err != nil || replayedCompletion.Disposition != journal.ReceiptReplay ||
		string(replayedCompletion.Output) != "action-output" ||
		workerServer.invokeCalls.Load() != 1 || workerServer.getCalls.Load() != 1 ||
		signer.calls.Load() != 1 {
		t.Fatalf("paid action terminal replay=%#v err=%v", replayedCompletion, err)
	}
}

func TestExecuteRegisteredPaidActionPreservesUncertainClaim(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, plan, fixture := prepareDispatchRequest(
		t, now, "paid-action-uncertain-0001",
	)
	defer core.Close()
	workerServer := &dispatchWorker{invokeError: true}
	worker := startDispatchWorkerClient(t, workerServer)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate, keyID: "runtime-auth-key",
	}
	resolution, err := core.ExecuteRegisteredPaidAction(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), plan, worker, fixture.manifest, signer,
		time.Minute,
	)
	if err == nil || !strings.Contains(err.Error(), "dispatch paid action") {
		t.Fatalf("missing dispatch error: %v", err)
	}
	disposition, dispositionErr := resolution.Disposition()
	claim, claimErr := resolution.Claim()
	if dispositionErr != nil || claimErr != nil ||
		disposition != ExecutionResolutionUncertain || claim.Request == nil ||
		claim.State.State != journal.StateRunning ||
		workerServer.invokeCalls.Load() != 1 || workerServer.getCalls.Load() != 0 ||
		signer.calls.Load() != 0 {
		t.Fatalf(
			"uncertain action lost claim: resolution=%#v disposition=%q errors=%v/%v",
			resolution, disposition, dispositionErr, claimErr,
		)
	}
}

func TestRecoverRegisteredPaidActionNeverReinvokes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, plan, fixture := prepareDispatchRequest(
		t, now, "paid-action-recovery-0001",
	)
	defer core.Close()
	claimWorker := startDispatchWorkerClient(t, &dispatchWorker{invokeError: true})
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), plan, claimWorker,
	)
	if err == nil {
		t.Fatal("fixture dispatch unexpectedly succeeded")
	}
	disposition, err := dispatch.Disposition()
	if err != nil || disposition != ExecutionDispatchUncertain {
		t.Fatalf("fixture dispatch=%q err=%v", disposition, err)
	}
	recoveryServer := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("recovered-output"),
	}
	recoveryWorker := startDispatchWorkerClient(t, recoveryServer)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate, keyID: "runtime-auth-key",
	}
	resolution, err := core.RecoverRegisteredPaidAction(
		context.Background(), scope, []byte("dispatch-intent"), plan,
		recoveryWorker, fixture.manifest, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := resolution.CompletedInvocation()
	if err != nil || string(completed.Output) != "recovered-output" ||
		recoveryServer.invokeCalls.Load() != 0 || recoveryServer.getCalls.Load() != 1 ||
		signer.calls.Load() != 1 {
		t.Fatalf("unsafe recovered action=%#v err=%v", completed, err)
	}
}

func TestRecoverRegisteredPaidActionReplaysTerminalFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, plan, fixture := prepareDispatchRequest(
		t, now, "paid-action-failure-replay-0001",
	)
	defer core.Close()
	claimWorker := startDispatchWorkerClient(t, &dispatchWorker{invokeError: true})
	if _, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), plan, claimWorker,
	); err == nil {
		t.Fatal("fixture dispatch unexpectedly succeeded")
	}
	recoveryServer := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_FAILED,
	}
	recoveryWorker := startDispatchWorkerClient(t, recoveryServer)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate, keyID: "runtime-auth-key",
	}
	first, err := core.RecoverRegisteredPaidAction(
		context.Background(), scope, []byte("dispatch-intent"), plan,
		recoveryWorker, fixture.manifest, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	terminated, err := first.TerminatedInvocation()
	if err != nil || terminated.Disposition != journal.ReceiptApplied {
		t.Fatalf("first terminal failure=%#v err=%v", terminated, err)
	}
	recoveryServer.completedAt.Store(terminated.Receipt.CompletedAt.UnixMilli())
	replayed, err := core.RecoverRegisteredPaidAction(
		context.Background(), scope, []byte("dispatch-intent"), plan,
		recoveryWorker, fixture.manifest, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, dispositionErr := replayed.Disposition()
	replayedTermination, terminationErr := replayed.TerminatedInvocation()
	if dispositionErr != nil || terminationErr != nil ||
		disposition != ExecutionResolutionFailed ||
		replayedTermination.Disposition != journal.ReceiptReplay ||
		recoveryServer.invokeCalls.Load() != 0 ||
		recoveryServer.getCalls.Load() != 2 || signer.calls.Load() != 1 {
		t.Fatalf(
			"terminal failure replay=%#v disposition=%q errors=%v/%v",
			replayedTermination, disposition, dispositionErr, terminationErr,
		)
	}
}

func TestProcessAuthorizedPaidActionRunsCompleteTransactionAndReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	intent := []byte("dispatch-intent")
	action, _, _ := authorizeCompletePaidAction(
		t, fixture, "complete-paid-action-0001", intent,
	)
	material, err := action.Material(now)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := payment.NewObserver(
		corePaymentResolver{state: chain.PaymentState{
			Network:         material.Network,
			AuthorizationID: "authorization-complete-paid-action-0001",
			QuoteID:         "quote-complete-paid-action-0001",
			RequestID:       material.RequestID,
			Reference:       "payment-reference-complete-paid-action-0001",
			Payer:           fixture.clientID, Payee: "service-wallet",
			AmountNanoTOS: 5, Confirmed: true, Finalized: true,
			ObservedMasterSeqno: material.MinimumMasterSeqno,
			ObservedAt:          now,
		}},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := completePaidActionPlan(t)
	workerServer := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("complete-action-output"),
	}
	worker := startDispatchWorkerClient(t, workerServer)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate, keyID: "runtime-auth-key",
	}
	first, err := core.ProcessAuthorizedPaidAction(
		context.Background(), action, observer, plan, worker, signer,
		30*time.Minute, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := first.CompletedInvocation()
	if err != nil || string(completed.Output) != "complete-action-output" ||
		completed.Disposition != journal.ReceiptApplied ||
		workerServer.invokeCalls.Load() != 1 || signer.calls.Load() != 1 {
		t.Fatalf("complete paid action=%#v err=%v", completed, err)
	}
	workerServer.completedAt.Store(completed.Receipt.CompletedAt.UnixMilli())
	replayed, err := core.ProcessAuthorizedPaidAction(
		context.Background(), action, observer, plan, worker, signer,
		30*time.Minute, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedCompletion, err := replayed.CompletedInvocation()
	if err != nil || string(replayedCompletion.Output) != "complete-action-output" ||
		replayedCompletion.Disposition != journal.ReceiptReplay ||
		workerServer.invokeCalls.Load() != 1 || workerServer.getCalls.Load() != 1 ||
		signer.calls.Load() != 1 {
		t.Fatalf("complete paid action replay=%#v err=%v", replayedCompletion, err)
	}
}

func TestPaidActionHTTPRouteIsOptInAndReturnsSignedResult(t *testing.T) {
	_, descriptor, catalog, _, _, _ := receiptDeliveryFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	descriptor.ExpiresAt = now.Add(time.Hour)
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	action, actionAuthorizer, credentials := authorizeCompletePaidAction(
		t, fixture, "http-paid-action-0001", []byte("dispatch-intent"),
	)
	jsonAuthorizer, err := NewJSONPaidActionAuthorizer(actionAuthorizer)
	if err != nil {
		t.Fatal(err)
	}
	material, err := action.Material(now)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := payment.NewObserver(
		corePaymentResolver{state: chain.PaymentState{
			Network:         material.Network,
			AuthorizationID: "authorization-http-paid-action-0001",
			QuoteID:         "quote-http-paid-action-0001",
			RequestID:       material.RequestID,
			Reference:       "payment-reference-http-paid-action-0001",
			Payer:           fixture.clientID, Payee: "service-wallet",
			AmountNanoTOS: 5, Confirmed: true, Finalized: true,
			ObservedMasterSeqno: material.MinimumMasterSeqno,
			ObservedAt:          now,
		}},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	workerServer := &dispatchWorker{output: []byte("http-output")}
	worker := startDispatchWorkerClient(t, workerServer)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate, keyID: "runtime-auth-key",
	}
	server, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{
			Core:                   core,
			ChainReadiness:         &testReadinessChecker{},
			ReceiptSignerReadiness: &testReadinessChecker{},
			ProfileReadiness:       &testReadinessChecker{},
			ActionStatusAuthorizer: &testActionStatusAuthorizer{scope: journal.Scope{
				Network: material.Network, Authority: material.Authority,
				ServiceID: material.ServiceID, SessionID: material.SessionID,
				Operation: material.Operation, RequestID: material.RequestID,
			}},
			PaidActionAuthorizer: jsonAuthorizer,
			PaymentObserver:      observer, ProfilePlan: completePaidActionPlan(t),
			Worker: worker, ReceiptSigner: signer,
			PaidActionRetention: 30 * time.Minute,
			ReceiptLifetime:     time.Minute, PaidActionMaxConcurrent: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	response := httptest.NewRecorder()
	document, err := json.Marshal(paidActionDocument{
		Version: protocol.BaseEnvelopeVersion, Intent: []byte("dispatch-intent"),
		SessionGrant: credentials.SessionGrant, Quote: credentials.Quote,
		Delegations:          credentials.Delegations,
		PaymentAuthorization: credentials.PaymentAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/tos/v1/actions", bytes.NewReader(document),
	)
	request.Header.Set("Content-Type", "application/json")
	server.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != PaidActionResultMediaType ||
		!strings.Contains(response.Body.String(), `"status":"succeeded"`) ||
		!strings.Contains(response.Body.String(), `"receipt":`) ||
		!strings.Contains(response.Body.String(), "runtime-auth-key\"") ||
		workerServer.invokeCalls.Load() != 1 || signer.calls.Load() != 1 {
		t.Fatalf(
			"paid action HTTP result status=%d body=%s invokes=%d signs=%d",
			response.Code, response.Body.String(),
			workerServer.invokeCalls.Load(), signer.calls.Load(),
		)
	}
	statusResponse := httptest.NewRecorder()
	server.Routes().ServeHTTP(statusResponse, httptest.NewRequest(
		http.MethodGet, "/tos/v1/actions/"+material.RequestID, nil,
	))
	var deliveredStatus publicActionStatus
	if statusResponse.Code != http.StatusOK ||
		json.Unmarshal(statusResponse.Body.Bytes(), &deliveredStatus) != nil ||
		deliveredStatus.Status != journal.StateSucceeded ||
		deliveredStatus.Receipt == nil || len(deliveredStatus.Receipt.Payload) == 0 ||
		strings.Contains(statusResponse.Body.String(), "http-output") {
		t.Fatalf(
			"terminal action status=%d value=%#v body=%s",
			statusResponse.Code, deliveredStatus, statusResponse.Body.String(),
		)
	}
	oversizedResponse := httptest.NewRecorder()
	oversizedRequest := httptest.NewRequest(
		http.MethodPost, "/tos/v1/actions", bytes.NewReader([]byte("x")),
	)
	oversizedRequest.Header.Set("Content-Type", "application/json")
	oversizedRequest.ContentLength = maxPaidActionRequestBytes + 1
	server.Routes().ServeHTTP(oversizedResponse, oversizedRequest)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized paid action status=%d", oversizedResponse.Code)
	}
	ambiguousMediaResponse := httptest.NewRecorder()
	ambiguousMediaRequest := httptest.NewRequest(
		http.MethodPost, "/tos/v1/actions", bytes.NewReader(document),
	)
	ambiguousMediaRequest.Header.Set(
		"Content-Type", "application/json; profile=unexpected",
	)
	server.Routes().ServeHTTP(ambiguousMediaResponse, ambiguousMediaRequest)
	if ambiguousMediaResponse.Code != http.StatusBadRequest ||
		workerServer.invokeCalls.Load() != 1 {
		t.Fatalf(
			"ambiguous paid-action media type status=%d invokes=%d",
			ambiguousMediaResponse.Code, workerServer.invokeCalls.Load(),
		)
	}
	storedReceipt, err := core.Receipt(journal.Scope{
		Network: material.Network, Authority: material.Authority,
		ServiceID: material.ServiceID, SessionID: material.SessionID,
		Operation: material.Operation, RequestID: material.RequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	workerServer.completedAt.Store(storedReceipt.CompletedAt.UnixMilli())
	workerServer.getStatus = edgev1.TaskStatus_TASK_STATUS_SUCCEEDED
	workerServer.healthError.Store(true)
	server.now = func() time.Time { return now.Add(2 * readinessCacheTTL) }
	unreadyResponse := httptest.NewRecorder()
	unreadyRequest := httptest.NewRequest(
		http.MethodPost, "/tos/v1/actions", bytes.NewReader(document),
	)
	unreadyRequest.Header.Set("Content-Type", "application/json")
	server.Routes().ServeHTTP(unreadyResponse, unreadyRequest)
	if unreadResponseCode := unreadyResponse.Code; unreadResponseCode != http.StatusOK ||
		workerServer.invokeCalls.Load() != 1 || workerServer.getCalls.Load() != 1 {
		t.Fatalf(
			"unready Worker recovery status=%d invokes=%d lookups=%d",
			unreadResponseCode, workerServer.invokeCalls.Load(),
			workerServer.getCalls.Load(),
		)
	}
	_, _, secondCredentials := authorizeCompletePaidAction(
		t, fixture, "http-paid-action-0002", []byte("second-intent"),
	)
	secondDocument, err := json.Marshal(paidActionDocument{
		Version: protocol.BaseEnvelopeVersion, Intent: []byte("second-intent"),
		SessionGrant: secondCredentials.SessionGrant,
		Quote:        secondCredentials.Quote, Delegations: secondCredentials.Delegations,
		PaymentAuthorization: secondCredentials.PaymentAuthorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	blockedResponse := httptest.NewRecorder()
	blockedRequest := httptest.NewRequest(
		http.MethodPost, "/tos/v1/actions", bytes.NewReader(secondDocument),
	)
	blockedRequest.Header.Set("Content-Type", "application/json")
	server.Routes().ServeHTTP(blockedResponse, blockedRequest)
	if blockedResponse.Code != http.StatusServiceUnavailable ||
		workerServer.invokeCalls.Load() != 1 || workerServer.getCalls.Load() != 1 {
		t.Fatalf(
			"unready Worker accepted new action status=%d invokes=%d lookups=%d",
			blockedResponse.Code, workerServer.invokeCalls.Load(),
			workerServer.getCalls.Load(),
		)
	}
	if _, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{
			Core: core, PaidActionAuthorizer: fixedPaidActionHTTPAuthorizer{action: action},
		},
	); err == nil {
		t.Fatal("partial paid-action server dependencies were accepted")
	}
}

func TestPaidActionHTTPProcessingContainsDependencyPanic(t *testing.T) {
	var server *Server
	if _, err := server.callProcessAuthorizedPaidAction(
		context.Background(), authorization.AuthorizedPaidAction{}, nil, nil,
		nil, nil, time.Minute, time.Minute,
	); err == nil {
		t.Fatal("paid-action dependency panic escaped the HTTP boundary")
	}
}

func authorizeCompletePaidAction(
	t *testing.T,
	fixture coreSessionFixture,
	requestID string,
	intent []byte,
) (
	authorization.AuthorizedPaidAction,
	*authorization.PaidActionAuthorizer,
	authorization.PaidActionCredentials,
) {
	t.Helper()
	digest, err := protocol.RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "invoke", intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	quote := protocol.Quote{
		Version: protocol.BaseEnvelopeVersion,
		QuoteID: "quote-" + requestID, RequestID: requestID,
		SessionID: fixture.sessionID, ServiceID: fixture.serviceID,
		ProfileID: "tos.ai.inference", Operation: "invoke",
		IntentDigest: digest, ServiceRevision: "manifest-revision-1",
		ResourceRevision: "resource-revision-1",
		Network:          fixture.network, Payee: "service-wallet",
		Settlement:   "payment-reference-" + requestID,
		PriceNanoTOS: 5, MaxInputBytes: 1024, MaxOutputBytes: 2048,
		IssuedAt: fixture.now, Deadline: fixture.now.Add(5 * time.Minute),
		ExpiresAt: fixture.now.Add(time.Minute),
	}
	quoteEnvelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.QuoteDomain, "runtime-auth-key",
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	paymentAuthorization := protocol.PaymentAuthorization{
		Version:         protocol.BaseEnvelopeVersion,
		AuthorizationID: "authorization-" + requestID,
		QuoteID:         quote.QuoteID, RequestID: requestID,
		Network: fixture.network, Payer: fixture.clientID,
		Payee: quote.Payee, MaxNanoTOS: quote.PriceNanoTOS,
		Reference: quote.Settlement, ExpiresAt: quote.ExpiresAt,
	}
	paymentEnvelope, err := identity.SignCanonical(
		fixture.clientPrivate, protocol.PaymentAuthorizationDomain,
		fixture.clientID, paymentAuthorization, fixture.now,
		paymentAuthorization.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authorization.NewVerifier(authorization.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authorization.NewPaidActionAuthorizer(
		authorization.PaidActionAuthorizerConfig{
			Verifier: verifier,
			AuthorityResolver: actionAuthorityResolver{
				snapshot: fixture.snapshot,
			},
			ClientKeyResolver: fixture.resolver,
			Reference: authorization.Reference{
				Network:   fixture.network,
				Address:   "tos:test:service-contract",
				ServiceID: fixture.serviceID,
			},
			ManifestEnvelope:   fixture.manifestEnvelope,
			InitialMasterSeqno: fixture.snapshot.ObservedMasterSeqno,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	credentials := authorization.PaidActionCredentials{
		SessionGrant: fixture.sessionEnvelope, Quote: quoteEnvelope,
		PaymentAuthorization: paymentEnvelope,
	}
	action, err := authorizer.Authorize(
		context.Background(), credentials, intent, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return action, authorizer, credentials
}

func completePaidActionPlan(t *testing.T) *ProfileInvocationPlan {
	t.Helper()
	plan, err := NewProfileInvocationPlan(
		[]ProfileInvocationRegistration{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke",
			Mapper: ProfileInvocationMapperFunc(func(
				context.Context,
				ProfileInvocationInput,
			) (ProfileInvocationOutput, error) {
				return ProfileInvocationOutput{
					Model: "dispatch-model", Payload: []byte("input"),
				}, nil
			}),
		}},
		[]ProfileInvocationRequirement{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
