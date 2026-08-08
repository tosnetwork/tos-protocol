package atosrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func (s *Server) GetProviderStatus(
	ctx context.Context,
	req *connect.Request[atostosv1.GetProviderStatusRequest],
) (*connect.Response[atostosv1.GetProviderStatusResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("provider_id", req.Msg.ProviderId); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("capability_id", req.Msg.CapabilityId); err != nil {
		return nil, err
	}
	response := &atostosv1.GetProviderStatusResponse{
		ProviderId: req.Msg.ProviderId, CapabilityId: req.Msg.CapabilityId,
		Readiness:          atostosv1.ProviderReadiness_PROVIDER_READINESS_UNAVAILABLE,
		ObservedUnixMillis: s.now().UnixMilli(),
		ExpiresUnixMillis:  s.now().Add(5 * time.Second).UnixMilli(),
	}
	if s.worker == nil || s.router == nil {
		response.ReasonCode = "WORKER_NOT_CONFIGURED"
		return connect.NewResponse(response), nil
	}
	var capability *atostosv1.CapabilityIdentity
	_ = s.store.view(func(tx *bolt.Tx) error {
		latest := tx.Bucket(bucketCapabilityLatest).Get([]byte(req.Msg.CapabilityId))
		if latest == nil {
			return nil
		}
		value := new(atostosv1.CapabilityIdentity)
		found, err := s.store.getProto(tx, bucketCapabilities, capabilityKey(req.Msg.CapabilityId, string(latest)), value)
		if err == nil && found {
			capability = value
		}
		return err
	})
	version := "*"
	if capability != nil {
		version = capability.Version
	}
	route, found := s.router.Resolve(req.Msg.ProviderId, req.Msg.CapabilityId, version)
	if !found {
		response.ReasonCode = "ROUTE_NOT_FOUND"
		return connect.NewResponse(response), nil
	}
	callContext, cancel, err := s.boundedContext(ctx, req.Msg.Context.DeadlineUnixMillis)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if err := s.worker.CheckReady(callContext); err != nil {
		response.ReasonCode = "WORKER_UNAVAILABLE"
		return connect.NewResponse(response), nil
	}
	capabilities, err := s.worker.GetCapabilities(callContext)
	if err != nil {
		response.ReasonCode = "WORKER_UNAVAILABLE"
		return connect.NewResponse(response), nil
	}
	for _, candidate := range capabilities.Capabilities {
		if candidate.ServiceId == route.ServiceID && candidate.Operation == route.Operation && candidate.Model == route.Model {
			response.Readiness = atostosv1.ProviderReadiness_PROVIDER_READINESS_READY
			response.CapacityRevision = capabilities.CapacityRevision
			if capability != nil {
				response.AvailableTrustModes = append([]atostosv1.TrustMode(nil), capability.ActiveTrustModes...)
			} else if s.supportsMode(atostosv1.TrustMode_TRUST_MODE_MANAGED) {
				response.AvailableTrustModes = []atostosv1.TrustMode{atostosv1.TrustMode_TRUST_MODE_MANAGED}
			}
			return connect.NewResponse(response), nil
		}
	}
	response.ReasonCode = "CAPABILITY_UNAVAILABLE"
	return connect.NewResponse(response), nil
}

func (s *Server) QuoteExecution(
	ctx context.Context,
	req *connect.Request[atostosv1.QuoteExecutionRequest],
) (*connect.Response[atostosv1.QuoteExecutionResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	for name, value := range map[string]string{
		"provider_id": req.Msg.ProviderId, "capability_id": req.Msg.CapabilityId,
		"capability_version": req.Msg.CapabilityVersion,
	} {
		if err := requiredIdentifier(name, value); err != nil {
			return nil, err
		}
	}
	if err := validateDigest(req.Msg.InputCommitment); err != nil {
		return nil, err
	}
	if err := validateModeProfile(req.Msg.IntendedTrustMode, req.Msg.IntendedProofProfile); err != nil {
		return nil, err
	}
	if err := s.ensureSupported(req.Msg.IntendedTrustMode); err != nil {
		return nil, err
	}
	if req.Msg.ExecutionDeadlineUnixMillis <= s.now().UnixMilli() {
		return nil, invalid("DEADLINE_EXCEEDED", "execution deadline has elapsed")
	}
	if s.worker == nil || s.router == nil {
		return nil, unavailable("PROVIDER_UNAVAILABLE", "private Worker route is not configured")
	}
	route, found := s.router.Resolve(req.Msg.ProviderId, req.Msg.CapabilityId, req.Msg.CapabilityVersion)
	if !found {
		return nil, notFound("CAPABILITY_UNAVAILABLE", "no private Worker route matches capability")
	}
	maxOutput := req.Msg.MaxOutputBytes
	if maxOutput == 0 || maxOutput > route.MaxOutputBytes {
		maxOutput = route.MaxOutputBytes
	}
	callContext, cancel, err := s.boundedContext(ctx, req.Msg.ExecutionDeadlineUnixMillis)
	if err != nil {
		return nil, err
	}
	defer cancel()
	workerQuote, err := s.worker.Quote(callContext, &edgev1.QuoteRequest{
		RequestId: req.Msg.Context.RequestId, ServiceId: route.ServiceID,
		Operation: route.Operation, Model: route.Model,
		InputBytes: req.Msg.InputBytes, MaxOutputBytes: maxOutput,
		DeadlineUnixMillis: req.Msg.ExecutionDeadlineUnixMillis,
		Priority:           route.Priority,
	})
	if err != nil {
		return nil, unavailable("PROVIDER_UNAVAILABLE", "private Worker quote failed: "+err.Error())
	}
	workerDigest, err := protoDigest("TOS-PRIVATE-WORKER-QUOTE-V1", workerQuote)
	if err != nil {
		return nil, err
	}
	rawDigest := strings.TrimPrefix(workerDigest, "sha256:")
	digestBytes, _ := hexDecode(rawDigest)
	ref, err := s.authority.Commit(ctx, "service-execution-quote", workerQuote.QuoteId, workerDigest)
	if err != nil {
		return nil, unavailable("NETWORK_UNAVAILABLE", "service quote commitment failed")
	}
	quote := &atostosv1.ServiceExecutionQuote{
		ServiceQuoteId: workerQuote.QuoteId, ProviderId: req.Msg.ProviderId,
		CapabilityId: req.Msg.CapabilityId, CapabilityVersion: req.Msg.CapabilityVersion,
		ProviderPrice:               &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: fmt.Sprintf("%d", workerQuote.PriceNanoTos)},
		ExpiresUnixMillis:           workerQuote.ExpiresUnixMillis,
		ExecutionDeadlineUnixMillis: req.Msg.ExecutionDeadlineUnixMillis,
		CapacityRevision:            workerQuote.CapacityRevision,
		RuntimeRevision:             workerQuote.RuntimeRevision,
		ModelRevision:               workerQuote.ModelRevision,
		SignedQuoteDigest:           &atostosv1.Digest{Algorithm: "sha256", Value: digestBytes},
		QuoteRef:                    &ref,
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(quote)
	if err != nil {
		return nil, err
	}
	if err := s.store.update(func(tx *bolt.Tx) error {
		inputCommitment, err := (proto.MarshalOptions{Deterministic: true}).Marshal(req.Msg.InputCommitment)
		if err != nil {
			return err
		}
		return s.store.putJSON(tx, bucketServiceQuotes, quote.ServiceQuoteId, storedServiceQuote{
			Quote: encoded, Route: route, InputCommitment: inputCommitment,
			MaxOutputBytes: maxOutput,
		})
	}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&atostosv1.QuoteExecutionResponse{Quote: quote}), nil
}

func hexDecode(value string) ([]byte, error) {
	if len(value)%2 != 0 {
		return nil, errors.New("invalid hex")
	}
	result := make([]byte, len(value)/2)
	for i := range result {
		high, ok := hexNibble(value[2*i])
		if !ok {
			return nil, errors.New("invalid hex")
		}
		low, ok := hexNibble(value[2*i+1])
		if !ok {
			return nil, errors.New("invalid hex")
		}
		result[i] = high<<4 | low
	}
	return result, nil
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func (s *Server) SubmitJob(
	ctx context.Context,
	req *connect.Request[atostosv1.SubmitJobRequest],
) (*connect.Response[atostosv1.SubmitJobResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateMutationContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	for name, value := range map[string]string{
		"job_id": req.Msg.JobId, "principal_id": req.Msg.PrincipalId,
		"provider_id": req.Msg.ProviderId, "capability_id": req.Msg.CapabilityId,
		"capability_version": req.Msg.CapabilityVersion, "quote_id": req.Msg.QuoteId,
		"service_quote_id": req.Msg.ServiceQuoteId, "escrow_id": req.Msg.EscrowId,
	} {
		if err := requiredIdentifier(name, value); err != nil {
			return nil, err
		}
	}
	if err := validateModeProfile(req.Msg.TrustMode, req.Msg.ProofProfile); err != nil {
		return nil, err
	}
	if err := s.ensureSupported(req.Msg.TrustMode); err != nil {
		return nil, err
	}
	if !digestEqual(req.Msg.InputCommitment, req.Msg.Input) {
		return nil, invalid("INPUT_COMMITMENT_MISMATCH", "input bytes do not match input_commitment")
	}
	if req.Msg.ExecutionDeadlineUnixMillis <= s.now().UnixMilli() {
		return nil, rpcError(connect.CodeDeadlineExceeded, "DEADLINE_EXCEEDED", "execution deadline has elapsed")
	}
	if req.Msg.RetainUntilUnixMillis <= req.Msg.ExecutionDeadlineUnixMillis {
		return nil, invalid("INVALID_ARGUMENT", "retain_until must be after execution deadline")
	}
	if s.worker == nil {
		return nil, unavailable("PROVIDER_UNAVAILABLE", "private Worker is not configured")
	}
	lock := s.jobLock(req.Msg.JobId)
	lock.Lock()
	defer lock.Unlock()

	requestDigest, err := protoDigest("ATOS-TOS-SUBMIT-JOB-V1", req.Msg)
	if err != nil {
		return nil, err
	}
	idemKey := idempotencyKey("SubmitJob", req.Msg.Context)
	response := new(atostosv1.SubmitJobResponse)
	newSubmission := false
	var stored storedExecutionJob
	err = s.store.update(func(tx *bolt.Tx) error {
		var idem idempotencyRecord
		found, err := s.store.getJSON(tx, bucketIdempotency, idemKey, &idem)
		if err != nil {
			return err
		}
		if found {
			if idem.RequestDigest != requestDigest {
				return conflict("IDEMPOTENCY_CONFLICT", "idempotency key is bound to another job request")
			}
			if idem.Status == idempotencyCompleted && len(idem.Response) > 0 {
				return proto.Unmarshal(idem.Response, response)
			}
			jobFound, err := s.store.getJSON(tx, bucketJobs, req.Msg.JobId, &stored)
			if err != nil {
				return err
			}
			if !jobFound {
				return unavailable("EXECUTION_UNCERTAIN", "idempotency claim exists without a durable job")
			}
			return nil
		}
		jobFound, err := s.store.getJSON(tx, bucketJobs, req.Msg.JobId, &stored)
		if err != nil {
			return err
		}
		if jobFound {
			if stored.RequestDigest != requestDigest {
				return conflict("JOB_MISMATCH", "job ID is already bound to different execution input")
			}
			return s.store.putJSON(tx, bucketIdempotency, idemKey, idempotencyRecord{
				RequestDigest: requestDigest, Status: idempotencyInProgress,
				CreatedAtMS: s.now().UnixMilli(), UpdatedAtMS: s.now().UnixMilli(),
			})
		}
		serviceQuote, route, quotedInput, quotedMaxOutput, err := s.loadServiceQuoteTx(tx, req.Msg.ServiceQuoteId)
		if err != nil {
			return err
		}
		if serviceQuote.ProviderId != req.Msg.ProviderId || serviceQuote.CapabilityId != req.Msg.CapabilityId ||
			serviceQuote.CapabilityVersion != req.Msg.CapabilityVersion ||
			serviceQuote.ExpiresUnixMillis <= s.now().UnixMilli() ||
			serviceQuote.ExecutionDeadlineUnixMillis != req.Msg.ExecutionDeadlineUnixMillis ||
			!proto.Equal(quotedInput, req.Msg.InputCommitment) ||
			(req.Msg.MaxOutputBytes > 0 && req.Msg.MaxOutputBytes > quotedMaxOutput) {
			return failedPrecondition("QUOTE_MISMATCH", "service execution quote does not match job")
		}
		quote := new(atostosv1.QuoteCommitment)
		found, err = s.store.getProto(tx, bucketQuoteCommitments, req.Msg.QuoteId, quote)
		if err != nil {
			return err
		}
		if !found || quote.Value == nil || quote.Value.PrincipalId != req.Msg.PrincipalId ||
			quote.Value.ProviderId != req.Msg.ProviderId || quote.Value.CapabilityId != req.Msg.CapabilityId ||
			quote.Value.CapabilityVersion != req.Msg.CapabilityVersion || quote.Value.TrustMode != req.Msg.TrustMode ||
			quote.Value.ProofProfile != req.Msg.ProofProfile ||
			quote.Value.UnderlyingServiceQuoteRef != req.Msg.ServiceQuoteId {
			return failedPrecondition("QUOTE_MISMATCH", "ATOS quote commitment does not match job")
		}
		escrow := new(atostosv1.Escrow)
		found, err = s.store.getProto(tx, bucketEscrows, req.Msg.EscrowId, escrow)
		if err != nil {
			return err
		}
		if !found || escrow.QuoteId != req.Msg.QuoteId || escrow.State != atostosv1.EscrowState_ESCROW_STATE_RESERVED {
			return failedPrecondition("ESCROW_MISMATCH", "reserved escrow does not match job")
		}
		maxOutput := req.Msg.MaxOutputBytes
		if maxOutput == 0 || maxOutput > route.MaxOutputBytes {
			maxOutput = route.MaxOutputBytes
		}
		workerRequest := &edgev1.InvokeRequest{
			RequestId: req.Msg.JobId, QuoteId: req.Msg.ServiceQuoteId,
			TaskId:    "task-" + strings.TrimPrefix(requestDigest, "sha256:")[:32],
			ServiceId: route.ServiceID, Operation: route.Operation, Model: route.Model,
			Payload: append([]byte(nil), req.Msg.Input...), MaxOutputBytes: maxOutput,
			DeadlineUnixMillis: req.Msg.ExecutionDeadlineUnixMillis,
			Priority:           route.Priority, RetainUntilUnixMillis: req.Msg.RetainUntilUnixMillis,
		}
		prepared, _, err := localrpc.BindInvocationRequest(workerRequest)
		if err != nil {
			return invalid("INVALID_ARGUMENT", "Worker invocation cannot be bound: "+err.Error())
		}
		workerRequest = prepared
		workerEncoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(workerRequest)
		if err != nil {
			return err
		}
		record := &atostosv1.JobRecord{
			JobId: req.Msg.JobId, EdgeActionId: "edge-" + req.Msg.JobId,
			WorkerTaskId: workerRequest.TaskId, QuoteId: req.Msg.QuoteId,
			ServiceQuoteId: req.Msg.ServiceQuoteId, EscrowId: req.Msg.EscrowId,
			ProviderId: req.Msg.ProviderId, CapabilityId: req.Msg.CapabilityId,
			CapabilityVersion: req.Msg.CapabilityVersion, TrustMode: req.Msg.TrustMode,
			ProofProfile: req.Msg.ProofProfile, State: atostosv1.JobState_JOB_STATE_SUBMITTED,
			ProofStatus:       initialExecutionProofStatus(req.Msg.TrustMode),
			CreatedUnixMillis: s.now().UnixMilli(), UpdatedUnixMillis: s.now().UnixMilli(),
		}
		recordEncoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(record)
		if err != nil {
			return err
		}
		stored = storedExecutionJob{
			Record: recordEncoded, WorkerRequest: workerEncoded,
			RequestDigest: requestDigest, Input: append([]byte(nil), req.Msg.Input...),
		}
		if err := s.store.putJSON(tx, bucketJobs, req.Msg.JobId, stored); err != nil {
			return err
		}
		nowMS := s.now().UnixMilli()
		if err := s.store.putJSON(tx, bucketIdempotency, idemKey, idempotencyRecord{
			RequestDigest: requestDigest, Status: idempotencyInProgress,
			CreatedAtMS: nowMS, UpdatedAtMS: nowMS,
		}); err != nil {
			return err
		}
		newSubmission = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if response.JobId != "" {
		return connect.NewResponse(response), nil
	}
	if req.Msg.TrustMode == TrustModeVerified {
		if err := s.acceptEconomicEscrow(ctx, req.Msg.EscrowId, req.Msg.ProviderId); err != nil {
			return nil, err
		}
		_, record, decodeErr := decodeExecutionJob(stored)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if record.ProofStatus == nil {
			record.ProofStatus = initialExecutionProofStatus(record.TrustMode)
		}
		record.ProofStatus.Escrow = atostosv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
		if err := s.updateStoredJobRecord(req.Msg.JobId, &stored, record); err != nil {
			return nil, err
		}
	}
	if newSubmission {
		response, err = s.invokeDurableJob(ctx, req.Msg.JobId, stored)
	} else {
		response, err = s.recoverDurableJob(ctx, req.Msg.JobId, stored)
	}
	if err != nil {
		return nil, err
	}
	if err := s.finishSubmitIdempotency(idemKey, requestDigest, response); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) loadServiceQuoteTx(tx *bolt.Tx, id string) (*atostosv1.ServiceExecutionQuote, Route, *atostosv1.Digest, uint64, error) {
	var stored storedServiceQuote
	found, err := s.store.getJSON(tx, bucketServiceQuotes, id, &stored)
	if err != nil {
		return nil, Route{}, nil, 0, err
	}
	if !found {
		return nil, Route{}, nil, 0, notFound("QUOTE_MISMATCH", "service execution quote not found")
	}
	quote := new(atostosv1.ServiceExecutionQuote)
	if err := proto.Unmarshal(stored.Quote, quote); err != nil {
		return nil, Route{}, nil, 0, err
	}
	inputCommitment := new(atostosv1.Digest)
	if len(stored.InputCommitment) == 0 {
		return nil, Route{}, nil, 0, failedPrecondition("QUOTE_MISMATCH", "service quote is missing its input commitment")
	}
	if err := proto.Unmarshal(stored.InputCommitment, inputCommitment); err != nil {
		return nil, Route{}, nil, 0, err
	}
	return quote, stored.Route, inputCommitment, stored.MaxOutputBytes, nil
}

func initialExecutionProofStatus(mode atostosv1.TrustMode) *atostosv1.ProofStatus {
	status := &atostosv1.ProofStatus{
		Quote:      atostosv1.VerificationStatus_VERIFICATION_STATUS_NOT_REQUIRED,
		Escrow:     atostosv1.VerificationStatus_VERIFICATION_STATUS_PENDING,
		Receipt:    atostosv1.VerificationStatus_VERIFICATION_STATUS_PENDING,
		Settlement: atostosv1.VerificationStatus_VERIFICATION_STATUS_PENDING,
	}
	if mode != atostosv1.TrustMode_TRUST_MODE_MANAGED {
		status.Quote = atostosv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
	}
	return status
}

func (s *Server) invokeDurableJob(ctx context.Context, jobID string, stored storedExecutionJob) (*atostosv1.SubmitJobResponse, error) {
	workerRequest, record, err := decodeExecutionJob(stored)
	if err != nil {
		return nil, err
	}
	record.State = atostosv1.JobState_JOB_STATE_WORKING
	record.UpdatedUnixMillis = s.now().UnixMilli()
	if err := s.updateStoredJobRecord(jobID, &stored, record); err != nil {
		return nil, err
	}
	callContext, cancel, err := s.boundedContext(ctx, workerRequest.DeadlineUnixMillis)
	if err != nil {
		return nil, err
	}
	defer cancel()
	validated, invokeErr := s.worker.Invoke(callContext, workerRequest)
	if invokeErr == nil {
		completion, err := validated.Completion(localrpc.InvocationBinding{
			RequestID: workerRequest.RequestId, QuoteID: workerRequest.QuoteId,
			ServiceID: workerRequest.ServiceId, Operation: workerRequest.Operation,
		})
		if err != nil {
			return nil, err
		}
		return s.completeDurableJob(jobID, &stored, record, completion)
	}
	// Never blindly resubmit. Resolve the exact task identity through the
	// private read-only recovery RPC.
	response, recoveryErr := s.recoverDurableJob(ctx, jobID, stored)
	if recoveryErr != nil {
		record.State = atostosv1.JobState_JOB_STATE_UNCERTAIN
		record.ErrorCode = "EXECUTION_UNCERTAIN"
		record.UpdatedUnixMillis = s.now().UnixMilli()
		_ = s.updateStoredJobRecord(jobID, &stored, record)
		return submitResponse(record), nil
	}
	return response, nil
}

func (s *Server) recoverDurableJob(ctx context.Context, jobID string, stored storedExecutionJob) (*atostosv1.SubmitJobResponse, error) {
	workerRequest, record, err := decodeExecutionJob(stored)
	if err != nil {
		return nil, err
	}
	if terminalJob(record.State) {
		return submitResponse(record), nil
	}
	callContext, cancel, err := s.boundedContext(ctx, 0)
	if err != nil {
		return nil, err
	}
	defer cancel()
	recovered, err := s.worker.GetTask(callContext, workerRequest)
	if err != nil {
		record.State = atostosv1.JobState_JOB_STATE_UNCERTAIN
		record.ErrorCode = "EXECUTION_UNCERTAIN"
		record.UpdatedUnixMillis = s.now().UnixMilli()
		_ = s.updateStoredJobRecord(jobID, &stored, record)
		return submitResponse(record), nil
	}
	status, err := recovered.Status()
	if err != nil {
		return nil, err
	}
	switch status {
	case edgev1.TaskStatus_TASK_STATUS_SUCCEEDED:
		completion, err := recovered.Completion(localrpc.InvocationBinding{
			RequestID: workerRequest.RequestId, QuoteID: workerRequest.QuoteId,
			ServiceID: workerRequest.ServiceId, Operation: workerRequest.Operation,
		})
		if err != nil {
			return nil, err
		}
		return s.completeDurableJob(jobID, &stored, record, completion)
	case edgev1.TaskStatus_TASK_STATUS_FAILED:
		record.State = atostosv1.JobState_JOB_STATE_FAILED
		record.ErrorCode, _ = recovered.ErrorCode()
	case edgev1.TaskStatus_TASK_STATUS_CANCELED:
		record.State = atostosv1.JobState_JOB_STATE_CANCELED
		record.ErrorCode = "CANCELED"
	case edgev1.TaskStatus_TASK_STATUS_TIMED_OUT:
		record.State = atostosv1.JobState_JOB_STATE_FAILED
		record.ErrorCode = "DEADLINE_EXCEEDED"
	case edgev1.TaskStatus_TASK_STATUS_ACCEPTED, edgev1.TaskStatus_TASK_STATUS_RUNNING:
		record.State = atostosv1.JobState_JOB_STATE_WORKING
		record.ErrorCode = ""
	default:
		record.State = atostosv1.JobState_JOB_STATE_UNCERTAIN
		record.ErrorCode = "EXECUTION_UNCERTAIN"
	}
	record.UpdatedUnixMillis = s.now().UnixMilli()
	if terminalJob(record.State) {
		record.CompletedUnixMillis = s.now().UnixMilli()
	}
	if err := s.updateStoredJobRecord(jobID, &stored, record); err != nil {
		return nil, err
	}
	return submitResponse(record), nil
}

func decodeExecutionJob(stored storedExecutionJob) (*edgev1.InvokeRequest, *atostosv1.JobRecord, error) {
	workerRequest := new(edgev1.InvokeRequest)
	if err := proto.Unmarshal(stored.WorkerRequest, workerRequest); err != nil {
		return nil, nil, err
	}
	record := new(atostosv1.JobRecord)
	if err := proto.Unmarshal(stored.Record, record); err != nil {
		return nil, nil, err
	}
	return workerRequest, record, nil
}

func (s *Server) completeDurableJob(jobID string, stored *storedExecutionJob, record *atostosv1.JobRecord, completion localrpc.InvocationCompletion) (*atostosv1.SubmitJobResponse, error) {
	usage := &atostosv1.Usage{
		InputBytes: completion.Usage.InputBytes, OutputBytes: completion.Usage.OutputBytes,
		InputTokens: completion.Usage.InputTokens, OutputTokens: completion.Usage.OutputTokens,
		ExecutionMillis: completion.Usage.ExecutionMillis,
		Extensions: map[string]string{
			"model_revision":        completion.ModelRevision,
			"runtime_revision":      completion.RuntimeRevision,
			"worker_request_digest": completion.RequestDigest,
		},
	}
	usageEncoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(usage)
	if err != nil {
		return nil, err
	}
	var authorization *atostosv1.ExecutionSignerAuthorization
	err = s.store.update(func(tx *bolt.Tx) error {
		if record.TrustMode == atostosv1.TrustMode_TRUST_MODE_MANAGED {
			var err error
			authorization, err = s.ensureLocalExecutionSignerTx(tx, record.ProviderId, record.CapabilityId, record.CapabilityVersion)
			return err
		}
		value := new(atostosv1.ExecutionSignerAuthorization)
		found, err := s.store.getProto(tx, bucketSignerAuths, signerKey(record.ProviderId, record.CapabilityId, record.CapabilityVersion, s.signerID), value)
		if err != nil {
			return err
		}
		if !found || value.Revoked {
			return failedPrecondition("SIGNER_NOT_AUTHORIZED", "Edge execution signer is not authorized for this capability version")
		}
		authorization = value
		return nil
	})
	if err != nil {
		return nil, err
	}
	if authorization == nil || authorization.Value == nil {
		return nil, failedPrecondition("SIGNER_NOT_AUTHORIZED", "execution signer authorization is unavailable")
	}
	receipt := &atostosv1.ExecutionReceiptEnvelope{
		QuoteId: record.QuoteId, EscrowId: record.EscrowId, JobId: record.JobId,
		PrincipalId: "", ProviderId: record.ProviderId, CapabilityId: record.CapabilityId,
		CapabilityVersion: record.CapabilityVersion, TrustMode: record.TrustMode,
		ProofProfile: record.ProofProfile, Result: atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS,
		InputCommitment: digestMessage(stored.Input), OutputCommitment: digestMessage(completion.Output),
		UsageCommitment: digestMessage(usageEncoded), Usage: usage,
		ExecutionSignerId:     s.signerID,
		SignerAuthorizationId: authorization.Value.AuthorizationId,
		CompletedUnixMillis:   completion.CompletedAt.UnixMilli(),
	}
	// Principal identity and the client-visible maximum charge are recovered
	// from the immutable ATOS quote commitment before the receipt is signed.
	// A caller must never need to mutate these signed bytes merely to settle
	// the job; doing so would invalidate the execution-signature chain.
	if err := s.store.view(func(tx *bolt.Tx) error {
		quote := new(atostosv1.QuoteCommitment)
		found, err := s.store.getProto(tx, bucketQuoteCommitments, record.QuoteId, quote)
		if err != nil {
			return err
		}
		if !found || quote.Value == nil || quote.Value.TotalMax == nil {
			return failedPrecondition("QUOTE_MISMATCH", "quote commitment disappeared or has no charge before receipt issuance")
		}
		receipt.PrincipalId = quote.Value.PrincipalId
		receipt.ClientCharge = cloneMessage(quote.Value.TotalMax)
		escrow := new(atostosv1.Escrow)
		found, err = s.store.getProto(tx, bucketEscrows, record.EscrowId, escrow)
		if err != nil {
			return err
		}
		if !found || escrow.Reserved == nil || escrow.QuoteId != record.QuoteId {
			return failedPrecondition("ESCROW_MISMATCH", "escrow disappeared before receipt issuance")
		}
		receipt.NetworkCharge = cloneMessage(escrow.Reserved)
		return nil
	}); err != nil {
		return nil, err
	}
	receiptSeed, err := protoDigest("ATOS-TOS-RECEIPT-ID-V1", receipt)
	if err != nil {
		return nil, err
	}
	receipt.ReceiptId = shortID("rcpt-", receiptSeed)
	if err := s.signReceipt(receipt); err != nil {
		return nil, err
	}
	canonicalReceipt, err := (proto.MarshalOptions{Deterministic: true}).Marshal(receipt)
	if err != nil {
		return nil, err
	}
	record.State = atostosv1.JobState_JOB_STATE_COMPLETED
	record.UpdatedUnixMillis = completion.CompletedAt.UnixMilli()
	record.CompletedUnixMillis = completion.CompletedAt.UnixMilli()
	record.ErrorCode = ""
	if record.ProofStatus == nil {
		record.ProofStatus = initialExecutionProofStatus(record.TrustMode)
	}
	record.ProofStatus.Receipt = atostosv1.VerificationStatus_VERIFICATION_STATUS_PENDING
	stored.Output = append([]byte(nil), completion.Output...)
	stored.OutputDigest = bytesDigest("ATOS-TOS-JOB-OUTPUT-V1", completion.Output)
	stored.Usage = usageEncoded
	stored.CanonicalReceipt = canonicalReceipt
	stored.ReceiptDigest = bytesDigest("ATOS-TOS-EXECUTION-RECEIPT-V1", canonicalReceipt)
	if err := s.updateStoredJobRecord(jobID, stored, record); err != nil {
		return nil, err
	}
	return submitResponse(record), nil
}

func (s *Server) updateStoredJobRecord(jobID string, stored *storedExecutionJob, record *atostosv1.JobRecord) error {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(record)
	if err != nil {
		return err
	}
	stored.Record = encoded
	return s.store.update(func(tx *bolt.Tx) error {
		return s.store.putJSON(tx, bucketJobs, jobID, stored)
	})
}

func (s *Server) finishSubmitIdempotency(key, requestDigest string, response *atostosv1.SubmitJobResponse) error {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(response)
	if err != nil {
		return err
	}
	return s.store.update(func(tx *bolt.Tx) error {
		var record idempotencyRecord
		found, err := s.store.getJSON(tx, bucketIdempotency, key, &record)
		if err != nil {
			return err
		}
		if found && record.RequestDigest != requestDigest {
			return conflict("IDEMPOTENCY_CONFLICT", "idempotency record changed during execution")
		}
		nowMS := s.now().UnixMilli()
		if !found {
			record.CreatedAtMS = nowMS
		}
		record.RequestDigest = requestDigest
		record.Response = encoded
		record.Status = idempotencyCompleted
		record.UpdatedAtMS = nowMS
		return s.store.putJSON(tx, bucketIdempotency, key, record)
	})
}

func submitResponse(record *atostosv1.JobRecord) *atostosv1.SubmitJobResponse {
	return &atostosv1.SubmitJobResponse{
		JobId: record.JobId, EdgeActionId: record.EdgeActionId,
		WorkerTaskId: record.WorkerTaskId, State: record.State,
		TrustMode: record.TrustMode, ProofProfile: record.ProofProfile,
		ProofStatus:                   cloneMessage(record.ProofStatus),
		CreatedUnixMillis:             record.CreatedUnixMillis,
		EstimatedCompletionUnixMillis: 0,
	}
}

func terminalJob(state atostosv1.JobState) bool {
	switch state {
	case atostosv1.JobState_JOB_STATE_COMPLETED, atostosv1.JobState_JOB_STATE_FAILED,
		atostosv1.JobState_JOB_STATE_CANCELED, atostosv1.JobState_JOB_STATE_REJECTED:
		return true
	default:
		return false
	}
}

func (s *Server) GetJob(
	ctx context.Context,
	req *connect.Request[atostosv1.GetJobRequest],
) (*connect.Response[atostosv1.GetJobResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("job_id", req.Msg.JobId); err != nil {
		return nil, err
	}
	lock := s.jobLock(req.Msg.JobId)
	lock.Lock()
	defer lock.Unlock()
	stored, found, err := s.loadStoredJob(req.Msg.JobId)
	if err != nil {
		return nil, err
	}
	if !found {
		return connect.NewResponse(&atostosv1.GetJobResponse{}), nil
	}
	_, record, err := decodeExecutionJob(stored)
	if err != nil {
		return nil, err
	}
	if !terminalJob(record.State) && s.worker != nil {
		_, _ = s.recoverDurableJob(ctx, req.Msg.JobId, stored)
		stored, _, _ = s.loadStoredJob(req.Msg.JobId)
		_, record, _ = decodeExecutionJob(stored)
	}
	return connect.NewResponse(&atostosv1.GetJobResponse{Job: record, Found: true}), nil
}

func (s *Server) loadStoredJob(jobID string) (storedExecutionJob, bool, error) {
	var stored storedExecutionJob
	found := false
	err := s.store.view(func(tx *bolt.Tx) error {
		var err error
		found, err = s.store.getJSON(tx, bucketJobs, jobID, &stored)
		return err
	})
	return stored, found, err
}

func (s *Server) CancelJob(
	ctx context.Context,
	req *connect.Request[atostosv1.CancelJobRequest],
) (*connect.Response[atostosv1.CancelJobResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateMutationContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("job_id", req.Msg.JobId); err != nil {
		return nil, err
	}
	lock := s.jobLock(req.Msg.JobId)
	lock.Lock()
	defer lock.Unlock()
	stored, found, err := s.loadStoredJob(req.Msg.JobId)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, notFound("NOT_FOUND", "job not found")
	}
	workerRequest, record, err := decodeExecutionJob(stored)
	if err != nil {
		return nil, err
	}
	if terminalJob(record.State) {
		return connect.NewResponse(&atostosv1.CancelJobResponse{Job: record, Accepted: record.State == atostosv1.JobState_JOB_STATE_CANCELED}), nil
	}
	if s.worker == nil {
		return nil, unavailable("PROVIDER_UNAVAILABLE", "private Worker is not configured")
	}
	callContext, cancel, err := s.boundedContext(ctx, req.Msg.Context.DeadlineUnixMillis)
	if err != nil {
		return nil, err
	}
	defer cancel()
	accepted, err := s.worker.Cancel(callContext, workerRequest)
	if err != nil {
		return nil, unavailable("PROVIDER_UNAVAILABLE", "private Worker cancellation failed")
	}
	if accepted {
		record.State = atostosv1.JobState_JOB_STATE_CANCELED
		record.ErrorCode = "CANCELED_BY_CALLER"
		record.UpdatedUnixMillis = s.now().UnixMilli()
		record.CompletedUnixMillis = record.UpdatedUnixMillis
		if err := s.updateStoredJobRecord(req.Msg.JobId, &stored, record); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(&atostosv1.CancelJobResponse{Job: record, Accepted: accepted}), nil
}

func (s *Server) StreamJob(
	ctx context.Context,
	req *connect.Request[atostosv1.StreamJobRequest],
	stream *connect.ServerStream[atostosv1.JobEvent],
) error {
	if req == nil || req.Msg == nil || stream == nil {
		return invalid("INVALID_ARGUMENT", "request and stream are required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return err
	}
	stored, found, err := s.loadStoredJob(req.Msg.JobId)
	if err != nil {
		return err
	}
	if !found {
		return notFound("NOT_FOUND", "job not found")
	}
	_, record, err := decodeExecutionJob(stored)
	if err != nil {
		return err
	}
	sequence := req.Msg.NextSequence
	if err := stream.Send(&atostosv1.JobEvent{
		JobId: record.JobId, Sequence: sequence,
		EventType: atostosv1.JobEventType_JOB_EVENT_TYPE_STATE,
		State:     record.State, ProofStatus: cloneMessage(record.ProofStatus),
		EventUnixMillis: s.now().UnixMilli(),
	}); err != nil {
		return err
	}
	sequence++
	if len(stored.Output) > 0 {
		chunkSize := req.Msg.MaxChunkBytes
		if chunkSize == 0 || chunkSize > 256<<10 {
			chunkSize = 256 << 10
		}
		for offset := uint64(0); offset < uint64(len(stored.Output)); offset += chunkSize {
			end := offset + chunkSize
			if end > uint64(len(stored.Output)) {
				end = uint64(len(stored.Output))
			}
			if err := stream.Send(&atostosv1.JobEvent{
				JobId: record.JobId, Sequence: sequence,
				EventType: atostosv1.JobEventType_JOB_EVENT_TYPE_OUTPUT_CHUNK,
				State:     record.State, Chunk: append([]byte(nil), stored.Output[offset:end]...),
				Offset: offset, TotalOutputBytes: uint64(len(stored.Output)),
				StreamDigest: digestMessage(stored.Output), EventUnixMillis: s.now().UnixMilli(),
			}); err != nil {
				return err
			}
			sequence++
		}
	}
	return stream.Send(&atostosv1.JobEvent{
		JobId: record.JobId, Sequence: sequence,
		EventType: atostosv1.JobEventType_JOB_EVENT_TYPE_TERMINAL,
		State:     record.State, Terminal: terminalJob(record.State),
		ProofStatus: cloneMessage(record.ProofStatus), EventUnixMillis: s.now().UnixMilli(),
		ErrorCode: record.ErrorCode,
	})
}

func (s *Server) FetchResult(
	ctx context.Context,
	req *connect.Request[atostosv1.FetchResultRequest],
) (*connect.Response[atostosv1.FetchResultResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	lock := s.jobLock(req.Msg.JobId)
	lock.Lock()
	defer lock.Unlock()
	stored, found, err := s.loadStoredJob(req.Msg.JobId)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, notFound("NOT_FOUND", "job not found")
	}
	_, record, err := decodeExecutionJob(stored)
	if err != nil {
		return nil, err
	}
	if !terminalJob(record.State) && s.worker != nil {
		_, _ = s.recoverDurableJob(ctx, req.Msg.JobId, stored)
		stored, _, _ = s.loadStoredJob(req.Msg.JobId)
		_, record, _ = decodeExecutionJob(stored)
	}
	usage := new(atostosv1.Usage)
	if len(stored.Usage) > 0 {
		_ = proto.Unmarshal(stored.Usage, usage)
	}
	response := &atostosv1.FetchResultResponse{
		JobId: record.JobId, State: record.State,
		Output: append([]byte(nil), stored.Output...), OutputCommitment: digestMessage(stored.Output),
		Usage: usage, CompletedUnixMillis: record.CompletedUnixMillis, ErrorCode: record.ErrorCode,
	}
	return connect.NewResponse(response), nil
}

func (s *Server) FetchExecutionReceipt(
	_ context.Context,
	req *connect.Request[atostosv1.FetchExecutionReceiptRequest],
) (*connect.Response[atostosv1.FetchExecutionReceiptResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	stored, found, err := s.loadStoredJob(req.Msg.JobId)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, notFound("NOT_FOUND", "job not found")
	}
	if len(stored.CanonicalReceipt) == 0 {
		return nil, failedPrecondition("RECEIPT_NOT_READY", "execution receipt is not available")
	}
	receipt := new(atostosv1.ExecutionReceiptEnvelope)
	if err := proto.Unmarshal(stored.CanonicalReceipt, receipt); err != nil {
		return nil, err
	}
	return connect.NewResponse(&atostosv1.FetchExecutionReceiptResponse{
		JobId: req.Msg.JobId, ReceiptId: receipt.ReceiptId,
		CanonicalReceipt:   append([]byte(nil), stored.CanonicalReceipt...),
		ReceiptDigest:      canonicalReceiptDigest(stored.CanonicalReceipt),
		VerificationStatus: atostosv1.VerificationStatus_VERIFICATION_STATUS_PENDING,
	}), nil
}

func marshalJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func equalBytes(left, right []byte) bool { return bytes.Equal(left, right) }
