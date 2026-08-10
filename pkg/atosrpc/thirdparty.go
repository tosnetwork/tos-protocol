package atosrpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// defaultThirdPartyQuoteTTL bounds how long a third-party ServiceExecutionQuote
// stays valid for SubmitJob to consume. There is no worker-supplied capacity/
// price TTL to inherit the way the native path inherits workerQuote.
// ExpiresUnixMillis, so this is a fixed, conservative bound instead.
const defaultThirdPartyQuoteTTL = 5 * time.Minute

func randomHexID(prefix string, byteLength int) (string, error) {
	raw := make([]byte, byteLength)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

// validateThirdPartyBinding validates an optional ThirdPartyBinding. A nil
// binding is valid -- it means an ordinary tos-native/model request, per
// atos-spec docs/THIRD_PARTY_EXECUTION_PLANE.md.
func validateThirdPartyBinding(b *atostosv1.ThirdPartyBinding) error {
	if b == nil {
		return nil
	}
	if b.Transport == atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_UNSPECIFIED {
		return invalid("INVALID_ARGUMENT", "third_party_binding.transport is required")
	}
	if strings.TrimSpace(b.EndpointRef) == "" {
		return invalid("INVALID_ARGUMENT", "third_party_binding.endpoint_ref is required")
	}
	if err := validateDigest(b.BindingCommitment); err != nil {
		return invalid("INVALID_ARGUMENT", "third_party_binding.binding_commitment: "+err.Error())
	}
	return nil
}

func mapThirdPartyTransport(t atostosv1.EndpointAdapterType) (edgev1.ThirdPartyTransport, error) {
	switch t {
	case atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_HTTP:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_HTTP, nil
	case atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_MCP:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_MCP, nil
	case atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_A2A:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_A2A, nil
	default:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_UNSPECIFIED, invalid("INVALID_ARGUMENT", "unsupported third_party_binding.transport")
	}
}

// toEdgeBindingRef maps an atos.tos.v1.ThirdPartyBinding (the ATOS-facing
// wire shape) to a tos.edge.v1.ThirdPartyBindingRef (the private Worker
// boundary wire shape) -- the two are intentionally independent proto
// definitions (see worker.proto's own doc comment on why this boundary
// stays decoupled from ATOS-specific types), so this is where they're
// reconciled.
func toEdgeBindingRef(b *atostosv1.ThirdPartyBinding, capabilityID, capabilityVersion string) (*edgev1.ThirdPartyBindingRef, error) {
	transport, err := mapThirdPartyTransport(b.Transport)
	if err != nil {
		return nil, err
	}
	commitment := ""
	if b.BindingCommitment != nil {
		commitment = b.BindingCommitment.Algorithm + ":" + hex.EncodeToString(b.BindingCommitment.Value)
	}
	return &edgev1.ThirdPartyBindingRef{
		Transport: transport, EndpointRef: b.EndpointRef,
		CapabilityId: capabilityID, CapabilityVersion: capabilityVersion,
		BindingCommitment: commitment,
	}, nil
}

// getThirdPartyProviderStatus is GetProviderStatus's third-party-binding
// branch: it probes tos.edge.v1.ThirdPartyExecutionService.Health instead of
// resolving a Router entry, since a third-party request already names its
// own transport + endpoint_ref -- there is no provider/capability -> service
// selector table to resolve, per atos-spec
// docs/THIRD_PARTY_EXECUTION_PLANE.md.
func (s *Server) getThirdPartyProviderStatus(
	ctx context.Context,
	req *connect.Request[atostosv1.GetProviderStatusRequest],
) (*connect.Response[atostosv1.GetProviderStatusResponse], error) {
	if err := validateThirdPartyBinding(req.Msg.ThirdPartyBinding); err != nil {
		return nil, err
	}
	response := &atostosv1.GetProviderStatusResponse{
		ProviderId: req.Msg.ProviderId, CapabilityId: req.Msg.CapabilityId,
		Readiness:          atostosv1.ProviderReadiness_PROVIDER_READINESS_UNAVAILABLE,
		ObservedUnixMillis: s.now().UnixMilli(),
		ExpiresUnixMillis:  s.now().Add(5 * time.Second).UnixMilli(),
	}
	if s.thirdPartyWorker == nil {
		response.ReasonCode = "THIRD_PARTY_WORKER_NOT_CONFIGURED"
		return connect.NewResponse(response), nil
	}
	binding, err := toEdgeBindingRef(req.Msg.ThirdPartyBinding, req.Msg.CapabilityId, req.Msg.CapabilityVersion)
	if err != nil {
		return nil, err
	}
	callContext, cancel, err := s.boundedContext(ctx, req.Msg.Context.DeadlineUnixMillis)
	if err != nil {
		return nil, err
	}
	defer cancel()
	health, err := s.thirdPartyWorker.Health(callContext, &edgev1.ThirdPartyHealthRequest{Binding: binding})
	if err != nil {
		response.ReasonCode = "THIRD_PARTY_WORKER_UNAVAILABLE"
		return connect.NewResponse(response), nil
	}
	response.DeepProbe = health.DeepProbe
	response.LatencyUnixMillis = health.LatencyMillis
	if !health.Healthy {
		response.ReasonCode = "CAPABILITY_UNAVAILABLE"
		if health.FailureReason != "" {
			response.ReasonCode = health.FailureReason
		}
		return connect.NewResponse(response), nil
	}
	response.Readiness = atostosv1.ProviderReadiness_PROVIDER_READINESS_READY
	if s.supportsMode(atostosv1.TrustMode_TRUST_MODE_MANAGED) {
		response.AvailableTrustModes = []atostosv1.TrustMode{atostosv1.TrustMode_TRUST_MODE_MANAGED}
	}
	return connect.NewResponse(response), nil
}

// quoteThirdPartyExecution is QuoteExecution's third-party-binding branch.
// Unlike the native path, it never calls a private Worker for a price:
// third-party Capability pricing is provider-declared at ATOS registration
// time and ATOS's own QuoteService computes the client-visible charge from
// that -- it never reads ServiceExecutionQuote.ProviderPrice (confirmed by
// reading atos's actual QuoteService.Create, which only consumes .ID/
// .ExpiresAt/.ExecutionDeadline/.Reference from this response). This
// quote's real job is producing a durable anti-substitution anchor
// (provider/capability identity, input commitment, deadline, the exact
// binding) that SubmitJob matches the eventual Job against -- not pricing
// it. ProviderPrice is populated with a fixed zero value so the field is
// never left as an ambiguous zero-value struct, but it is not authoritative
// for third-party bindings.
func (s *Server) quoteThirdPartyExecution(
	ctx context.Context,
	req *connect.Request[atostosv1.QuoteExecutionRequest],
) (*connect.Response[atostosv1.QuoteExecutionResponse], error) {
	if err := validateThirdPartyBinding(req.Msg.ThirdPartyBinding); err != nil {
		return nil, err
	}
	if s.thirdPartyWorker == nil {
		return nil, unavailable("PROVIDER_UNAVAILABLE", "private third-party execution Worker is not configured")
	}
	binding, err := toEdgeBindingRef(req.Msg.ThirdPartyBinding, req.Msg.CapabilityId, req.Msg.CapabilityVersion)
	if err != nil {
		return nil, err
	}
	serviceQuoteID, err := randomHexID("tpq-", 16)
	if err != nil {
		return nil, err
	}
	maxOutput := req.Msg.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = uint64(DefaultMaxMessageBytes)
	}
	expires := s.now().Add(defaultThirdPartyQuoteTTL)
	if deadline := time.UnixMilli(req.Msg.ExecutionDeadlineUnixMillis); deadline.Before(expires) {
		expires = deadline
	}
	quote := &atostosv1.ServiceExecutionQuote{
		ServiceQuoteId: serviceQuoteID, ProviderId: req.Msg.ProviderId,
		CapabilityId: req.Msg.CapabilityId, CapabilityVersion: req.Msg.CapabilityVersion,
		ProviderPrice:               &atostosv1.NetworkAmount{Asset: "TOS", AtomicAmount: "0"},
		ExpiresUnixMillis:           expires.UnixMilli(),
		ExecutionDeadlineUnixMillis: req.Msg.ExecutionDeadlineUnixMillis,
	}
	quoteDigest, err := protoDigest("TOS-THIRD-PARTY-QUOTE-V1", quote)
	if err != nil {
		return nil, err
	}
	digestBytes, err := hexDecode(strings.TrimPrefix(quoteDigest, "sha256:"))
	if err != nil {
		return nil, err
	}
	ref, err := s.authority.Commit(ctx, "service-execution-quote", quote.ServiceQuoteId, quoteDigest)
	if err != nil {
		return nil, unavailable("NETWORK_UNAVAILABLE", "service quote commitment failed")
	}
	quote.SignedQuoteDigest = &atostosv1.Digest{Algorithm: "sha256", Value: digestBytes}
	quote.QuoteRef = &ref
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
			Quote: encoded, ThirdPartyBinding: binding, InputCommitment: inputCommitment,
			MaxOutputBytes: maxOutput,
		})
	}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&atostosv1.QuoteExecutionResponse{Quote: quote}), nil
}

func (s *Server) loadThirdPartyServiceQuoteTx(tx *bolt.Tx, id string) (*atostosv1.ServiceExecutionQuote, *edgev1.ThirdPartyBindingRef, *atostosv1.Digest, uint64, error) {
	var stored storedServiceQuote
	found, err := s.store.getJSON(tx, bucketServiceQuotes, id, &stored)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if !found {
		return nil, nil, nil, 0, notFound("QUOTE_MISMATCH", "service execution quote not found")
	}
	if stored.ThirdPartyBinding == nil {
		return nil, nil, nil, 0, failedPrecondition("QUOTE_MISMATCH", "service execution quote is not a third-party quote")
	}
	quote := new(atostosv1.ServiceExecutionQuote)
	if err := proto.Unmarshal(stored.Quote, quote); err != nil {
		return nil, nil, nil, 0, err
	}
	if len(stored.InputCommitment) == 0 {
		return nil, nil, nil, 0, failedPrecondition("QUOTE_MISMATCH", "service quote is missing its input commitment")
	}
	inputCommitment := new(atostosv1.Digest)
	if err := proto.Unmarshal(stored.InputCommitment, inputCommitment); err != nil {
		return nil, nil, nil, 0, err
	}
	return quote, stored.ThirdPartyBinding, inputCommitment, stored.MaxOutputBytes, nil
}

// submitThirdPartyJob is SubmitJob's third-party-binding branch: a parallel
// durable exact-once state machine to the native invokeDurableJob/
// recoverDurableJob, deliberately NOT sharing their internals (both are
// deeply, concretely typed to edgev1.InvokeRequest at the storage layer).
// It shares the same store/idempotency primitives, the same bucketJobs
// storage and atostosv1.JobRecord shape, and -- critically -- the exact
// same, unmodified completeDurableJob for receipt signing, escrow charge
// and execution-signer authorization, since that function only ever touches
// stored.Input/record/completion, none of which are transport-specific.
func (s *Server) submitThirdPartyJob(
	ctx context.Context,
	req *connect.Request[atostosv1.SubmitJobRequest],
) (*connect.Response[atostosv1.SubmitJobResponse], error) {
	if err := validateThirdPartyBinding(req.Msg.ThirdPartyBinding); err != nil {
		return nil, err
	}
	if s.thirdPartyWorker == nil {
		return nil, unavailable("PROVIDER_UNAVAILABLE", "private third-party execution Worker is not configured")
	}
	submittedBinding, err := toEdgeBindingRef(req.Msg.ThirdPartyBinding, req.Msg.CapabilityId, req.Msg.CapabilityVersion)
	if err != nil {
		return nil, err
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
		serviceQuote, quotedBinding, quotedInput, quotedMaxOutput, err := s.loadThirdPartyServiceQuoteTx(tx, req.Msg.ServiceQuoteId)
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
		// A Job cannot silently redirect to a different endpoint/transport
		// than what the principal was quoted against.
		if quotedBinding.Transport != submittedBinding.Transport ||
			quotedBinding.EndpointRef != submittedBinding.EndpointRef ||
			quotedBinding.BindingCommitment != submittedBinding.BindingCommitment {
			return failedPrecondition("QUOTE_MISMATCH", "third_party_binding does not match the quoted binding")
		}
		quoteCommitment := new(atostosv1.QuoteCommitment)
		found, err = s.store.getProto(tx, bucketQuoteCommitments, req.Msg.QuoteId, quoteCommitment)
		if err != nil {
			return err
		}
		if !found || quoteCommitment.Value == nil || quoteCommitment.Value.PrincipalId != req.Msg.PrincipalId ||
			quoteCommitment.Value.ProviderId != req.Msg.ProviderId || quoteCommitment.Value.CapabilityId != req.Msg.CapabilityId ||
			quoteCommitment.Value.CapabilityVersion != req.Msg.CapabilityVersion || quoteCommitment.Value.TrustMode != req.Msg.TrustMode ||
			quoteCommitment.Value.ProofProfile != req.Msg.ProofProfile ||
			quoteCommitment.Value.UnderlyingServiceQuoteRef != req.Msg.ServiceQuoteId {
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
		if maxOutput == 0 || maxOutput > quotedMaxOutput {
			maxOutput = quotedMaxOutput
		}
		workerRequest := &edgev1.ThirdPartyInvokeRequest{
			RequestId: req.Msg.JobId, JobId: req.Msg.JobId, ProviderId: req.Msg.ProviderId,
			Binding: quotedBinding, Input: append([]byte(nil), req.Msg.Input...),
			DeadlineUnixMillis: req.Msg.ExecutionDeadlineUnixMillis, RetainUntilUnixMillis: req.Msg.RetainUntilUnixMillis,
			MaxOutputBytes: maxOutput,
		}
		boundDigest, err := protoDigest("TOS-THIRD-PARTY-INVOKE-V1", workerRequest)
		if err != nil {
			return err
		}
		workerRequest.RequestDigest = boundDigest
		workerEncoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(workerRequest)
		if err != nil {
			return err
		}
		record := &atostosv1.JobRecord{
			JobId: req.Msg.JobId, EdgeActionId: "edge-" + req.Msg.JobId,
			WorkerTaskId:   "task-" + strings.TrimPrefix(requestDigest, "sha256:")[:32],
			QuoteId:        req.Msg.QuoteId,
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
			Record: recordEncoded, Kind: jobKindThirdParty, ThirdPartyWorkerRequest: workerEncoded,
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
		_, record, decodeErr := decodeThirdPartyExecutionJob(stored)
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
		response, err = s.invokeThirdPartyDurableJob(ctx, req.Msg.JobId, stored)
	} else {
		response, err = s.recoverThirdPartyDurableJob(ctx, req.Msg.JobId, stored)
	}
	if err != nil {
		return nil, err
	}
	if err := s.finishSubmitIdempotency(idemKey, requestDigest, response); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func decodeThirdPartyExecutionJob(stored storedExecutionJob) (*edgev1.ThirdPartyInvokeRequest, *atostosv1.JobRecord, error) {
	workerRequest := new(edgev1.ThirdPartyInvokeRequest)
	if err := proto.Unmarshal(stored.ThirdPartyWorkerRequest, workerRequest); err != nil {
		return nil, nil, err
	}
	record := new(atostosv1.JobRecord)
	if err := proto.Unmarshal(stored.Record, record); err != nil {
		return nil, nil, err
	}
	return workerRequest, record, nil
}

// thirdPartyInvocationCompletion builds the same plain localrpc.
// InvocationCompletion type completeDurableJob already accepts, directly
// from a ThirdPartyInvokeResponse -- there is no ValidatedInvocation-style
// wrapper for this path (no model-digest/runtime-binding concept applies to
// a third-party endpoint), so the one substitution check that matters
// (the response answers the exact request it was asked) is done here
// explicitly instead.
func thirdPartyInvocationCompletion(req *edgev1.ThirdPartyInvokeRequest, resp *edgev1.ThirdPartyInvokeResponse) (localrpc.InvocationCompletion, error) {
	if resp == nil || resp.RequestId != req.RequestId {
		return localrpc.InvocationCompletion{}, invalid("INVALID_ARGUMENT", "third-party worker response request_id does not match the invocation")
	}
	// A third-party provider has no contractual obligation to bound its own
	// output the way the native model-serving Worker is expected to (it
	// receives max_output_bytes too, but this caller does not otherwise
	// re-validate a native Worker's own self-enforcement). Reject an
	// oversized result here, before it ever reaches completeDurableJob /
	// the signed Receipt / settlement -- never silently accept it because
	// it happened to be under the worker's own wire-envelope
	// MaxResponseBytes, a smaller and unrelated limit.
	if req.MaxOutputBytes > 0 && uint64(len(resp.Output)) > req.MaxOutputBytes {
		return localrpc.InvocationCompletion{}, failedPrecondition("OUTPUT_LIMIT_EXCEEDED",
			fmt.Sprintf("third-party provider output (%d bytes) exceeds the quoted max_output_bytes (%d)", len(resp.Output), req.MaxOutputBytes))
	}
	completedAt := time.UnixMilli(resp.CompletedUnixMillis)
	if resp.CompletedUnixMillis == 0 {
		completedAt = time.Now().UTC()
	}
	usage := localrpc.InvocationUsage{}
	if resp.Usage != nil {
		usage = localrpc.InvocationUsage{
			InputBytes: resp.Usage.InputBytes, OutputBytes: resp.Usage.OutputBytes,
			InputTokens: resp.Usage.InputTokens, OutputTokens: resp.Usage.OutputTokens,
			ExecutionMillis: resp.Usage.ExecutionMillis,
		}
	}
	return localrpc.InvocationCompletion{
		Binding:       localrpc.InvocationBinding{RequestID: req.RequestId},
		Output:        append([]byte(nil), resp.Output...),
		Usage:         usage,
		TaskID:        req.RequestId,
		RequestDigest: req.RequestDigest,
		Deadline:      time.UnixMilli(req.DeadlineUnixMillis),
		CompletedAt:   completedAt,
	}, nil
}

func (s *Server) invokeThirdPartyDurableJob(ctx context.Context, jobID string, stored storedExecutionJob) (*atostosv1.SubmitJobResponse, error) {
	workerRequest, record, err := decodeThirdPartyExecutionJob(stored)
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
	invokeResponse, invokeErr := s.thirdPartyWorker.Invoke(callContext, workerRequest)
	if invokeErr == nil && invokeResponse != nil {
		switch invokeResponse.Status {
		case edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_COMPLETED:
			completion, err := thirdPartyInvocationCompletion(workerRequest, invokeResponse)
			if err != nil {
				return nil, err
			}
			return s.completeDurableJob(jobID, &stored, record, completion)
		case edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_FAILED:
			record.State = atostosv1.JobState_JOB_STATE_FAILED
			record.ErrorCode = invokeResponse.FailureReason
			record.UpdatedUnixMillis = s.now().UnixMilli()
			record.CompletedUnixMillis = record.UpdatedUnixMillis
			if err := s.updateStoredJobRecord(jobID, &stored, record); err != nil {
				return nil, err
			}
			return submitResponse(record), nil
		default:
			// Pending or unspecified: the true outcome is not known yet --
			// never inferred as terminal from an ambiguous signal. Fall
			// through to recovery via Query, exactly like a transport
			// error does.
		}
	}
	// Never blindly resubmit. Resolve the exact task identity through the
	// private read-only recovery RPC (Query).
	response, recoveryErr := s.recoverThirdPartyDurableJob(ctx, jobID, stored)
	if recoveryErr != nil {
		record.State = atostosv1.JobState_JOB_STATE_UNCERTAIN
		record.ErrorCode = "EXECUTION_UNCERTAIN"
		record.UpdatedUnixMillis = s.now().UnixMilli()
		_ = s.updateStoredJobRecord(jobID, &stored, record)
		return submitResponse(record), nil
	}
	return response, nil
}

func (s *Server) recoverThirdPartyDurableJob(ctx context.Context, jobID string, stored storedExecutionJob) (*atostosv1.SubmitJobResponse, error) {
	workerRequest, record, err := decodeThirdPartyExecutionJob(stored)
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
	queried, err := s.thirdPartyWorker.Query(callContext, &edgev1.ThirdPartyQueryRequest{
		RequestId: workerRequest.RequestId, Binding: workerRequest.Binding,
	})
	if err != nil {
		record.State = atostosv1.JobState_JOB_STATE_UNCERTAIN
		record.ErrorCode = "EXECUTION_UNCERTAIN"
		record.UpdatedUnixMillis = s.now().UnixMilli()
		_ = s.updateStoredJobRecord(jobID, &stored, record)
		return submitResponse(record), nil
	}
	if !queried.Found {
		// No record of ever attempting this key: honestly uncertain, not a
		// license to retry (mirrors the native path's identical treatment
		// of "recovered not-found" as observation, not retry permission).
		record.State = atostosv1.JobState_JOB_STATE_UNCERTAIN
		record.ErrorCode = "EXECUTION_UNCERTAIN"
		record.UpdatedUnixMillis = s.now().UnixMilli()
		if err := s.updateStoredJobRecord(jobID, &stored, record); err != nil {
			return nil, err
		}
		return submitResponse(record), nil
	}
	switch queried.Result.GetStatus() {
	case edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_COMPLETED:
		completion, err := thirdPartyInvocationCompletion(workerRequest, queried.Result)
		if err != nil {
			return nil, err
		}
		return s.completeDurableJob(jobID, &stored, record, completion)
	case edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_FAILED:
		record.State = atostosv1.JobState_JOB_STATE_FAILED
		record.ErrorCode = queried.Result.GetFailureReason()
	case edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_PENDING:
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
