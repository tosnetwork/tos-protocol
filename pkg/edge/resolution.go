package edge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type ExecutionResolutionDisposition string

const (
	ExecutionResolutionUncertain ExecutionResolutionDisposition = "uncertain"
	ExecutionResolutionNotFound  ExecutionResolutionDisposition = "not_found"
	ExecutionResolutionAccepted  ExecutionResolutionDisposition = "accepted"
	ExecutionResolutionRunning   ExecutionResolutionDisposition = "running"
	ExecutionResolutionSucceeded ExecutionResolutionDisposition = "succeeded"
	ExecutionResolutionFailed    ExecutionResolutionDisposition = "failed"
	ExecutionResolutionCanceled  ExecutionResolutionDisposition = "canceled"
	ExecutionResolutionTimedOut  ExecutionResolutionDisposition = "timed_out"
)

// ExecutionResolution is an opaque dispatch interpretation. Nonterminal
// dispositions never contain or create a receipt.
type ExecutionResolution struct {
	valid       bool
	disposition ExecutionResolutionDisposition
	claim       ClaimedInvocation
	completed   CompletedInvocation
	terminated  TerminatedInvocation
}

func (r ExecutionResolution) Disposition() (
	ExecutionResolutionDisposition,
	error,
) {
	if !r.valid {
		return "", errors.New("invalid execution resolution")
	}
	return r.disposition, nil
}

func (r ExecutionResolution) Claim() (ClaimedInvocation, error) {
	if !r.valid {
		return ClaimedInvocation{}, errors.New("invalid execution resolution")
	}
	return cloneClaimedInvocation(r.claim), nil
}

func (r ExecutionResolution) CompletedInvocation() (
	CompletedInvocation,
	error,
) {
	if !r.valid || r.disposition != ExecutionResolutionSucceeded {
		return CompletedInvocation{}, errors.New(
			"execution resolution has no successful completion",
		)
	}
	output := r.completed
	return cloneCompletedInvocation(output), nil
}

func (r ExecutionResolution) TerminatedInvocation() (
	TerminatedInvocation,
	error,
) {
	if !r.valid ||
		(r.disposition != ExecutionResolutionFailed &&
			r.disposition != ExecutionResolutionCanceled &&
			r.disposition != ExecutionResolutionTimedOut) {
		return TerminatedInvocation{}, errors.New(
			"execution resolution has no terminal failure",
		)
	}
	return cloneTerminatedInvocation(r.terminated), nil
}

type executionReceiptIdentity struct {
	Version         string `json:"version"`
	Network         string `json:"network"`
	ServiceID       string `json:"serviceId"`
	RequestID       string `json:"requestId"`
	TaskID          string `json:"taskId"`
	RequestDigest   string `json:"requestDigest"`
	AuthorizationID string `json:"authorizationId"`
	QuoteID         string `json:"quoteId"`
}

// ResolveExecutionDispatch converts only validated terminal Worker outcomes
// into the atomic receipt paths and requires the immutable exact-profile plan
// that authorized dispatch. Active, missing, and uncertain outcomes remain
// explicit no-op resolutions. Non-success outcomes retain zero charge.
func (c *Core) ResolveExecutionDispatch(
	ctx context.Context,
	dispatch ExecutionDispatch,
	manifest *authorization.VerifiedManifest,
	paymentAuthorization authorization.AuthorizedPayment,
	plan *ProfileInvocationPlan,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	if plan == nil {
		return ExecutionResolution{}, errors.New(
			"nil profile invocation plan",
		)
	}
	return c.resolveExecutionDispatch(
		ctx,
		dispatch,
		manifest,
		paymentAuthorization,
		plan,
		signer,
		receiptLifetime,
	)
}

func (c *Core) resolveExecutionDispatch(
	ctx context.Context,
	dispatch ExecutionDispatch,
	manifest *authorization.VerifiedManifest,
	paymentAuthorization authorization.AuthorizedPayment,
	plan *ProfileInvocationPlan,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	if c == nil {
		return ExecutionResolution{}, errors.New("nil Edge Core")
	}
	if ctx == nil {
		return ExecutionResolution{}, errors.New(
			"nil execution resolution context",
		)
	}
	if err := ctx.Err(); err != nil {
		return ExecutionResolution{}, err
	}
	if !dispatch.valid {
		return ExecutionResolution{}, errors.New("invalid execution dispatch")
	}
	claim := cloneClaimedInvocation(dispatch.claim)
	base := ExecutionResolution{valid: true, claim: claim}
	switch dispatch.disposition {
	case ExecutionDispatchUncertain:
		base.disposition = ExecutionResolutionUncertain
		return base, nil
	case ExecutionDispatchInvoked:
		return c.resolveSuccessfulExecution(
			ctx,
			base,
			dispatch.invocation,
			manifest,
			paymentAuthorization,
			plan,
			signer,
			receiptLifetime,
		)
	case ExecutionDispatchRecovered:
	default:
		return ExecutionResolution{}, errors.New(
			"invalid execution dispatch disposition",
		)
	}
	status, err := dispatch.recovery.Status()
	if err != nil {
		return ExecutionResolution{}, fmt.Errorf(
			"read recovered Worker status: %w",
			err,
		)
	}
	switch status {
	case edgev1.TaskStatus_TASK_STATUS_NOT_FOUND:
		base.disposition = ExecutionResolutionNotFound
		return base, nil
	case edgev1.TaskStatus_TASK_STATUS_ACCEPTED:
		base.disposition = ExecutionResolutionAccepted
		return base, nil
	case edgev1.TaskStatus_TASK_STATUS_RUNNING:
		base.disposition = ExecutionResolutionRunning
		return base, nil
	case edgev1.TaskStatus_TASK_STATUS_SUCCEEDED:
		invocation, err := dispatch.recovery.Invocation()
		if err != nil {
			return ExecutionResolution{}, fmt.Errorf(
				"read recovered Worker invocation: %w",
				err,
			)
		}
		return c.resolveSuccessfulExecution(
			ctx,
			base,
			invocation,
			manifest,
			paymentAuthorization,
			plan,
			signer,
			receiptLifetime,
		)
	case edgev1.TaskStatus_TASK_STATUS_FAILED:
		return c.resolveFailedExecution(
			ctx,
			base,
			ExecutionResolutionFailed,
			InvocationFailed,
			manifest,
			paymentAuthorization,
			signer,
			receiptLifetime,
		)
	case edgev1.TaskStatus_TASK_STATUS_CANCELED:
		return c.resolveFailedExecution(
			ctx,
			base,
			ExecutionResolutionCanceled,
			InvocationCanceled,
			manifest,
			paymentAuthorization,
			signer,
			receiptLifetime,
		)
	case edgev1.TaskStatus_TASK_STATUS_TIMED_OUT:
		return c.resolveFailedExecution(
			ctx,
			base,
			ExecutionResolutionTimedOut,
			InvocationTimedOut,
			manifest,
			paymentAuthorization,
			signer,
			receiptLifetime,
		)
	default:
		return ExecutionResolution{}, errors.New(
			"unsupported recovered Worker status",
		)
	}
}

// ResolveRecoveredExecutionDispatch is the restart-safe counterpart of
// ResolveExecutionDispatch. It derives the selector and quote from durable
// payment state before applying the same required immutable success policy.
func (c *Core) ResolveRecoveredExecutionDispatch(
	ctx context.Context,
	dispatch ExecutionDispatch,
	manifest *authorization.VerifiedManifest,
	plan *ProfileInvocationPlan,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	if plan == nil {
		return ExecutionResolution{}, errors.New(
			"nil profile invocation plan",
		)
	}
	return c.resolveRecoveredExecutionDispatch(
		ctx,
		dispatch,
		manifest,
		plan,
		signer,
		receiptLifetime,
	)
}

func (c *Core) resolveRecoveredExecutionDispatch(
	ctx context.Context,
	dispatch ExecutionDispatch,
	manifest *authorization.VerifiedManifest,
	plan *ProfileInvocationPlan,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	if c == nil {
		return ExecutionResolution{}, errors.New("nil Edge Core")
	}
	if ctx == nil {
		return ExecutionResolution{}, errors.New(
			"nil execution resolution context",
		)
	}
	if err := ctx.Err(); err != nil {
		return ExecutionResolution{}, err
	}
	if !dispatch.valid {
		return ExecutionResolution{}, errors.New("invalid execution dispatch")
	}
	claim := cloneClaimedInvocation(dispatch.claim)
	base := ExecutionResolution{valid: true, claim: claim}
	resolveSuccess := func(
		invocation localrpc.ValidatedInvocation,
	) (ExecutionResolution, error) {
		receiptID, err := executionReceiptID(base.claim)
		if err != nil {
			return ExecutionResolution{}, err
		}
		completed, err := c.CompleteRecoveredSuccessfulInvocation(
			ctx,
			base.claim.State.Scope,
			base.claim.State.Revision,
			manifest,
			invocation,
			plan,
			signer,
			receiptID,
			receiptLifetime,
		)
		if err != nil {
			return ExecutionResolution{}, err
		}
		base.disposition = ExecutionResolutionSucceeded
		base.completed = completed
		return base, nil
	}
	resolveFailure := func(
		disposition ExecutionResolutionDisposition,
		status NonSuccessStatus,
	) (ExecutionResolution, error) {
		receiptID, err := executionReceiptID(base.claim)
		if err != nil {
			return ExecutionResolution{}, err
		}
		terminated, err := c.CompleteRecoveredInvocationFailure(
			ctx,
			base.claim.State.Scope,
			base.claim.State.Revision,
			manifest,
			signer,
			receiptID,
			status,
			receiptLifetime,
		)
		if err != nil {
			return ExecutionResolution{}, err
		}
		base.disposition = disposition
		base.terminated = terminated
		return base, nil
	}
	switch dispatch.disposition {
	case ExecutionDispatchUncertain:
		base.disposition = ExecutionResolutionUncertain
		return base, nil
	case ExecutionDispatchInvoked:
		return resolveSuccess(dispatch.invocation)
	case ExecutionDispatchRecovered:
	default:
		return ExecutionResolution{}, errors.New(
			"invalid execution dispatch disposition",
		)
	}
	status, err := dispatch.recovery.Status()
	if err != nil {
		return ExecutionResolution{}, fmt.Errorf(
			"read recovered Worker status: %w", err,
		)
	}
	switch status {
	case edgev1.TaskStatus_TASK_STATUS_NOT_FOUND:
		base.disposition = ExecutionResolutionNotFound
		return base, nil
	case edgev1.TaskStatus_TASK_STATUS_ACCEPTED:
		base.disposition = ExecutionResolutionAccepted
		return base, nil
	case edgev1.TaskStatus_TASK_STATUS_RUNNING:
		base.disposition = ExecutionResolutionRunning
		return base, nil
	case edgev1.TaskStatus_TASK_STATUS_SUCCEEDED:
		invocation, err := dispatch.recovery.Invocation()
		if err != nil {
			return ExecutionResolution{}, fmt.Errorf(
				"read recovered Worker invocation: %w", err,
			)
		}
		return resolveSuccess(invocation)
	case edgev1.TaskStatus_TASK_STATUS_FAILED:
		return resolveFailure(
			ExecutionResolutionFailed,
			InvocationFailed,
		)
	case edgev1.TaskStatus_TASK_STATUS_CANCELED:
		return resolveFailure(
			ExecutionResolutionCanceled,
			InvocationCanceled,
		)
	case edgev1.TaskStatus_TASK_STATUS_TIMED_OUT:
		return resolveFailure(
			ExecutionResolutionTimedOut,
			InvocationTimedOut,
		)
	default:
		return ExecutionResolution{}, errors.New(
			"unsupported recovered Worker status",
		)
	}
}

func (c *Core) resolveSuccessfulExecution(
	ctx context.Context,
	base ExecutionResolution,
	invocation localrpc.ValidatedInvocation,
	manifest *authorization.VerifiedManifest,
	paymentAuthorization authorization.AuthorizedPayment,
	plan *ProfileInvocationPlan,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	receiptID, err := executionReceiptID(base.claim)
	if err != nil {
		return ExecutionResolution{}, err
	}
	completed, err := c.CompleteSuccessfulInvocation(
		ctx,
		base.claim.State.Scope,
		base.claim.State.Revision,
		manifest,
		paymentAuthorization,
		invocation,
		plan,
		signer,
		receiptID,
		receiptLifetime,
	)
	if err != nil {
		return ExecutionResolution{}, err
	}
	base.disposition = ExecutionResolutionSucceeded
	base.completed = completed
	return base, nil
}

func (c *Core) resolveFailedExecution(
	ctx context.Context,
	base ExecutionResolution,
	disposition ExecutionResolutionDisposition,
	status NonSuccessStatus,
	manifest *authorization.VerifiedManifest,
	paymentAuthorization authorization.AuthorizedPayment,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	receiptID, err := executionReceiptID(base.claim)
	if err != nil {
		return ExecutionResolution{}, err
	}
	terminated, err := c.CompleteInvocationFailure(
		ctx,
		base.claim.State.Scope,
		base.claim.State.Revision,
		manifest,
		paymentAuthorization,
		signer,
		receiptID,
		status,
		receiptLifetime,
	)
	if err != nil {
		return ExecutionResolution{}, err
	}
	base.disposition = disposition
	base.terminated = terminated
	return base, nil
}

func executionReceiptID(claim ClaimedInvocation) (string, error) {
	if claim.Request == nil || claim.Execution.TaskID == "" ||
		claim.Execution.RequestDigest == "" {
		return "", errors.New("invalid execution claim for receipt identity")
	}
	digest, err := codec.Digest(
		"tos.execution-receipt-id.v1",
		executionReceiptIdentity{
			Version:         protocol.BaseEnvelopeVersion,
			Network:         claim.Execution.Scope.Network,
			ServiceID:       claim.Execution.Scope.ServiceID,
			RequestID:       claim.Execution.Scope.RequestID,
			TaskID:          claim.Execution.TaskID,
			RequestDigest:   claim.Execution.RequestDigest,
			AuthorizationID: claim.Execution.AuthorizationID,
			QuoteID:         claim.Execution.QuoteID,
		},
	)
	if err != nil {
		return "", fmt.Errorf("commit execution receipt identity: %w", err)
	}
	return "receipt-" + strings.TrimPrefix(digest, "sha256:"), nil
}

func cloneCompletedInvocation(value CompletedInvocation) CompletedInvocation {
	value.Output = append([]byte(nil), value.Output...)
	value.Receipt = cloneResolutionReceipt(value.Receipt)
	return value
}

func cloneTerminatedInvocation(value TerminatedInvocation) TerminatedInvocation {
	value.Receipt = cloneResolutionReceipt(value.Receipt)
	return value
}

func cloneResolutionReceipt(value journal.ReceiptRecord) journal.ReceiptRecord {
	value.Usage = append([]journal.ReceiptUsage(nil), value.Usage...)
	value.Envelope.Payload = append([]byte(nil), value.Envelope.Payload...)
	return value
}
