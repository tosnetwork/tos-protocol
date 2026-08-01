package edge

import (
	"context"
	"errors"
	"fmt"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"google.golang.org/protobuf/proto"
)

type ExecutionDispatchDisposition string

const (
	// ExecutionDispatchInvoked means the one permitted Invoke returned a
	// validated successful result.
	ExecutionDispatchInvoked ExecutionDispatchDisposition = "invoked"
	// ExecutionDispatchRecovered means an existing claim was inspected only
	// through GetTask. It never means the task was submitted again.
	ExecutionDispatchRecovered ExecutionDispatchDisposition = "recovered"
	// ExecutionDispatchUncertain means a claim exists but Invoke or GetTask did
	// not return a trustworthy result. Recovery must query; it must not retry.
	ExecutionDispatchUncertain ExecutionDispatchDisposition = "uncertain"
)

// ExecutionDispatch is an opaque result that always retains a successfully
// committed claim, including when the subsequent private RPC fails.
type ExecutionDispatch struct {
	valid       bool
	disposition ExecutionDispatchDisposition
	claim       ClaimedInvocation
	invocation  localrpc.ValidatedInvocation
	recovery    localrpc.RecoveredTask
}

func (d ExecutionDispatch) Disposition() (
	ExecutionDispatchDisposition,
	error,
) {
	if !d.valid {
		return "", errors.New("invalid execution dispatch")
	}
	return d.disposition, nil
}

// Claim returns a defensive copy of the exact durable execution claim.
func (d ExecutionDispatch) Claim() (ClaimedInvocation, error) {
	if !d.valid {
		return ClaimedInvocation{}, errors.New("invalid execution dispatch")
	}
	return cloneClaimedInvocation(d.claim), nil
}

// Invocation is available only after the first Invoke returned a validated
// successful response. It can enter CompleteSuccessfulInvocation.
func (d ExecutionDispatch) Invocation() (localrpc.ValidatedInvocation, error) {
	if !d.valid || d.disposition != ExecutionDispatchInvoked {
		return localrpc.ValidatedInvocation{}, errors.New(
			"execution dispatch has no direct invocation result",
		)
	}
	return d.invocation, nil
}

// RecoveredTask is available only for a validated GetTask response. Its
// status determines whether it contains a successful invocation result.
func (d ExecutionDispatch) RecoveredTask() (localrpc.RecoveredTask, error) {
	if !d.valid || d.disposition != ExecutionDispatchRecovered {
		return localrpc.RecoveredTask{}, errors.New(
			"execution dispatch has no recovered task result",
		)
	}
	return d.recovery, nil
}

// DispatchRegisteredPaidExecution maps and atomically claims a paid request,
// then performs exactly one safe next action. A new claim invokes the Worker
// once. An exact replay only queries GetTask and never resubmits work.
//
// If either private RPC fails, the returned dispatch remains valid and exposes
// the committed claim with disposition uncertain. Callers must preserve that
// result even when handling the non-nil error.
func (c *Core) DispatchRegisteredPaidExecution(
	ctx context.Context,
	scope journal.Scope,
	expectedRevision uint64,
	paymentAuthorization authorization.AuthorizedPayment,
	intent []byte,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
) (ExecutionDispatch, error) {
	claimed, err := c.MapAndClaimRegisteredPaidExecution(
		ctx,
		scope,
		expectedRevision,
		paymentAuthorization,
		intent,
		plan,
		worker,
	)
	return dispatchClaimedExecution(ctx, claimed, worker, err)
}

// DispatchRecoveredPaidExecution performs the same one-safe-next-action rule
// using only the exact durable payment context committed before restart. A
// previously running request is queried through GetTask and is never invoked
// again.
func (c *Core) DispatchRecoveredPaidExecution(
	ctx context.Context,
	scope journal.Scope,
	intent []byte,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
) (ExecutionDispatch, error) {
	claimed, err := c.MapAndClaimRecoveredPaidExecution(
		ctx,
		scope,
		intent,
		plan,
		worker,
	)
	return dispatchClaimedExecution(ctx, claimed, worker, err)
}

func dispatchClaimedExecution(
	ctx context.Context,
	claimed ClaimedInvocation,
	worker *localrpc.WorkerClient,
	claimErr error,
) (ExecutionDispatch, error) {
	if worker == nil {
		return ExecutionDispatch{}, errors.New("nil Worker client")
	}
	if claimErr != nil {
		if claimed.Request != nil && claimed.Disposition != "" {
			return ExecutionDispatch{
				valid: true, disposition: ExecutionDispatchUncertain,
				claim: cloneClaimedInvocation(claimed),
			}, claimErr
		}
		return ExecutionDispatch{}, claimErr
	}
	dispatch := ExecutionDispatch{
		valid: true, disposition: ExecutionDispatchUncertain,
		claim: cloneClaimedInvocation(claimed),
	}
	switch claimed.Disposition {
	case journal.ExecutionClaimed:
		invocation, err := worker.Invoke(ctx, claimed.Request)
		if err != nil {
			return dispatch, fmt.Errorf(
				"invoke newly claimed Worker task: %w",
				err,
			)
		}
		dispatch.disposition = ExecutionDispatchInvoked
		dispatch.invocation = invocation
		return dispatch, nil
	case journal.ExecutionReplay:
		recovered, err := worker.GetTask(ctx, claimed.Request)
		if err != nil {
			return dispatch, fmt.Errorf(
				"recover existing Worker task: %w",
				err,
			)
		}
		dispatch.disposition = ExecutionDispatchRecovered
		dispatch.recovery = recovered
		return dispatch, nil
	default:
		return dispatch, errors.New(
			"execution claim returned an unknown disposition",
		)
	}
}

func cloneClaimedInvocation(value ClaimedInvocation) ClaimedInvocation {
	if value.Request != nil {
		value.Request = proto.Clone(value.Request).(*edgev1.InvokeRequest)
	}
	return value
}
