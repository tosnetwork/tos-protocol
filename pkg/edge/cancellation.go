package edge

import (
	"context"
	"errors"
	"fmt"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
)

type ExecutionCancellationDisposition string

const (
	ExecutionCancellationAccepted  ExecutionCancellationDisposition = "accepted"
	ExecutionCancellationRejected  ExecutionCancellationDisposition = "rejected"
	ExecutionCancellationUncertain ExecutionCancellationDisposition = "uncertain"
)

// ExecutionCancellation is an opaque cancellation attempt. Accepted means
// only that the Worker accepted the exact cancellation request; a subsequent
// validated GetTask observation is still required before terminal settlement.
type ExecutionCancellation struct {
	valid       bool
	disposition ExecutionCancellationDisposition
	claim       ClaimedInvocation
}

func (c ExecutionCancellation) Disposition() (
	ExecutionCancellationDisposition,
	error,
) {
	if !c.valid {
		return "", errors.New("invalid execution cancellation")
	}
	return c.disposition, nil
}

func (c ExecutionCancellation) Claim() (ClaimedInvocation, error) {
	if !c.valid {
		return ClaimedInvocation{}, errors.New(
			"invalid execution cancellation",
		)
	}
	return cloneClaimedInvocation(c.claim), nil
}

// CancelExecutionDispatch asks the Worker to cancel only a validated
// nonterminal dispatch whose exact durable claim still owns the running
// request. It never writes a receipt or declares a terminal state.
func (c *Core) CancelExecutionDispatch(
	ctx context.Context,
	dispatch ExecutionDispatch,
	worker *localrpc.WorkerClient,
) (ExecutionCancellation, error) {
	if c == nil {
		return ExecutionCancellation{}, errors.New("nil Edge Core")
	}
	if ctx == nil {
		return ExecutionCancellation{}, errors.New(
			"nil execution cancellation context",
		)
	}
	if err := ctx.Err(); err != nil {
		return ExecutionCancellation{}, err
	}
	if worker == nil {
		return ExecutionCancellation{}, errors.New("nil Worker client")
	}
	if !dispatch.valid {
		return ExecutionCancellation{}, errors.New("invalid execution dispatch")
	}
	if err := validateCancellableDispatch(dispatch); err != nil {
		return ExecutionCancellation{}, err
	}
	claim := cloneClaimedInvocation(dispatch.claim)
	if claim.Request == nil {
		return ExecutionCancellation{}, errors.New(
			"cancellable dispatch has no Worker request",
		)
	}
	now := c.now().UTC()
	request, err := c.requests.Get(claim.State.Scope, now)
	if err != nil {
		return ExecutionCancellation{}, fmt.Errorf(
			"load cancellation request: %w",
			err,
		)
	}
	if request.State != journal.StateRunning ||
		request.Revision != claim.State.Revision {
		return ExecutionCancellation{}, journal.ErrTransition
	}
	execution, err := c.requests.GetExecution(claim.State.Scope, now)
	if err != nil {
		return ExecutionCancellation{}, fmt.Errorf(
			"load cancellation execution claim: %w",
			err,
		)
	}
	if execution != claim.Execution {
		return ExecutionCancellation{}, journal.ErrConflict
	}
	result := ExecutionCancellation{
		valid: true, disposition: ExecutionCancellationUncertain,
		claim: claim,
	}
	accepted, err := worker.Cancel(ctx, claim.Request)
	if err != nil {
		return result, fmt.Errorf("cancel claimed Worker task: %w", err)
	}
	if accepted {
		result.disposition = ExecutionCancellationAccepted
	} else {
		result.disposition = ExecutionCancellationRejected
	}
	return result, nil
}

func validateCancellableDispatch(dispatch ExecutionDispatch) error {
	switch dispatch.disposition {
	case ExecutionDispatchUncertain:
		return nil
	case ExecutionDispatchRecovered:
		status, err := dispatch.recovery.Status()
		if err != nil {
			return fmt.Errorf("read recovered Worker status: %w", err)
		}
		switch status {
		case edgev1.TaskStatus_TASK_STATUS_NOT_FOUND,
			edgev1.TaskStatus_TASK_STATUS_ACCEPTED,
			edgev1.TaskStatus_TASK_STATUS_RUNNING:
			return nil
		default:
			return errors.New("terminal execution dispatch cannot be canceled")
		}
	case ExecutionDispatchInvoked:
		return errors.New("completed execution dispatch cannot be canceled")
	default:
		return errors.New("invalid execution dispatch disposition")
	}
}
