package edge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
)

// ExecuteRegisteredPaidAction performs the only safe live paid-action
// sequence: map and durably claim the exact profile invocation, invoke a new
// Worker task at most once (or read an existing task), and convert only a
// validated terminal outcome into a signed durable receipt. A private RPC
// failure returns a valid uncertain resolution together with the error; callers
// must retain that resolution and must not retry Invoke.
func (c *Core) ExecuteRegisteredPaidAction(
	ctx context.Context,
	scope journal.Scope,
	expectedRevision uint64,
	paymentAuthorization authorization.AuthorizedPayment,
	intent []byte,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
	manifest *authorization.VerifiedManifest,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	dispatch, dispatchErr := c.DispatchRegisteredPaidExecution(
		ctx, scope, expectedRevision, paymentAuthorization, intent, plan, worker,
	)
	if !dispatch.valid {
		if dispatchErr == nil {
			dispatchErr = errors.New("paid action produced an invalid dispatch")
		}
		return ExecutionResolution{}, dispatchErr
	}
	resolution, resolutionErr := c.ResolveExecutionDispatch(
		ctx, dispatch, manifest, paymentAuthorization, plan, signer,
		receiptLifetime,
	)
	if resolutionErr != nil {
		return ExecutionResolution{}, errors.Join(dispatchErr, fmt.Errorf(
			"resolve paid action dispatch: %w", resolutionErr,
		))
	}
	if dispatchErr != nil {
		return resolution, fmt.Errorf("dispatch paid action: %w", dispatchErr)
	}
	return resolution, nil
}

// ProcessAuthorizedPaidAction is the complete non-streaming paid-action
// transaction after public credential verification: atomically admit the
// exact session/payment request, observe and apply the matching chain payment,
// then either execute a new claim once or recover an existing claim through
// GetTask only. A retry never bypasses the journal state machine.
func (c *Core) ProcessAuthorizedPaidAction(
	ctx context.Context,
	action authorization.AuthorizedPaidAction,
	observer *payment.Observer,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
	signer authorization.ReceiptSigner,
	taskRetention time.Duration,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	if c == nil {
		return ExecutionResolution{}, errors.New("nil Edge Core")
	}
	if ctx == nil {
		return ExecutionResolution{}, errors.New("nil paid-action context")
	}
	if observer == nil {
		return ExecutionResolution{}, errors.New("nil payment observer")
	}
	if taskRetention <= 0 ||
		taskRetention > localrpc.MaximumWorkerTaskRetention {
		return ExecutionResolution{}, errors.New("invalid paid-action retention")
	}
	now := c.now().UTC()
	material, err := action.Material(now)
	if err != nil {
		return ExecutionResolution{}, fmt.Errorf(
			"extract paid-action authorization: %w", err,
		)
	}
	scope, err := paidActionScope(material)
	if err != nil {
		return ExecutionResolution{}, err
	}
	retainUntil := now.Add(taskRetention)
	if !retainUntil.After(now) {
		return ExecutionResolution{}, errors.New(
			"paid-action retention overflows time",
		)
	}
	request, _, err := c.AdmitAuthorizedPayment(
		scope,
		material.IntentDigest,
		material.PaymentAuthorization,
		retainUntil,
	)
	if err != nil {
		return ExecutionResolution{}, fmt.Errorf(
			"admit paid action: %w", err,
		)
	}
	if request.State == journal.StatePending {
		observation, observeErr := observer.Observe(
			ctx,
			material.PaymentAuthorization,
			material.MinimumMasterSeqno,
			now,
		)
		if observeErr != nil {
			return ExecutionResolution{}, fmt.Errorf(
				"observe paid-action payment: %w", observeErr,
			)
		}
		request, _, _, err = c.ApplyVerifiedPayment(
			scope,
			material.IntentDigest,
			material.PaymentAuthorization,
			observation,
			material.MinimumMasterSeqno,
		)
		if err != nil {
			return ExecutionResolution{}, fmt.Errorf(
				"apply paid-action payment: %w", err,
			)
		}
	}
	switch request.State {
	case journal.StateAuthorized:
		return c.ExecuteRegisteredPaidAction(
			ctx,
			scope,
			request.Revision,
			material.PaymentAuthorization,
			material.Intent,
			plan,
			worker,
			material.Manifest,
			signer,
			receiptLifetime,
		)
	case journal.StateRunning,
		journal.StateSucceeded,
		journal.StateFailed,
		journal.StateCanceled,
		journal.StateTimedOut:
		return c.RecoverRegisteredPaidAction(
			ctx,
			scope,
			material.Intent,
			plan,
			worker,
			material.Manifest,
			signer,
			receiptLifetime,
		)
	default:
		return ExecutionResolution{}, fmt.Errorf(
			"paid action is not executable from state %q", request.State,
		)
	}
}

// HasAuthorizedPaidAction performs the read-only state classification needed
// by public admission. New requests must pass current capacity readiness;
// existing paid claims must remain recoverable even when the Worker is full or
// draining. This method never creates, extends, or transitions a record.
func (c *Core) HasAuthorizedPaidAction(
	action authorization.AuthorizedPaidAction,
) (bool, error) {
	if c == nil {
		return false, errors.New("nil Edge Core")
	}
	material, err := action.Material(c.now().UTC())
	if err != nil {
		return false, fmt.Errorf("extract paid-action state scope: %w", err)
	}
	scope, err := paidActionScope(material)
	if err != nil {
		return false, err
	}
	if _, err := c.requests.Get(scope, c.now().UTC()); err != nil {
		if errors.Is(err, journal.ErrNotFound) ||
			errors.Is(err, journal.ErrExpired) {
			return false, nil
		}
		return false, fmt.Errorf("read paid-action state: %w", err)
	}
	return true, nil
}

func paidActionScope(
	material authorization.PaidActionMaterial,
) (journal.Scope, error) {
	scope := journal.Scope{
		Network: material.Network, Authority: material.Authority,
		ServiceID: material.ServiceID, SessionID: material.SessionID,
		Operation: material.Operation, RequestID: material.RequestID,
	}
	if err := scope.Validate(); err != nil {
		return journal.Scope{}, fmt.Errorf("validate paid-action scope: %w", err)
	}
	return scope, nil
}

// RecoverRegisteredPaidAction performs the restart-safe counterpart. It uses
// only the durable payment/execution binding and GetTask; it never calls
// Invoke for an existing claim. Terminal outcomes enter the recovered receipt
// path, while missing, active, or uncertain tasks remain explicit nonterminal
// results.
func (c *Core) RecoverRegisteredPaidAction(
	ctx context.Context,
	scope journal.Scope,
	intent []byte,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
	manifest *authorization.VerifiedManifest,
	signer authorization.ReceiptSigner,
	receiptLifetime time.Duration,
) (ExecutionResolution, error) {
	dispatch, dispatchErr := c.DispatchRecoveredPaidExecution(
		ctx, scope, intent, plan, worker,
	)
	if !dispatch.valid {
		if dispatchErr == nil {
			dispatchErr = errors.New("paid action recovery produced an invalid dispatch")
		}
		return ExecutionResolution{}, dispatchErr
	}
	resolution, resolutionErr := c.ResolveRecoveredExecutionDispatch(
		ctx, dispatch, manifest, plan, signer, receiptLifetime,
	)
	if resolutionErr != nil {
		return ExecutionResolution{}, errors.Join(dispatchErr, fmt.Errorf(
			"resolve recovered paid action dispatch: %w", resolutionErr,
		))
	}
	if dispatchErr != nil {
		return resolution, fmt.Errorf("recover paid action dispatch: %w", dispatchErr)
	}
	return resolution, nil
}
