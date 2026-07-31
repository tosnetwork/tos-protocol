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

// ProfileInvocationInput gives a vertical mapper the authenticated request
// identity and the exact quoted bounds. Intent is a defensive copy of the
// bytes committed by IntentDigest.
type ProfileInvocationInput struct {
	Network           string
	ServiceID         string
	ProfileID         string
	ProfileVersion    string
	ProfileExtensions []string
	SessionID         string
	Operation         string
	RequestID         string
	IntentDigest      string
	Intent            []byte
	MaxInputBytes     uint64
	MaxOutputBytes    uint64
	Deadline          time.Time
	ServiceRevision   string
	ResourceRevision  string
}

// ProfileInvocationOutput contains only profile-owned fields. Edge Core
// derives all request, payment, task, priority, limit, and deadline fields.
type ProfileInvocationOutput struct {
	Model   string
	Payload []byte
}

// ProfileInvocationMapper parses and semantically validates one negotiated
// profile intent, then maps it to the private Worker's model and payload.
type ProfileInvocationMapper interface {
	MapInvocation(context.Context, ProfileInvocationInput) (ProfileInvocationOutput, error)
}

type ProfileInvocationMapperFunc func(
	context.Context,
	ProfileInvocationInput,
) (ProfileInvocationOutput, error)

func (f ProfileInvocationMapperFunc) MapInvocation(
	ctx context.Context,
	input ProfileInvocationInput,
) (ProfileInvocationOutput, error) {
	return f(ctx, input)
}

type workerTaskCommitment struct {
	Version           string   `json:"version"`
	Network           string   `json:"network"`
	ServiceID         string   `json:"serviceId"`
	ProfileID         string   `json:"profileId"`
	ProfileVersion    string   `json:"profileVersion"`
	ProfileExtensions []string `json:"profileExtensions,omitempty"`
	SessionID         string   `json:"sessionId"`
	Operation         string   `json:"operation"`
	RequestID         string   `json:"requestId"`
	IntentDigest      string   `json:"intentDigest"`
	AuthorizationID   string   `json:"authorizationId"`
	QuoteID           string   `json:"quoteId"`
}

// mapAndClaimPaidExecution is the common internal bridge from a committed
// public profile intent to a private Worker request. Public package callers
// enter only through the exact-selector registry boundary.
func (c *Core) mapAndClaimPaidExecution(
	ctx context.Context,
	scope journal.Scope,
	expectedRevision uint64,
	paymentAuthorization authorization.AuthorizedPayment,
	intent []byte,
	mapper ProfileInvocationMapper,
	worker *localrpc.WorkerClient,
) (ClaimedInvocation, error) {
	if ctx == nil {
		return ClaimedInvocation{}, errors.New("nil profile mapping context")
	}
	if mapper == nil {
		return ClaimedInvocation{}, errors.New("nil profile invocation mapper")
	}
	if worker == nil {
		return ClaimedInvocation{}, errors.New("nil Worker client")
	}
	if err := ctx.Err(); err != nil {
		return ClaimedInvocation{}, err
	}
	material, err := paymentAuthorization.ReceiptInvocationMaterial()
	if err != nil {
		return ClaimedInvocation{}, fmt.Errorf(
			"extract profile invocation binding: %w",
			err,
		)
	}
	if scope.Network != material.Network ||
		scope.ServiceID != material.ServiceID ||
		scope.SessionID != material.SessionID ||
		scope.Operation != material.Operation ||
		scope.RequestID != material.RequestID {
		return ClaimedInvocation{}, errors.New(
			"profile invocation does not match paid request",
		)
	}
	if uint64(len(intent)) > material.MaxInputBytes {
		return ClaimedInvocation{}, errors.New(
			"profile intent exceeds quoted input limit",
		)
	}
	intentDigest, err := protocol.RequestIntentDigest(
		material.ProfileID,
		material.ProfileVersion,
		material.ProfileExtensions,
		material.Operation,
		intent,
	)
	if err != nil {
		return ClaimedInvocation{}, fmt.Errorf("commit profile intent: %w", err)
	}
	if intentDigest != material.IntentDigest {
		return ClaimedInvocation{}, errors.New(
			"profile intent does not match paid request commitment",
		)
	}
	state, err := c.requests.Get(scope, c.now().UTC())
	if err != nil {
		return ClaimedInvocation{}, err
	}
	if state.IntentDigest != material.IntentDigest {
		return ClaimedInvocation{}, errors.New(
			"profile intent does not match durable request",
		)
	}
	switch state.State {
	case journal.StateAuthorized:
		if state.Revision != expectedRevision {
			return ClaimedInvocation{}, journal.ErrRevision
		}
	case journal.StateRunning:
		// An exact deterministic reconstruction is required for replay below.
	default:
		return ClaimedInvocation{}, journal.ErrTransition
	}
	input := ProfileInvocationInput{
		Network: material.Network, ServiceID: material.ServiceID,
		ProfileID: material.ProfileID, ProfileVersion: material.ProfileVersion,
		ProfileExtensions: append([]string(nil), material.ProfileExtensions...),
		SessionID:         material.SessionID, Operation: material.Operation,
		RequestID: material.RequestID, IntentDigest: material.IntentDigest,
		Intent:        append([]byte(nil), intent...),
		MaxInputBytes: material.MaxInputBytes, MaxOutputBytes: material.MaxOutputBytes,
		Deadline: material.Deadline, ServiceRevision: material.ServiceRevision,
		ResourceRevision: material.ResourceRevision,
	}
	mapped, err := callProfileInvocationMapper(ctx, mapper, input)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	taskID, err := profileWorkerTaskID(material)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	request := &edgev1.InvokeRequest{
		RequestId: material.RequestID, QuoteId: material.QuoteID,
		TaskId: taskID, ServiceId: material.ServiceID,
		Operation: material.Operation, Model: mapped.Model,
		Payload:               append([]byte(nil), mapped.Payload...),
		MaxOutputBytes:        material.MaxOutputBytes,
		DeadlineUnixMillis:    material.Deadline.UnixMilli(),
		RetainUntilUnixMillis: ceilUnixMillis(state.RetainUntil),
		Priority:              edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
	}
	if state.State == journal.StateRunning {
		claimed, err := c.ClaimPaidExecution(
			scope,
			expectedRevision,
			paymentAuthorization,
			request,
		)
		if err != nil {
			return ClaimedInvocation{}, err
		}
		prepared, err := worker.PrepareTaskLookup(claimed.Request)
		if err != nil {
			return claimed, fmt.Errorf(
				"validate mapped Worker recovery request: %w",
				err,
			)
		}
		claimed.Request = prepared
		return claimed, nil
	}
	request, err = worker.PrepareInvocation(request)
	if err != nil {
		return ClaimedInvocation{}, fmt.Errorf(
			"validate mapped Worker invocation request: %w",
			err,
		)
	}
	return c.ClaimPaidExecution(
		scope,
		expectedRevision,
		paymentAuthorization,
		request,
	)
}

func callProfileInvocationMapper(
	ctx context.Context,
	mapper ProfileInvocationMapper,
	input ProfileInvocationInput,
) (output ProfileInvocationOutput, err error) {
	defer func() {
		if recover() != nil {
			output = ProfileInvocationOutput{}
			err = errors.New("profile invocation mapper panicked")
		}
	}()
	output, err = mapper.MapInvocation(ctx, input)
	if err != nil {
		return ProfileInvocationOutput{}, fmt.Errorf(
			"map profile invocation: %w",
			err,
		)
	}
	if err := ctx.Err(); err != nil {
		return ProfileInvocationOutput{}, err
	}
	output.Payload = append([]byte(nil), output.Payload...)
	return output, nil
}

func profileWorkerTaskID(
	material authorization.ReceiptInvocationMaterial,
) (string, error) {
	digest, err := codec.Digest("tos.private-worker-task.v1", workerTaskCommitment{
		Version: protocol.BaseEnvelopeVersion,
		Network: material.Network, ServiceID: material.ServiceID,
		ProfileID: material.ProfileID, ProfileVersion: material.ProfileVersion,
		ProfileExtensions: append([]string(nil), material.ProfileExtensions...),
		SessionID:         material.SessionID, Operation: material.Operation,
		RequestID: material.RequestID, IntentDigest: material.IntentDigest,
		AuthorizationID: material.AuthorizationID, QuoteID: material.QuoteID,
	})
	if err != nil {
		return "", fmt.Errorf("commit private Worker task identity: %w", err)
	}
	return "task-" + strings.TrimPrefix(digest, "sha256:"), nil
}
