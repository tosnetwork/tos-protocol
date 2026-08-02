package localrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
)

const (
	DefaultWorkerStreamChunkBytes = 64 << 10
	MaximumWorkerStreamChunkBytes = 1 << 20
	MaximumWorkerStreamEvents     = 65_536
)

// InvokeStream executes exactly once and validates the complete ordered stream
// before returning the same opaque completion type used by unary Invoke.
func (c *WorkerClient) InvokeStream(
	ctx context.Context, request *edgev1.InvokeRequest, chunkBytes uint64,
) (ValidatedInvocation, error) {
	if c == nil || c.stream == nil {
		return ValidatedInvocation{}, errors.New("nil worker streaming client")
	}
	prepared, err := c.PrepareInvocation(request)
	if err != nil {
		return ValidatedInvocation{}, err
	}
	chunkBytes, err = validateStreamChunkLimit(chunkBytes, prepared.MaxOutputBytes)
	if err != nil {
		return ValidatedInvocation{}, err
	}
	if chunkBytes > uint64(c.maxMessageBytes) {
		return ValidatedInvocation{}, errors.New("worker stream chunk exceeds client message policy")
	}
	callContext, cancel, err := boundedContext(ctx, time.UnixMilli(prepared.DeadlineUnixMillis))
	if err != nil {
		return ValidatedInvocation{}, err
	}
	defer cancel()
	stream, err := c.stream.InvokeStream(callContext, connect.NewRequest(&edgev1.InvokeStreamRequest{
		Invocation: prepared, MaxChunkBytes: chunkBytes,
	}))
	if err != nil {
		return ValidatedInvocation{}, fmt.Errorf("worker InvokeStream: %w", err)
	}
	return c.consumeStream(stream, prepared, 0, nil, "", chunkBytes)
}

// ResumeStream resumes a retained result at the exact next sequence. prefix is
// the already validated output. A resume never invokes model execution.
func (c *WorkerClient) ResumeStream(
	ctx context.Context, request *edgev1.InvokeRequest, nextSequence uint64,
	prefix []byte, expectedDigest string, chunkBytes uint64,
) (ValidatedInvocation, error) {
	if c == nil || c.stream == nil {
		return ValidatedInvocation{}, errors.New("nil worker streaming client")
	}
	prepared, err := c.PrepareInvocation(request)
	if err != nil {
		return ValidatedInvocation{}, err
	}
	chunkBytes, err = validateStreamChunkLimit(chunkBytes, prepared.MaxOutputBytes)
	if err != nil {
		return ValidatedInvocation{}, err
	}
	if chunkBytes > uint64(c.maxMessageBytes) {
		return ValidatedInvocation{}, errors.New("worker stream chunk exceeds client message policy")
	}
	if nextSequence == 0 || len(prefix) == 0 || uint64(len(prefix)) > prepared.MaxOutputBytes ||
		!workerDigestPattern.MatchString(expectedDigest) {
		return ValidatedInvocation{}, errors.New("invalid worker stream resume cursor")
	}
	callContext, cancel, err := boundedContext(ctx, time.UnixMilli(prepared.DeadlineUnixMillis))
	if err != nil {
		return ValidatedInvocation{}, err
	}
	defer cancel()
	stream, err := c.stream.ResumeStream(callContext, connect.NewRequest(&edgev1.ResumeStreamRequest{
		Task: &edgev1.GetTaskRequest{
			RequestId: prepared.RequestId, TaskId: prepared.TaskId,
			RequestDigest:         prepared.RequestDigest,
			RetainUntilUnixMillis: prepared.RetainUntilUnixMillis,
		},
		NextSequence: nextSequence, MaxChunkBytes: chunkBytes,
		ExpectedStreamDigest: expectedDigest,
		NextOffset:           uint64(len(prefix)),
	}))
	if err != nil {
		return ValidatedInvocation{}, fmt.Errorf("worker ResumeStream: %w", err)
	}
	return c.consumeStream(stream, prepared, nextSequence, prefix, expectedDigest, chunkBytes)
}

type streamReceiver interface {
	Receive() bool
	Msg() *edgev1.StreamEvent
	Err() error
}

func (c *WorkerClient) consumeStream(
	stream streamReceiver, request *edgev1.InvokeRequest, sequence uint64,
	prefix []byte, expectedDigest string, chunkBytes uint64,
) (ValidatedInvocation, error) {
	output := append(make([]byte, 0, request.MaxOutputBytes), prefix...)
	var terminal *edgev1.StreamEvent
	var modelRevision, runtimeRevision, streamDigest string
	var totalOutput uint64
	eventCount := 0
	for stream.Receive() {
		eventCount++
		event := stream.Msg()
		if eventCount > MaximumWorkerStreamEvents || terminal != nil || event == nil || event.RequestId != request.RequestId ||
			event.TaskId != request.TaskId || event.RequestDigest != request.RequestDigest ||
			event.Sequence != sequence || event.Offset != uint64(len(output)) ||
			uint64(len(event.Chunk)) > chunkBytes ||
			event.TotalOutputBytes > request.MaxOutputBytes ||
			(expectedDigest != "" && event.StreamDigest != expectedDigest) ||
			!workerDigestPattern.MatchString(event.StreamDigest) {
			return ValidatedInvocation{}, errors.New("invalid worker stream event")
		}
		if eventCount == 1 {
			totalOutput = event.TotalOutputBytes
			streamDigest = event.StreamDigest
		} else if event.TotalOutputBytes != totalOutput {
			return ValidatedInvocation{}, errors.New("worker stream total changed")
		} else if event.StreamDigest != streamDigest {
			return ValidatedInvocation{}, errors.New("worker stream digest changed")
		}
		if event.Terminal {
			if len(event.Chunk) != 0 {
				return ValidatedInvocation{}, errors.New("terminal worker stream event contains data")
			}
		} else if len(event.Chunk) == 0 || event.TerminalStatus != edgev1.TaskStatus_TASK_STATUS_UNSPECIFIED ||
			event.Usage != nil || event.ErrorCode != "" || event.CompletedUnixMillis != 0 {
			return ValidatedInvocation{}, errors.New("nonterminal worker stream event contains terminal state")
		}
		if err := boundedWorkerString("stream model revision", event.ModelRevision, 1, 512); err != nil {
			return ValidatedInvocation{}, err
		}
		if err := boundedWorkerString("stream runtime revision", event.RuntimeRevision, 1, 512); err != nil {
			return ValidatedInvocation{}, err
		}
		if modelRevision == "" {
			modelRevision, runtimeRevision = event.ModelRevision, event.RuntimeRevision
		} else if event.ModelRevision != modelRevision || event.RuntimeRevision != runtimeRevision {
			return ValidatedInvocation{}, errors.New("worker stream revision changed")
		}
		if uint64(len(output)) > request.MaxOutputBytes-uint64(len(event.Chunk)) {
			return ValidatedInvocation{}, errors.New("worker stream output exceeds bound")
		}
		output = append(output, event.Chunk...)
		if uint64(len(output)) > totalOutput {
			return ValidatedInvocation{}, errors.New("worker stream exceeded declared total")
		}
		sequence++
		if event.Terminal {
			terminal = event
		}
	}
	if err := stream.Err(); err != nil {
		return ValidatedInvocation{}, fmt.Errorf("receive worker stream: %w", err)
	}
	if terminal == nil || terminal.TerminalStatus != edgev1.TaskStatus_TASK_STATUS_SUCCEEDED ||
		terminal.Usage == nil || terminal.ErrorCode != "" ||
		terminal.TotalOutputBytes != uint64(len(output)) ||
		terminal.Usage.OutputBytes != uint64(len(output)) ||
		terminal.Usage.InputBytes != uint64(len(request.Payload)) ||
		terminal.CompletedUnixMillis == 0 ||
		terminal.CompletedUnixMillis > request.DeadlineUnixMillis {
		return ValidatedInvocation{}, errors.New("invalid terminal worker stream event")
	}
	digest := sha256.Sum256(output)
	computedDigest := "sha256:" + hex.EncodeToString(digest[:])
	if terminal.StreamDigest != computedDigest ||
		(expectedDigest != "" && expectedDigest != computedDigest) {
		return ValidatedInvocation{}, errors.New("worker stream digest mismatch")
	}
	response := &edgev1.InvokeResponse{
		RequestId: request.RequestId, Output: output, Usage: terminal.Usage,
		ModelRevision:       terminal.ModelRevision,
		RuntimeRevision:     terminal.RuntimeRevision,
		CompletedUnixMillis: terminal.CompletedUnixMillis,
	}
	if err := validateInvokeResponse(response, request); err != nil {
		return ValidatedInvocation{}, err
	}
	completedAt := time.UnixMilli(terminal.CompletedUnixMillis).UTC()
	now := c.now().UTC()
	if completedAt.Before(now.Add(-c.maxInvocationDuration-maxWorkerRecoveryClockSkew)) ||
		completedAt.After(now.Add(maxWorkerRecoveryClockSkew)) ||
		!time.UnixMilli(request.RetainUntilUnixMillis).After(completedAt) {
		return ValidatedInvocation{}, errors.New("worker stream completion time is invalid")
	}
	return validatedInvocationFromResponse(
		request, response, request.RequestDigest, completedAt,
	), nil
}

func validateStreamChunkLimit(value, maxOutput uint64) (uint64, error) {
	if value == 0 {
		value = DefaultWorkerStreamChunkBytes
		if maxOutput < value {
			value = maxOutput
		}
	}
	if value == 0 || value > MaximumWorkerStreamChunkBytes || value > maxOutput {
		return 0, errors.New("worker stream chunk limit is outside policy")
	}
	return value, nil
}
