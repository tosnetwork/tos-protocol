package localrpc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
)

type fakeStreamReceiver struct {
	events []*edgev1.StreamEvent
	index  int
	err    error
}

func (f *fakeStreamReceiver) Receive() bool {
	if f.index >= len(f.events) {
		return false
	}
	f.index++
	return true
}
func (f *fakeStreamReceiver) Msg() *edgev1.StreamEvent { return f.events[f.index-1] }
func (f *fakeStreamReceiver) Err() error               { return f.err }

func streamFixture(t *testing.T) (*WorkerClient, *edgev1.InvokeRequest, []*edgev1.StreamEvent) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	request, _, err := BindInvocationRequest(&edgev1.InvokeRequest{
		RequestId: "stream-request-0001", QuoteId: "stream-quote-0001", TaskId: "stream-task-0001",
		ServiceId: "tos.ai.mock", Operation: "generate", Model: "mock-model",
		Payload: []byte("input"), MaxOutputBytes: 8,
		DeadlineUnixMillis:    now.Add(time.Minute).UnixMilli(),
		RetainUntilUnixMillis: now.Add(time.Hour).UnixMilli(),
		Priority:              edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
	})
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256([]byte("hello"))
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	events := []*edgev1.StreamEvent{
		{RequestId: request.RequestId, TaskId: request.TaskId, RequestDigest: request.RequestDigest, Sequence: 0, Offset: 0, Chunk: []byte("he"), TotalOutputBytes: 5, StreamDigest: digest, ModelRevision: "sha256:" + strings.Repeat("a", 64), RuntimeRevision: "mock-v1"},
		{RequestId: request.RequestId, TaskId: request.TaskId, RequestDigest: request.RequestDigest, Sequence: 1, Offset: 2, Chunk: []byte("llo"), TotalOutputBytes: 5, StreamDigest: digest, ModelRevision: "sha256:" + strings.Repeat("a", 64), RuntimeRevision: "mock-v1"},
		{RequestId: request.RequestId, TaskId: request.TaskId, RequestDigest: request.RequestDigest, Sequence: 2, Offset: 5, TotalOutputBytes: 5, StreamDigest: digest, Terminal: true, TerminalStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED, Usage: &edgev1.Usage{InputBytes: 5, OutputBytes: 5}, ModelRevision: "sha256:" + strings.Repeat("a", 64), RuntimeRevision: "mock-v1", CompletedUnixMillis: now.UnixMilli()},
	}
	return &WorkerClient{maxInvocationDuration: time.Hour, maxTaskRetention: time.Hour, now: func() time.Time { return now }}, request, events
}

func TestConsumeStreamValidatesOrderingBindingLimitsAndDigest(t *testing.T) {
	client, request, events := streamFixture(t)
	validated, err := client.consumeStream(&fakeStreamReceiver{events: events}, request, 0, nil, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := validated.Completion(InvocationBinding{RequestID: request.RequestId, QuoteID: request.QuoteId, ServiceID: request.ServiceId, Operation: request.Operation})
	if err != nil || string(completion.Output) != "hello" {
		t.Fatalf("completion=%#v err=%v", completion, err)
	}

	for name, mutate := range map[string]func([]*edgev1.StreamEvent){
		"duplicate sequence": func(values []*edgev1.StreamEvent) { values[1].Sequence = 0 },
		"missing bytes":      func(values []*edgev1.StreamEvent) { values[1].Offset = 3 },
		"binding conflict":   func(values []*edgev1.StreamEvent) { values[0].TaskId = "different-task" },
		"chunk overflow":     func(values []*edgev1.StreamEvent) { values[0].Chunk = []byte("four") },
		"digest conflict":    func(values []*edgev1.StreamEvent) { values[2].StreamDigest = "sha256:" + strings.Repeat("0", 64) },
		"revision conflict":  func(values []*edgev1.StreamEvent) { values[1].RuntimeRevision = "mock-v2" },
		"total conflict":     func(values []*edgev1.StreamEvent) { values[1].TotalOutputBytes = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			_, _, clean := streamFixture(t)
			mutate(clean)
			if _, err := client.consumeStream(&fakeStreamReceiver{events: clean}, request, 0, nil, "", 3); err == nil {
				t.Fatal("invalid stream accepted")
			}
		})
	}
	if _, err := client.consumeStream(&fakeStreamReceiver{events: events, err: errors.New("disconnect")}, request, 0, nil, "", 3); err == nil {
		t.Fatal("transport disconnect accepted as terminal")
	}
}

func TestConsumeStreamResumeRequiresExactPrefix(t *testing.T) {
	client, request, events := streamFixture(t)
	resumed := events[1:]
	validated, err := client.consumeStream(&fakeStreamReceiver{events: resumed}, request, 1, []byte("he"), events[0].StreamDigest, 3)
	if err != nil {
		t.Fatal(err)
	}
	completion, _ := validated.Completion(InvocationBinding{RequestID: request.RequestId, QuoteID: request.QuoteId, ServiceID: request.ServiceId, Operation: request.Operation})
	if string(completion.Output) != "hello" {
		t.Fatalf("output=%q", completion.Output)
	}
	if _, err := client.consumeStream(&fakeStreamReceiver{events: resumed}, request, 1, []byte("xx"), events[0].StreamDigest, 3); err == nil {
		t.Fatal("wrong resume prefix accepted")
	}
}

func TestStreamDefaultChunkClampsToSmallOutput(t *testing.T) {
	value, err := validateStreamChunkLimit(0, 8)
	if err != nil || value != 8 {
		t.Fatalf("chunk=%d err=%v", value, err)
	}
}
