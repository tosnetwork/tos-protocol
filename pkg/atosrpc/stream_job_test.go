package atosrpc

import (
	"bytes"
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/gen/atos/tos/v1/atostosv1connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func TestStreamJobResumesAtExactOffsetAndBindsDigest(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	server := openStreamTestServer(t, now)
	defer server.Close()
	output := []byte("abcdefghij")
	seedStreamTestJob(t, server, "job-stream-resume", atostosv1.JobState_JOB_STATE_COMPLETED, output)
	client, stop := streamTestClient(t, server)
	defer stop()

	request := &atostosv1.StreamJobRequest{
		Context: streamTestContext(now), JobId: "job-stream-resume",
		NextSequence: 7, NextOffset: 4, MaxChunkBytes: 3,
		ExpectedStreamDigest: digestMessage(output),
	}
	events, err := collectStreamEvents(context.Background(), client, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("events=%d want=4: %#v", len(events), events)
	}
	if events[0].Sequence != 7 || events[0].EventType != atostosv1.JobEventType_JOB_EVENT_TYPE_STATE {
		t.Fatalf("state event=%#v", events[0])
	}
	if events[1].Sequence != 8 || events[1].Offset != 4 || string(events[1].Chunk) != "efg" {
		t.Fatalf("first resumed chunk=%#v", events[1])
	}
	if events[2].Sequence != 9 || events[2].Offset != 7 || string(events[2].Chunk) != "hij" {
		t.Fatalf("second resumed chunk=%#v", events[2])
	}
	if events[3].Sequence != 10 || !events[3].Terminal || events[3].EventType != atostosv1.JobEventType_JOB_EVENT_TYPE_TERMINAL {
		t.Fatalf("terminal event=%#v", events[3])
	}
	for _, event := range events {
		if !proto.Equal(event.StreamDigest, digestMessage(output)) {
			t.Fatalf("event %d lost stream digest: %#v", event.Sequence, event.StreamDigest)
		}
	}
}

func TestStreamJobRejectsResumeWithoutMatchingDigest(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	server := openStreamTestServer(t, now)
	defer server.Close()
	output := []byte("abcdefghij")
	seedStreamTestJob(t, server, "job-stream-digest", atostosv1.JobState_JOB_STATE_COMPLETED, output)
	client, stop := streamTestClient(t, server)
	defer stop()

	cases := []*atostosv1.StreamJobRequest{
		{Context: streamTestContext(now), JobId: "job-stream-digest", NextOffset: 1},
		{Context: streamTestContext(now), JobId: "job-stream-digest", NextOffset: 1, ExpectedStreamDigest: digestMessage([]byte("different"))},
		{Context: streamTestContext(now), JobId: "job-stream-digest", NextOffset: uint64(len(output) + 1), ExpectedStreamDigest: digestMessage(output)},
	}
	for index, request := range cases {
		_, err := collectStreamEvents(context.Background(), client, request)
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("case %d error=%v code=%s", index, err, connect.CodeOf(err))
		}
	}
}

func TestStreamJobNonTerminalJobEmitsNoFalseTerminalEvent(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	server := openStreamTestServer(t, now)
	defer server.Close()
	seedStreamTestJob(t, server, "job-stream-working", atostosv1.JobState_JOB_STATE_WORKING, nil)
	client, stop := streamTestClient(t, server)
	defer stop()

	events, err := collectStreamEvents(context.Background(), client, &atostosv1.StreamJobRequest{
		Context: streamTestContext(now), JobId: "job-stream-working", NextSequence: 3, MaxChunkBytes: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Sequence != 3 || events[0].EventType != atostosv1.JobEventType_JOB_EVENT_TYPE_STATE || events[0].Terminal {
		t.Fatalf("events=%#v", events)
	}
}

func openStreamTestServer(t *testing.T, now time.Time) *Server {
	t.Helper()
	server, err := Open(Config{
		StatePath: filepath.Join(t.TempDir(), "atos-rpc.db"), BearerToken: "stream-test-secret",
		Authority: NewLocalAuthority("tos-local"), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func seedStreamTestJob(t *testing.T, server *Server, jobID string, state atostosv1.JobState, output []byte) {
	t.Helper()
	workerRequest, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&edgev1.InvokeRequest{
		RequestId: jobID, TaskId: "task-" + jobID,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&atostosv1.JobRecord{
		JobId: jobID, State: state, ProofStatus: &atostosv1.ProofStatus{},
		CreatedUnixMillis: server.now().UnixMilli(), UpdatedUnixMillis: server.now().UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.update(func(tx *bolt.Tx) error {
		return server.store.putJSON(tx, bucketJobs, jobID, storedExecutionJob{
			Record: record, WorkerRequest: workerRequest, RequestDigest: "sha256:test",
			Output: append([]byte(nil), output...),
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func streamTestClient(t *testing.T, server *Server) (atostosv1connect.ExecutionGatewayServiceClient, func()) {
	t.Helper()
	httpServer := httptest.NewServer(server.Handler())
	client := atostosv1connect.NewExecutionGatewayServiceClient(httpServer.Client(), httpServer.URL)
	return client, httpServer.Close
}

func streamTestContext(now time.Time) *atostosv1.RequestContext {
	return &atostosv1.RequestContext{
		RequestId: "request-stream-test", CallerId: "caller-stream-test",
		DeadlineUnixMillis: now.Add(time.Minute).UnixMilli(),
	}
}

func collectStreamEvents(
	ctx context.Context,
	client atostosv1connect.ExecutionGatewayServiceClient,
	message *atostosv1.StreamJobRequest,
) ([]*atostosv1.JobEvent, error) {
	request := connect.NewRequest(message)
	request.Header().Set("Authorization", "Bearer stream-test-secret")
	stream, err := client.StreamJob(ctx, request)
	if err != nil {
		return nil, err
	}
	var events []*atostosv1.JobEvent
	for stream.Receive() {
		events = append(events, proto.Clone(stream.Msg()).(*atostosv1.JobEvent))
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func TestStreamJobDigestUsesExactRetainedBytes(t *testing.T) {
	output := []byte{0, 1, 2, 3, 4}
	if bytes.Equal(digestMessage(output).Value, digestMessage(output[:4]).Value) {
		t.Fatal("stream digest did not bind all retained bytes")
	}
}
