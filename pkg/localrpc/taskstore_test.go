package localrpc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func TestWorkerTaskStoreLifecycleAndExactReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := openTestWorkerTaskStore(t, 10)
	request := testStoredInvokeRequest(now, "lifecycle")
	claimed, disposition, err := store.ClaimTask(request, now)
	if err != nil || disposition != TaskClaimed ||
		claimed.Status != edgev1.TaskStatus_TASK_STATUS_ACCEPTED ||
		claimed.Request.RequestDigest == "" || request.RequestDigest != "" {
		t.Fatalf(
			"claim=%#v disposition=%q caller_digest=%q err=%v",
			claimed,
			disposition,
			request.RequestDigest,
			err,
		)
	}
	identity := identityForStoredTask(claimed)
	derivedIdentity, err := claimed.Identity()
	if err != nil || derivedIdentity != identity {
		t.Fatalf("derived identity=%#v err=%v", derivedIdentity, err)
	}
	claimed.Request.Payload[0] ^= 1
	replayed, disposition, err := store.ClaimTask(request, now.Add(time.Second))
	if err != nil || disposition != TaskReplay ||
		string(replayed.Request.Payload) != "input-lifecycle" {
		t.Fatalf("claim replay=%#v disposition=%q err=%v", replayed, disposition, err)
	}
	running, transition, err := store.MarkTaskRunning(
		identity,
		now.Add(2*time.Second),
	)
	if err != nil || transition != TaskTransitionApplied ||
		running.Status != edgev1.TaskStatus_TASK_STATUS_RUNNING {
		t.Fatalf("running=%#v disposition=%q err=%v", running, transition, err)
	}
	if _, transition, err := store.MarkTaskRunning(
		identity,
		now.Add(3*time.Second),
	); err != nil || transition != TaskTransitionReplay {
		t.Fatalf("running replay disposition=%q err=%v", transition, err)
	}
	result := testStoredInvokeResult(replayed.Request, "output-lifecycle")
	completedAt := now.Add(4 * time.Second)
	completed, transition, err := store.CompleteTaskSuccess(
		identity,
		result,
		completedAt,
		completedAt,
	)
	if err != nil || transition != TaskTransitionApplied ||
		completed.Status != edgev1.TaskStatus_TASK_STATUS_SUCCEEDED ||
		string(completed.Result.Output) != "output-lifecycle" {
		t.Fatalf("completed=%#v disposition=%q err=%v", completed, transition, err)
	}
	if _, transition, err := store.CompleteTaskSuccess(
		identity,
		result,
		completedAt,
		completedAt.Add(time.Second),
	); err != nil || transition != TaskTransitionReplay {
		t.Fatalf("completion replay disposition=%q err=%v", transition, err)
	}
	changed := testStoredInvokeResult(replayed.Request, "changed-output")
	if _, _, err := store.CompleteTaskSuccess(
		identity,
		changed,
		completedAt,
		completedAt.Add(time.Second),
	); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("changed completion error=%v", err)
	}
	lookup := lookupForStoredTask(replayed)
	response, err := store.GetTask(lookup, completedAt.Add(time.Second))
	if err != nil || response.Status != edgev1.TaskStatus_TASK_STATUS_SUCCEEDED ||
		response.Result == nil || string(response.Result.Output) != "output-lifecycle" ||
		response.CompletedUnixMillis != completedAt.UnixMilli() {
		t.Fatalf("GetTask response=%#v err=%v", response, err)
	}
	response.Result.Output[0] ^= 1
	again, err := store.GetTask(lookup, completedAt.Add(time.Second))
	if err != nil || string(again.Result.Output) != "output-lifecycle" {
		t.Fatalf("GetTask aliases stored result: response=%#v err=%v", again, err)
	}
	if _, _, err := store.CompleteTaskFailure(
		identity,
		edgev1.TaskStatus_TASK_STATUS_FAILED,
		completedAt,
		completedAt.Add(time.Second),
	); !errors.Is(err, ErrTaskTransition) {
		t.Fatalf("contradictory terminal transition error=%v", err)
	}
	wrong := proto.Clone(lookup).(*edgev1.GetTaskRequest)
	wrong.RequestDigest = "sha256:" + strings.Repeat("a", 64)
	if _, err := store.GetTask(
		wrong,
		completedAt.Add(time.Second),
	); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("mismatched lookup error=%v", err)
	}
	missing := &edgev1.GetTaskRequest{
		RequestId: "request-missing-lifecycle",
		TaskId:    "task-missing-lifecycle", RequestDigest: wrong.RequestDigest,
		RetainUntilUnixMillis: now.Add(time.Hour).UnixMilli(),
	}
	notFound, err := store.GetTask(missing, completedAt.Add(time.Second))
	if err != nil || notFound.Status != edgev1.TaskStatus_TASK_STATUS_NOT_FOUND ||
		notFound.RetainUntilUnixMillis != 0 || notFound.Result != nil {
		t.Fatalf("missing task response=%#v err=%v", notFound, err)
	}
	expired, err := store.GetTask(lookup, now.Add(2*time.Hour))
	if err != nil || expired.Status != edgev1.TaskStatus_TASK_STATUS_NOT_FOUND ||
		expired.Result != nil {
		t.Fatalf("expired task response=%#v err=%v", expired, err)
	}
	removed, hasMore, err := store.Cleanup(now.Add(2*time.Hour), 1)
	if err != nil || removed != 1 || hasMore {
		t.Fatalf("terminal cleanup removed=%d more=%v err=%v", removed, hasMore, err)
	}
	key := workerTaskKey(replayed.Request.TaskId)
	if err := store.db.View(func(transaction *bolt.Tx) error {
		if transaction.Bucket(taskRecordsBucket).Get(key[:]) != nil ||
			transaction.Bucket(taskRequestsBucket).Get(key[:]) != nil ||
			transaction.Bucket(taskResultsBucket).Get(key[:]) != nil {
			return errors.New("expired task payloads remain")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerTaskStoreConcurrentClaimAndConflict(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := openTestWorkerTaskStore(t, 100)
	request := testStoredInvokeRequest(now, "concurrent")
	const attempts = 32
	var claimed atomic.Int32
	var replayed atomic.Int32
	errorsSeen := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, disposition, err := store.ClaimTask(request, now)
			switch {
			case err != nil:
				errorsSeen <- err
			case disposition == TaskClaimed:
				claimed.Add(1)
			case disposition == TaskReplay:
				replayed.Add(1)
			default:
				errorsSeen <- fmt.Errorf("unexpected disposition %q", disposition)
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	stats, err := store.Stats()
	if err != nil || claimed.Load() != 1 || replayed.Load() != attempts-1 ||
		stats.Tasks != 1 {
		t.Fatalf(
			"claimed=%d replayed=%d stats=%#v err=%v",
			claimed.Load(),
			replayed.Load(),
			stats,
			err,
		)
	}
	changed := testStoredInvokeRequest(now, "concurrent")
	changed.Payload = []byte("substituted")
	if _, _, err := store.ClaimTask(changed, now); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("changed task replay error=%v", err)
	}
}

func TestWorkerTaskStoreConcurrentTerminalReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := openTestWorkerTaskStore(t, 10)
	request := testStoredInvokeRequest(now, "terminal-concurrent")
	claimed, _, err := store.ClaimTask(request, now)
	if err != nil {
		t.Fatal(err)
	}
	identity := identityForStoredTask(claimed)
	completedAt := now.Add(time.Second)
	const attempts = 24
	var applied atomic.Int32
	var replayed atomic.Int32
	errorsSeen := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, disposition, err := store.CompleteTaskFailure(
				identity,
				edgev1.TaskStatus_TASK_STATUS_FAILED,
				completedAt,
				completedAt,
			)
			switch {
			case err != nil:
				errorsSeen <- err
			case disposition == TaskTransitionApplied:
				applied.Add(1)
			case disposition == TaskTransitionReplay:
				replayed.Add(1)
			default:
				errorsSeen <- fmt.Errorf("unexpected disposition %q", disposition)
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if applied.Load() != 1 || replayed.Load() != attempts-1 {
		t.Fatalf("applied=%d replayed=%d", applied.Load(), replayed.Load())
	}
	response, err := store.GetTask(
		lookupForStoredTask(claimed),
		completedAt,
	)
	if err != nil || response.Status != edgev1.TaskStatus_TASK_STATUS_FAILED ||
		response.ErrorCode != "RUNTIME_FAILED" {
		t.Fatalf("terminal response=%#v err=%v", response, err)
	}
}

func TestWorkerTaskStoreRecoversAfterRestartAndDeadline(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := privateWorkerTaskStorePath(t)
	config := DefaultWorkerTaskStoreConfig(path)
	first, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	request := testStoredInvokeRequest(now, "restart")
	claimed, disposition, err := first.ClaimTask(request, now)
	if err != nil || disposition != TaskClaimed {
		t.Fatalf("claim disposition=%q err=%v", disposition, err)
	}
	identity := identityForStoredTask(claimed)
	if _, _, err := first.MarkTaskRunning(identity, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.UnixMilli(request.DeadlineUnixMillis).UTC()
	second, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	replayed, disposition, err := second.ClaimTask(
		request,
		deadline.Add(time.Second),
	)
	if err != nil || disposition != TaskReplay ||
		replayed.Status != edgev1.TaskStatus_TASK_STATUS_RUNNING {
		t.Fatalf("post-deadline replay=%#v disposition=%q err=%v", replayed, disposition, err)
	}
	if _, transition, err := second.CompleteTaskFailure(
		identity,
		edgev1.TaskStatus_TASK_STATUS_TIMED_OUT,
		deadline,
		deadline.Add(time.Second),
	); err != nil || transition != TaskTransitionApplied {
		t.Fatalf("timeout disposition=%q err=%v", transition, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	response, err := third.GetTask(
		lookupForStoredTask(claimed),
		deadline.Add(2*time.Second),
	)
	if err != nil || response.Status != edgev1.TaskStatus_TASK_STATUS_TIMED_OUT ||
		response.ErrorCode != "DEADLINE_EXCEEDED" || response.Result != nil {
		t.Fatalf("recovered timeout=%#v err=%v", response, err)
	}
	newTask := testStoredInvokeRequest(now, "missing-after-deadline")
	if _, _, err := third.ClaimTask(
		newTask,
		time.UnixMilli(newTask.DeadlineUnixMillis).Add(time.Second),
	); err == nil {
		t.Fatal("new task was claimed after its execution deadline")
	}
}

func TestWorkerTaskStoreCapacityAndBoundedCleanup(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := privateWorkerTaskStorePath(t)
	config := DefaultWorkerTaskStoreConfig(path)
	config.MaxTasks = 2
	config.MaxPrunePerWrite = 1
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := testStoredInvokeRequest(now, "cleanup-first")
	first.DeadlineUnixMillis = now.Add(time.Minute).UnixMilli()
	first.RetainUntilUnixMillis = now.Add(2 * time.Minute).UnixMilli()
	second := testStoredInvokeRequest(now, "cleanup-second")
	second.DeadlineUnixMillis = now.Add(time.Minute).UnixMilli()
	second.RetainUntilUnixMillis = now.Add(3 * time.Minute).UnixMilli()
	if _, _, err := store.ClaimTask(first, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ClaimTask(second, now); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats()
	if err != nil || stats.Tasks != 2 || stats.Capacity != 2 ||
		stats.Available != 0 {
		t.Fatalf("saturated stats=%#v err=%v", stats, err)
	}
	third := testStoredInvokeRequest(now, "cleanup-third")
	if _, _, err := store.ClaimTask(third, now); !errors.Is(err, ErrTaskCapacity) {
		t.Fatalf("capacity error=%v", err)
	}
	removed, hasMore, err := store.Cleanup(now.Add(4*time.Minute), 1)
	if err != nil || removed != 1 || !hasMore {
		t.Fatalf("first cleanup removed=%d more=%v err=%v", removed, hasMore, err)
	}
	removed, hasMore, err = store.Cleanup(now.Add(4*time.Minute), 1)
	if err != nil || removed != 1 || hasMore {
		t.Fatalf("second cleanup removed=%d more=%v err=%v", removed, hasMore, err)
	}
	stats, err = store.Stats()
	if err != nil || stats.Tasks != 0 || stats.Capacity != 2 ||
		stats.Available != 2 {
		t.Fatalf("cleanup stats=%#v err=%v", stats, err)
	}
	third.DeadlineUnixMillis = now.Add(5 * time.Minute).UnixMilli()
	third.RetainUntilUnixMillis = now.Add(10 * time.Minute).UnixMilli()
	if _, disposition, err := store.ClaimTask(
		third,
		now.Add(4*time.Minute),
	); err != nil || disposition != TaskClaimed {
		t.Fatalf("post-cleanup claim disposition=%q err=%v", disposition, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stats(); !errors.Is(err, ErrTaskClosed) {
		t.Fatalf("closed stats error=%v", err)
	}
}

func TestWorkerTaskStoreFailsClosedOnCorruption(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := privateWorkerTaskStorePath(t)
	config := DefaultWorkerTaskStoreConfig(path)
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	request := testStoredInvokeRequest(now, "corrupt")
	claimed, _, err := store.ClaimTask(request, now)
	if err != nil {
		t.Fatal(err)
	}
	key := workerTaskKey(claimed.Request.TaskId)
	if err := store.db.Update(func(transaction *bolt.Tx) error {
		return transaction.Bucket(taskRequestsBucket).Put(key[:], []byte{0xff})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetTask(
		lookupForStoredTask(claimed),
		now.Add(time.Second),
	); !errors.Is(err, ErrTaskCorrupt) {
		t.Fatalf("corrupt request error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWorkerTaskStore(config); !errors.Is(err, ErrTaskCorrupt) {
		t.Fatalf("corrupt store reopened: %v", err)
	}
}

func TestWorkerTaskStoreRejectsOrphansAndRestrictsFile(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := privateWorkerTaskStorePath(t)
	config := DefaultWorkerTaskStoreConfig(path)
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	request := testStoredInvokeRequest(now, "orphan")
	if _, _, err := store.ClaimTask(request, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("task store mode=%v err=%v", info.Mode().Perm(), err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	orphan := workerTaskKey("task-orphaned-payload")
	if err := db.Update(func(transaction *bolt.Tx) error {
		return transaction.Bucket(taskRequestsBucket).Put(orphan[:], []byte{1})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWorkerTaskStore(config); !errors.Is(err, ErrTaskCorrupt) {
		t.Fatalf("orphaned store reopened: %v", err)
	}
}

func TestWorkerTaskStoreRejectsUnsafePath(t *testing.T) {
	t.Run("directory mode", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		config := DefaultWorkerTaskStoreConfig(
			filepath.Join(directory, "worker-tasks.db"),
		)
		if _, err := OpenWorkerTaskStore(config); err == nil {
			t.Fatal("task store accepted a non-private directory")
		}
	})
	t.Run("file symlink", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(directory, "target.db")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "worker-tasks.db")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenWorkerTaskStore(
			DefaultWorkerTaskStoreConfig(link),
		); err == nil {
			t.Fatal("task store accepted a symlink")
		}
	})
}

func TestWorkerTaskStoreFailurePolicyAndClose(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	for index, test := range []struct {
		status edgev1.TaskStatus
		code   string
	}{
		{edgev1.TaskStatus_TASK_STATUS_FAILED, "RUNTIME_FAILED"},
		{edgev1.TaskStatus_TASK_STATUS_CANCELED, "CANCELED"},
		{edgev1.TaskStatus_TASK_STATUS_TIMED_OUT, "DEADLINE_EXCEEDED"},
	} {
		t.Run(test.status.String(), func(t *testing.T) {
			store := openTestWorkerTaskStore(t, 10)
			request := testStoredInvokeRequest(now, fmt.Sprintf("failure-%d", index))
			claimed, _, err := store.ClaimTask(request, now)
			if err != nil {
				t.Fatal(err)
			}
			identity := identityForStoredTask(claimed)
			completedAt := now.Add(time.Second)
			completionNow := completedAt
			if test.status == edgev1.TaskStatus_TASK_STATUS_TIMED_OUT {
				deadline := time.UnixMilli(request.DeadlineUnixMillis).UTC()
				if _, _, err := store.CompleteTaskFailure(
					identity,
					test.status,
					completedAt,
					completedAt,
				); err == nil {
					t.Fatal("early timeout was accepted")
				}
				completedAt = deadline
				completionNow = deadline
			}
			terminal, disposition, err := store.CompleteTaskFailure(
				identity,
				test.status,
				completedAt,
				completionNow,
			)
			if err != nil || disposition != TaskTransitionApplied ||
				terminal.ErrorCode != test.code || terminal.Result != nil {
				t.Fatalf("terminal=%#v disposition=%q err=%v", terminal, disposition, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Stats(); !errors.Is(err, ErrTaskClosed) {
				t.Fatalf("closed store error=%v", err)
			}
		})
	}
}

func TestWorkerTaskStoreRejectsUnknownProtobufFields(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := openTestWorkerTaskStore(t, 10)
	unknown := []byte{0xa0, 0x06, 0x01}
	request := testStoredInvokeRequest(now, "unknown-fields")
	request.ProtoReflect().SetUnknown(unknown)
	if _, _, err := store.ClaimTask(request, now); err == nil {
		t.Fatal("unknown Invoke fields were persisted")
	}
	request = testStoredInvokeRequest(now, "unknown-fields")
	claimed, _, err := store.ClaimTask(request, now)
	if err != nil {
		t.Fatal(err)
	}
	result := testStoredInvokeResult(claimed.Request, "output")
	result.ProtoReflect().SetUnknown(unknown)
	if _, _, err := store.CompleteTaskSuccess(
		identityForStoredTask(claimed),
		result,
		now.Add(time.Second),
		now.Add(time.Second),
	); err == nil {
		t.Fatal("unknown Invoke result fields were persisted")
	}
	lookup := lookupForStoredTask(claimed)
	lookup.ProtoReflect().SetUnknown(unknown)
	if _, err := store.GetTask(lookup, now.Add(time.Second)); err == nil {
		t.Fatal("unknown GetTask fields were accepted")
	}
}

func openTestWorkerTaskStore(
	t *testing.T,
	maxTasks int,
) *WorkerTaskStore {
	t.Helper()
	config := DefaultWorkerTaskStoreConfig(privateWorkerTaskStorePath(t))
	config.MaxTasks = maxTasks
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func privateWorkerTaskStorePath(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "worker-tasks.db")
}

func testStoredInvokeRequest(
	now time.Time,
	suffix string,
) *edgev1.InvokeRequest {
	return &edgev1.InvokeRequest{
		RequestId:             "request-" + suffix,
		QuoteId:               "quote-" + suffix,
		TaskId:                "task-" + suffix,
		ServiceId:             "edge.example.ai",
		Operation:             "invoke",
		Model:                 "test-model",
		Payload:               []byte("input-" + suffix),
		MaxOutputBytes:        1024,
		DeadlineUnixMillis:    now.Add(time.Minute).UnixMilli(),
		Priority:              edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
		RetainUntilUnixMillis: now.Add(time.Hour).UnixMilli(),
	}
}

func testStoredInvokeResult(
	request *edgev1.InvokeRequest,
	output string,
) *edgev1.InvokeResponse {
	return &edgev1.InvokeResponse{
		RequestId: request.RequestId,
		Output:    []byte(output),
		Usage: &edgev1.Usage{
			InputBytes:  uint64(len(request.Payload)),
			OutputBytes: uint64(len(output)),
		},
		ModelRevision:   "model-revision-1",
		RuntimeRevision: "runtime-revision-1",
	}
}

func identityForStoredTask(task StoredWorkerTask) WorkerTaskIdentity {
	return WorkerTaskIdentity{
		RequestID: task.Request.RequestId, TaskID: task.Request.TaskId,
		RequestDigest: task.Request.RequestDigest,
		RetainUntil:   task.RetainUntil,
	}
}

func lookupForStoredTask(task StoredWorkerTask) *edgev1.GetTaskRequest {
	return &edgev1.GetTaskRequest{
		RequestId: task.Request.RequestId, TaskId: task.Request.TaskId,
		RequestDigest:         task.Request.RequestDigest,
		RetainUntilUnixMillis: task.RetainUntil.UnixMilli(),
	}
}
