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
	completedAt := now.Add(4 * time.Second)
	result := testStoredInvokeResult(replayed.Request, "output-lifecycle", completedAt)
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
	changed := testStoredInvokeResult(replayed.Request, "changed-output", completedAt)
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

func TestWorkerTaskStoreScansActiveTasksWithBoundedPagination(t *testing.T) {
	createdAt := time.Unix(1_800_000_000, 0).UTC()
	store := openTestWorkerTaskStore(t, 10)
	claim := func(suffix string, retainUntil time.Time) StoredWorkerTask {
		t.Helper()
		request := testStoredInvokeRequest(createdAt, suffix)
		request.DeadlineUnixMillis = createdAt.Add(time.Minute).UnixMilli()
		request.RetainUntilUnixMillis = retainUntil.UnixMilli()
		task, disposition, err := store.ClaimTask(request, createdAt)
		if err != nil || disposition != TaskClaimed {
			t.Fatalf("claim %s disposition=%q err=%v", suffix, disposition, err)
		}
		return task
	}

	accepted := claim("scan-accepted", createdAt.Add(time.Hour))
	running := claim("scan-running", createdAt.Add(time.Hour))
	if _, _, err := store.MarkTaskRunning(
		identityForStoredTask(running), createdAt.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	terminal := claim("scan-terminal", createdAt.Add(time.Hour))
	if _, _, err := store.CompleteTaskFailure(
		identityForStoredTask(terminal),
		edgev1.TaskStatus_TASK_STATUS_FAILED,
		createdAt.Add(time.Second),
		createdAt.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	_ = claim("scan-expired", createdAt.Add(2*time.Minute))

	seen := make(map[string]edgev1.TaskStatus)
	cursor := ""
	for pageNumber := 0; ; pageNumber++ {
		if pageNumber > 4 {
			t.Fatal("active task scan did not terminate")
		}
		page, err := store.ScanActiveTasks(
			cursor, 1, createdAt.Add(3*time.Minute),
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, task := range page.Tasks {
			if _, duplicate := seen[task.Identity.TaskID]; duplicate {
				t.Fatalf("duplicate active task %q", task.Identity.TaskID)
			}
			seen[task.Identity.TaskID] = task.Status
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor == cursor || len(page.NextCursor) > 64 {
			t.Fatalf("invalid continuation cursor %q", page.NextCursor)
		}
		cursor = page.NextCursor
	}
	if len(seen) != 2 ||
		seen[accepted.Request.TaskId] != edgev1.TaskStatus_TASK_STATUS_ACCEPTED ||
		seen[running.Request.TaskId] != edgev1.TaskStatus_TASK_STATUS_RUNNING {
		t.Fatalf("active scan=%v", seen)
	}
	if _, err := store.ScanActiveTasks("not-a-cursor", 1, createdAt); err == nil {
		t.Fatal("invalid active task cursor was accepted")
	}
	if _, err := store.ScanActiveTasks("", 0, createdAt); err == nil {
		t.Fatal("zero active task scan limit was accepted")
	}
	if _, err := store.ScanActiveTasks(
		"", maximumWorkerActiveScan+1, createdAt,
	); err == nil {
		t.Fatal("excessive active task scan limit was accepted")
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
	if _, err := store.ScanActiveTasks(
		"", 1, now.Add(4*time.Minute),
	); !errors.Is(err, ErrTaskClosed) {
		t.Fatalf("closed active scan error=%v", err)
	}
}

func TestWorkerTaskStoreOwnerReserveIsAtomicAndMigrates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := privateWorkerTaskStorePath(t)
	config := DefaultWorkerTaskStoreConfig(path)
	config.MaxTasks = 4
	config.OwnerReservedTasks = 1
	config.AllowedPriorities = []edgev1.Priority{
		edgev1.Priority_PRIORITY_LOCAL_ASYNC,
		edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
		edgev1.Priority_PRIORITY_BACKGROUND,
	}
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(suffix string, priority edgev1.Priority, retain time.Time) error {
		request := testStoredInvokeRequest(now, suffix)
		request.Priority = priority
		request.DeadlineUnixMillis = now.Add(time.Minute).UnixMilli()
		request.RetainUntilUnixMillis = retain.UnixMilli()
		_, _, err := store.ClaimTask(request, now)
		return err
	}
	for index := range 3 {
		retain := now.Add(time.Hour)
		if index == 0 {
			retain = now.Add(2 * time.Minute)
		}
		if err := claim(
			fmt.Sprintf("reserve-external-%d", index),
			edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
			retain,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := claim(
		"reserve-external-blocked",
		edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
		now.Add(time.Hour),
	); !errors.Is(err, ErrTaskCapacity) {
		t.Fatalf("external task consumed owner reserve: %v", err)
	}
	if err := claim(
		"reserve-background-blocked",
		edgev1.Priority_PRIORITY_BACKGROUND,
		now.Add(time.Hour),
	); !errors.Is(err, ErrTaskCapacity) {
		t.Fatalf("background task consumed owner reserve: %v", err)
	}
	stats, err := store.Stats()
	if err != nil || stats.Tasks != 3 || stats.OwnerTasks != 0 ||
		stats.ExternalTasks != 3 || stats.OwnerReserved != 1 ||
		stats.Available != 1 || stats.AvailableExternal != 0 ||
		stats.OwnerReservedBytes != stats.MaximumTaskBytes ||
		stats.OwnerBytes != 0 || stats.ExternalBytes != stats.ReservedBytes ||
		stats.AvailableExternalBytes == 0 {
		t.Fatalf("reserved stats=%#v err=%v", stats, err)
	}
	if err := claim(
		"reserve-owner",
		edgev1.Priority_PRIORITY_LOCAL_ASYNC,
		now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	stats, err = store.Stats()
	if err != nil || stats.Tasks != 4 || stats.OwnerTasks != 1 ||
		stats.ExternalTasks != 3 || stats.Available != 0 ||
		stats.AvailableExternal != 0 || stats.OwnerBytes == 0 ||
		stats.ExternalBytes+stats.OwnerBytes != stats.ReservedBytes {
		t.Fatalf("full owner stats=%#v err=%v", stats, err)
	}
	removed, _, err := store.Cleanup(now.Add(3*time.Minute), 1)
	if err != nil || removed != 1 {
		t.Fatalf("owner-reserve cleanup removed=%d err=%v", removed, err)
	}
	stats, err = store.Stats()
	if err != nil || stats.Tasks != 3 || stats.OwnerTasks != 1 ||
		stats.ExternalTasks != 2 || stats.Available != 1 ||
		stats.AvailableExternal != 1 {
		t.Fatalf("post-cleanup owner stats=%#v err=%v", stats, err)
	}

	if err := store.db.Update(func(transaction *bolt.Tx) error {
		meta := transaction.Bucket(taskMetaBucket)
		for _, key := range [][]byte{
			taskOwnerCountKey, taskBytesKey, taskOwnerBytesKey,
		} {
			if err := meta.Delete(key); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	stats, err = migrated.Stats()
	if err != nil || stats.OwnerTasks != 1 || stats.ExternalTasks != 2 ||
		stats.ReservedBytes == 0 || stats.OwnerBytes == 0 ||
		stats.ExternalBytes+stats.OwnerBytes != stats.ReservedBytes {
		t.Fatalf("migrated owner stats=%#v err=%v", stats, err)
	}
}

func TestWorkerTaskStoreRetainedByteBudgetIsAtomicAndReleased(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := privateWorkerTaskStorePath(t)
	config := DefaultWorkerTaskStoreConfig(path)
	config.MaxTasks = 4
	maximumTaskBytes, err := WorkerTaskMaximumReservationBytes(
		config.MaxMessageBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxRetainedBytes = maximumTaskBytes
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := testStoredInvokeRequest(now, "byte-budget-first")
	firstRequest.RetainUntilUnixMillis = now.Add(2 * time.Minute).UnixMilli()
	first, disposition, err := store.ClaimTask(firstRequest, now)
	if err != nil || disposition != TaskClaimed {
		t.Fatalf("first claim disposition=%q err=%v", disposition, err)
	}
	stats, err := store.Stats()
	if err != nil || stats.ReservedBytes == 0 ||
		stats.ReservedBytes > stats.ByteCapacity ||
		stats.AvailableBytes != stats.ByteCapacity-stats.ReservedBytes ||
		stats.MaximumTaskBytes != maximumTaskBytes {
		t.Fatalf("claimed byte stats=%#v err=%v", stats, err)
	}
	reservedAfterClaim := stats.ReservedBytes
	completedAt := now.Add(time.Second)
	result := testStoredInvokeResult(first.Request, "terminal-output", completedAt)
	if _, _, err := store.CompleteTaskSuccess(
		identityForStoredTask(first),
		result,
		completedAt,
		completedAt,
	); err != nil {
		t.Fatal(err)
	}
	stats, err = store.Stats()
	if err != nil || stats.ReservedBytes != reservedAfterClaim {
		t.Fatalf("terminal reservation changed stats=%#v err=%v", stats, err)
	}
	secondRequest := testStoredInvokeRequest(now, "byte-budget-second")
	if _, _, err := store.ClaimTask(
		secondRequest, now,
	); !errors.Is(err, ErrTaskCapacity) {
		t.Fatalf("second retained-byte claim error=%v", err)
	}
	removed, hasMore, err := store.Cleanup(now.Add(3*time.Minute), 1)
	if err != nil || removed != 1 || hasMore {
		t.Fatalf("byte cleanup removed=%d more=%v err=%v", removed, hasMore, err)
	}
	stats, err = store.Stats()
	if err != nil || stats.ReservedBytes != 0 ||
		stats.AvailableBytes != stats.ByteCapacity {
		t.Fatalf("released byte stats=%#v err=%v", stats, err)
	}
	secondRequest.DeadlineUnixMillis = now.Add(5 * time.Minute).UnixMilli()
	secondRequest.RetainUntilUnixMillis = now.Add(time.Hour).UnixMilli()
	if _, disposition, err := store.ClaimTask(
		secondRequest, now.Add(3*time.Minute),
	); err != nil || disposition != TaskClaimed {
		t.Fatalf("post-cleanup byte claim disposition=%q err=%v", disposition, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerTaskStoreOwnerByteReserveRejectsExternalWork(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	config := DefaultWorkerTaskStoreConfig(privateWorkerTaskStorePath(t))
	config.MaxTasks = 4
	config.OwnerReservedTasks = 1
	config.AllowedPriorities = []edgev1.Priority{
		edgev1.Priority_PRIORITY_LOCAL_ASYNC,
		edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
	}
	maximumTaskBytes, err := WorkerTaskMaximumReservationBytes(
		config.MaxMessageBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxRetainedBytes = 2 * maximumTaskBytes
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := testStoredInvokeRequest(now, "owner-byte-external-first")
	if _, _, err := store.ClaimTask(first, now); err != nil {
		t.Fatal(err)
	}
	second := testStoredInvokeRequest(now, "owner-byte-external-blocked")
	if _, _, err := store.ClaimTask(
		second, now,
	); !errors.Is(err, ErrTaskCapacity) {
		t.Fatalf("external task consumed owner byte reserve: %v", err)
	}
	owner := testStoredInvokeRequest(now, "owner-byte-local")
	owner.Priority = edgev1.Priority_PRIORITY_LOCAL_ASYNC
	if _, disposition, err := store.ClaimTask(
		owner, now,
	); err != nil || disposition != TaskClaimed {
		t.Fatalf("owner byte claim disposition=%q err=%v", disposition, err)
	}
	stats, err := store.Stats()
	if err != nil || stats.Tasks != 2 || stats.OwnerTasks != 1 ||
		stats.ExternalTasks != 1 || stats.AvailableExternalBytes >=
		stats.MaximumTaskBytes || stats.OwnerReservedBytes != maximumTaskBytes ||
		stats.OwnerBytes == 0 {
		t.Fatalf("owner byte stats=%#v err=%v", stats, err)
	}
}

func TestWorkerTaskStoreConcurrentRetainedByteCapacity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	config := DefaultWorkerTaskStoreConfig(privateWorkerTaskStorePath(t))
	config.MaxTasks = 32
	maximumTaskBytes, err := WorkerTaskMaximumReservationBytes(
		config.MaxMessageBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxRetainedBytes = maximumTaskBytes
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const attempts = 16
	var claimed atomic.Int32
	var exhausted atomic.Int32
	errorsSeen := make(chan error, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := testStoredInvokeRequest(
				now, fmt.Sprintf("concurrent-byte-%d", index),
			)
			_, disposition, err := store.ClaimTask(request, now)
			switch {
			case err == nil && disposition == TaskClaimed:
				claimed.Add(1)
			case errors.Is(err, ErrTaskCapacity):
				exhausted.Add(1)
			default:
				errorsSeen <- fmt.Errorf(
					"disposition=%q error=%w", disposition, err,
				)
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	stats, err := store.Stats()
	if err != nil || claimed.Load() != 1 || exhausted.Load() != attempts-1 ||
		stats.Tasks != 1 || stats.ReservedBytes > stats.ByteCapacity {
		t.Fatalf(
			"claimed=%d exhausted=%d stats=%#v err=%v",
			claimed.Load(), exhausted.Load(), stats, err,
		)
	}
}

func TestWorkerTaskStoreRejectsReserveWithoutOwnerPriority(t *testing.T) {
	config := DefaultWorkerTaskStoreConfig(privateWorkerTaskStorePath(t))
	config.OwnerReservedTasks = 1
	if _, err := OpenWorkerTaskStore(config); err == nil {
		t.Fatal("owner reserve without local-async priority was accepted")
	}
}

func TestWorkerTaskStoreRejectsInvalidRetainedByteCapacity(t *testing.T) {
	config := DefaultWorkerTaskStoreConfig(privateWorkerTaskStorePath(t))
	config.MaxRetainedBytes = 1
	if _, err := OpenWorkerTaskStore(config); err == nil {
		t.Fatal("task store accepted a byte capacity below one maximum task")
	}
	config = DefaultWorkerTaskStoreConfig(privateWorkerTaskStorePath(t))
	config.OwnerReservedTasks = config.MaxTasks
	config.AllowedPriorities = append(
		config.AllowedPriorities,
		edgev1.Priority_PRIORITY_LOCAL_ASYNC,
	)
	if _, err := OpenWorkerTaskStore(config); err == nil {
		t.Fatal("task store accepted an owner byte reserve above byte capacity")
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

func TestWorkerTaskStoreRejectsRetainedByteCounterMismatch(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := privateWorkerTaskStorePath(t)
	config := DefaultWorkerTaskStoreConfig(path)
	store, err := OpenWorkerTaskStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ClaimTask(
		testStoredInvokeRequest(now, "corrupt-byte-counter"), now,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.db.Update(func(transaction *bolt.Tx) error {
		return writeTaskReservedBytes(transaction, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWorkerTaskStore(config); !errors.Is(err, ErrTaskCorrupt) {
		t.Fatalf("mismatched retained-byte counter reopened: %v", err)
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
	completedAt := now.Add(time.Second)
	result := testStoredInvokeResult(claimed.Request, "output", completedAt)
	result.ProtoReflect().SetUnknown(unknown)
	if _, _, err := store.CompleteTaskSuccess(
		identityForStoredTask(claimed),
		result,
		completedAt,
		completedAt,
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
	completedAt time.Time,
) *edgev1.InvokeResponse {
	return &edgev1.InvokeResponse{
		RequestId: request.RequestId,
		Output:    []byte(output),
		Usage: &edgev1.Usage{
			InputBytes:  uint64(len(request.Payload)),
			OutputBytes: uint64(len(output)),
		},
		ModelRevision:       "model-revision-1",
		RuntimeRevision:     "runtime-revision-1",
		CompletedUnixMillis: completedAt.UnixMilli(),
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
