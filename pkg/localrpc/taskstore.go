package localrpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultWorkerMaxTasks         = 10_000
	DefaultWorkerMaxRetainedBytes = 8 << 30
	DefaultWorkerMaxPrunePerWrite = 64
	DefaultWorkerActiveScanLimit  = 256
	DefaultWorkerTaskOpenTimeout  = 5 * time.Second

	maximumWorkerTasks         = 1_000_000
	maximumWorkerRetainedBytes = 1 << 40
	maximumWorkerPrunePerWrite = 4096
	maximumWorkerActiveScan    = 4096
	maximumTaskMetadataBytes   = 16 << 10
	taskRecordVersion          = "1"
)

var (
	ErrTaskConflict   = errors.New("worker task binding conflict")
	ErrTaskCapacity   = errors.New("worker task store capacity exhausted")
	ErrTaskTransition = errors.New("invalid worker task transition")
	ErrTaskCorrupt    = errors.New("corrupt worker task store")
	ErrTaskClosed     = errors.New("worker task store is closed")
)

var (
	taskRecordsBucket  = []byte("task-records-v1")
	taskRequestsBucket = []byte("task-requests-v1")
	taskResultsBucket  = []byte("task-results-v1")
	taskExpiryBucket   = []byte("task-expiry-v1")
	taskMetaBucket     = []byte("task-meta-v1")
	taskCountKey       = []byte("task-count")
	taskOwnerCountKey  = []byte("task-owner-count")
	taskBytesKey       = []byte("task-reserved-bytes")
	taskOwnerBytesKey  = []byte("task-owner-reserved-bytes")
)

// WorkerTaskStoreConfig bounds the durable idempotency table owned by one
// vertical Worker. It intentionally repeats the private RPC byte, duration,
// retention, and priority policies so the server cannot persist a request
// that the Edge-side client would reject.
type WorkerTaskStoreConfig struct {
	Path                  string
	MaxTasks              int
	OwnerReservedTasks    int
	MaxRetainedBytes      uint64
	MaxMessageBytes       int
	MaxInvocationDuration time.Duration
	MaxTaskRetention      time.Duration
	MaxPrunePerWrite      int
	OpenTimeout           time.Duration
	AllowedPriorities     []edgev1.Priority
}

// DefaultWorkerTaskStoreConfig returns the private RPC defaults with an
// external-service-only priority policy.
func DefaultWorkerTaskStoreConfig(path string) WorkerTaskStoreConfig {
	return WorkerTaskStoreConfig{
		Path:                  path,
		MaxTasks:              DefaultWorkerMaxTasks,
		MaxRetainedBytes:      DefaultWorkerMaxRetainedBytes,
		MaxMessageBytes:       DefaultWorkerMaxMessageBytes,
		MaxInvocationDuration: DefaultWorkerMaxInvocationDuration,
		MaxTaskRetention:      DefaultWorkerMaxTaskRetention,
		MaxPrunePerWrite:      DefaultWorkerMaxPrunePerWrite,
		OpenTimeout:           DefaultWorkerTaskOpenTimeout,
		AllowedPriorities: []edgev1.Priority{
			edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
		},
	}
}

func (config WorkerTaskStoreConfig) validate() error {
	if !filepath.IsAbs(config.Path) {
		return errors.New("Worker task store path must be absolute")
	}
	if config.MaxTasks <= 0 || config.MaxTasks > maximumWorkerTasks ||
		config.OwnerReservedTasks < 0 ||
		config.OwnerReservedTasks > config.MaxTasks ||
		config.MaxRetainedBytes == 0 ||
		config.MaxRetainedBytes > maximumWorkerRetainedBytes ||
		config.MaxMessageBytes <= 0 ||
		config.MaxMessageBytes > maxWorkerMessageBytes ||
		config.MaxInvocationDuration <= 0 ||
		config.MaxInvocationDuration > maxWorkerInvocationDuration ||
		config.MaxTaskRetention <= 0 ||
		config.MaxTaskRetention > MaximumWorkerTaskRetention ||
		config.MaxPrunePerWrite <= 0 ||
		config.MaxPrunePerWrite > maximumWorkerPrunePerWrite ||
		config.OpenTimeout <= 0 || config.OpenTimeout > time.Minute {
		return errors.New("invalid Worker task store configuration")
	}
	priorities, err := validateAllowedPriorities(config.AllowedPriorities)
	if err != nil {
		return err
	}
	if config.OwnerReservedTasks != 0 {
		if _, allowed := priorities[edgev1.Priority_PRIORITY_LOCAL_ASYNC]; !allowed {
			return errors.New("owner task reserve requires local-async priority")
		}
	}
	maximumReservation, err := workerTaskMaximumReservationBytes(
		config.MaxMessageBytes,
	)
	if err != nil || config.MaxRetainedBytes < maximumReservation {
		return errors.New("Worker task byte capacity is too small")
	}
	ownerByteReserve, err := checkedMultiplyUint64(
		uint64(config.OwnerReservedTasks), maximumReservation,
	)
	if err != nil || ownerByteReserve > config.MaxRetainedBytes {
		return errors.New("owner task byte reserve exceeds capacity")
	}
	return nil
}

// TaskClaimDisposition distinguishes the one request that acquired execution
// ownership from an exact replay that MUST NOT start the workload again.
type TaskClaimDisposition string

const (
	TaskClaimed TaskClaimDisposition = "claimed"
	TaskReplay  TaskClaimDisposition = "replay"
)

// TaskTransitionDisposition reports whether a durable state transition was
// newly committed or was an exact idempotent replay.
type TaskTransitionDisposition string

const (
	TaskTransitionApplied TaskTransitionDisposition = "applied"
	TaskTransitionReplay  TaskTransitionDisposition = "replay"
)

// WorkerTaskIdentity is the complete immutable identity repeated by GetTask,
// cancellation, and executor completion callbacks.
type WorkerTaskIdentity struct {
	RequestID     string
	TaskID        string
	RequestDigest string
	RetainUntil   time.Time
}

// StoredWorkerTask is a defensive snapshot. Request and Result are cloned on
// every return so callers cannot mutate durable replay state.
type StoredWorkerTask struct {
	Request     *edgev1.InvokeRequest
	Status      edgev1.TaskStatus
	Result      *edgev1.InvokeResponse
	ErrorCode   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CompletedAt time.Time
	RetainUntil time.Time
}

// WorkerActiveTask is the minimum private identity required to reconcile an
// interrupted ACCEPTED or RUNNING task. It deliberately excludes request
// payloads, results, runtime diagnostics, and database keys.
type WorkerActiveTask struct {
	Identity WorkerTaskIdentity
	Status   edgev1.TaskStatus
}

// WorkerActiveTaskPage is one bounded startup scan page. NextCursor is an
// opaque, private continuation token and is empty after the final page.
type WorkerActiveTaskPage struct {
	Tasks      []WorkerActiveTask
	NextCursor string
}

// Identity returns the immutable callback identity for this defensive task
// snapshot. It rejects caller-constructed or internally inconsistent values.
func (task StoredWorkerTask) Identity() (WorkerTaskIdentity, error) {
	if task.Request == nil ||
		task.Request.RetainUntilUnixMillis != task.RetainUntil.UnixMilli() {
		return WorkerTaskIdentity{}, errors.New("invalid stored Worker task")
	}
	bound, _, err := BindInvocationRequest(task.Request)
	if err != nil || bound.RequestDigest != task.Request.RequestDigest {
		return WorkerTaskIdentity{}, errors.New("invalid stored Worker task")
	}
	return validateWorkerTaskIdentity(WorkerTaskIdentity{
		RequestID:     bound.RequestId,
		TaskID:        bound.TaskId,
		RequestDigest: bound.RequestDigest,
		RetainUntil:   task.RetainUntil,
	})
}

type workerTaskMetadata struct {
	Version       string            `json:"version"`
	RequestID     string            `json:"requestId"`
	TaskID        string            `json:"taskId"`
	RequestDigest string            `json:"requestDigest"`
	Status        edgev1.TaskStatus `json:"status"`
	ErrorCode     string            `json:"errorCode,omitempty"`
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"updatedAt"`
	CompletedAt   time.Time         `json:"completedAt,omitempty"`
	RetainUntil   time.Time         `json:"retainUntil"`
}

// WorkerTaskStore owns one Worker's crash-safe task idempotency table.
type WorkerTaskStore struct {
	db        *bolt.DB
	config    WorkerTaskStoreConfig
	validator *WorkerClient
	closeOnce sync.Once
	closed    atomic.Bool
}

// OpenWorkerTaskStore opens and fully audits the bounded Worker database
// before it can accept private RPC work.
func OpenWorkerTaskStore(config WorkerTaskStoreConfig) (*WorkerTaskStore, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if err := validateWorkerTaskStorePath(config.Path); err != nil {
		return nil, err
	}
	allowed, err := validateAllowedPriorities(config.AllowedPriorities)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(
		config.Path,
		0o600,
		&bolt.Options{Timeout: config.OpenTimeout},
	)
	if err != nil {
		return nil, fmt.Errorf("open Worker task store: %w", err)
	}
	if err := os.Chmod(config.Path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict Worker task store permissions: %w", err)
	}
	store := &WorkerTaskStore{
		db: db, config: config,
		validator: &WorkerClient{
			maxInvocationDuration: config.MaxInvocationDuration,
			maxMessageBytes:       config.MaxMessageBytes,
			maxTaskRetention:      config.MaxTaskRetention,
			allowedPriorities:     allowed,
		},
	}
	if err := db.Update(store.initialize); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize Worker task store: %w", err)
	}
	return store, nil
}

func validateWorkerTaskStorePath(path string) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		parent.Mode().Perm() != 0o700 || !ownedByCurrentUser(parent) {
		return errors.New("Worker task store directory must be private and owned")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!ownedByCurrentUser(info) {
		return errors.New("Worker task store must be a private owned regular file")
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func (store *WorkerTaskStore) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	var err error
	store.closeOnce.Do(func() {
		store.closed.Store(true)
		err = store.db.Close()
	})
	return err
}

func (store *WorkerTaskStore) initialize(transaction *bolt.Tx) error {
	for _, name := range [][]byte{
		taskRecordsBucket,
		taskRequestsBucket,
		taskResultsBucket,
		taskExpiryBucket,
		taskMetaBucket,
	} {
		if _, err := transaction.CreateBucketIfNotExists(name); err != nil {
			return err
		}
	}
	records := transaction.Bucket(taskRecordsBucket)
	requests := transaction.Bucket(taskRequestsBucket)
	results := transaction.Bucket(taskResultsBucket)
	expiry := transaction.Bucket(taskExpiryBucket)
	count := 0
	ownerCount := 0
	var reservedBytes uint64
	var ownerReservedBytes uint64
	if err := records.ForEach(func(key, encoded []byte) error {
		if len(key) != sha256.Size {
			return fmt.Errorf("%w: malformed task key", ErrTaskCorrupt)
		}
		metadata, err := store.decodeMetadata(encoded)
		if err != nil {
			return err
		}
		request := requests.Get(key)
		result := results.Get(key)
		task, err := store.decodeStoredTask(key, metadata, request, result)
		if err != nil {
			return err
		}
		if ownerTaskPriority(task.Request.Priority) {
			ownerCount++
		}
		reservation, err := workerTaskReservationBytes(
			len(request), store.config.MaxMessageBytes,
		)
		if err != nil {
			return fmt.Errorf("%w: invalid task byte reservation", ErrTaskCorrupt)
		}
		reservedBytes, err = checkedAddUint64(reservedBytes, reservation)
		if err != nil {
			return fmt.Errorf("%w: task byte accounting overflow", ErrTaskCorrupt)
		}
		if ownerTaskPriority(task.Request.Priority) {
			ownerReservedBytes, err = checkedAddUint64(
				ownerReservedBytes, reservation,
			)
			if err != nil {
				return fmt.Errorf("%w: owner byte accounting overflow", ErrTaskCorrupt)
			}
		}
		if expiry.Get(taskExpiryKey(metadata.RetainUntil, key)) == nil {
			return fmt.Errorf("%w: task has no expiry index", ErrTaskCorrupt)
		}
		count++
		return nil
	}); err != nil {
		return err
	}
	if count > store.config.MaxTasks {
		return ErrTaskCapacity
	}
	if reservedBytes > store.config.MaxRetainedBytes {
		return ErrTaskCapacity
	}
	if requests.Stats().KeyN != count || expiry.Stats().KeyN != count ||
		results.Stats().KeyN > count {
		return fmt.Errorf("%w: inconsistent task buckets", ErrTaskCorrupt)
	}
	for _, bucket := range []*bolt.Bucket{requests, results} {
		if err := bucket.ForEach(func(key, _ []byte) error {
			if len(key) != sha256.Size || records.Get(key) == nil {
				return fmt.Errorf(
					"%w: orphaned Worker task payload", ErrTaskCorrupt,
				)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if err := expiry.ForEach(func(key, _ []byte) error {
		if len(key) != 8+sha256.Size || records.Get(key[8:]) == nil {
			return fmt.Errorf(
				"%w: orphaned Worker task expiry", ErrTaskCorrupt,
			)
		}
		return nil
	}); err != nil {
		return err
	}
	meta := transaction.Bucket(taskMetaBucket)
	existingCount := meta.Get(taskCountKey)
	if existingCount != nil {
		if len(existingCount) != 8 ||
			binary.BigEndian.Uint64(existingCount) != uint64(count) {
			return fmt.Errorf("%w: task count mismatch", ErrTaskCorrupt)
		}
	} else if err := writeTaskCount(transaction, uint64(count)); err != nil {
		return err
	}
	existingOwnerCount := meta.Get(taskOwnerCountKey)
	if existingOwnerCount != nil {
		if len(existingOwnerCount) != 8 ||
			binary.BigEndian.Uint64(existingOwnerCount) != uint64(ownerCount) {
			return fmt.Errorf("%w: owner task count mismatch", ErrTaskCorrupt)
		}
	} else if err := writeTaskOwnerCount(transaction, uint64(ownerCount)); err != nil {
		return err
	}
	if err := verifyOrMigrateTaskUint64(
		transaction, taskBytesKey, reservedBytes, "task byte reservation",
	); err != nil {
		return err
	}
	return verifyOrMigrateTaskUint64(
		transaction,
		taskOwnerBytesKey,
		ownerReservedBytes,
		"owner task byte reservation",
	)
}

// ClaimTask atomically creates one ACCEPTED task or identifies an exact
// replay. Only TaskClaimed authorizes the caller to start execution.
func (store *WorkerTaskStore) ClaimTask(
	request *edgev1.InvokeRequest,
	now time.Time,
) (StoredWorkerTask, TaskClaimDisposition, error) {
	if store == nil || store.db == nil || store.closed.Load() {
		return StoredWorkerTask{}, "", ErrTaskClosed
	}
	now, err := validateTaskStoreNow(now)
	if err != nil {
		return StoredWorkerTask{}, "", err
	}
	request, _, err = BindInvocationRequest(request)
	if err != nil {
		return StoredWorkerTask{}, "", err
	}
	if err := store.validator.validateTaskLookupInvocation(request, now); err != nil {
		return StoredWorkerTask{}, "", err
	}
	encodedRequest, err := marshalTaskMessage(request, store.config.MaxMessageBytes)
	if err != nil {
		return StoredWorkerTask{}, "", err
	}
	reservationBytes, err := workerTaskReservationBytes(
		len(encodedRequest), store.config.MaxMessageBytes,
	)
	if err != nil {
		return StoredWorkerTask{}, "", err
	}
	key := workerTaskKey(request.TaskId)
	var output StoredWorkerTask
	var disposition TaskClaimDisposition
	err = store.db.Update(func(transaction *bolt.Tx) error {
		if _, _, err := store.pruneExpiredTx(
			transaction,
			now,
			store.config.MaxPrunePerWrite,
		); err != nil {
			return err
		}
		records := transaction.Bucket(taskRecordsBucket)
		if existing := records.Get(key[:]); existing != nil {
			metadata, err := store.decodeMetadata(existing)
			if err != nil {
				return err
			}
			storedRequest := transaction.Bucket(taskRequestsBucket).Get(key[:])
			storedResult := transaction.Bucket(taskResultsBucket).Get(key[:])
			task, err := store.decodeStoredTask(
				key[:], metadata, storedRequest, storedResult,
			)
			if err != nil {
				return err
			}
			if !bytes.Equal(storedRequest, encodedRequest) {
				return ErrTaskConflict
			}
			output = task
			disposition = TaskReplay
			return nil
		}
		count, err := readTaskCount(transaction)
		if err != nil {
			return err
		}
		ownerCount, err := readTaskOwnerCount(transaction)
		if err != nil || ownerCount > count {
			return ErrTaskCorrupt
		}
		if count >= uint64(store.config.MaxTasks) {
			return ErrTaskCapacity
		}
		ownerTask := ownerTaskPriority(request.Priority)
		externalCount := count - ownerCount
		externalCapacity := uint64(
			store.config.MaxTasks - store.config.OwnerReservedTasks,
		)
		if !ownerTask && externalCount >= externalCapacity {
			return ErrTaskCapacity
		}
		reservedBytes, err := readTaskReservedBytes(transaction)
		if err != nil || reservedBytes > store.config.MaxRetainedBytes {
			return ErrTaskCorrupt
		}
		ownerReservedBytes, err := readTaskOwnerReservedBytes(transaction)
		if err != nil || ownerReservedBytes > reservedBytes {
			return ErrTaskCorrupt
		}
		nextReservedBytes, err := checkedAddUint64(
			reservedBytes, reservationBytes,
		)
		if err != nil || nextReservedBytes > store.config.MaxRetainedBytes {
			return ErrTaskCapacity
		}
		maximumReservation, err := workerTaskMaximumReservationBytes(
			store.config.MaxMessageBytes,
		)
		if err != nil {
			return err
		}
		ownerByteReserve, err := checkedMultiplyUint64(
			uint64(store.config.OwnerReservedTasks), maximumReservation,
		)
		if err != nil || ownerByteReserve > store.config.MaxRetainedBytes {
			return ErrTaskCorrupt
		}
		if !ownerTask {
			externalBytes := reservedBytes - ownerReservedBytes
			nextExternalBytes, err := checkedAddUint64(
				externalBytes, reservationBytes,
			)
			if err != nil ||
				nextExternalBytes > store.config.MaxRetainedBytes-ownerByteReserve {
				return ErrTaskCapacity
			}
		}
		if err := store.validator.validateInvokeRequest(request, now); err != nil {
			return err
		}
		metadata := workerTaskMetadata{
			Version: taskRecordVersion, RequestID: request.RequestId,
			TaskID: request.TaskId, RequestDigest: request.RequestDigest,
			Status:    edgev1.TaskStatus_TASK_STATUS_ACCEPTED,
			CreatedAt: now, UpdatedAt: now,
			RetainUntil: time.UnixMilli(
				request.RetainUntilUnixMillis,
			).UTC(),
		}
		encodedMetadata, err := store.encodeMetadata(metadata)
		if err != nil {
			return err
		}
		if err := records.Put(key[:], encodedMetadata); err != nil {
			return err
		}
		if err := transaction.Bucket(taskRequestsBucket).Put(
			key[:], encodedRequest,
		); err != nil {
			return err
		}
		if err := transaction.Bucket(taskExpiryBucket).Put(
			taskExpiryKey(metadata.RetainUntil, key[:]),
			[]byte{1},
		); err != nil {
			return err
		}
		if err := writeTaskCount(transaction, count+1); err != nil {
			return err
		}
		if ownerTask {
			if err := writeTaskOwnerCount(transaction, ownerCount+1); err != nil {
				return err
			}
		}
		if err := writeTaskReservedBytes(transaction, nextReservedBytes); err != nil {
			return err
		}
		if ownerTask {
			nextOwnerBytes, err := checkedAddUint64(
				ownerReservedBytes, reservationBytes,
			)
			if err != nil {
				return err
			}
			if err := writeTaskOwnerReservedBytes(
				transaction, nextOwnerBytes,
			); err != nil {
				return err
			}
		}
		output = StoredWorkerTask{
			Request: cloneInvokeRequest(request), Status: metadata.Status,
			CreatedAt: now, UpdatedAt: now,
			RetainUntil: metadata.RetainUntil,
		}
		disposition = TaskClaimed
		return nil
	})
	return output, disposition, err
}

// MarkTaskRunning records executor ownership. An exact running replay has no
// second effect; a terminal or mismatched task fails closed.
func (store *WorkerTaskStore) MarkTaskRunning(
	identity WorkerTaskIdentity,
	now time.Time,
) (StoredWorkerTask, TaskTransitionDisposition, error) {
	return store.transitionTask(
		identity,
		now,
		edgev1.TaskStatus_TASK_STATUS_RUNNING,
		nil,
		"",
		time.Time{},
	)
}

// CompleteTaskSuccess atomically stores the exact result used by subsequent
// Invoke/GetTask replay. A result completed after its execution deadline is
// rejected and must be recorded as TIMED_OUT instead.
func (store *WorkerTaskStore) CompleteTaskSuccess(
	identity WorkerTaskIdentity,
	result *edgev1.InvokeResponse,
	completedAt time.Time,
	now time.Time,
) (StoredWorkerTask, TaskTransitionDisposition, error) {
	return store.transitionTask(
		identity,
		now,
		edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		result,
		"",
		completedAt,
	)
}

// CompleteTaskFailure records only the protocol-defined bounded error code;
// raw diagnostics stay outside the durable externally observable task table.
func (store *WorkerTaskStore) CompleteTaskFailure(
	identity WorkerTaskIdentity,
	status edgev1.TaskStatus,
	completedAt time.Time,
	now time.Time,
) (StoredWorkerTask, TaskTransitionDisposition, error) {
	errorCode := taskStatusErrorCode(status)
	if errorCode == "" {
		return StoredWorkerTask{}, "", errors.New(
			"unsupported terminal Worker task status",
		)
	}
	return store.transitionTask(
		identity,
		now,
		status,
		nil,
		errorCode,
		completedAt,
	)
}

func (store *WorkerTaskStore) transitionTask(
	identity WorkerTaskIdentity,
	now time.Time,
	status edgev1.TaskStatus,
	result *edgev1.InvokeResponse,
	errorCode string,
	completedAt time.Time,
) (StoredWorkerTask, TaskTransitionDisposition, error) {
	if store == nil || store.db == nil || store.closed.Load() {
		return StoredWorkerTask{}, "", ErrTaskClosed
	}
	now, err := validateTaskStoreNow(now)
	if err != nil {
		return StoredWorkerTask{}, "", err
	}
	identity, err = validateWorkerTaskIdentity(identity)
	if err != nil {
		return StoredWorkerTask{}, "", err
	}
	completedAt = normalizeTaskTime(completedAt)
	var output StoredWorkerTask
	var disposition TaskTransitionDisposition
	err = store.db.Update(func(transaction *bolt.Tx) error {
		key := workerTaskKey(identity.TaskID)
		metadata, request, existingResult, err := store.loadTaskTx(
			transaction,
			key[:],
		)
		if err != nil {
			return err
		}
		if err := matchWorkerTaskIdentity(metadata, identity); err != nil {
			return err
		}
		if !metadata.RetainUntil.After(now) {
			return ErrTaskTransition
		}
		var encodedResult []byte
		if status == edgev1.TaskStatus_TASK_STATUS_RUNNING {
			if result != nil || errorCode != "" || !completedAt.IsZero() {
				return ErrTaskTransition
			}
		} else {
			if completedAt.IsZero() || completedAt.Before(metadata.CreatedAt) ||
				completedAt.After(now) ||
				!metadata.RetainUntil.After(completedAt) {
				return errors.New("invalid Worker task completion time")
			}
			deadline := time.UnixMilli(request.DeadlineUnixMillis).UTC()
			if status == edgev1.TaskStatus_TASK_STATUS_SUCCEEDED {
				if errorCode != "" || completedAt.After(deadline) {
					return errors.New("successful Worker task completed after deadline")
				}
				if result == nil || !time.UnixMilli(
					result.CompletedUnixMillis,
				).UTC().Equal(completedAt) {
					return errors.New("Worker result completion time mismatch")
				}
				if err := validateInvokeResponse(result, request); err != nil {
					return err
				}
				encodedResult, err = marshalTaskMessage(
					result,
					store.config.MaxMessageBytes,
				)
				if err != nil {
					return err
				}
			} else if result != nil || errorCode != taskStatusErrorCode(status) {
				return ErrTaskTransition
			}
			if status == edgev1.TaskStatus_TASK_STATUS_TIMED_OUT &&
				(now.Before(deadline) || completedAt.Before(deadline)) {
				return errors.New("Worker task timed out before deadline")
			}
		}
		if metadata.Status == status {
			if metadata.ErrorCode != errorCode ||
				!metadata.CompletedAt.Equal(completedAt) ||
				!bytes.Equal(existingResult, encodedResult) {
				return ErrTaskConflict
			}
			task, err := store.decodeStoredTask(
				key[:], metadata,
				transaction.Bucket(taskRequestsBucket).Get(key[:]),
				existingResult,
			)
			if err != nil {
				return err
			}
			output = task
			disposition = TaskTransitionReplay
			return nil
		}
		if metadata.Status != edgev1.TaskStatus_TASK_STATUS_ACCEPTED &&
			metadata.Status != edgev1.TaskStatus_TASK_STATUS_RUNNING {
			return ErrTaskTransition
		}
		if status == edgev1.TaskStatus_TASK_STATUS_RUNNING &&
			metadata.Status != edgev1.TaskStatus_TASK_STATUS_ACCEPTED {
			return ErrTaskTransition
		}
		metadata.Status = status
		metadata.ErrorCode = errorCode
		metadata.UpdatedAt = now
		metadata.CompletedAt = completedAt
		encodedMetadata, err := store.encodeMetadata(metadata)
		if err != nil {
			return err
		}
		if err := transaction.Bucket(taskRecordsBucket).Put(
			key[:], encodedMetadata,
		); err != nil {
			return err
		}
		results := transaction.Bucket(taskResultsBucket)
		if len(encodedResult) == 0 {
			if err := results.Delete(key[:]); err != nil {
				return err
			}
		} else if err := results.Put(key[:], encodedResult); err != nil {
			return err
		}
		output, err = store.decodeStoredTask(
			key[:], metadata,
			transaction.Bucket(taskRequestsBucket).Get(key[:]),
			encodedResult,
		)
		if err != nil {
			return err
		}
		disposition = TaskTransitionApplied
		return nil
	})
	return output, disposition, err
}

// GetTask returns the exact protocol response expected by WorkerService.
// Missing and expired records become NOT_FOUND; a mismatched identity is an
// error rather than a task-existence oracle.
func (store *WorkerTaskStore) GetTask(
	request *edgev1.GetTaskRequest,
	now time.Time,
) (*edgev1.GetTaskResponse, error) {
	if store == nil || store.db == nil || store.closed.Load() {
		return nil, ErrTaskClosed
	}
	now, err := validateTaskStoreNow(now)
	if err != nil {
		return nil, err
	}
	identity, err := taskIdentityFromLookup(request)
	if err != nil {
		return nil, err
	}
	notFound := &edgev1.GetTaskResponse{
		RequestId: identity.RequestID, TaskId: identity.TaskID,
		RequestDigest: identity.RequestDigest,
		Status:        edgev1.TaskStatus_TASK_STATUS_NOT_FOUND,
	}
	key := workerTaskKey(identity.TaskID)
	var task StoredWorkerTask
	err = store.db.View(func(transaction *bolt.Tx) error {
		metadata, _, _, err := store.loadTaskTx(transaction, key[:])
		if errors.Is(err, bolt.ErrBucketNotFound) {
			return ErrTaskCorrupt
		}
		if err != nil {
			if errors.Is(err, errTaskMissing) {
				return nil
			}
			return err
		}
		if !metadata.RetainUntil.After(now) {
			return nil
		}
		if err := matchWorkerTaskIdentity(metadata, identity); err != nil {
			return err
		}
		var loadErr error
		task, loadErr = store.decodeStoredTask(
			key[:], metadata,
			transaction.Bucket(taskRequestsBucket).Get(key[:]),
			transaction.Bucket(taskResultsBucket).Get(key[:]),
		)
		return loadErr
	})
	if err != nil {
		return nil, err
	}
	if task.Request == nil {
		return notFound, nil
	}
	response := &edgev1.GetTaskResponse{
		RequestId: task.Request.RequestId,
		TaskId:    task.Request.TaskId, RequestDigest: task.Request.RequestDigest,
		Status:                task.Status,
		RetainUntilUnixMillis: task.RetainUntil.UnixMilli(),
	}
	if task.Status == edgev1.TaskStatus_TASK_STATUS_SUCCEEDED {
		response.Result = cloneInvokeResponse(task.Result)
		response.CompletedUnixMillis = task.CompletedAt.UnixMilli()
	} else if task.Status == edgev1.TaskStatus_TASK_STATUS_FAILED ||
		task.Status == edgev1.TaskStatus_TASK_STATUS_CANCELED ||
		task.Status == edgev1.TaskStatus_TASK_STATUS_TIMED_OUT {
		response.ErrorCode = task.ErrorCode
		response.CompletedUnixMillis = task.CompletedAt.UnixMilli()
	}
	return response, nil
}

// Cleanup deletes at most limit expired tasks and all associated payloads.
func (store *WorkerTaskStore) Cleanup(
	now time.Time,
	limit int,
) (removed int, hasMore bool, err error) {
	if store == nil || store.db == nil || store.closed.Load() {
		return 0, false, ErrTaskClosed
	}
	now, err = validateTaskStoreNow(now)
	if err != nil {
		return 0, false, err
	}
	if limit <= 0 || limit > maximumWorkerPrunePerWrite {
		return 0, false, errors.New("invalid Worker task cleanup limit")
	}
	err = store.db.Update(func(transaction *bolt.Tx) error {
		var pruneErr error
		removed, hasMore, pruneErr = store.pruneExpiredTx(
			transaction,
			now,
			limit,
		)
		return pruneErr
	})
	return removed, hasMore, err
}

// WorkerTaskStoreStats is an O(1) logical capacity snapshot. It contains no
// database path, task identity, payload, or retention metadata.
type WorkerTaskStoreStats struct {
	Tasks                  uint64
	Capacity               uint64
	Available              uint64
	OwnerReserved          uint64
	OwnerTasks             uint64
	ExternalTasks          uint64
	AvailableExternal      uint64
	ReservedBytes          uint64
	ByteCapacity           uint64
	AvailableBytes         uint64
	MaximumTaskBytes       uint64
	OwnerReservedBytes     uint64
	OwnerBytes             uint64
	ExternalBytes          uint64
	AvailableExternalBytes uint64
}

func (store *WorkerTaskStore) Stats() (WorkerTaskStoreStats, error) {
	if store == nil || store.db == nil || store.closed.Load() {
		return WorkerTaskStoreStats{}, ErrTaskClosed
	}
	var output WorkerTaskStoreStats
	err := store.db.View(func(transaction *bolt.Tx) error {
		count, err := readTaskCount(transaction)
		if err != nil {
			return err
		}
		capacity := uint64(store.config.MaxTasks)
		ownerCount, err := readTaskOwnerCount(transaction)
		if err != nil || count > capacity || ownerCount > count {
			return ErrTaskCorrupt
		}
		ownerReserved := uint64(store.config.OwnerReservedTasks)
		externalCount := count - ownerCount
		externalCapacity := capacity - ownerReserved
		availableExternal := uint64(0)
		if externalCount < externalCapacity && count < capacity {
			availableExternal = min(
				externalCapacity-externalCount,
				capacity-count,
			)
		}
		reservedBytes, err := readTaskReservedBytes(transaction)
		if err != nil || reservedBytes > store.config.MaxRetainedBytes {
			return ErrTaskCorrupt
		}
		ownerBytes, err := readTaskOwnerReservedBytes(transaction)
		if err != nil || ownerBytes > reservedBytes {
			return ErrTaskCorrupt
		}
		maximumTaskBytes, err := workerTaskMaximumReservationBytes(
			store.config.MaxMessageBytes,
		)
		if err != nil {
			return err
		}
		ownerReservedBytes, err := checkedMultiplyUint64(
			ownerReserved, maximumTaskBytes,
		)
		if err != nil || ownerReservedBytes > store.config.MaxRetainedBytes {
			return ErrTaskCorrupt
		}
		externalBytes := reservedBytes - ownerBytes
		externalByteCapacity := store.config.MaxRetainedBytes - ownerReservedBytes
		availableExternalBytes := uint64(0)
		if externalBytes < externalByteCapacity &&
			reservedBytes < store.config.MaxRetainedBytes {
			availableExternalBytes = min(
				externalByteCapacity-externalBytes,
				store.config.MaxRetainedBytes-reservedBytes,
			)
		}
		output = WorkerTaskStoreStats{
			Tasks: count, Capacity: capacity, Available: capacity - count,
			OwnerReserved: ownerReserved, OwnerTasks: ownerCount,
			ExternalTasks: externalCount, AvailableExternal: availableExternal,
			ReservedBytes:      reservedBytes,
			ByteCapacity:       store.config.MaxRetainedBytes,
			AvailableBytes:     store.config.MaxRetainedBytes - reservedBytes,
			MaximumTaskBytes:   maximumTaskBytes,
			OwnerReservedBytes: ownerReservedBytes,
			OwnerBytes:         ownerBytes, ExternalBytes: externalBytes,
			AvailableExternalBytes: availableExternalBytes,
		}
		return nil
	})
	return output, err
}

// ScanActiveTasks returns a bounded page of unexpired ACCEPTED/RUNNING task
// identities without loading their request payloads. The cursor advances by
// scanned database records rather than returned active tasks, so terminal
// records cannot create an unbounded scan. Callers use this only before
// accepting new Invoke requests; it is not a transactional executor snapshot.
func (store *WorkerTaskStore) ScanActiveTasks(
	cursor string,
	limit int,
	now time.Time,
) (WorkerActiveTaskPage, error) {
	if store == nil || store.db == nil || store.closed.Load() {
		return WorkerActiveTaskPage{}, ErrTaskClosed
	}
	if limit <= 0 || limit > maximumWorkerActiveScan {
		return WorkerActiveTaskPage{}, errors.New("invalid active task scan limit")
	}
	now, err := validateTaskStoreNow(now)
	if err != nil {
		return WorkerActiveTaskPage{}, err
	}
	resume, err := decodeActiveTaskCursor(cursor)
	if err != nil {
		return WorkerActiveTaskPage{}, err
	}
	output := WorkerActiveTaskPage{
		Tasks: make([]WorkerActiveTask, 0, limit),
	}
	err = store.db.View(func(transaction *bolt.Tx) error {
		records := transaction.Bucket(taskRecordsBucket)
		if records == nil {
			return ErrTaskCorrupt
		}
		iterator := records.Cursor()
		key, value := iterator.First()
		if len(resume) != 0 {
			key, value = iterator.Seek(resume)
			if key != nil && bytes.Equal(key, resume) {
				key, value = iterator.Next()
			}
		}
		var last []byte
		for scanned := 0; key != nil && scanned < limit; scanned++ {
			if len(key) != sha256.Size {
				return fmt.Errorf("%w: invalid task record key", ErrTaskCorrupt)
			}
			metadata, err := store.decodeMetadata(value)
			if err != nil {
				return err
			}
			if metadata.RetainUntil.After(now) &&
				(metadata.Status == edgev1.TaskStatus_TASK_STATUS_ACCEPTED ||
					metadata.Status == edgev1.TaskStatus_TASK_STATUS_RUNNING) {
				identity, err := validateWorkerTaskIdentity(WorkerTaskIdentity{
					RequestID: metadata.RequestID, TaskID: metadata.TaskID,
					RequestDigest: metadata.RequestDigest,
					RetainUntil:   metadata.RetainUntil,
				})
				if err != nil {
					return fmt.Errorf("%w: invalid active task identity", ErrTaskCorrupt)
				}
				boundKey := workerTaskKey(identity.TaskID)
				if !bytes.Equal(boundKey[:], key) {
					return fmt.Errorf("%w: active task key mismatch", ErrTaskCorrupt)
				}
				output.Tasks = append(output.Tasks, WorkerActiveTask{
					Identity: identity, Status: metadata.Status,
				})
			}
			last = append(last[:0], key...)
			key, value = iterator.Next()
		}
		if key != nil {
			output.NextCursor = base64.RawURLEncoding.EncodeToString(last)
		}
		return nil
	})
	if err != nil {
		return WorkerActiveTaskPage{}, err
	}
	return output, nil
}

func decodeActiveTaskCursor(cursor string) ([]byte, error) {
	if cursor == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid active task scan cursor")
	}
	return decoded, nil
}

func (store *WorkerTaskStore) loadTaskTx(
	transaction *bolt.Tx,
	key []byte,
) (workerTaskMetadata, *edgev1.InvokeRequest, []byte, error) {
	records := transaction.Bucket(taskRecordsBucket)
	requests := transaction.Bucket(taskRequestsBucket)
	results := transaction.Bucket(taskResultsBucket)
	if records == nil || requests == nil || results == nil {
		return workerTaskMetadata{}, nil, nil, ErrTaskCorrupt
	}
	encoded := records.Get(key)
	if encoded == nil {
		return workerTaskMetadata{}, nil, nil, errTaskMissing
	}
	metadata, err := store.decodeMetadata(encoded)
	if err != nil {
		return workerTaskMetadata{}, nil, nil, err
	}
	requestEncoded := requests.Get(key)
	resultEncoded := results.Get(key)
	task, err := store.decodeStoredTask(
		key,
		metadata,
		requestEncoded,
		resultEncoded,
	)
	if err != nil {
		return workerTaskMetadata{}, nil, nil, err
	}
	return metadata, task.Request, append([]byte(nil), resultEncoded...), nil
}

func (store *WorkerTaskStore) decodeStoredTask(
	key []byte,
	metadata workerTaskMetadata,
	requestEncoded []byte,
	resultEncoded []byte,
) (StoredWorkerTask, error) {
	if err := store.validateMetadata(metadata); err != nil {
		return StoredWorkerTask{}, err
	}
	if len(requestEncoded) == 0 || len(requestEncoded) > store.config.MaxMessageBytes {
		return StoredWorkerTask{}, fmt.Errorf(
			"%w: invalid stored Worker request size", ErrTaskCorrupt,
		)
	}
	request := new(edgev1.InvokeRequest)
	if err := proto.Unmarshal(requestEncoded, request); err != nil ||
		len(request.ProtoReflect().GetUnknown()) != 0 {
		return StoredWorkerTask{}, fmt.Errorf(
			"%w: invalid stored Worker request", ErrTaskCorrupt,
		)
	}
	canonicalRequest, err := marshalTaskMessage(
		request,
		store.config.MaxMessageBytes,
	)
	if err != nil || !bytes.Equal(canonicalRequest, requestEncoded) {
		return StoredWorkerTask{}, fmt.Errorf(
			"%w: noncanonical stored Worker request", ErrTaskCorrupt,
		)
	}
	bound, _, err := BindInvocationRequest(request)
	if err != nil {
		return StoredWorkerTask{}, fmt.Errorf(
			"%w: stored Worker request binding mismatch", ErrTaskCorrupt,
		)
	}
	boundKey := workerTaskKey(bound.TaskId)
	if !bytes.Equal(boundKey[:], key) {
		return StoredWorkerTask{}, fmt.Errorf(
			"%w: stored Worker request binding mismatch", ErrTaskCorrupt,
		)
	}
	if err := store.validateStoredInvocation(bound, metadata); err != nil {
		return StoredWorkerTask{}, err
	}
	var result *edgev1.InvokeResponse
	if metadata.Status == edgev1.TaskStatus_TASK_STATUS_SUCCEEDED {
		if len(resultEncoded) == 0 || len(resultEncoded) > store.config.MaxMessageBytes {
			return StoredWorkerTask{}, fmt.Errorf(
				"%w: invalid stored Worker result size", ErrTaskCorrupt,
			)
		}
		result = new(edgev1.InvokeResponse)
		if err := proto.Unmarshal(resultEncoded, result); err != nil ||
			len(result.ProtoReflect().GetUnknown()) != 0 ||
			validateInvokeResponse(result, bound) != nil {
			return StoredWorkerTask{}, fmt.Errorf(
				"%w: invalid stored Worker result", ErrTaskCorrupt,
			)
		}
		canonicalResult, err := marshalTaskMessage(
			result,
			store.config.MaxMessageBytes,
		)
		if err != nil || !bytes.Equal(canonicalResult, resultEncoded) {
			return StoredWorkerTask{}, fmt.Errorf(
				"%w: noncanonical stored Worker result", ErrTaskCorrupt,
			)
		}
	} else if len(resultEncoded) != 0 {
		return StoredWorkerTask{}, fmt.Errorf(
			"%w: non-success task has a stored result", ErrTaskCorrupt,
		)
	}
	return StoredWorkerTask{
		Request: cloneInvokeRequest(bound), Status: metadata.Status,
		Result: cloneInvokeResponse(result), ErrorCode: metadata.ErrorCode,
		CreatedAt: metadata.CreatedAt, UpdatedAt: metadata.UpdatedAt,
		CompletedAt: metadata.CompletedAt, RetainUntil: metadata.RetainUntil,
	}, nil
}

func (store *WorkerTaskStore) validateStoredInvocation(
	request *edgev1.InvokeRequest,
	metadata workerTaskMetadata,
) error {
	if request.RequestId != metadata.RequestID || request.TaskId != metadata.TaskID ||
		request.RequestDigest != metadata.RequestDigest {
		return fmt.Errorf("%w: stored task identity mismatch", ErrTaskCorrupt)
	}
	if err := validateWorkerID("request ID", request.RequestId); err != nil {
		return fmt.Errorf("%w: %v", ErrTaskCorrupt, err)
	}
	if err := validateWorkerID("quote ID", request.QuoteId); err != nil {
		return fmt.Errorf("%w: %v", ErrTaskCorrupt, err)
	}
	if err := validateWorkerID("task ID", request.TaskId); err != nil {
		return fmt.Errorf("%w: %v", ErrTaskCorrupt, err)
	}
	if err := validateWorkerSelector(
		request.ServiceId,
		request.Operation,
		request.Model,
	); err != nil {
		return fmt.Errorf("%w: %v", ErrTaskCorrupt, err)
	}
	if len(request.Payload) > store.config.MaxMessageBytes ||
		request.MaxOutputBytes == 0 ||
		request.MaxOutputBytes > uint64(store.config.MaxMessageBytes) {
		return fmt.Errorf("%w: stored task exceeds byte policy", ErrTaskCorrupt)
	}
	if _, allowed := store.validator.allowedPriorities[request.Priority]; !allowed {
		return fmt.Errorf("%w: stored task priority is disallowed", ErrTaskCorrupt)
	}
	deadline := time.UnixMilli(request.DeadlineUnixMillis).UTC()
	retainUntil := time.UnixMilli(request.RetainUntilUnixMillis).UTC()
	if request.DeadlineUnixMillis == 0 || request.RetainUntilUnixMillis == 0 ||
		!deadline.After(metadata.CreatedAt) ||
		!retainUntil.After(deadline) ||
		!retainUntil.Equal(metadata.RetainUntil) ||
		retainUntil.After(
			metadata.CreatedAt.Add(
				store.config.MaxTaskRetention+maxWorkerRetentionRounding,
			),
		) ||
		deadline.After(metadata.CreatedAt.Add(store.config.MaxInvocationDuration)) {
		return fmt.Errorf("%w: stored task timing is invalid", ErrTaskCorrupt)
	}
	return nil
}

func (store *WorkerTaskStore) validateMetadata(
	metadata workerTaskMetadata,
) error {
	if metadata.Version != taskRecordVersion ||
		metadata.CreatedAt.IsZero() || metadata.UpdatedAt.Before(metadata.CreatedAt) ||
		!metadata.RetainUntil.After(metadata.CreatedAt) {
		return fmt.Errorf("%w: invalid task metadata", ErrTaskCorrupt)
	}
	active := metadata.Status == edgev1.TaskStatus_TASK_STATUS_ACCEPTED ||
		metadata.Status == edgev1.TaskStatus_TASK_STATUS_RUNNING
	if active {
		if metadata.ErrorCode != "" || !metadata.CompletedAt.IsZero() {
			return fmt.Errorf("%w: active task has terminal metadata", ErrTaskCorrupt)
		}
		return nil
	}
	if metadata.Status != edgev1.TaskStatus_TASK_STATUS_SUCCEEDED &&
		taskStatusErrorCode(metadata.Status) == "" {
		return fmt.Errorf("%w: invalid terminal task status", ErrTaskCorrupt)
	}
	if metadata.CompletedAt.IsZero() ||
		!metadata.RetainUntil.After(metadata.CompletedAt) ||
		metadata.UpdatedAt.Before(metadata.CompletedAt) {
		return fmt.Errorf("%w: invalid terminal task time", ErrTaskCorrupt)
	}
	if metadata.Status == edgev1.TaskStatus_TASK_STATUS_SUCCEEDED {
		if metadata.ErrorCode != "" {
			return fmt.Errorf("%w: successful task has an error", ErrTaskCorrupt)
		}
	} else if metadata.ErrorCode != taskStatusErrorCode(metadata.Status) {
		return fmt.Errorf("%w: terminal task error mismatch", ErrTaskCorrupt)
	}
	return nil
}

func (store *WorkerTaskStore) encodeMetadata(
	metadata workerTaskMetadata,
) ([]byte, error) {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maximumTaskMetadataBytes {
		return nil, errors.New("Worker task metadata exceeds byte limit")
	}
	return encoded, nil
}

func (store *WorkerTaskStore) decodeMetadata(
	encoded []byte,
) (workerTaskMetadata, error) {
	if len(encoded) == 0 || len(encoded) > maximumTaskMetadataBytes {
		return workerTaskMetadata{}, fmt.Errorf(
			"%w: invalid task metadata size", ErrTaskCorrupt,
		)
	}
	var metadata workerTaskMetadata
	if err := jsonstrict.Decode(encoded, &metadata); err != nil {
		return workerTaskMetadata{}, fmt.Errorf(
			"%w: decode task metadata: %v", ErrTaskCorrupt, err,
		)
	}
	return metadata, nil
}

func (store *WorkerTaskStore) pruneExpiredTx(
	transaction *bolt.Tx,
	now time.Time,
	limit int,
) (removed int, hasMore bool, err error) {
	expiry := transaction.Bucket(taskExpiryBucket)
	records := transaction.Bucket(taskRecordsBucket)
	requests := transaction.Bucket(taskRequestsBucket)
	results := transaction.Bucket(taskResultsBucket)
	if expiry == nil || records == nil || requests == nil || results == nil {
		return 0, false, ErrTaskCorrupt
	}
	cursor := expiry.Cursor()
	ownerRemoved := 0
	var bytesRemoved uint64
	var ownerBytesRemoved uint64
	for key, _ := cursor.First(); key != nil && removed < limit; key, _ = cursor.Next() {
		if len(key) != 8+sha256.Size {
			return removed, false, fmt.Errorf(
				"%w: malformed task expiry key", ErrTaskCorrupt,
			)
		}
		if int64(binary.BigEndian.Uint64(key[:8])) > now.UnixMilli() {
			break
		}
		taskKey := append([]byte(nil), key[8:]...)
		encoded := records.Get(taskKey)
		if encoded == nil {
			return removed, false, fmt.Errorf(
				"%w: expiry index has no task", ErrTaskCorrupt,
			)
		}
		metadata, err := store.decodeMetadata(encoded)
		if err != nil {
			return removed, false, err
		}
		if !bytes.Equal(taskExpiryKey(metadata.RetainUntil, taskKey), key) {
			return removed, false, fmt.Errorf(
				"%w: task expiry binding mismatch", ErrTaskCorrupt,
			)
		}
		task, err := store.decodeStoredTask(
			taskKey,
			metadata,
			requests.Get(taskKey),
			results.Get(taskKey),
		)
		if err != nil {
			return removed, false, err
		}
		if ownerTaskPriority(task.Request.Priority) {
			ownerRemoved++
		}
		reservationBytes, err := workerTaskReservationBytes(
			len(requests.Get(taskKey)), store.config.MaxMessageBytes,
		)
		if err != nil {
			return removed, false, fmt.Errorf(
				"%w: invalid task byte reservation", ErrTaskCorrupt,
			)
		}
		bytesRemoved, err = checkedAddUint64(bytesRemoved, reservationBytes)
		if err != nil {
			return removed, false, ErrTaskCorrupt
		}
		if ownerTaskPriority(task.Request.Priority) {
			ownerBytesRemoved, err = checkedAddUint64(
				ownerBytesRemoved, reservationBytes,
			)
			if err != nil {
				return removed, false, ErrTaskCorrupt
			}
		}
		if err := records.Delete(taskKey); err != nil {
			return removed, false, err
		}
		if err := requests.Delete(taskKey); err != nil {
			return removed, false, err
		}
		if err := results.Delete(taskKey); err != nil {
			return removed, false, err
		}
		if err := cursor.Delete(); err != nil {
			return removed, false, err
		}
		removed++
	}
	count, err := readTaskCount(transaction)
	if err != nil {
		return removed, false, err
	}
	if uint64(removed) > count {
		return removed, false, ErrTaskCorrupt
	}
	if removed != 0 {
		if err := writeTaskCount(transaction, count-uint64(removed)); err != nil {
			return removed, false, err
		}
	}
	ownerCount, err := readTaskOwnerCount(transaction)
	if err != nil || uint64(ownerRemoved) > ownerCount || ownerCount > count {
		return removed, false, ErrTaskCorrupt
	}
	if ownerRemoved != 0 {
		if err := writeTaskOwnerCount(
			transaction, ownerCount-uint64(ownerRemoved),
		); err != nil {
			return removed, false, err
		}
	}
	reservedBytes, err := readTaskReservedBytes(transaction)
	if err != nil || bytesRemoved > reservedBytes {
		return removed, false, ErrTaskCorrupt
	}
	if bytesRemoved != 0 {
		if err := writeTaskReservedBytes(
			transaction, reservedBytes-bytesRemoved,
		); err != nil {
			return removed, false, err
		}
	}
	ownerReservedBytes, err := readTaskOwnerReservedBytes(transaction)
	if err != nil || ownerBytesRemoved > ownerReservedBytes ||
		ownerReservedBytes > reservedBytes {
		return removed, false, ErrTaskCorrupt
	}
	if ownerBytesRemoved != 0 {
		if err := writeTaskOwnerReservedBytes(
			transaction, ownerReservedBytes-ownerBytesRemoved,
		); err != nil {
			return removed, false, err
		}
	}
	key, _ := cursor.First()
	hasMore = len(key) == 8+sha256.Size &&
		int64(binary.BigEndian.Uint64(key[:8])) <= now.UnixMilli()
	return removed, hasMore, nil
}

func validateWorkerTaskIdentity(
	identity WorkerTaskIdentity,
) (WorkerTaskIdentity, error) {
	if err := validateWorkerID("request ID", identity.RequestID); err != nil {
		return WorkerTaskIdentity{}, err
	}
	if err := validateWorkerID("task ID", identity.TaskID); err != nil {
		return WorkerTaskIdentity{}, err
	}
	if !workerDigestPattern.MatchString(identity.RequestDigest) {
		return WorkerTaskIdentity{}, errors.New("invalid Worker task request digest")
	}
	identity.RetainUntil = normalizeTaskTime(identity.RetainUntil)
	if identity.RetainUntil.IsZero() {
		return WorkerTaskIdentity{}, errors.New("invalid Worker task retention")
	}
	return identity, nil
}

func taskIdentityFromLookup(
	request *edgev1.GetTaskRequest,
) (WorkerTaskIdentity, error) {
	if request == nil {
		return WorkerTaskIdentity{}, errors.New("nil Worker GetTask request")
	}
	if len(request.ProtoReflect().GetUnknown()) != 0 {
		return WorkerTaskIdentity{}, errors.New(
			"unknown Worker GetTask request fields",
		)
	}
	if request.RetainUntilUnixMillis == 0 {
		return WorkerTaskIdentity{}, errors.New("invalid Worker task retention")
	}
	return validateWorkerTaskIdentity(WorkerTaskIdentity{
		RequestID: request.RequestId, TaskID: request.TaskId,
		RequestDigest: request.RequestDigest,
		RetainUntil: time.UnixMilli(
			request.RetainUntilUnixMillis,
		).UTC(),
	})
}

func matchWorkerTaskIdentity(
	metadata workerTaskMetadata,
	identity WorkerTaskIdentity,
) error {
	if metadata.RequestID != identity.RequestID ||
		metadata.TaskID != identity.TaskID ||
		metadata.RequestDigest != identity.RequestDigest ||
		!metadata.RetainUntil.Equal(identity.RetainUntil) {
		return ErrTaskConflict
	}
	return nil
}

func workerTaskKey(taskID string) [sha256.Size]byte {
	hasher := sha256.New()
	hasher.Write([]byte("TOS-WORKER-TASK-STORE-V1"))
	hasher.Write([]byte{0})
	hasher.Write([]byte(taskID))
	var output [sha256.Size]byte
	copy(output[:], hasher.Sum(nil))
	return output
}

func taskExpiryKey(retainUntil time.Time, taskKey []byte) []byte {
	key := make([]byte, 8+sha256.Size)
	binary.BigEndian.PutUint64(key[:8], uint64(retainUntil.UnixMilli()))
	copy(key[8:], taskKey)
	return key
}

func readTaskCount(transaction *bolt.Tx) (uint64, error) {
	meta := transaction.Bucket(taskMetaBucket)
	if meta == nil {
		return 0, ErrTaskCorrupt
	}
	encoded := meta.Get(taskCountKey)
	if len(encoded) != 8 {
		return 0, fmt.Errorf("%w: invalid task count", ErrTaskCorrupt)
	}
	return binary.BigEndian.Uint64(encoded), nil
}

func writeTaskCount(transaction *bolt.Tx, count uint64) error {
	meta := transaction.Bucket(taskMetaBucket)
	if meta == nil {
		return ErrTaskCorrupt
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, count)
	return meta.Put(taskCountKey, encoded)
}

func readTaskOwnerCount(transaction *bolt.Tx) (uint64, error) {
	meta := transaction.Bucket(taskMetaBucket)
	if meta == nil {
		return 0, ErrTaskCorrupt
	}
	encoded := meta.Get(taskOwnerCountKey)
	if len(encoded) != 8 {
		return 0, fmt.Errorf("%w: invalid owner task count", ErrTaskCorrupt)
	}
	return binary.BigEndian.Uint64(encoded), nil
}

func writeTaskOwnerCount(transaction *bolt.Tx, count uint64) error {
	meta := transaction.Bucket(taskMetaBucket)
	if meta == nil {
		return ErrTaskCorrupt
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, count)
	return meta.Put(taskOwnerCountKey, encoded)
}

func readTaskReservedBytes(transaction *bolt.Tx) (uint64, error) {
	return readTaskUint64(transaction, taskBytesKey, "task byte reservation")
}

func writeTaskReservedBytes(transaction *bolt.Tx, value uint64) error {
	return writeTaskUint64(transaction, taskBytesKey, value)
}

func readTaskOwnerReservedBytes(transaction *bolt.Tx) (uint64, error) {
	return readTaskUint64(
		transaction, taskOwnerBytesKey, "owner task byte reservation",
	)
}

func writeTaskOwnerReservedBytes(transaction *bolt.Tx, value uint64) error {
	return writeTaskUint64(transaction, taskOwnerBytesKey, value)
}

func readTaskUint64(
	transaction *bolt.Tx,
	key []byte,
	name string,
) (uint64, error) {
	meta := transaction.Bucket(taskMetaBucket)
	if meta == nil {
		return 0, ErrTaskCorrupt
	}
	encoded := meta.Get(key)
	if len(encoded) != 8 {
		return 0, fmt.Errorf("%w: invalid %s", ErrTaskCorrupt, name)
	}
	return binary.BigEndian.Uint64(encoded), nil
}

func writeTaskUint64(transaction *bolt.Tx, key []byte, value uint64) error {
	meta := transaction.Bucket(taskMetaBucket)
	if meta == nil {
		return ErrTaskCorrupt
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return meta.Put(key, encoded)
}

func verifyOrMigrateTaskUint64(
	transaction *bolt.Tx,
	key []byte,
	expected uint64,
	name string,
) error {
	meta := transaction.Bucket(taskMetaBucket)
	if meta == nil {
		return ErrTaskCorrupt
	}
	existing := meta.Get(key)
	if existing == nil {
		return writeTaskUint64(transaction, key, expected)
	}
	if len(existing) != 8 || binary.BigEndian.Uint64(existing) != expected {
		return fmt.Errorf("%w: %s mismatch", ErrTaskCorrupt, name)
	}
	return nil
}

func ownerTaskPriority(priority edgev1.Priority) bool {
	return priority == edgev1.Priority_PRIORITY_LOCAL_ASYNC
}

// WorkerTaskMaximumReservationBytes returns the conservative retained-byte
// reservation advertised for one task. The reservation covers a maximum-size
// deterministic request, a maximum-size terminal result, bounded metadata,
// and the fixed logical bucket keys/index value. It deliberately excludes
// bbolt page and freelist overhead, which requires a filesystem quota.
func WorkerTaskMaximumReservationBytes(maxMessageBytes int) (uint64, error) {
	if maxMessageBytes <= 0 || maxMessageBytes > maxWorkerMessageBytes {
		return 0, errors.New("invalid Worker task message byte limit")
	}
	return workerTaskReservationBytes(maxMessageBytes, maxMessageBytes)
}

func workerTaskMaximumReservationBytes(maxMessageBytes int) (uint64, error) {
	return WorkerTaskMaximumReservationBytes(maxMessageBytes)
}

func workerTaskReservationBytes(
	encodedRequestBytes int,
	maxMessageBytes int,
) (uint64, error) {
	if encodedRequestBytes <= 0 || encodedRequestBytes > maxMessageBytes ||
		maxMessageBytes <= 0 || maxMessageBytes > maxWorkerMessageBytes {
		return 0, errors.New("invalid Worker task reservation inputs")
	}
	// Three payload-bucket keys plus the timestamped expiry key/value are
	// fixed-size. Metadata is charged at its hard ceiling so every legal state
	// transition remains writable after ClaimTask commits.
	fixed := uint64(maximumTaskMetadataBytes + 4*sha256.Size + 8 + 1)
	return checkedAddUint64(
		fixed,
		uint64(encodedRequestBytes),
		uint64(maxMessageBytes),
	)
}

func checkedAddUint64(values ...uint64) (uint64, error) {
	var output uint64
	for _, value := range values {
		if ^uint64(0)-output < value {
			return 0, errors.New("Worker task byte accounting overflow")
		}
		output += value
	}
	return output, nil
}

func checkedMultiplyUint64(left, right uint64) (uint64, error) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, errors.New("Worker task byte accounting overflow")
	}
	return left * right, nil
}

func marshalTaskMessage(message proto.Message, maximum int) ([]byte, error) {
	if message == nil {
		return nil, errors.New("nil Worker task message")
	}
	reflection := message.ProtoReflect()
	if !reflection.IsValid() || len(reflection.GetUnknown()) != 0 {
		return nil, errors.New("invalid or unknown Worker task message fields")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode Worker task message: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, errors.New("Worker task message exceeds byte limit")
	}
	return encoded, nil
}

func cloneInvokeResponse(
	response *edgev1.InvokeResponse,
) *edgev1.InvokeResponse {
	if response == nil {
		return nil
	}
	return proto.Clone(response).(*edgev1.InvokeResponse)
}

func validateTaskStoreNow(now time.Time) (time.Time, error) {
	if now.IsZero() || now.Year() < 1970 || now.Year() > 9999 {
		return time.Time{}, errors.New("invalid Worker task store time")
	}
	return normalizeTaskTime(now), nil
}

func normalizeTaskTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return time.UnixMilli(value.UnixMilli()).UTC()
}

var errTaskMissing = errors.New("worker task is missing")
