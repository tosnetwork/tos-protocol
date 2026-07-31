// Package journal provides the durable, bounded request state owned by Edge
// Core. It does not authorize a request or execute a vertical operation.
package journal

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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	bolt "go.etcd.io/bbolt"
)

const (
	DefaultMaxRecords       = 100_000
	DefaultMaxNonces        = 200_000
	DefaultMaxRecordBytes   = 32 << 10
	DefaultMaxRetention     = 48 * time.Hour
	DefaultMaxPrunePerWrite = 1_024

	maxConfiguredRecords     = 10_000_000
	maxConfiguredRecordBytes = 1 << 20
	maxConfiguredRetention   = 365 * 24 * time.Hour
	expiryPrefixBytes        = 12
	expiryKeyBytes           = expiryPrefixBytes + sha256.Size
)

var (
	ErrConflict    = errors.New("request ID is already bound to different intent")
	ErrCapacity    = errors.New("request journal is at capacity")
	ErrNotFound    = errors.New("request journal record not found")
	ErrExpired     = errors.New("request journal record expired")
	ErrRevision    = errors.New("request journal revision mismatch")
	ErrTransition  = errors.New("illegal request journal transition")
	ErrNonceReplay = errors.New("signed envelope nonce was already used")
	ErrCorrupt     = errors.New("request journal is corrupt")

	recordsBucket     = []byte("records-v1")
	expiryBucket      = []byte("expiry-v1")
	metaBucket        = []byte("meta-v1")
	countKey          = []byte("record-count")
	expiryMarker      = []byte{1}
	noncesBucket      = []byte("nonces-v1")
	nonceExpiryBucket = []byte("nonce-expiry-v1")
	nonceCountKey     = []byte("nonce-count")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{2,127}$`)
	domainPattern = regexp.MustCompile(`^tos\.[a-z0-9.-]+$`)
)

type Limits struct {
	MaxRecords       uint64
	MaxNonces        uint64
	MaxRecordBytes   int
	MaxRetention     time.Duration
	MaxPrunePerWrite int
	OpenTimeout      time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxRecords:       DefaultMaxRecords,
		MaxNonces:        DefaultMaxNonces,
		MaxRecordBytes:   DefaultMaxRecordBytes,
		MaxRetention:     DefaultMaxRetention,
		MaxPrunePerWrite: DefaultMaxPrunePerWrite,
		OpenTimeout:      2 * time.Second,
	}
}

type Scope struct {
	Network   string `json:"network"`
	Authority string `json:"authority"`
	ServiceID string `json:"serviceId"`
	SessionID string `json:"sessionId"`
	Operation string `json:"operation"`
	RequestID string `json:"requestId"`
}

type State string

const (
	StatePending    State = "pending"
	StateAuthorized State = "authorized"
	StateRunning    State = "running"
	StateSucceeded  State = "succeeded"
	StateRejected   State = "rejected"
	StateFailed     State = "failed"
	StateCanceled   State = "canceled"
	StateTimedOut   State = "timed_out"
)

func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateRejected, StateFailed, StateCanceled, StateTimedOut:
		return true
	default:
		return false
	}
}

type Record struct {
	Version      string    `json:"version"`
	Scope        Scope     `json:"scope"`
	IntentDigest string    `json:"intentDigest"`
	State        State     `json:"state"`
	Revision     uint64    `json:"revision"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	RetainUntil  time.Time `json:"retainUntil"`
	ResultDigest string    `json:"resultDigest,omitempty"`
	ErrorCode    string    `json:"errorCode,omitempty"`
}

// Admission binds an already verified signed envelope to one idempotent
// request. Signature, manifest role, and revocation checks happen before this
// local state operation.
type Admission struct {
	Scope             Scope
	IntentDigest      string
	EnvelopeDigest    string
	Domain            string
	Nonce             string
	EnvelopeExpiresAt time.Time
	RetainUntil       time.Time
}

type NonceClaim struct {
	Version        string    `json:"version"`
	Network        string    `json:"network"`
	Authority      string    `json:"authority"`
	ServiceID      string    `json:"serviceId"`
	SessionID      string    `json:"sessionId"`
	Operation      string    `json:"operation"`
	RequestID      string    `json:"requestId"`
	Domain         string    `json:"domain"`
	Nonce          string    `json:"nonce"`
	EnvelopeDigest string    `json:"envelopeDigest"`
	ClaimedAt      time.Time `json:"claimedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type BeginDisposition string

const (
	BeginCreated BeginDisposition = "created"
	BeginReplay  BeginDisposition = "replay"
)

type nonceDisposition uint8

const (
	nonceCreated nonceDisposition = iota + 1
	nonceReplay
)

type Stats struct {
	Records  uint64
	Nonces   uint64
	FileSize int64
}

type Store struct {
	db        *bolt.DB
	path      string
	limits    Limits
	closeOnce sync.Once
}

func Open(path string, limits Limits) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("request journal path must be absolute")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: limits.OpenTimeout})
	if err != nil {
		return nil, fmt.Errorf("open request journal: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict request journal permissions: %w", err)
	}
	store := &Store{db: db, path: path, limits: limits}
	if err := db.Update(store.initialize); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize request journal: %w", err)
	}
	return store, nil
}

func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.db.Close()
	})
	return err
}

func (s *Store) Begin(
	scope Scope,
	intentDigest string,
	now, retainUntil time.Time,
) (Record, BeginDisposition, error) {
	if err := scope.Validate(); err != nil {
		return Record{}, "", err
	}
	if !digestPattern.MatchString(intentDigest) {
		return Record{}, "", errors.New("intent digest must be sha256:<lowercase hex>")
	}
	now, retainUntil, err := s.validateWindow(now, retainUntil)
	if err != nil {
		return Record{}, "", err
	}
	key := scopeKey(scope)
	var output Record
	var disposition BeginDisposition
	err = s.db.Update(func(transaction *bolt.Tx) error {
		if _, _, err := s.pruneExpiredTx(transaction, now, s.limits.MaxPrunePerWrite); err != nil {
			return err
		}
		var beginErr error
		output, disposition, beginErr = s.beginTx(
			transaction, key, scope, intentDigest, now, retainUntil,
		)
		return beginErr
	})
	if err != nil {
		return Record{}, "", err
	}
	return output, disposition, nil
}

// Admit atomically claims a verified envelope nonce and creates or replays its
// idempotent request record.
func (s *Store) Admit(
	admission Admission,
	now time.Time,
) (Record, BeginDisposition, error) {
	now, err := admission.validate(s.limits, now)
	if err != nil {
		return Record{}, "", err
	}
	requestKey := scopeKey(admission.Scope)
	claim := NonceClaim{
		Version: "1", Network: admission.Scope.Network,
		Authority: admission.Scope.Authority, ServiceID: admission.Scope.ServiceID,
		SessionID: admission.Scope.SessionID, Operation: admission.Scope.Operation,
		RequestID: admission.Scope.RequestID, Domain: admission.Domain,
		Nonce: admission.Nonce, EnvelopeDigest: admission.EnvelopeDigest,
		ClaimedAt: now,
		ExpiresAt: admission.EnvelopeExpiresAt.UTC(),
	}
	var output Record
	var disposition BeginDisposition
	err = s.db.Update(func(transaction *bolt.Tx) error {
		if _, _, pruneErr := s.pruneExpiredTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		if _, _, pruneErr := s.pruneNoncesTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		nonceDisposition, claimErr := s.claimNonceTx(transaction, claim, now)
		if claimErr != nil {
			return claimErr
		}
		var beginErr error
		output, disposition, beginErr = s.beginTx(
			transaction, requestKey, admission.Scope, admission.IntentDigest,
			now, admission.RetainUntil.UTC(),
		)
		if beginErr != nil {
			return beginErr
		}
		if nonceDisposition == nonceReplay && disposition == BeginCreated {
			return ErrNonceReplay
		}
		return nil
	})
	if err != nil {
		return Record{}, "", err
	}
	return output, disposition, nil
}

// ClaimNonce records a verified envelope nonce without creating a request.
// Exact duplicate claims are rejected; callers that need idempotent request
// replay use Admit instead.
func (s *Store) ClaimNonce(claim NonceClaim, now time.Time) error {
	if err := validateNow(now); err != nil {
		return err
	}
	now = now.UTC()
	claim.Version = "1"
	claim.ClaimedAt = now
	claim.ExpiresAt = claim.ExpiresAt.UTC()
	if err := claim.validate(s.limits, now); err != nil {
		return err
	}
	return s.db.Update(func(transaction *bolt.Tx) error {
		if _, _, pruneErr := s.pruneNoncesTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		disposition, claimErr := s.claimNonceTx(transaction, claim, now)
		if claimErr != nil {
			return claimErr
		}
		if disposition == nonceReplay {
			return ErrNonceReplay
		}
		return nil
	})
}

func (s *Store) Get(scope Scope, now time.Time) (Record, error) {
	if err := scope.Validate(); err != nil {
		return Record{}, err
	}
	if err := validateNow(now); err != nil {
		return Record{}, err
	}
	key := scopeKey(scope)
	var output Record
	err := s.db.View(func(transaction *bolt.Tx) error {
		encoded := transaction.Bucket(recordsBucket).Get(key[:])
		if encoded == nil {
			return ErrNotFound
		}
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return err
		}
		if record.Scope != scope {
			return fmt.Errorf("%w: request key collision", ErrCorrupt)
		}
		if !record.RetainUntil.After(now.UTC()) {
			return ErrExpired
		}
		output = record
		return nil
	})
	return output, err
}

func (s *Store) Transition(
	scope Scope,
	expectedRevision uint64,
	next State,
	resultDigest, errorCode string,
	now time.Time,
) (Record, error) {
	if err := scope.Validate(); err != nil {
		return Record{}, err
	}
	if expectedRevision == 0 {
		return Record{}, errors.New("expected revision must be positive")
	}
	if err := validateNow(now); err != nil {
		return Record{}, err
	}
	if err := validateOutcome(next, resultDigest, errorCode); err != nil {
		return Record{}, err
	}
	now = now.UTC()
	key := scopeKey(scope)
	var output Record
	err := s.db.Update(func(transaction *bolt.Tx) error {
		records := transaction.Bucket(recordsBucket)
		encoded := records.Get(key[:])
		if encoded == nil {
			return ErrNotFound
		}
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return err
		}
		if record.Scope != scope {
			return fmt.Errorf("%w: request key collision", ErrCorrupt)
		}
		if !record.RetainUntil.After(now) {
			return ErrExpired
		}
		if record.Revision != expectedRevision {
			return ErrRevision
		}
		if !canTransition(record.State, next) {
			return ErrTransition
		}
		record.State = next
		record.Revision++
		if now.After(record.UpdatedAt) {
			record.UpdatedAt = now
		}
		record.ResultDigest = resultDigest
		record.ErrorCode = errorCode
		encoded, err = s.encodeRecord(record)
		if err != nil {
			return err
		}
		if err := records.Put(key[:], encoded); err != nil {
			return err
		}
		output = record
		return nil
	})
	return output, err
}

func (s *Store) beginTx(
	transaction *bolt.Tx,
	key [32]byte,
	scope Scope,
	intentDigest string,
	now, retainUntil time.Time,
) (Record, BeginDisposition, error) {
	records := transaction.Bucket(recordsBucket)
	if encoded := records.Get(key[:]); encoded != nil {
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return Record{}, "", err
		}
		if record.Scope != scope {
			return Record{}, "", fmt.Errorf("%w: request key collision", ErrCorrupt)
		}
		if !record.RetainUntil.After(now) {
			expiries := transaction.Bucket(expiryBucket)
			recordExpiryKey := expiryKey(record.RetainUntil, key)
			if !bytes.Equal(expiries.Get(recordExpiryKey), expiryMarker) {
				return Record{}, "", fmt.Errorf("%w: missing expiry index", ErrCorrupt)
			}
			if err := expiries.Delete(recordExpiryKey); err != nil {
				return Record{}, "", err
			}
			if err := records.Delete(key[:]); err != nil {
				return Record{}, "", err
			}
			count, err := readCount(transaction)
			if err != nil {
				return Record{}, "", err
			}
			if count == 0 {
				return Record{}, "", fmt.Errorf("%w: record count underflow", ErrCorrupt)
			}
			if err := writeCount(transaction, count-1); err != nil {
				return Record{}, "", err
			}
		} else {
			if record.IntentDigest != intentDigest {
				return Record{}, "", ErrConflict
			}
			return record, BeginReplay, nil
		}
	}
	count, err := readCount(transaction)
	if err != nil {
		return Record{}, "", err
	}
	if count >= s.limits.MaxRecords {
		return Record{}, "", ErrCapacity
	}
	record := Record{
		Version: "1", Scope: scope, IntentDigest: intentDigest,
		State: StatePending, Revision: 1,
		CreatedAt: now, UpdatedAt: now, RetainUntil: retainUntil,
	}
	encoded, err := s.encodeRecord(record)
	if err != nil {
		return Record{}, "", err
	}
	if err := records.Put(key[:], encoded); err != nil {
		return Record{}, "", err
	}
	if err := transaction.Bucket(expiryBucket).Put(
		expiryKey(retainUntil, key), expiryMarker,
	); err != nil {
		return Record{}, "", err
	}
	if err := writeCount(transaction, count+1); err != nil {
		return Record{}, "", err
	}
	return record, BeginCreated, nil
}

func (s *Store) claimNonceTx(
	transaction *bolt.Tx,
	claim NonceClaim,
	now time.Time,
) (nonceDisposition, error) {
	key := nonceKey(claim)
	nonces := transaction.Bucket(noncesBucket)
	if encoded := nonces.Get(key[:]); encoded != nil {
		existing, err := s.decodeNonce(encoded)
		if err != nil {
			return 0, err
		}
		if !sameNonceKey(existing, claim) {
			return 0, fmt.Errorf("%w: nonce key collision", ErrCorrupt)
		}
		if !existing.ExpiresAt.After(now) {
			expiries := transaction.Bucket(nonceExpiryBucket)
			existingExpiryKey := expiryKey(existing.ExpiresAt, key)
			if !bytes.Equal(expiries.Get(existingExpiryKey), expiryMarker) {
				return 0, fmt.Errorf("%w: missing nonce expiry index", ErrCorrupt)
			}
			if err := expiries.Delete(existingExpiryKey); err != nil {
				return 0, err
			}
			if err := nonces.Delete(key[:]); err != nil {
				return 0, err
			}
			count, err := readNonceCount(transaction)
			if err != nil {
				return 0, err
			}
			if count == 0 {
				return 0, fmt.Errorf("%w: nonce count underflow", ErrCorrupt)
			}
			if err := writeNonceCount(transaction, count-1); err != nil {
				return 0, err
			}
		} else {
			if !sameNonceBinding(existing, claim) {
				return 0, ErrNonceReplay
			}
			return nonceReplay, nil
		}
	}
	count, err := readNonceCount(transaction)
	if err != nil {
		return 0, err
	}
	if count >= s.limits.MaxNonces {
		return 0, ErrCapacity
	}
	encoded, err := s.encodeNonce(claim)
	if err != nil {
		return 0, err
	}
	if err := nonces.Put(key[:], encoded); err != nil {
		return 0, err
	}
	if err := transaction.Bucket(nonceExpiryBucket).Put(
		expiryKey(claim.ExpiresAt, key), expiryMarker,
	); err != nil {
		return 0, err
	}
	if err := writeNonceCount(transaction, count+1); err != nil {
		return 0, err
	}
	return nonceCreated, nil
}

// PruneExpired removes at most maxDelete records. more reports whether the
// oldest remaining expiry is already due, allowing a caller to continue in
// bounded batches.
func (s *Store) PruneExpired(now time.Time, maxDelete int) (deleted int, more bool, err error) {
	if err := validateNow(now); err != nil {
		return 0, false, err
	}
	if maxDelete <= 0 || maxDelete > s.limits.MaxPrunePerWrite {
		return 0, false, errors.New("prune batch exceeds configured limit")
	}
	err = s.db.Update(func(transaction *bolt.Tx) error {
		var pruneErr error
		deleted, more, pruneErr = s.pruneExpiredTx(transaction, now.UTC(), maxDelete)
		return pruneErr
	})
	return deleted, more, err
}

func (s *Store) PruneNonces(now time.Time, maxDelete int) (deleted int, more bool, err error) {
	if err := validateNow(now); err != nil {
		return 0, false, err
	}
	if maxDelete <= 0 || maxDelete > s.limits.MaxPrunePerWrite {
		return 0, false, errors.New("nonce prune batch exceeds configured limit")
	}
	err = s.db.Update(func(transaction *bolt.Tx) error {
		var pruneErr error
		deleted, more, pruneErr = s.pruneNoncesTx(transaction, now.UTC(), maxDelete)
		return pruneErr
	})
	return deleted, more, err
}

func (s *Store) Stats() (Stats, error) {
	var output Stats
	err := s.db.View(func(transaction *bolt.Tx) error {
		count, err := readCount(transaction)
		if err != nil {
			return err
		}
		output.Records = count
		nonceCount, err := readNonceCount(transaction)
		if err != nil {
			return err
		}
		output.Nonces = nonceCount
		return nil
	})
	if err != nil {
		return Stats{}, err
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return Stats{}, err
	}
	output.FileSize = info.Size()
	return output, nil
}

func (s *Store) initialize(transaction *bolt.Tx) error {
	records, err := transaction.CreateBucketIfNotExists(recordsBucket)
	if err != nil {
		return err
	}
	expiries, err := transaction.CreateBucketIfNotExists(expiryBucket)
	if err != nil {
		return err
	}
	nonces, err := transaction.CreateBucketIfNotExists(noncesBucket)
	if err != nil {
		return err
	}
	nonceExpiries, err := transaction.CreateBucketIfNotExists(nonceExpiryBucket)
	if err != nil {
		return err
	}
	meta, err := transaction.CreateBucketIfNotExists(metaBucket)
	if err != nil {
		return err
	}
	if err := initializeCount(meta, countKey, uint64(records.Stats().KeyN), "record"); err != nil {
		return err
	}
	if expiries.Stats().KeyN != records.Stats().KeyN {
		return fmt.Errorf("%w: expiry index count mismatch", ErrCorrupt)
	}
	if err := initializeCount(meta, nonceCountKey, uint64(nonces.Stats().KeyN), "nonce"); err != nil {
		return err
	}
	if nonceExpiries.Stats().KeyN != nonces.Stats().KeyN {
		return fmt.Errorf("%w: nonce expiry index count mismatch", ErrCorrupt)
	}
	return nil
}

func (s *Store) pruneExpiredTx(
	transaction *bolt.Tx,
	now time.Time,
	maxDelete int,
) (deleted int, more bool, err error) {
	records := transaction.Bucket(recordsBucket)
	expiries := transaction.Bucket(expiryBucket)
	cursor := expiries.Cursor()
	cutoff := expiryPrefix(now)
	for key, marker := cursor.First(); key != nil; key, marker = cursor.Next() {
		if len(key) != expiryKeyBytes {
			return deleted, false, fmt.Errorf("%w: invalid expiry key", ErrCorrupt)
		}
		if !bytes.Equal(marker, expiryMarker) {
			return deleted, false, fmt.Errorf("%w: invalid expiry marker", ErrCorrupt)
		}
		if bytes.Compare(key[:expiryPrefixBytes], cutoff[:]) > 0 {
			break
		}
		if deleted >= maxDelete {
			more = true
			break
		}
		recordKey := key[expiryPrefixBytes:]
		encoded := records.Get(recordKey)
		if encoded == nil {
			return deleted, false, fmt.Errorf("%w: expiry references missing record", ErrCorrupt)
		}
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return deleted, false, err
		}
		expectedKey := expiryKey(record.RetainUntil, array32(recordKey))
		if !bytes.Equal(expectedKey, key) || record.RetainUntil.After(now) {
			return deleted, false, fmt.Errorf("%w: expiry index mismatch", ErrCorrupt)
		}
		if err := records.Delete(recordKey); err != nil {
			return deleted, false, err
		}
		if err := cursor.Delete(); err != nil {
			return deleted, false, err
		}
		deleted++
	}
	if deleted != 0 {
		count, err := readCount(transaction)
		if err != nil {
			return deleted, false, err
		}
		if uint64(deleted) > count {
			return deleted, false, fmt.Errorf("%w: record count underflow", ErrCorrupt)
		}
		if err := writeCount(transaction, count-uint64(deleted)); err != nil {
			return deleted, false, err
		}
	}
	return deleted, more, nil
}

func (s *Store) pruneNoncesTx(
	transaction *bolt.Tx,
	now time.Time,
	maxDelete int,
) (deleted int, more bool, err error) {
	nonces := transaction.Bucket(noncesBucket)
	expiries := transaction.Bucket(nonceExpiryBucket)
	cursor := expiries.Cursor()
	cutoff := expiryPrefix(now)
	for key, marker := cursor.First(); key != nil; key, marker = cursor.Next() {
		if len(key) != expiryKeyBytes {
			return deleted, false, fmt.Errorf("%w: invalid nonce expiry key", ErrCorrupt)
		}
		if !bytes.Equal(marker, expiryMarker) {
			return deleted, false, fmt.Errorf("%w: invalid nonce expiry marker", ErrCorrupt)
		}
		if bytes.Compare(key[:expiryPrefixBytes], cutoff[:]) > 0 {
			break
		}
		if deleted >= maxDelete {
			more = true
			break
		}
		nonceKeyBytes := key[expiryPrefixBytes:]
		encoded := nonces.Get(nonceKeyBytes)
		if encoded == nil {
			return deleted, false, fmt.Errorf("%w: expiry references missing nonce", ErrCorrupt)
		}
		claim, err := s.decodeNonce(encoded)
		if err != nil {
			return deleted, false, err
		}
		expectedKey := expiryKey(claim.ExpiresAt, array32(nonceKeyBytes))
		if !bytes.Equal(expectedKey, key) || claim.ExpiresAt.After(now) {
			return deleted, false, fmt.Errorf("%w: nonce expiry index mismatch", ErrCorrupt)
		}
		if err := nonces.Delete(nonceKeyBytes); err != nil {
			return deleted, false, err
		}
		if err := cursor.Delete(); err != nil {
			return deleted, false, err
		}
		deleted++
	}
	if deleted != 0 {
		count, err := readNonceCount(transaction)
		if err != nil {
			return deleted, false, err
		}
		if uint64(deleted) > count {
			return deleted, false, fmt.Errorf("%w: nonce count underflow", ErrCorrupt)
		}
		if err := writeNonceCount(transaction, count-uint64(deleted)); err != nil {
			return deleted, false, err
		}
	}
	return deleted, more, nil
}

func (s *Store) encodeRecord(record Record) ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if record.RetainUntil.Sub(record.CreatedAt) > s.limits.MaxRetention {
		return nil, fmt.Errorf("%w: record retention exceeds configured limit", ErrCorrupt)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(encoded) > s.limits.MaxRecordBytes {
		return nil, errors.New("request journal record exceeds byte limit")
	}
	return encoded, nil
}

func (s *Store) decodeRecord(encoded []byte) (Record, error) {
	if len(encoded) == 0 || len(encoded) > s.limits.MaxRecordBytes {
		return Record{}, fmt.Errorf("%w: invalid record size", ErrCorrupt)
	}
	var record Record
	if err := jsonstrict.Decode(encoded, &record); err != nil {
		return Record{}, fmt.Errorf("%w: decode record: %v", ErrCorrupt, err)
	}
	if err := record.validate(); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if record.RetainUntil.Sub(record.CreatedAt) > s.limits.MaxRetention {
		return Record{}, fmt.Errorf("%w: record retention exceeds configured limit", ErrCorrupt)
	}
	return record, nil
}

func (s *Store) encodeNonce(claim NonceClaim) ([]byte, error) {
	if err := claim.validateStored(s.limits); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	encoded, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	if len(encoded) > s.limits.MaxRecordBytes {
		return nil, errors.New("nonce claim exceeds byte limit")
	}
	return encoded, nil
}

func (s *Store) decodeNonce(encoded []byte) (NonceClaim, error) {
	if len(encoded) == 0 || len(encoded) > s.limits.MaxRecordBytes {
		return NonceClaim{}, fmt.Errorf("%w: invalid nonce claim size", ErrCorrupt)
	}
	var claim NonceClaim
	if err := jsonstrict.Decode(encoded, &claim); err != nil {
		return NonceClaim{}, fmt.Errorf("%w: decode nonce claim: %v", ErrCorrupt, err)
	}
	if err := claim.validateStored(s.limits); err != nil {
		return NonceClaim{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return claim, nil
}

func (l Limits) validate() error {
	if l.MaxRecords == 0 || l.MaxRecords > maxConfiguredRecords ||
		l.MaxNonces == 0 || l.MaxNonces > maxConfiguredRecords ||
		l.MaxRecordBytes < 1_024 || l.MaxRecordBytes > maxConfiguredRecordBytes ||
		l.MaxRetention <= 0 || l.MaxRetention > maxConfiguredRetention ||
		l.MaxPrunePerWrite <= 0 || uint64(l.MaxPrunePerWrite) > l.MaxRecords ||
		l.OpenTimeout <= 0 || l.OpenTimeout > time.Minute {
		return errors.New("invalid request journal limits")
	}
	return nil
}

func (a Admission) validate(limits Limits, now time.Time) (time.Time, error) {
	if err := validateNow(now); err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	if err := a.Scope.Validate(); err != nil {
		return time.Time{}, err
	}
	if !digestPattern.MatchString(a.IntentDigest) {
		return time.Time{}, errors.New("intent digest must be sha256:<lowercase hex>")
	}
	if !digestPattern.MatchString(a.EnvelopeDigest) {
		return time.Time{}, errors.New("envelope digest must be sha256:<lowercase hex>")
	}
	if err := validateDomainAndNonce(a.Domain, a.Nonce); err != nil {
		return time.Time{}, err
	}
	expiresAt := a.EnvelopeExpiresAt.UTC()
	retainUntil := a.RetainUntil.UTC()
	if !expiresAt.After(now) || expiresAt.Sub(now) > limits.MaxRetention {
		return time.Time{}, errors.New("invalid envelope nonce retention window")
	}
	if retainUntil.Before(expiresAt) || !retainUntil.After(now) ||
		retainUntil.Sub(now) > limits.MaxRetention {
		return time.Time{}, errors.New("request retention must cover the envelope nonce")
	}
	return now, nil
}

func (n NonceClaim) validate(limits Limits, now time.Time) error {
	if err := n.validateStored(limits); err != nil {
		return err
	}
	if !n.ExpiresAt.After(now) {
		return errors.New("nonce claim is already expired")
	}
	return nil
}

func (n NonceClaim) validateStored(limits Limits) error {
	if n.Version != "1" {
		return errors.New("unsupported nonce claim version")
	}
	scope := Scope{
		Network: n.Network, Authority: n.Authority, ServiceID: n.ServiceID,
		SessionID: n.SessionID, Operation: n.Operation, RequestID: n.RequestID,
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateDomainAndNonce(n.Domain, n.Nonce); err != nil {
		return err
	}
	if !digestPattern.MatchString(n.EnvelopeDigest) {
		return errors.New("invalid signed envelope digest")
	}
	if n.ClaimedAt.IsZero() || n.ExpiresAt.IsZero() ||
		!n.ExpiresAt.After(n.ClaimedAt) ||
		n.ExpiresAt.Sub(n.ClaimedAt) > limits.MaxRetention {
		return errors.New("invalid nonce claim time ordering")
	}
	return nil
}

func (s Scope) Validate() error {
	for name, value := range map[string]string{
		"network": s.Network, "authority": s.Authority,
	} {
		if err := bounded(name, value, 1, 512); err != nil {
			return err
		}
	}
	if !idPattern.MatchString(s.ServiceID) {
		return errors.New("invalid service ID")
	}
	if err := bounded("session ID", s.SessionID, 8, 128); err != nil {
		return err
	}
	if err := bounded("operation", s.Operation, 1, 128); err != nil {
		return err
	}
	if err := bounded("request ID", s.RequestID, 8, 128); err != nil {
		return err
	}
	return nil
}

func (r Record) validate() error {
	if r.Version != "1" {
		return errors.New("unsupported record version")
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if !digestPattern.MatchString(r.IntentDigest) || r.Revision == 0 {
		return errors.New("invalid record digest or revision")
	}
	if !validState(r.State) {
		return errors.New("invalid record state")
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.RetainUntil.IsZero() ||
		r.UpdatedAt.Before(r.CreatedAt) || !r.RetainUntil.After(r.UpdatedAt) {
		return errors.New("invalid record time ordering")
	}
	return validateOutcome(r.State, r.ResultDigest, r.ErrorCode)
}

func (s *Store) validateWindow(now, retainUntil time.Time) (time.Time, time.Time, error) {
	if err := validateNow(now); err != nil {
		return time.Time{}, time.Time{}, err
	}
	now = now.UTC()
	retainUntil = retainUntil.UTC()
	if !retainUntil.After(now) || retainUntil.Sub(now) > s.limits.MaxRetention {
		return time.Time{}, time.Time{}, errors.New("invalid request journal retention window")
	}
	return now, retainUntil, nil
}

func validateNow(now time.Time) error {
	if now.IsZero() || now.Year() < 1970 || now.Year() > 9999 {
		return errors.New("invalid request journal time")
	}
	return nil
}

func validState(state State) bool {
	switch state {
	case StatePending, StateAuthorized, StateRunning, StateSucceeded,
		StateRejected, StateFailed, StateCanceled, StateTimedOut:
		return true
	default:
		return false
	}
}

func canTransition(current, next State) bool {
	switch current {
	case StatePending:
		return next == StateAuthorized || next == StateRejected ||
			next == StateFailed || next == StateCanceled || next == StateTimedOut
	case StateAuthorized:
		return next == StateRunning || next == StateFailed ||
			next == StateCanceled || next == StateTimedOut
	case StateRunning:
		return next == StateSucceeded || next == StateFailed ||
			next == StateCanceled || next == StateTimedOut
	default:
		return false
	}
}

func validateOutcome(state State, resultDigest, errorCode string) error {
	switch state {
	case StateSucceeded:
		if !digestPattern.MatchString(resultDigest) || errorCode != "" {
			return errors.New("successful state requires only a result digest")
		}
	case StateRejected, StateFailed, StateTimedOut:
		if resultDigest != "" || bounded("error code", errorCode, 1, 128) != nil {
			return errors.New("failed state requires only a bounded error code")
		}
	case StateCanceled:
		if resultDigest != "" {
			return errors.New("canceled state must not contain a result digest")
		}
		if errorCode != "" {
			if err := bounded("error code", errorCode, 1, 128); err != nil {
				return err
			}
		}
	case StatePending, StateAuthorized, StateRunning:
		if resultDigest != "" || errorCode != "" {
			return errors.New("nonterminal state must not contain an outcome")
		}
	default:
		return errors.New("invalid request journal state")
	}
	return nil
}

func bounded(name, value string, minimum, maximum int) error {
	if len(value) < minimum || len(value) > maximum || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s has invalid length or content", name)
	}
	return nil
}

func validateDomainAndNonce(domain, nonce string) error {
	if len(domain) < 5 || len(domain) > 128 || !domainPattern.MatchString(domain) {
		return errors.New("invalid signed envelope domain")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(decoded) != 16 {
		return errors.New("invalid signed envelope nonce")
	}
	return nil
}

func scopeKey(scope Scope) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte("TOS-EDGE-JOURNAL-SCOPE-V1"))
	for _, value := range []string{
		scope.Network, scope.Authority, scope.ServiceID,
		scope.SessionID, scope.Operation, scope.RequestID,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hasher.Write(length[:])
		hasher.Write([]byte(value))
	}
	var output [32]byte
	copy(output[:], hasher.Sum(nil))
	return output
}

func nonceKey(claim NonceClaim) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte("TOS-EDGE-JOURNAL-NONCE-V1"))
	for _, value := range []string{
		claim.Network, claim.Authority, claim.ServiceID, claim.Nonce,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hasher.Write(length[:])
		hasher.Write([]byte(value))
	}
	var output [32]byte
	copy(output[:], hasher.Sum(nil))
	return output
}

func sameNonceKey(left, right NonceClaim) bool {
	return left.Network == right.Network &&
		left.Authority == right.Authority &&
		left.ServiceID == right.ServiceID &&
		left.Nonce == right.Nonce
}

func sameNonceBinding(left, right NonceClaim) bool {
	return sameNonceKey(left, right) &&
		left.SessionID == right.SessionID &&
		left.Operation == right.Operation &&
		left.RequestID == right.RequestID &&
		left.Domain == right.Domain &&
		left.EnvelopeDigest == right.EnvelopeDigest &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

func expiryPrefix(value time.Time) [expiryPrefixBytes]byte {
	var output [expiryPrefixBytes]byte
	value = value.UTC()
	binary.BigEndian.PutUint64(output[:8], uint64(value.Unix()))
	binary.BigEndian.PutUint32(output[8:], uint32(value.Nanosecond()))
	return output
}

func expiryKey(retainUntil time.Time, recordKey [32]byte) []byte {
	prefix := expiryPrefix(retainUntil)
	output := make([]byte, expiryKeyBytes)
	copy(output[:expiryPrefixBytes], prefix[:])
	copy(output[expiryPrefixBytes:], recordKey[:])
	return output
}

func array32(value []byte) [32]byte {
	var output [32]byte
	copy(output[:], value)
	return output
}

func readCount(transaction *bolt.Tx) (uint64, error) {
	return readNamedCount(transaction, countKey, "record")
}

func writeCount(transaction *bolt.Tx, count uint64) error {
	return writeNamedCount(transaction, countKey, count)
}

func readNonceCount(transaction *bolt.Tx) (uint64, error) {
	return readNamedCount(transaction, nonceCountKey, "nonce")
}

func writeNonceCount(transaction *bolt.Tx, count uint64) error {
	return writeNamedCount(transaction, nonceCountKey, count)
}

func readNamedCount(transaction *bolt.Tx, key []byte, name string) (uint64, error) {
	encoded := transaction.Bucket(metaBucket).Get(key)
	if len(encoded) != 8 {
		return 0, fmt.Errorf("%w: invalid %s count", ErrCorrupt, name)
	}
	return binary.BigEndian.Uint64(encoded), nil
}

func writeNamedCount(transaction *bolt.Tx, key []byte, count uint64) error {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], count)
	return transaction.Bucket(metaBucket).Put(key, encoded[:])
}

func initializeCount(
	meta *bolt.Bucket,
	key []byte,
	actual uint64,
	name string,
) error {
	encoded := meta.Get(key)
	if encoded == nil {
		var value [8]byte
		binary.BigEndian.PutUint64(value[:], actual)
		return meta.Put(key, value[:])
	}
	if len(encoded) != 8 || binary.BigEndian.Uint64(encoded) != actual {
		return fmt.Errorf("%w: %s count mismatch", ErrCorrupt, name)
	}
	return nil
}
