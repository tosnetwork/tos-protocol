package taskescrowpublisher

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	bolt "go.etcd.io/bbolt"
)

var actionBucket = []byte("task-escrow-actions-v1")
var metadataBucket = []byte("task-escrow-publisher-metadata-v1")
var journalIdentityKey = []byte("journal-identity")

const (
	recordStatePending   = "pending"
	recordStateCompleted = "completed"
	maxRecordBytes       = 2 << 20
)

type actionRecord struct {
	Version        string                         `json:"version"`
	SemanticDigest string                         `json:"semanticDigest"`
	State          string                         `json:"state"`
	Action         chain.TaskEscrowAction         `json:"action"`
	Prepared       PreparedAction                 `json:"prepared"`
	Receipt        *chain.TaskEscrowActionReceipt `json:"receipt,omitempty"`
	Attempts       uint32                         `json:"attempts"`
	LastAttemptAt  int64                          `json:"lastAttemptAtUnixMillis,omitempty"`
	CreatedAt      int64                          `json:"createdAtUnixMillis"`
	UpdatedAt      int64                          `json:"updatedAtUnixMillis"`
}

type actionStore struct{ db *bolt.DB }

const JournalVersion = "1"

// InitializeJournal explicitly enrolls an empty journal. Normal startup never
// creates one, so a lost or mistyped volume cannot become authoritative
// absence for previously broadcast economic actions.
func InitializeJournal(path, identity string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || identity == "" || len(identity) > 256 {
		return errors.New("invalid task escrow journal enrollment")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create task escrow journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket(actionBucket); err != nil {
			return err
		}
		metadata, err := tx.CreateBucket(metadataBucket)
		if err != nil {
			return err
		}
		return metadata.Put(journalIdentityKey, []byte(identity))
	})
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
	}
	return errors.Join(err, closeErr)
}

func openActionStore(path, identity string) (*actionStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("publisher state path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("enrolled owner-private task escrow journal is missing")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("task escrow journal owner mismatch")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoGrowSync: false})
	if err != nil {
		return nil, fmt.Errorf("open publisher state: %w", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		actions, metadata := tx.Bucket(actionBucket), tx.Bucket(metadataBucket)
		if actions == nil || metadata == nil || identity == "" || string(metadata.Get(journalIdentityKey)) != identity {
			return errors.New("task escrow journal identity mismatch")
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open enrolled task escrow journal: %w", err)
	}
	return &actionStore{db: db}, nil
}

func (s *actionStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *actionStore) get(actionID string) (*actionRecord, error) {
	if s == nil || s.db == nil || actionID == "" {
		return nil, errors.New("invalid publisher state read")
	}
	var record *actionRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		encoded := tx.Bucket(actionBucket).Get([]byte(actionID))
		if encoded == nil {
			return nil
		}
		if len(encoded) > maxRecordBytes {
			return errors.New("publisher state record exceeds byte limit")
		}
		var decoded actionRecord
		if err := json.Unmarshal(append([]byte(nil), encoded...), &decoded); err != nil {
			return fmt.Errorf("decode publisher state: %w", err)
		}
		record = &decoded
		return nil
	})
	return record, err
}

func (s *actionStore) put(record *actionRecord) error {
	if s == nil || s.db == nil || record == nil || record.Action.ActionID == "" {
		return errors.New("invalid publisher state write")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(encoded) > maxRecordBytes {
		return errors.New("publisher state record exceeds byte limit")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(actionBucket).Put([]byte(record.Action.ActionID), encoded)
	})
}
