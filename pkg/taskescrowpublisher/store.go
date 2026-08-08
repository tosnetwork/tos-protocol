package taskescrowpublisher

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	bolt "go.etcd.io/bbolt"
)

var actionBucket = []byte("task-escrow-actions-v1")

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

func openActionStore(path string) (*actionStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("publisher state path must be absolute and clean")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create publisher state directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoGrowSync: false})
	if err != nil {
		return nil, fmt.Errorf("open publisher state: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(actionBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize publisher state: %w", err)
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
