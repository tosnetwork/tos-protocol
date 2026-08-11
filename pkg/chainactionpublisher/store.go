package chainactionpublisher

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	bolt "go.etcd.io/bbolt"
)

const JournalVersion = "1"

var actionBucket = []byte("chain-actions-v1")

type record struct {
	Version  string               `json:"version"`
	Digest   string               `json:"semanticDigest"`
	State    string               `json:"state"`
	Action   chain.Action         `json:"action"`
	Receipt  *chain.ActionReceipt `json:"receipt,omitempty"`
	Attempts uint32               `json:"attempts"`
}

type journal struct{ db *bolt.DB }

func openJournal(path string) (*journal, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("publisher journal path must be absolute and clean")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2_000_000_000})
	if err != nil {
		return nil, fmt.Errorf("open publisher journal: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists(actionBucket); return err }); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &journal{db: db}, nil
}
func (j *journal) close() error {
	if j == nil || j.db == nil {
		return nil
	}
	return j.db.Close()
}
func (j *journal) get(id string) (*record, error) {
	var out *record
	err := j.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(actionBucket).Get([]byte(id))
		if raw == nil {
			return nil
		}
		var r record
		if len(raw) > 1<<20 {
			return errors.New("publisher journal record too large")
		}
		if err := json.Unmarshal(append([]byte(nil), raw...), &r); err != nil {
			return err
		}
		out = &r
		return nil
	})
	return out, err
}
func (j *journal) put(r *record) error {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 1<<20 {
		return errors.New("invalid publisher journal record")
	}
	return j.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(actionBucket).Put([]byte(r.Action.ActionID), raw) })
}
