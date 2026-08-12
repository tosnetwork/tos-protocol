package chainactionpublisher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	bolt "go.etcd.io/bbolt"
)

const JournalVersion = "1"

var actionBucket = []byte("chain-actions-v1")
var metadataBucket = []byte("chain-action-publisher-metadata-v1")
var journalIdentityKey = []byte("journal-identity")
var journalBindingKey = []byte("journal-binding-v1")

type record struct {
	Version  string               `json:"version"`
	Digest   string               `json:"semanticDigest"`
	State    string               `json:"state"`
	Action   chain.Action         `json:"action"`
	Receipt  *chain.ActionReceipt `json:"receipt,omitempty"`
	Attempts uint32               `json:"attempts"`
}

type journal struct{ db *bolt.DB }

// InitializeJournal performs the explicit, one-time enrollment of a journal.
// Normal publisher startup never creates state: a missing enrolled volume is
// therefore an availability failure, not authoritative absence.
func InitializeJournal(path, identity, network string, policy SpendingPolicy, backendBinding string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || identity == "" || len(identity) > 256 {
		return errors.New("invalid publisher journal enrollment")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create publisher journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2_000_000_000})
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	binding, err := chainJournalBinding(network, policy, backendBinding)
	if err != nil {
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
		if err := metadata.Put(journalIdentityKey, []byte(identity)); err != nil {
			return err
		}
		return metadata.Put(journalBindingKey, []byte(binding))
	})
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
	}
	return errors.Join(err, closeErr)
}

func openJournal(path, identity, network string, policy SpendingPolicy, backendBinding string) (*journal, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("publisher journal path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("enrolled owner-private publisher journal is missing")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("publisher journal owner mismatch")
	}
	binding, err := chainJournalBinding(network, policy, backendBinding)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2_000_000_000, ReadOnly: false})
	if err != nil {
		return nil, fmt.Errorf("open publisher journal: %w", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		actions, metadata := tx.Bucket(actionBucket), tx.Bucket(metadataBucket)
		if actions == nil || metadata == nil || string(metadata.Get(journalIdentityKey)) != identity || string(metadata.Get(journalBindingKey)) != binding || identity == "" {
			return errors.New("publisher journal identity mismatch")
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open enrolled publisher journal: %w", err)
	}
	return &journal{db: db}, nil
}

func chainJournalBinding(network string, policy SpendingPolicy, backendBinding string) (string, error) {
	policy, err := validatePolicy(policy)
	if err != nil || network == "" || backendBinding == "" {
		return "", errors.New("invalid publisher journal binding")
	}
	raw, err := json.Marshal(struct {
		Version, Network, Backend string
		Policy                    SpendingPolicy
	}{"1", network, backendBinding, policy})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
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
