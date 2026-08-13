package nativeregistrypublisher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
	bolt "go.etcd.io/bbolt"
)

var recordsBucket = []byte("native-registry-actions-v1")
var metadataBucket = []byte("native-registry-metadata-v1")
var identityKey = []byte("journal-identity")
var bindingKey = []byte("journal-binding-v1")

const (
	JournalVersion = "1"
	statePending   = "pending"
	stateCompleted = "completed"
	maxRecordBytes = 256 << 10
)

type actionRecord struct {
	Version        string                    `json:"version"`
	ActionID       string                    `json:"action_id"`
	SemanticDigest string                    `json:"semantic_digest"`
	State          string                    `json:"state"`
	Submission     nativeregistry.Submission `json:"submission"`
	Prepared       *PreparedMutation         `json:"prepared,omitempty"`
	Receipt        *Receipt                  `json:"receipt,omitempty"`
	Attempts       uint32                    `json:"attempts"`
	CreatedAtMS    int64                     `json:"created_at_unix_millis"`
	UpdatedAtMS    int64                     `json:"updated_at_unix_millis"`
}

type actionStore struct {
	db                *bolt.DB
	identity, binding string
}

func InitializeJournal(path, identity string, policy Policy, backendBinding string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || identity == "" || len(identity) > 256 {
		return errors.New("invalid native registry journal enrollment")
	}
	binding, err := enrollmentBinding(policy, backendBinding)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create native registry journal: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket(recordsBucket); err != nil {
			return err
		}
		meta, err := tx.CreateBucket(metadataBucket)
		if err != nil {
			return err
		}
		if err := meta.Put(identityKey, []byte(identity)); err != nil {
			return err
		}
		return meta.Put(bindingKey, []byte(binding))
	})
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
	}
	return errors.Join(err, closeErr)
}

func openActionStore(path, identity string, policy Policy, backendBinding string) (*actionStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("native registry journal path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("enrolled owner-private native registry journal is missing")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("native registry journal owner mismatch")
	}
	binding, err := enrollmentBinding(policy, backendBinding)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoGrowSync: false})
	if err != nil {
		return nil, err
	}
	if err := db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metadataBucket)
		if tx.Bucket(recordsBucket) == nil || meta == nil || string(meta.Get(identityKey)) != identity || string(meta.Get(bindingKey)) != binding {
			return errors.New("native registry journal identity mismatch")
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &actionStore{db: db, identity: identity, binding: binding}, nil
}

func enrollmentBinding(policy Policy, backendBinding string) (string, error) {
	if err := validatePolicy(policy); err != nil || backendBinding == "" {
		return "", errors.New("invalid native registry enrollment binding")
	}
	raw, err := json.Marshal(struct {
		Version string `json:"version"`
		Policy  Policy `json:"policy"`
		Backend string `json:"backend_binding"`
	}{JournalVersion, policy, backendBinding})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validatePolicy(p Policy) error {
	network := nativeprotocol.NetworkDomain{NetworkID: p.NetworkID, GenesisRootHash: p.GenesisRootHash, GenesisFileHash: p.GenesisFileHash}
	addressPattern := regexp.MustCompile(`^-?(0|[1-9][0-9]*):[0-9a-f]{64}$`)
	codeHashPattern := regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
	if network.Validate() != nil || p.RegistryWorkchain < -128 || p.RegistryWorkchain > 127 ||
		!codeHashPattern.MatchString(p.ContractCodeHash) || p.LocatorVersion != nativeexecution.LocatorVersion ||
		p.ActionVersion != nativeexecution.Version || !addressPattern.MatchString(p.PayerIdentity) {
		return errors.New("incomplete native registry publisher policy")
	}
	return nil
}

func (s *actionStore) close() error { return s.db.Close() }

func (s *actionStore) get(id string) (*actionRecord, error) {
	var result *actionRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(recordsBucket).Get([]byte(id))
		if raw == nil {
			return nil
		}
		if len(raw) > maxRecordBytes {
			return errors.New("native registry journal record exceeds limit")
		}
		var record actionRecord
		if err := json.Unmarshal(append([]byte(nil), raw...), &record); err != nil {
			return err
		}
		result = &record
		return nil
	})
	return result, err
}

func (s *actionStore) claim(id, digest string, submission nativeregistry.Submission) (*actionRecord, error) {
	var result actionRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(recordsBucket)
		if raw := bucket.Get([]byte(id)); raw != nil {
			if err := json.Unmarshal(append([]byte(nil), raw...), &result); err != nil {
				return err
			}
			if result.SemanticDigest != digest {
				return errors.New("native registry publisher idempotency conflict")
			}
			return nil
		}
		now := time.Now().UnixMilli()
		result = actionRecord{Version: JournalVersion, ActionID: id, SemanticDigest: digest, State: statePending, Submission: submission, CreatedAtMS: now, UpdatedAtMS: now}
		return putRecord(bucket, result)
	})
	return &result, err
}

func (s *actionStore) markAttempt(id, digest string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(recordsBucket)
		var record actionRecord
		raw := bucket.Get([]byte(id))
		if raw == nil || json.Unmarshal(append([]byte(nil), raw...), &record) != nil || record.SemanticDigest != digest || record.State != statePending || record.Prepared == nil {
			return errors.New("native registry pending journal record changed")
		}
		record.Attempts++
		record.UpdatedAtMS = time.Now().UnixMilli()
		return putRecord(bucket, record)
	})
}

func (s *actionStore) prepare(id, digest string, prepared PreparedMutation) error {
	if prepared.Version != PreparedMutationVersion || prepared.MessageBOCBase64 == "" || prepared.MessageDigest == "" {
		return errors.New("invalid native registry prepared mutation")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(recordsBucket)
		var record actionRecord
		raw := bucket.Get([]byte(id))
		if raw == nil || json.Unmarshal(append([]byte(nil), raw...), &record) != nil || record.SemanticDigest != digest || record.State != statePending || record.Attempts != 0 {
			return errors.New("native registry preparation record changed")
		}
		if record.Prepared != nil {
			if *record.Prepared != prepared {
				return errors.New("native registry prepared mutation conflict")
			}
			return nil
		}
		record.Prepared = &prepared
		record.UpdatedAtMS = time.Now().UnixMilli()
		return putRecord(bucket, record)
	})
}

func (s *actionStore) complete(id, digest string, receipt Receipt) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(recordsBucket)
		var record actionRecord
		raw := bucket.Get([]byte(id))
		if raw == nil || json.Unmarshal(append([]byte(nil), raw...), &record) != nil || record.SemanticDigest != digest || record.Prepared == nil {
			return errors.New("native registry journal completion conflict")
		}
		if record.State == stateCompleted {
			if record.Receipt == nil || *record.Receipt != receipt {
				return errors.New("native registry terminal receipt conflict")
			}
			return nil
		}
		record.State, record.Receipt, record.UpdatedAtMS = stateCompleted, &receipt, time.Now().UnixMilli()
		return putRecord(bucket, record)
	})
}

func putRecord(bucket *bolt.Bucket, record actionRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(raw) > maxRecordBytes {
		return errors.New("native registry journal record exceeds limit")
	}
	return bucket.Put([]byte(record.ActionID), raw)
}
