package nativecore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type RelayJournal interface {
	Lookup(idempotencyKey string, intent RelayIntent) (found, complete bool, existingHash string, err error)
	Begin(idempotencyKey string, intent RelayIntent) (complete bool, existingHash string, err error)
	Complete(idempotencyKey string, intent RelayIntent) error
}

type RelayIntent struct {
	ActionHash     string `json:"action_hash"`
	Destination    string `json:"destination"`
	QueryID        uint64 `json:"query_id"`
	BodyHash       string `json:"body_hash"`
	StateInitHash  string `json:"state_init_hash"`
	FundingNanoTOS uint64 `json:"funding_nano_tos"`
}

func (i RelayIntent) valid() bool {
	return i.ActionHash != "" && i.Destination != "" && i.QueryID != 0 &&
		i.BodyHash != "" && i.StateInitHash != "" && i.FundingNanoTOS != 0
}

func (j *FileRelayJournal) Lookup(key string, intent RelayIntent) (bool, bool, string, error) {
	if key == "" || !intent.valid() {
		return false, false, "", errors.New("empty Native relay journal identity")
	}
	raw, err := os.ReadFile(j.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return false, false, "", nil
	}
	var record relayJournalRecord
	if err != nil || json.Unmarshal(raw, &record) != nil || record.IdempotencyKey != key {
		return false, false, "", errors.New("invalid Native relay journal record")
	}
	if record.Intent != intent {
		return true, record.Complete, record.Intent.ActionHash, errors.New("Native idempotency key was reused for a different outbound intent")
	}
	return true, record.Complete, record.Intent.ActionHash, nil
}

type FileRelayJournal struct{ directory string }

type relayJournalRecord struct {
	IdempotencyKey string      `json:"idempotency_key"`
	Intent         RelayIntent `json:"intent"`
	Complete       bool        `json:"complete"`
}

func NewFileRelayJournal(directory string) (*FileRelayJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("Native relay journal directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	stat, owned := infoSyscallStat(info)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !owned || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("Native relay journal directory must be owner-private")
	}
	return &FileRelayJournal{directory: directory}, nil
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func (j *FileRelayJournal) path(key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(j.directory, hex.EncodeToString(hash[:])+".json")
}

func (j *FileRelayJournal) Begin(key string, intent RelayIntent) (bool, string, error) {
	if key == "" || !intent.valid() {
		return false, "", errors.New("empty Native relay journal identity")
	}
	record := relayJournalRecord{IdempotencyKey: key, Intent: intent}
	raw, _ := json.Marshal(record)
	path := j.path(key)
	temp, err := os.CreateTemp(j.directory, ".relay-begin-")
	if err != nil {
		return false, "", err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.Write(append(raw, '\n'))
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return false, "", err
	}
	err = os.Link(tempPath, path)
	if err == nil {
		return false, "", syncDirectory(j.directory)
	}
	if !errors.Is(err, os.ErrExist) {
		return false, "", err
	}
	raw, err = os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &record) != nil || record.IdempotencyKey != key {
		return false, "", errors.New("invalid Native relay journal record")
	}
	if record.Intent != intent {
		return false, record.Intent.ActionHash, errors.New("Native idempotency key was reused for a different outbound intent")
	}
	return record.Complete, record.Intent.ActionHash, nil
}

func (j *FileRelayJournal) Complete(key string, intent RelayIntent) error {
	path := j.path(key)
	raw, err := os.ReadFile(path)
	var record relayJournalRecord
	if err != nil || json.Unmarshal(raw, &record) != nil || record.IdempotencyKey != key || record.Intent != intent {
		return errors.New("Native relay journal completion mismatch")
	}
	record.Complete = true
	raw, _ = json.Marshal(record)
	temp, err := os.CreateTemp(j.directory, ".relay-complete-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.Write(append(raw, '\n'))
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(j.directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
