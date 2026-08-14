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

// RelayJournal provides two independent uniqueness boundaries. Request keys
// are retry aliases; action identities are the canonical fee-spend claims.
type RelayJournal interface {
	Lookup(requestKey, actionIdentity string, intent RelayIntent) (found, complete bool, existingHash string, err error)
	Begin(requestKey, actionIdentity string, intent RelayIntent) (complete bool, existingHash string, err error)
	Complete(actionIdentity string, intent RelayIntent) error
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

type FileRelayJournal struct{ directory string }

type relayRequestRecord struct {
	RequestKey     string `json:"request_key"`
	ActionIdentity string `json:"action_identity"`
}

type relayActionRecord struct {
	ActionIdentity string      `json:"action_identity"`
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

func (j *FileRelayJournal) requestPath(key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(j.directory, "request-"+hex.EncodeToString(hash[:])+".json")
}

func (j *FileRelayJournal) actionPath(identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return filepath.Join(j.directory, "action-"+hex.EncodeToString(hash[:])+".json")
}

func (j *FileRelayJournal) Lookup(requestKey, actionIdentity string, intent RelayIntent) (bool, bool, string, error) {
	if requestKey == "" || actionIdentity == "" || !intent.valid() {
		return false, false, "", errors.New("empty Native relay journal identity")
	}
	if request, found, err := j.readRequest(requestKey); err != nil {
		return false, false, "", err
	} else if found && request.ActionIdentity != actionIdentity {
		return false, false, "", errors.New("Native idempotency key was reused for a different action")
	}
	record, found, err := j.readAction(actionIdentity)
	if err != nil || !found {
		return false, false, "", err
	}
	if record.Intent != intent {
		return true, record.Complete, record.Intent.ActionHash, errors.New("Native action was reused with a different outbound intent")
	}
	return true, record.Complete, record.Intent.ActionHash, nil
}

func (j *FileRelayJournal) Begin(requestKey, actionIdentity string, intent RelayIntent) (bool, string, error) {
	if requestKey == "" || actionIdentity == "" || !intent.valid() {
		return false, "", errors.New("empty Native relay journal identity")
	}
	request := relayRequestRecord{RequestKey: requestKey, ActionIdentity: actionIdentity}
	requestRaw, err := json.Marshal(request)
	if err != nil {
		return false, "", err
	}
	if created, err := j.atomicCreate(j.requestPath(requestKey), requestRaw); err != nil {
		return false, "", err
	} else if !created {
		existing, found, err := j.readRequest(requestKey)
		if err != nil || !found || existing != request {
			return false, "", errors.New("Native idempotency key was reused for a different action")
		}
	}
	record := relayActionRecord{ActionIdentity: actionIdentity, Intent: intent}
	recordRaw, err := json.Marshal(record)
	if err != nil {
		return false, "", err
	}
	if created, err := j.atomicCreate(j.actionPath(actionIdentity), recordRaw); err != nil {
		return false, "", err
	} else if created {
		return false, "", nil
	}
	existing, found, err := j.readAction(actionIdentity)
	if err != nil || !found {
		return false, "", errors.New("invalid Native relay action record")
	}
	if existing.Intent != intent {
		return false, existing.Intent.ActionHash, errors.New("Native action was reused with a different outbound intent")
	}
	return existing.Complete, existing.Intent.ActionHash, nil
}

func (j *FileRelayJournal) Complete(actionIdentity string, intent RelayIntent) error {
	record, found, err := j.readAction(actionIdentity)
	if err != nil || !found || record.Intent != intent {
		return errors.New("Native relay journal completion mismatch")
	}
	if record.Complete {
		return nil
	}
	record.Complete = true
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return j.atomicReplace(j.actionPath(actionIdentity), raw)
}

func (j *FileRelayJournal) readRequest(key string) (relayRequestRecord, bool, error) {
	var record relayRequestRecord
	raw, err := os.ReadFile(j.requestPath(key))
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil || json.Unmarshal(raw, &record) != nil || record.RequestKey != key || record.ActionIdentity == "" {
		return relayRequestRecord{}, false, errors.New("invalid Native relay request record")
	}
	return record, true, nil
}

func (j *FileRelayJournal) readAction(identity string) (relayActionRecord, bool, error) {
	var record relayActionRecord
	raw, err := os.ReadFile(j.actionPath(identity))
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil || json.Unmarshal(raw, &record) != nil || record.ActionIdentity != identity || !record.Intent.valid() {
		return relayActionRecord{}, false, errors.New("invalid Native relay action record")
	}
	return record, true, nil
}

func (j *FileRelayJournal) atomicCreate(path string, raw []byte) (bool, error) {
	tempPath, err := j.writeTemporary(raw)
	if err != nil {
		return false, err
	}
	defer os.Remove(tempPath)
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, syncDirectory(j.directory)
}

func (j *FileRelayJournal) atomicReplace(path string, raw []byte) error {
	tempPath, err := j.writeTemporary(raw)
	if err != nil {
		return err
	}
	defer os.Remove(tempPath)
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(j.directory)
}

func (j *FileRelayJournal) writeTemporary(raw []byte) (string, error) {
	temp, err := os.CreateTemp(j.directory, ".relay-")
	if err != nil {
		return "", err
	}
	path := temp.Name()
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
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
