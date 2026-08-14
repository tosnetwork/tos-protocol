package nativecore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// RelayJournal provides three independent uniqueness boundaries. Request keys
// are retry aliases, state slots are canonical fee-spend claims, and action
// identities bind the exact signed intent occupying a slot.
type RelayJournal interface {
	Lookup(requestKey, actionIdentity string, intent RelayIntent) (found, complete bool, existingHash string, err error)
	Begin(requestKey, actionIdentity string, intent RelayIntent, limits RelaySpendLimits, now time.Time) (complete bool, existingHash string, err error)
	Complete(actionIdentity string, intent RelayIntent) error
}

type RelaySpendLimits struct {
	Window                     time.Duration
	MaxActionsPerTarget        uint64
	MaxFundingPerTargetNanoTOS uint64
	MaxActionsPerWallet        uint64
	MaxFundingPerWalletNanoTOS uint64
}

func (l RelaySpendLimits) valid() bool {
	return l.Window >= time.Minute && l.Window <= 31*24*time.Hour &&
		l.MaxActionsPerTarget > 0 && l.MaxFundingPerTargetNanoTOS > 0 &&
		l.MaxActionsPerWallet > 0 && l.MaxFundingPerWalletNanoTOS > 0 &&
		l.MaxActionsPerTarget <= l.MaxActionsPerWallet &&
		l.MaxFundingPerTargetNanoTOS <= l.MaxFundingPerWalletNanoTOS
}

func (l RelaySpendLimits) permitsSingle(funding uint64) bool {
	return l.valid() && funding <= l.MaxFundingPerTargetNanoTOS && funding <= l.MaxFundingPerWalletNanoTOS
}

type RelayIntent struct {
	ActionHash        string `json:"action_hash"`
	Destination       string `json:"destination"`
	QueryID           uint64 `json:"query_id"`
	BodyHash          string `json:"body_hash"`
	StateInitHash     string `json:"state_init_hash"`
	FundingNanoTOS    uint64 `json:"funding_nano_tos"`
	StateSlotIdentity string `json:"state_slot_identity"`
	TargetObjectID    string `json:"target_object_id"`
}

func (i RelayIntent) valid() bool {
	return i.ActionHash != "" && i.Destination != "" && i.QueryID != 0 &&
		i.BodyHash != "" && i.StateInitHash != "" && i.FundingNanoTOS != 0 &&
		i.StateSlotIdentity != "" && i.TargetObjectID != ""
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

type relaySlotRecord struct {
	StateSlotIdentity string `json:"state_slot_identity"`
	ActionIdentity    string `json:"action_identity"`
	ActionHash        string `json:"action_hash"`
	TargetObjectID    string `json:"target_object_id"`
	FundingNanoTOS    uint64 `json:"funding_nano_tos"`
	ClaimedUnix       int64  `json:"claimed_unix"`
}

func (r relaySlotRecord) valid() bool {
	return r.StateSlotIdentity != "" && r.ActionIdentity != "" && r.ActionHash != "" &&
		r.TargetObjectID != "" && r.FundingNanoTOS != 0 && r.ClaimedUnix > 0
}

func (r relaySlotRecord) matches(actionIdentity string, intent RelayIntent) bool {
	return r.ActionIdentity == actionIdentity && r.StateSlotIdentity == intent.StateSlotIdentity &&
		r.ActionHash == intent.ActionHash && r.TargetObjectID == intent.TargetObjectID &&
		r.FundingNanoTOS == intent.FundingNanoTOS
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

func (j *FileRelayJournal) slotPath(identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return filepath.Join(j.directory, "slot-"+hex.EncodeToString(hash[:])+".json")
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
	if slot, found, err := j.readSlot(intent.StateSlotIdentity); err != nil {
		return false, false, "", err
	} else if found && slot.ActionIdentity != actionIdentity {
		return true, false, slot.ActionHash, errors.New("Native state slot is already claimed by a different action")
	} else if found && !slot.matches(actionIdentity, intent) {
		return true, false, slot.ActionHash, errors.New("Native state slot record does not match its outbound intent")
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

func (j *FileRelayJournal) Begin(requestKey, actionIdentity string, intent RelayIntent, limits RelaySpendLimits, now time.Time) (bool, string, error) {
	if requestKey == "" || actionIdentity == "" || !intent.valid() || !limits.permitsSingle(intent.FundingNanoTOS) || now.IsZero() {
		return false, "", errors.New("empty Native relay journal identity")
	}
	var complete bool
	var existingHash string
	err := j.withExclusiveLock(func() error {
		var err error
		complete, existingHash, err = j.beginLocked(requestKey, actionIdentity, intent, limits, now.UTC())
		return err
	})
	return complete, existingHash, err
}

func (j *FileRelayJournal) beginLocked(requestKey, actionIdentity string, intent RelayIntent, limits RelaySpendLimits, now time.Time) (bool, string, error) {
	if request, found, err := j.readRequest(requestKey); err != nil {
		return false, "", err
	} else if found && request.ActionIdentity != actionIdentity {
		return false, "", errors.New("Native idempotency key was reused for a different action")
	}
	slot, slotFound, err := j.readSlot(intent.StateSlotIdentity)
	if err != nil {
		return false, "", err
	}
	if slotFound && slot.ActionIdentity != actionIdentity {
		return false, slot.ActionHash, errors.New("Native state slot is already claimed by a different action")
	}
	if slotFound && !slot.matches(actionIdentity, intent) {
		return false, slot.ActionHash, errors.New("Native state slot record does not match its outbound intent")
	}
	if !slotFound {
		if err := j.enforceSpendLimits(intent, limits, now); err != nil {
			return false, "", err
		}
		slot = relaySlotRecord{StateSlotIdentity: intent.StateSlotIdentity, ActionIdentity: actionIdentity,
			ActionHash: intent.ActionHash, TargetObjectID: intent.TargetObjectID,
			FundingNanoTOS: intent.FundingNanoTOS, ClaimedUnix: now.Unix()}
		raw, err := json.Marshal(slot)
		if err != nil {
			return false, "", err
		}
		if created, err := j.atomicCreate(j.slotPath(intent.StateSlotIdentity), raw); err != nil || !created {
			return false, "", errors.New("failed to claim Native state slot")
		}
	}
	record := relayActionRecord{ActionIdentity: actionIdentity, Intent: intent}
	recordRaw, err := json.Marshal(record)
	if err != nil {
		return false, "", err
	}
	if created, err := j.atomicCreate(j.actionPath(actionIdentity), recordRaw); err != nil {
		return false, "", err
	} else if !created {
		existing, found, err := j.readAction(actionIdentity)
		if err != nil || !found {
			return false, "", errors.New("invalid Native relay action record")
		}
		if existing.Intent != intent {
			return false, existing.Intent.ActionHash, errors.New("Native action was reused with a different outbound intent")
		}
		record = existing
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
	if record.Complete {
		return true, record.Intent.ActionHash, nil
	}
	if slotFound {
		return false, record.Intent.ActionHash, nil
	}
	return false, "", nil
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

func (j *FileRelayJournal) enforceSpendLimits(intent RelayIntent, limits RelaySpendLimits, now time.Time) error {
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return err
	}
	cutoff := now.Add(-limits.Window).Unix()
	var walletActions, walletFunding, targetActions, targetFunding uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "slot-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(j.directory, entry.Name()))
		if err != nil {
			return err
		}
		var slot relaySlotRecord
		if json.Unmarshal(raw, &slot) != nil || !slot.valid() {
			return errors.New("invalid Native relay state-slot record")
		}
		if slot.ClaimedUnix < cutoff {
			continue
		}
		if walletActions == ^uint64(0) || walletFunding > ^uint64(0)-slot.FundingNanoTOS {
			return errors.New("Native relay wallet budget counter overflow")
		}
		walletActions++
		walletFunding += slot.FundingNanoTOS
		if slot.TargetObjectID == intent.TargetObjectID {
			if targetActions == ^uint64(0) || targetFunding > ^uint64(0)-slot.FundingNanoTOS {
				return errors.New("Native relay target budget counter overflow")
			}
			targetActions++
			targetFunding += slot.FundingNanoTOS
		}
	}
	if walletActions >= limits.MaxActionsPerWallet || walletFunding > limits.MaxFundingPerWalletNanoTOS-intent.FundingNanoTOS {
		return errors.New("Native relay wallet spend limit exceeded")
	}
	if targetActions >= limits.MaxActionsPerTarget || targetFunding > limits.MaxFundingPerTargetNanoTOS-intent.FundingNanoTOS {
		return errors.New("Native relay target spend limit exceeded")
	}
	return nil
}

func (j *FileRelayJournal) withExclusiveLock(fn func() error) error {
	path := filepath.Join(j.directory, ".relay-journal.lock")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

func (j *FileRelayJournal) readSlot(identity string) (relaySlotRecord, bool, error) {
	var record relaySlotRecord
	raw, err := os.ReadFile(j.slotPath(identity))
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil || json.Unmarshal(raw, &record) != nil || !record.valid() || record.StateSlotIdentity != identity {
		return relaySlotRecord{}, false, errors.New("invalid Native relay state-slot record")
	}
	return record, true, nil
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
