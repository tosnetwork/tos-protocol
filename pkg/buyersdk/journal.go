package buyersdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
)

type BudgetLimits struct {
	Window               time.Duration
	MaxPurchases         uint64
	MaxPerPurchaseAtomic string
	MaxTotalAtomic       string
}

type fundingIntent struct {
	Identity        string `json:"identity"`
	NetworkID       string `json:"network_id"`
	EscrowAddress   string `json:"escrow_address"`
	QuoteCommitment string `json:"quote_commitment"`
	AssetIdentity   string `json:"asset_identity"`
	BuyerWallet     string `json:"buyer_wallet"`
	AmountAtomic    string `json:"amount_atomic"`
	QueryID         uint64 `json:"query_id"`
}

type budgetPhase string

const (
	budgetPrepared     budgetPhase = "prepared"
	budgetBroadcasting budgetPhase = "broadcasting"
	budgetComplete     budgetPhase = "complete"
)

type budgetRecord struct {
	Intent      fundingIntent `json:"intent"`
	Phase       budgetPhase   `json:"phase"`
	ClaimedUnix int64         `json:"claimed_unix"`
}

type budgetRequest struct {
	RequestKey string `json:"request_key"`
	Identity   string `json:"identity"`
}

type FileBudgetJournal struct{ directory string }

func NewFileBudgetJournal(directory string) (*FileBudgetJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("buyer budget directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, errors.New("buyer budget directory must be owner-private")
	}
	return &FileBudgetJournal{directory: directory}, nil
}

func (j *FileBudgetJournal) begin(requestKey string, intent fundingIntent, limits BudgetLimits, now time.Time) (budgetPhase, error) {
	if requestKey == "" || !intent.valid() || !limits.permits(intent.AmountAtomic) || now.IsZero() {
		return "", errors.New("invalid buyer budget claim")
	}
	var phase budgetPhase
	err := j.withLock(func() error {
		request, requestFound, err := j.readRequest(requestKey)
		if err != nil {
			return err
		}
		if requestFound && request.Identity != intent.Identity {
			return errors.New("buyer idempotency key was reused for another purchase")
		}
		record, recordFound, err := j.readRecord(intent.Identity)
		if err != nil {
			return err
		}
		if requestFound && !recordFound {
			return errors.New("buyer budget record is missing for an existing request")
		}
		if recordFound && record.Intent != intent {
			return errors.New("buyer purchase identity conflicts with another funding intent")
		}
		if !recordFound {
			if err := j.enforce(limits, intent, now.UTC()); err != nil {
				return err
			}
			record = budgetRecord{Intent: intent, Phase: budgetPrepared, ClaimedUnix: now.UTC().Unix()}
			raw, _ := json.Marshal(record)
			created, err := j.atomicCreate(j.recordPath(intent.Identity), raw)
			if err != nil || !created {
				return errors.New("failed to claim buyer purchase budget")
			}
		}
		request = budgetRequest{RequestKey: requestKey, Identity: intent.Identity}
		raw, _ := json.Marshal(request)
		created, err := j.atomicCreate(j.requestPath(requestKey), raw)
		if err != nil {
			return err
		}
		if !created {
			existing, found, err := j.readRequest(requestKey)
			if err != nil || !found || existing != request {
				return errors.New("buyer idempotency key was reused for another purchase")
			}
		}
		phase = record.Phase
		return nil
	})
	return phase, err
}

func (j *FileBudgetJournal) acquire(intent fundingIntent) (bool, budgetPhase, error) {
	var acquired bool
	var phase budgetPhase
	err := j.withLock(func() error {
		record, found, err := j.readRecord(intent.Identity)
		if err != nil || !found || record.Intent != intent {
			return errors.New("buyer funding lease does not match budget claim")
		}
		phase = record.Phase
		if record.Phase == budgetPrepared {
			record.Phase = budgetBroadcasting
			raw, _ := json.Marshal(record)
			if err := j.atomicReplace(j.recordPath(intent.Identity), raw); err != nil {
				return err
			}
			phase, acquired = budgetBroadcasting, true
		}
		return nil
	})
	return acquired, phase, err
}

func (j *FileBudgetJournal) complete(intent fundingIntent) error {
	return j.withLock(func() error {
		record, found, err := j.readRecord(intent.Identity)
		if err != nil || !found || record.Intent != intent {
			return errors.New("buyer funding completion does not match budget claim")
		}
		if record.Phase == budgetComplete {
			return nil
		}
		if record.Phase != budgetBroadcasting {
			return errors.New("buyer funding completed without a broadcast lease")
		}
		record.Phase = budgetComplete
		raw, _ := json.Marshal(record)
		return j.atomicReplace(j.recordPath(intent.Identity), raw)
	})
}

func (i fundingIntent) valid() bool {
	return i.Identity != "" && i.NetworkID != "" && i.EscrowAddress != "" &&
		i.QuoteCommitment != "" && i.AssetIdentity != "" && i.BuyerWallet != "" &&
		i.QueryID != 0 && positiveAtomic(i.AmountAtomic) != nil
}

func (l BudgetLimits) permits(amount string) bool {
	value, per, total := positiveAtomic(amount), positiveAtomic(l.MaxPerPurchaseAtomic), positiveAtomic(l.MaxTotalAtomic)
	return l.Window >= time.Minute && l.Window <= 31*24*time.Hour && l.MaxPurchases > 0 &&
		value != nil && per != nil && total != nil && value.Cmp(per) <= 0 && value.Cmp(total) <= 0
}

func positiveAtomic(value string) *big.Int {
	if value == "" || value[0] == '0' || strings.TrimSpace(value) != value {
		return nil
	}
	result, ok := new(big.Int).SetString(value, 10)
	if !ok || result.Sign() <= 0 || result.BitLen() > 120 || result.String() != value {
		return nil
	}
	return result
}

func (j *FileBudgetJournal) enforce(limits BudgetLimits, intent fundingIntent, now time.Time) error {
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return err
	}
	cutoff := now.Add(-limits.Window).Unix()
	count := uint64(0)
	total := new(big.Int)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "purchase-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := j.readRecordPath(filepath.Join(j.directory, entry.Name()))
		if err != nil {
			return err
		}
		if record.ClaimedUnix < cutoff || record.Intent.AssetIdentity != intent.AssetIdentity {
			continue
		}
		count++
		total.Add(total, positiveAtomic(record.Intent.AmountAtomic))
	}
	maximum := positiveAtomic(limits.MaxTotalAtomic)
	if count >= limits.MaxPurchases || total.Add(total, positiveAtomic(intent.AmountAtomic)).Cmp(maximum) > 0 {
		return errors.New("buyer stablecoin budget exceeded")
	}
	return nil
}

func (j *FileBudgetJournal) recordPath(identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return filepath.Join(j.directory, "purchase-"+hex.EncodeToString(hash[:])+".json")
}

func (j *FileBudgetJournal) requestPath(key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(j.directory, "request-"+hex.EncodeToString(hash[:])+".json")
}

func (j *FileBudgetJournal) readRecord(identity string) (budgetRecord, bool, error) {
	path := j.recordPath(identity)
	record, err := j.readRecordPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return budgetRecord{}, false, nil
	}
	return record, err == nil, err
}

func (j *FileBudgetJournal) readRecordPath(path string) (budgetRecord, error) {
	var record budgetRecord
	if err := readStrict(path, &record); err != nil {
		return record, err
	}
	if !record.Intent.valid() || record.ClaimedUnix <= 0 ||
		(record.Phase != budgetPrepared && record.Phase != budgetBroadcasting && record.Phase != budgetComplete) {
		return record, errors.New("invalid buyer budget record")
	}
	return record, nil
}

func (j *FileBudgetJournal) readRequest(key string) (budgetRequest, bool, error) {
	var request budgetRequest
	err := readStrict(j.requestPath(key), &request)
	if errors.Is(err, os.ErrNotExist) {
		return request, false, nil
	}
	if err != nil || request.RequestKey != key || request.Identity == "" {
		return request, false, errors.New("invalid buyer budget request record")
	}
	return request, true, nil
}

func readStrict(path string, target any) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || !osguard.CurrentUserOwns(before) ||
		before.Size() <= 0 || before.Size() > 64<<10 {
		return errors.New("buyer budget record is not an owner-private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return errors.New("buyer budget record changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, (64<<10)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("buyer budget record has trailing data")
	}
	return nil
}

func (j *FileBudgetJournal) withLock(fn func() error) error {
	return osguard.WithExclusiveFileLock(filepath.Join(j.directory, ".buyer-budget.lock"), 0o600, fn)
}

func (j *FileBudgetJournal) atomicCreate(path string, raw []byte) (bool, error) {
	temporary, err := os.CreateTemp(j.directory, ".buyer-create-")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, syncDirectory(j.directory)
}

func (j *FileBudgetJournal) atomicReplace(path string, raw []byte) error {
	temporary, err := os.CreateTemp(j.directory, ".buyer-replace-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
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
