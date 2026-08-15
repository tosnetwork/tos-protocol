package capabilitycatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
)

type catalogEntry struct {
	CapabilityID        string `json:"capability_id"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
	TVMStateHash        string `json:"tvm_state_hash"`
}

type fileStore struct {
	directory  string
	maxEntries uint32
}

func (s *fileStore) observe(state *nativev1.NativeStateV1) error {
	return s.withLock(func() error {
		entries, err := s.entriesUnlocked()
		if err != nil {
			return err
		}
		capability := state.GetCapability()
		path := s.entryPath(capability.CapabilityId)
		current, found, err := s.readEntry(path)
		if err != nil {
			return err
		}
		if !found && uint32(len(entries)) >= s.maxEntries {
			return errors.New("Capability catalog entry bound reached")
		}
		if found && (state.Reference.FinalizedCheckpoint < current.FinalizedCheckpoint ||
			state.Reference.FinalizedCheckpoint == current.FinalizedCheckpoint && state.TvmStateHash != current.TVMStateHash) {
			return errors.New("Capability catalog rejected a rollback or conflicting finalized observation")
		}
		if found && state.Reference.FinalizedCheckpoint == current.FinalizedCheckpoint {
			return nil
		}
		entry := catalogEntry{CapabilityID: capability.CapabilityId,
			FinalizedCheckpoint: state.Reference.FinalizedCheckpoint, TVMStateHash: state.TvmStateHash}
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if found {
			return s.atomicReplace(path, append(raw, '\n'))
		}
		created, err := s.atomicCreate(path, append(raw, '\n'))
		if err != nil || !created {
			return errors.New("failed to create Capability catalog entry")
		}
		return nil
	})
}

func newFileStore(directory string, maxEntries uint32) (*fileStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("Capability catalog directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByProcess(info) {
		return nil, errors.New("Capability catalog directory must be owner-private")
	}
	return &fileStore{directory: directory, maxEntries: maxEntries}, nil
}

func (s *fileStore) publish(state *nativev1.NativeStateV1, digest string, manifest []byte) error {
	return s.withLock(func() error {
		capability := state.GetCapability()
		path := s.entryPath(capability.CapabilityId)
		current, found, err := s.readEntry(path)
		if err != nil {
			return err
		}
		if !found {
			entries, err := s.entriesUnlocked()
			if err != nil {
				return err
			}
			if uint32(len(entries)) >= s.maxEntries {
				return errors.New("Capability catalog entry bound reached")
			}
		}
		if found && (state.Reference.FinalizedCheckpoint < current.FinalizedCheckpoint ||
			state.Reference.FinalizedCheckpoint == current.FinalizedCheckpoint && state.TvmStateHash != current.TVMStateHash) {
			return errors.New("Capability catalog rejected a rollback or conflicting finalized observation")
		}
		manifestPath, err := s.manifestPath(digest)
		if err != nil {
			return err
		}
		created, err := s.atomicCreate(manifestPath, manifest)
		if err != nil {
			return err
		}
		if !created {
			existing, err := readOwnerFile(manifestPath, 1<<20)
			if err != nil || !bytes.Equal(existing, manifest) {
				return errors.New("Capability manifest digest conflicts with stored bytes")
			}
		}
		entry := catalogEntry{CapabilityID: capability.CapabilityId,
			FinalizedCheckpoint: state.Reference.FinalizedCheckpoint, TVMStateHash: state.TvmStateHash}
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if found {
			return s.atomicReplace(path, append(raw, '\n'))
		}
		created, err = s.atomicCreate(path, append(raw, '\n'))
		if err != nil || !created {
			return errors.New("failed to create Capability catalog entry")
		}
		return nil
	})
}

func (s *fileStore) manifest(digest string) ([]byte, error) {
	path, err := s.manifestPath(digest)
	if err != nil {
		return nil, err
	}
	raw, err := readOwnerFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	if digest != "sha256:"+hex.EncodeToString(hash[:]) {
		return nil, errors.New("stored Capability manifest digest mismatch")
	}
	if _, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(raw); err != nil {
		return nil, errors.New("stored Capability manifest is not canonical")
	}
	return raw, nil
}

func (s *fileStore) entries() ([]catalogEntry, error) {
	var result []catalogEntry
	err := s.withLock(func() error {
		var err error
		result, err = s.entriesUnlocked()
		return err
	})
	return result, err
}

func (s *fileStore) entriesUnlocked() ([]catalogEntry, error) {
	items, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, err
	}
	result := make([]catalogEntry, 0)
	for _, item := range items {
		if item.IsDir() || !strings.HasPrefix(item.Name(), "capability-") || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		entry, found, err := s.readEntry(filepath.Join(s.directory, item.Name()))
		if err != nil || !found {
			return nil, err
		}
		result = append(result, entry)
		if uint32(len(result)) > s.maxEntries {
			return nil, errors.New("Capability catalog exceeds configured entry bound")
		}
	}
	return result, nil
}

func (s *fileStore) readEntry(path string) (catalogEntry, bool, error) {
	var entry catalogEntry
	raw, err := readOwnerFile(path, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return entry, false, nil
	}
	if err != nil {
		return entry, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		return entry, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return entry, false, errors.New("Capability catalog entry has trailing data")
	}
	if !capabilityIDValid(entry.CapabilityID) || entry.FinalizedCheckpoint == 0 || entry.TVMStateHash == "" ||
		path != s.entryPath(entry.CapabilityID) {
		return entry, false, errors.New("invalid Capability catalog entry")
	}
	return entry, true, nil
}

func (s *fileStore) entryPath(capabilityID string) string {
	hash := sha256.Sum256([]byte(capabilityID))
	return filepath.Join(s.directory, "capability-"+hex.EncodeToString(hash[:])+".json")
}

func (s *fileStore) manifestPath(digest string) (string, error) {
	if !digestValid(digest) {
		return "", errors.New("invalid Capability manifest digest")
	}
	return filepath.Join(s.directory, "manifest-"+digest[7:]+".cbor"), nil
}

func (s *fileStore) withLock(fn func() error) error {
	lock, err := os.OpenFile(filepath.Join(s.directory, ".capability-catalog.lock"), os.O_CREATE|os.O_RDWR, 0o600)
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

func (s *fileStore) atomicCreate(path string, raw []byte) (bool, error) {
	temporary, err := os.CreateTemp(s.directory, ".catalog-create-")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := writeSyncClose(temporary, raw); err != nil {
		return false, err
	}
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, syncDirectory(s.directory)
}

func (s *fileStore) atomicReplace(path string, raw []byte) error {
	temporary, err := os.CreateTemp(s.directory, ".catalog-replace-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := writeSyncClose(temporary, raw); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

func writeSyncClose(file *os.File, raw []byte) error {
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readOwnerFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || !ownedByProcess(before) ||
		before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("Capability catalog file is not an owner-private bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("Capability catalog file changed while opening")
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func ownedByProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
