package toschain

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
)

const maxRelayCheckpointFenceBytes = 8 << 10

type tosRelayCheckpointFence struct{ path string }

type tosRelayCheckpointFenceRecord struct {
	Schema       string `json:"schema"`
	Sequence     uint64 `json:"sequence"`
	CheckpointID string `json:"checkpoint_id"`
}

func newTOSRelayCheckpointFence(path string) (*tosRelayCheckpointFence, error) {
	if !osguard.OwnerPrivateStorageSupported() {
		return nil, errors.New("TOS relay checkpoint storage cannot verify owner-private ACLs on this platform")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("TOS relay checkpoint path must be absolute and clean")
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, errors.New("TOS relay checkpoint directory must be owner-private")
	}
	return &tosRelayCheckpointFence{path: path}, nil
}

// checkAndAdvance rejects both rollback and a different checkpoint identity at
// the same sequence. The latter is important because a numeric high-water mark
// alone cannot detect a same-height fork after process restart.
func (fence *tosRelayCheckpointFence) checkAndAdvance(sequence uint64, checkpointID string) error {
	if fence == nil || sequence == 0 || checkpointID == "" || len(checkpointID) > 1024 {
		return errors.New("invalid TOS relay checkpoint observation")
	}
	return osguard.WithExclusiveFileLock(fence.path+".lock", 0o600, func() error {
		previous, found, err := readTOSRelayCheckpointFence(fence.path)
		if err != nil {
			return err
		}
		if found {
			if sequence < previous.Sequence {
				return errors.New("TOS relay finalized checkpoint regressed")
			}
			if sequence == previous.Sequence {
				if checkpointID != previous.CheckpointID {
					return errors.New("TOS relay finalized checkpoint forked at the high-water sequence")
				}
				return nil
			}
		}
		record := tosRelayCheckpointFenceRecord{Schema: "tos.relay-checkpoint-fence.v1",
			Sequence: sequence, CheckpointID: checkpointID}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		temporary, err := os.CreateTemp(filepath.Dir(fence.path), ".relay-checkpoint-")
		if err != nil {
			return err
		}
		name := temporary.Name()
		defer os.Remove(name)
		if err = temporary.Chmod(0o600); err == nil {
			_, err = temporary.Write(append(raw, '\n'))
		}
		if err == nil {
			err = temporary.Sync()
		}
		if closeErr := temporary.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err := os.Rename(name, fence.path); err != nil {
			return err
		}
		directory, err := os.Open(filepath.Dir(fence.path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	})
}

func readTOSRelayCheckpointFence(path string) (tosRelayCheckpointFenceRecord, bool, error) {
	var record tosRelayCheckpointFenceRecord
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 ||
		!osguard.CurrentUserOwns(before) || before.Size() <= 0 || before.Size() > maxRelayCheckpointFenceBytes {
		return record, false, errors.New("TOS relay checkpoint fence is not an owner-private bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return record, false, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return record, false, errors.New("TOS relay checkpoint fence changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxRelayCheckpointFenceBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return record, false, errors.New("TOS relay checkpoint fence has trailing data")
	}
	if record.Schema != "tos.relay-checkpoint-fence.v1" || record.Sequence == 0 ||
		record.CheckpointID == "" || len(record.CheckpointID) > 1024 {
		return record, false, errors.New("TOS relay checkpoint fence is corrupt")
	}
	return record, true, nil
}
