package toschain

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
)

// checkpointStore is a process-independent monotonic finality fence.
// The lock and fsync make a successful advance durable before state is served.
type checkpointStore struct{ path string }

func newCheckpointStore(path string) (*checkpointStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Native checkpoint path must be absolute and clean")
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Native checkpoint directory must be owner-private")
	}
	if !osguard.CurrentUserOwns(info) {
		return nil, errors.New("Native checkpoint directory must be owner-private")
	}
	return &checkpointStore{path: path}, nil
}

func (s *checkpointStore) checkAndAdvance(value uint64) error {
	return osguard.WithExclusiveFileLock(s.path, 0o600, func() error {
		file, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("Native checkpoint must be an owner-private regular file")
		}
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		raw, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		var previous uint64
		if text := strings.TrimSpace(string(raw)); text != "" {
			previous, err = strconv.ParseUint(text, 10, 64)
			if err != nil || previous == 0 {
				return errors.New("Native checkpoint file is corrupt")
			}
		}
		if value == 0 || value < previous {
			return fmt.Errorf("Native finalized checkpoint regressed from %d to %d", previous, value)
		}
		if value == previous {
			return nil
		}
		if err := file.Truncate(0); err != nil {
			return err
		}
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		if _, err := file.WriteString(strconv.FormatUint(value, 10) + "\n"); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		directory, err := os.Open(filepath.Dir(s.path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	})
}
