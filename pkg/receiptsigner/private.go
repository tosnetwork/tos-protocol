package receiptsigner

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const MaxSeedFileBytes = 256

// LoadPrivateKey reads one base64url-encoded 32-byte Ed25519 seed without
// following a final symlink. The file must be an owner-only regular file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("seed file path must be absolute and clean")
	}
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("seed directory: %w", err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open receipt signing seed")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open receipt signing seed")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		requireCurrentOwner(info) != nil || info.Size() <= 0 || info.Size() > MaxSeedFileBytes {
		return nil, errors.New("receipt signing seed is not a private regular file")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, errors.New("read receipt signing seed")
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	seed, err := base64.RawURLEncoding.DecodeString(string(data))
	for index := range data {
		data[index] = 0
	}
	if err != nil || len(seed) != ed25519.SeedSize {
		for index := range seed {
			seed[index] = 0
		}
		return nil, errors.New("receipt signing seed must be 32-byte base64url")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	for index := range seed {
		seed[index] = 0
	}
	return privateKey, nil
}

// ListenPrivateUnix creates a new owner-only Unix socket. Existing filesystem
// entries are never removed or replaced.
func ListenPrivateUnix(path string) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("socket path must be absolute and clean")
	}
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("socket directory: %w", err)
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("socket path already exists or cannot be inspected")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errors.New("listen on receipt signer socket")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, errors.New("protect receipt signer socket")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 ||
		requireCurrentOwner(info) != nil {
		_ = listener.Close()
		return nil, errors.New("receipt signer socket failed ownership validation")
	}
	return listener, nil
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("inspect private directory")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("directory is not private")
	}
	return requireCurrentOwner(info)
}

func requireCurrentOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("owner does not match current process")
	}
	return nil
}
