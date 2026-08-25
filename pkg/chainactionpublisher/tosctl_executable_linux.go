//go:build linux

package chainactionpublisher

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func captureChainExecutableIdentity(path string) (chainExecutableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 {
		return chainExecutableIdentity{}, errors.New("executable is not a regular executable file")
	}
	file, err := os.Open(path)
	if err != nil {
		return chainExecutableIdentity{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		return chainExecutableIdentity{}, errors.New("executable changed while its identity was captured")
	}
	if err := validateChainExecutablePath(path, info); err != nil {
		return chainExecutableIdentity{}, err
	}
	return chainExecutableIdentityFromFile(file, info)
}

func validateChainExecutablePath(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || os.Geteuid() == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("executable must be root-owned, non-group-writable, and used by an unprivileged publisher")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		directoryInfo, err := os.Lstat(directory)
		if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o022 != 0 {
			return errors.New("executable path contains an untrusted directory")
		}
		directoryStat, ok := directoryInfo.Sys().(*syscall.Stat_t)
		if !ok || directoryStat.Uid != 0 {
			return errors.New("executable path is not rooted in root-owned directories")
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func chainExecutableIdentityFromFile(file *os.File, info os.FileInfo) (chainExecutableIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return chainExecutableIdentity{}, errors.New("executable identity is unavailable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return chainExecutableIdentity{}, err
	}
	return chainExecutableIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), digest: "sha256:" + hex.EncodeToString(hash.Sum(nil))}, nil
}

func openVerifiedChainExecutable(path string, expected chainExecutableIdentity) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("enrolled tosctl executable path is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		file.Close()
		return nil, errors.New("enrolled tosctl executable changed while opening")
	}
	if err := validateChainExecutablePath(path, info); err != nil {
		file.Close()
		return nil, err
	}
	actual, err := chainExecutableIdentityFromFile(file, info)
	if err != nil || actual != expected {
		file.Close()
		return nil, errors.New("enrolled tosctl executable identity changed")
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
