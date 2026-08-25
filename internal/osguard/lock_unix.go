//go:build !windows

package osguard

import (
	"os"
	"syscall"
)

func WithExclusiveFileLock(path string, permission os.FileMode, fn func() error) error {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, permission)
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
