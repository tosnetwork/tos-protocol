//go:build windows

package nativecore

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func relayJournalDirectoryIsPrivate(info os.FileInfo) bool {
	// Windows does not expose Unix ownership/mode bits through FileInfo. Reject
	// reparse points here; deployment ACL policy remains an operator preflight.
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func withRelayJournalFileLock(path string, fn func() error) error {
	encoded, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("encode Native relay journal lock path")
	}
	handle, err := windows.CreateFile(encoded, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errors.New("open Native relay journal lock")
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return errors.New("Native relay journal lock is not a regular file")
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return errors.New("lock Native relay journal")
	}
	defer windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
	return fn()
}
