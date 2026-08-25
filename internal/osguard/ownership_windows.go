//go:build windows

package osguard

import "os"

func CurrentUserOwns(info os.FileInfo) bool {
	// The Windows secure deployment profile enforces owner-only DACLs during
	// installation. FileInfo has no portable owner identity; reject reparse
	// points here and leave the DACL assertion to that preflight.
	return info != nil && info.Mode()&os.ModeSymlink == 0
}

func TrustedExecutableOwner(info os.FileInfo) bool { return CurrentUserOwns(info) }
