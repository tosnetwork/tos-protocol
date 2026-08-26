//go:build !windows

package osguard

// OwnerPrivateStorageSupported reports whether this build can verify file
// ownership and POSIX permission bits at runtime.
func OwnerPrivateStorageSupported() bool { return true }
