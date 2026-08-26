//go:build windows

package osguard

// OwnerPrivateStorageSupported is false until the Windows implementation can
// inspect and enforce an owner-only DACL. Relay journals contain bearer
// transactions and recovery tokens, so silently trusting installation policy
// is not an acceptable production boundary.
func OwnerPrivateStorageSupported() bool { return false }
