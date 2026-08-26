package toschain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
)

const maxTOSRelayObservationBytes = 64 << 10

type tosRelayObservationStore struct{ directory string }

func newTOSRelayObservationStore(directory string) (*tosRelayObservationStore, error) {
	if !osguard.OwnerPrivateStorageSupported() {
		return nil, errors.New("TOS relay observation storage cannot verify owner-private ACLs on this platform")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("TOS relay observation directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, errors.New("TOS relay observation directory must be owner-private")
	}
	return &tosRelayObservationStore{directory: directory}, nil
}

func (store *tosRelayObservationStore) put(reference TOSRelayRPCObservationReference) (string, error) {
	if store == nil {
		return "", errors.New("TOS relay observation store is unavailable")
	}
	digest, err := TOSRelayRPCObservationReferenceDigest(reference)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(reference)
	if err != nil || len(raw) == 0 || len(raw) > maxTOSRelayObservationBytes {
		return "", errors.New("TOS relay observation exceeds the durable record bound")
	}
	path, err := store.path(digest)
	if err != nil {
		return "", err
	}
	err = osguard.WithExclusiveFileLock(filepath.Join(store.directory, ".relay-observations.lock"), 0o600,
		func() error {
			existing, found, readErr := store.readPath(path)
			if readErr != nil {
				return readErr
			}
			if found {
				if existing != reference {
					return errors.New("TOS relay observation digest is bound to different evidence")
				}
				return nil
			}
			temporary, createErr := os.CreateTemp(store.directory, ".relay-observation-")
			if createErr != nil {
				return createErr
			}
			name := temporary.Name()
			defer os.Remove(name)
			if createErr = temporary.Chmod(0o600); createErr == nil {
				_, createErr = temporary.Write(append(raw, '\n'))
			}
			if createErr == nil {
				createErr = temporary.Sync()
			}
			if closeErr := temporary.Close(); createErr == nil {
				createErr = closeErr
			}
			if createErr != nil {
				return createErr
			}
			if createErr = os.Link(name, path); createErr != nil {
				if !errors.Is(createErr, os.ErrExist) {
					return createErr
				}
				existing, found, createErr = store.readPath(path)
				if createErr != nil || !found || existing != reference {
					return errors.New("TOS relay observation raced with conflicting evidence")
				}
				return nil
			}
			directory, syncErr := os.Open(store.directory)
			if syncErr != nil {
				return syncErr
			}
			defer directory.Close()
			return directory.Sync()
		})
	return digest, err
}

func (store *tosRelayObservationStore) get(digest string) (TOSRelayRPCObservationReference, error) {
	if store == nil {
		return TOSRelayRPCObservationReference{}, errors.New("TOS relay observation store is unavailable")
	}
	path, err := store.path(digest)
	if err != nil {
		return TOSRelayRPCObservationReference{}, err
	}
	reference, found, err := store.readPath(path)
	if err != nil {
		return TOSRelayRPCObservationReference{}, err
	}
	if !found {
		return TOSRelayRPCObservationReference{}, os.ErrNotExist
	}
	actual, err := TOSRelayRPCObservationReferenceDigest(reference)
	if err != nil || actual != digest {
		return TOSRelayRPCObservationReference{}, errors.New("TOS relay observation digest mismatch")
	}
	return reference, nil
}

func (store *tosRelayObservationStore) readPath(path string) (TOSRelayRPCObservationReference, bool, error) {
	var reference TOSRelayRPCObservationReference
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return reference, false, nil
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 ||
		!osguard.CurrentUserOwns(before) || before.Size() <= 0 || before.Size() > maxTOSRelayObservationBytes {
		return reference, false, errors.New("TOS relay observation is not an owner-private bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return reference, false, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return reference, false, errors.New("TOS relay observation changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxTOSRelayObservationBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reference); err != nil {
		return reference, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return reference, false, errors.New("TOS relay observation has trailing data")
	}
	if _, err := TOSRelayRPCObservationReferenceDigest(reference); err != nil {
		return reference, false, err
	}
	return reference, true, nil
}

func (store *tosRelayObservationStore) path(digest string) (string, error) {
	if !canonicalSHA256Digest(digest) {
		return "", errors.New("invalid TOS relay observation digest")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid TOS relay observation digest")
	}
	return filepath.Join(store.directory, "relay-observation-"+hex.EncodeToString(raw)+".json"), nil
}
