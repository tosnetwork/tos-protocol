package executiongate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type record struct {
	Schema   string   `json:"schema"`
	Request  Request  `json:"request"`
	Evidence Evidence `json:"evidence"`
}

type store struct{ dir string }

func newStore(dir string) (*store, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("execution gate directory must be absolute and clean")
	}
	i, err := os.Lstat(dir)
	if err != nil || !i.IsDir() || i.Mode().Perm() != 0700 || !owned(i) {
		return nil, errors.New("execution gate directory must be owner-private")
	}
	return &store{dir}, nil
}

func (s *store) claim(req Request, evidence Evidence) error {
	return s.lock(func() error {
		path := s.path(req)
		existing, found, err := s.read(path)
		if err != nil {
			return err
		}
		if found {
			if existing.Request != req {
				return errors.New("paid Quote is already bound to another execution intent")
			}
			if !sameAuthority(existing.Evidence, evidence) {
				return errors.New("execution authority changed for an existing claim")
			}
			if evidence.EscrowFinalizedCheckpoint < existing.Evidence.EscrowFinalizedCheckpoint ||
				evidence.AgentFinalizedCheckpoint < existing.Evidence.AgentFinalizedCheckpoint ||
				evidence.CapabilityFinalizedCheckpoint < existing.Evidence.CapabilityFinalizedCheckpoint {
				return errors.New("execution authority checkpoint regressed")
			}
			if !sameObservation(existing.Evidence.EscrowFinalizedCheckpoint, existing.Evidence.EscrowTransactionHash,
				evidence.EscrowFinalizedCheckpoint, evidence.EscrowTransactionHash) ||
				!sameObservation(existing.Evidence.AgentFinalizedCheckpoint, existing.Evidence.AgentTransactionHash,
					evidence.AgentFinalizedCheckpoint, evidence.AgentTransactionHash) ||
				!sameObservation(existing.Evidence.CapabilityFinalizedCheckpoint, existing.Evidence.CapabilityTransactionHash,
					evidence.CapabilityFinalizedCheckpoint, evidence.CapabilityTransactionHash) {
				return errors.New("execution authority changed at the same finalized checkpoint")
			}
			if evidence == existing.Evidence {
				return nil
			}
			return s.write(path, record{Schema: "tos.service.execution-claim.v1", Request: req, Evidence: evidence}, true)
		}
		return s.write(path, record{Schema: "tos.service.execution-claim.v1", Request: req, Evidence: evidence}, false)
	})
}

func sameObservation(oldCheckpoint uint64, oldTransaction string, newCheckpoint uint64, newTransaction string) bool {
	return oldCheckpoint != newCheckpoint || oldTransaction == newTransaction
}

func sameAuthority(a, b Evidence) bool {
	a.EscrowFinalizedCheckpoint, b.EscrowFinalizedCheckpoint = 0, 0
	a.AgentFinalizedCheckpoint, b.AgentFinalizedCheckpoint = 0, 0
	a.CapabilityFinalizedCheckpoint, b.CapabilityFinalizedCheckpoint = 0, 0
	a.EscrowTransactionHash, b.EscrowTransactionHash = "", ""
	a.AgentTransactionHash, b.AgentTransactionHash = "", ""
	a.CapabilityTransactionHash, b.CapabilityTransactionHash = "", ""
	return a == b
}

func (s *store) write(path string, value record, replace bool) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".claim-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(raw, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if replace {
		if err := os.Rename(name, path); err != nil {
			return err
		}
	} else if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("execution claim raced with another intent")
		}
		return err
	}
	return syncDir(s.dir)
}

func (s *store) path(req Request) string {
	h := sha256.Sum256([]byte(req.QuoteCommitment + "\x00" + req.EscrowAddress))
	return filepath.Join(s.dir, "claim-"+hex.EncodeToString(h[:])+".json")
}

func (s *store) read(path string) (record, bool, error) {
	var r record
	i, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, false, nil
	}
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || !owned(i) || i.Size() <= 0 || i.Size() > 64<<10 {
		return r, false, errors.New("invalid execution claim record")
	}
	f, err := os.Open(path)
	if err != nil {
		return r, false, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(i, after) {
		return r, false, errors.New("execution claim changed while opening")
	}
	d := json.NewDecoder(io.LimitReader(f, (64<<10)+1))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return r, false, err
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) {
		return r, false, errors.New("execution claim has trailing data")
	}
	if r.Schema != "tos.service.execution-claim.v1" || !validRequest(r.Request) || !validEvidence(r.Evidence) ||
		r.Evidence.QuoteCommitment != r.Request.QuoteCommitment || r.Evidence.EscrowAddress != r.Request.EscrowAddress {
		return r, false, errors.New("invalid execution claim")
	}
	return r, true, nil
}

func validRequest(r Request) bool {
	return rawAddress(r.EscrowAddress) && cellDigest(r.QuoteCommitment) &&
		shaDigest(r.ExecutionID) && shaDigest(r.InputDigest) && shaDigest(r.SourceDigest)
}

func validEvidence(e Evidence) bool {
	return e.NetworkID != "" && agentID(e.ProviderAgentID) && rawAddress(e.ProviderAddress) &&
		stringsCapabilityID(e.CapabilityID) && e.CapabilityVersion != "" && shaDigest(e.ManifestDigest) &&
		cellDigest(e.QuoteCommitment) && rawAddress(e.EscrowAddress) && cellDigest(e.EscrowCodeHash) &&
		cellDigest(e.RegistryCodeHash) && shaDigest(e.EscrowTransactionHash) &&
		shaDigest(e.AgentTransactionHash) && shaDigest(e.CapabilityTransactionHash) &&
		e.EscrowFinalizedCheckpoint > 0 && e.AgentFinalizedCheckpoint > 0 && e.CapabilityFinalizedCheckpoint > 0
}

func stringsCapabilityID(v string) bool {
	return len(v) == 68 && len(v) > 4 && v[:4] == "cap_" && validDigest("sha256:"+v[4:], "sha256:")
}

func (s *store) lock(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(s.dir, ".execution-gate.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func owned(i os.FileInfo) bool {
	v, ok := i.Sys().(*syscall.Stat_t)
	return ok && v.Uid == uint32(os.Geteuid())
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
