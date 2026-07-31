package edge

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
)

const (
	DefaultCleanupInterval = 30 * time.Second
	minCleanupInterval     = 10 * time.Millisecond
	maxCleanupInterval     = time.Hour
)

// CoreConfig contains only generic Edge Core state policy. Vertical runtime,
// wallet, and owner policy configuration remain outside this package.
type CoreConfig struct {
	RequestJournalPath   string
	RequestJournalLimits journal.Limits
	CleanupInterval      time.Duration
}

func DefaultCoreConfig(journalPath string) CoreConfig {
	return CoreConfig{
		RequestJournalPath:   journalPath,
		RequestJournalLimits: journal.DefaultLimits(),
		CleanupInterval:      DefaultCleanupInterval,
	}
}

type CoreHealth struct {
	RequestRecords       uint64
	NonceClaims          uint64
	JournalFileBytes     int64
	LastCleanupAt        time.Time
	LastCleanupDeleted   int
	LastCleanupHasMore   bool
	LastCleanupSucceeded bool
}

// Core owns durable request replay state and its bounded cleanup lifecycle.
// It intentionally has no public HTTP action handler yet.
type Core struct {
	requests *journal.Store
	limits   journal.Limits
	now      func() time.Time

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	healthMu      sync.RWMutex
	lastCleanupAt time.Time
	lastDeleted   int
	lastMore      bool
	lastError     error
}

func OpenCore(config CoreConfig) (*Core, error) {
	return openCore(config, time.Now)
}

func openCore(config CoreConfig, now func() time.Time) (*Core, error) {
	if config.CleanupInterval < minCleanupInterval ||
		config.CleanupInterval > maxCleanupInterval {
		return nil, errors.New("invalid Edge Core cleanup interval")
	}
	if now == nil {
		return nil, errors.New("nil Edge Core clock")
	}
	requests, err := journal.Open(config.RequestJournalPath, config.RequestJournalLimits)
	if err != nil {
		return nil, fmt.Errorf("open Edge Core request state: %w", err)
	}
	core := &Core{
		requests: requests, limits: config.RequestJournalLimits,
		now: now, stop: make(chan struct{}), done: make(chan struct{}),
	}
	go core.cleanupLoop(config.CleanupInterval)
	return core, nil
}

func (c *Core) Close() error {
	c.closeOnce.Do(func() {
		close(c.stop)
		<-c.done
		c.closeErr = c.requests.Close()
	})
	return c.closeErr
}

func (c *Core) BeginRequest(
	scope journal.Scope,
	intentDigest string,
	retainUntil time.Time,
) (journal.Record, journal.BeginDisposition, error) {
	return c.requests.Begin(scope, intentDigest, c.now(), retainUntil)
}

// AdmitVerifiedEnvelope atomically binds a caller-verified signed envelope to
// its durable request record. The caller must first verify the signature,
// manifest role, delegation, revocation, profile, and semantic payload.
func (c *Core) AdmitVerifiedEnvelope(
	scope journal.Scope,
	intentDigest string,
	envelope identity.Envelope,
	retainUntil time.Time,
) (journal.Record, journal.BeginDisposition, error) {
	if scope.Authority != envelope.KeyID {
		return journal.Record{}, "", errors.New("envelope key does not match request authority")
	}
	envelopeDigest, err := envelope.Fingerprint()
	if err != nil {
		return journal.Record{}, "", fmt.Errorf("fingerprint verified envelope: %w", err)
	}
	return c.requests.Admit(journal.Admission{
		Scope: scope, IntentDigest: intentDigest,
		EnvelopeDigest: envelopeDigest,
		Domain:         envelope.Domain, Nonce: envelope.Nonce,
		EnvelopeExpiresAt: time.UnixMilli(envelope.ExpiresAt),
		RetainUntil:       retainUntil,
	}, c.now())
}

func (c *Core) Request(scope journal.Scope) (journal.Record, error) {
	return c.requests.Get(scope, c.now())
}

func (c *Core) TransitionRequest(
	scope journal.Scope,
	expectedRevision uint64,
	next journal.State,
	resultDigest, errorCode string,
) (journal.Record, error) {
	return c.requests.Transition(
		scope, expectedRevision, next, resultDigest, errorCode, c.now(),
	)
}

func (c *Core) PruneNow() (deleted int, more bool, err error) {
	requestDeleted, requestMore, requestErr := c.requests.PruneExpired(
		c.now(), c.limits.MaxPrunePerWrite,
	)
	nonceDeleted, nonceMore, nonceErr := c.requests.PruneNonces(
		c.now(), c.limits.MaxPrunePerWrite,
	)
	deleted = requestDeleted + nonceDeleted
	more = requestMore || nonceMore
	if requestErr != nil {
		err = requestErr
	} else {
		err = nonceErr
	}
	c.recordCleanup(deleted, more, err)
	return deleted, more, err
}

func (c *Core) Health() (CoreHealth, error) {
	stats, err := c.requests.Stats()
	if err != nil {
		return CoreHealth{}, err
	}
	c.healthMu.RLock()
	defer c.healthMu.RUnlock()
	output := CoreHealth{
		RequestRecords: stats.Records, NonceClaims: stats.Nonces,
		JournalFileBytes: stats.FileSize,
		LastCleanupAt:    c.lastCleanupAt, LastCleanupDeleted: c.lastDeleted,
		LastCleanupHasMore:   c.lastMore,
		LastCleanupSucceeded: !c.lastCleanupAt.IsZero() && c.lastError == nil,
	}
	if c.lastError != nil {
		return output, fmt.Errorf("Edge Core request cleanup: %w", c.lastError)
	}
	return output, nil
}

func (c *Core) cleanupLoop(interval time.Duration) {
	defer close(c.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, _, _ = c.PruneNow()
		case <-c.stop:
			return
		}
	}
}

func (c *Core) recordCleanup(deleted int, more bool, err error) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.lastCleanupAt = c.now().UTC()
	c.lastDeleted = deleted
	c.lastMore = more
	c.lastError = err
}
