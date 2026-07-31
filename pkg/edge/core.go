package edge

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
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
	BudgetUsages         uint64
	PaymentRecords       uint64
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

// AdmitAuthorizedEnvelope atomically binds a manifest-authorized, semantically
// validated signed envelope to its durable request record.
func (c *Core) AdmitAuthorizedEnvelope(
	scope journal.Scope,
	intentDigest string,
	authorized authorization.AuthorizedEnvelope,
	retainUntil time.Time,
) (journal.Record, journal.BeginDisposition, error) {
	now := c.now()
	binding := authorization.AdmissionBinding{
		SessionID: scope.SessionID, Operation: scope.Operation,
		RequestID: scope.RequestID, IntentDigest: intentDigest,
	}
	envelope, err := authorized.EnvelopeForAdmission(
		scope.Network, scope.ServiceID, scope.Authority, binding, now,
	)
	if err != nil {
		return journal.Record{}, "", fmt.Errorf("authorize Edge Core admission: %w", err)
	}
	return c.admitVerifiedEnvelope(
		scope, intentDigest, envelope, now, retainUntil,
	)
}

// AdmitAuthorizedSessionEnvelope atomically binds a verified client envelope
// and consumes every cumulative session/delegation budget. A successful replay
// returns the existing request without charging those budgets again.
func (c *Core) AdmitAuthorizedSessionEnvelope(
	scope journal.Scope,
	intentDigest string,
	chargeNanoTOS uint64,
	authorized authorization.AuthorizedSessionEnvelope,
	retainUntil time.Time,
) (journal.Record, journal.BeginDisposition, error) {
	now := c.now()
	binding := authorization.AdmissionBinding{
		SessionID: scope.SessionID, Operation: scope.Operation,
		RequestID: scope.RequestID, IntentDigest: intentDigest,
	}
	material, err := authorized.AdmissionMaterial(
		scope.Network, scope.ServiceID, scope.Authority,
		binding, chargeNanoTOS, now,
	)
	if err != nil {
		return journal.Record{}, "", fmt.Errorf(
			"authorize session Edge Core admission: %w", err,
		)
	}
	envelopeDigest, err := material.Envelope.Fingerprint()
	if err != nil {
		return journal.Record{}, "", fmt.Errorf(
			"fingerprint authorized session envelope: %w", err,
		)
	}
	budgets := make([]journal.UsageBudget, len(material.Budgets))
	for index, budget := range material.Budgets {
		budgets[index] = journal.UsageBudget{
			Kind: budget.Kind, ID: budget.ID,
			GrantDigest: budget.GrantDigest,
			MaxActions:  budget.MaxActions, MaxNanoTOS: budget.MaxNanoTOS,
		}
	}
	return c.requests.AdmitSession(journal.SessionAdmission{
		Admission: journal.Admission{
			Scope: scope, IntentDigest: intentDigest,
			EnvelopeDigest: envelopeDigest,
			Domain:         material.Envelope.Domain, Nonce: material.Envelope.Nonce,
			EnvelopeExpiresAt: time.UnixMilli(material.Envelope.ExpiresAt),
			RetainUntil:       retainUntil,
		},
		ClientID:         material.ClientID,
		SessionExpiresAt: material.SessionExpiresAt,
		ChargeNanoTOS:    material.ChargeNanoTOS,
		Budgets:          budgets,
	}, now)
}

// AdmitAuthorizedPayment atomically admits the client-signed payment
// authorization request and its exact quoted charge. Chain observation and
// the pending-to-authorized transition remain separate subsequent steps.
func (c *Core) AdmitAuthorizedPayment(
	scope journal.Scope,
	intentDigest string,
	authorized authorization.AuthorizedPayment,
	retainUntil time.Time,
) (journal.Record, journal.BeginDisposition, error) {
	requestAuthorization, chargeNanoTOS, err := authorized.RequestAuthorization()
	if err != nil {
		return journal.Record{}, "", fmt.Errorf(
			"extract payment request authorization: %w", err,
		)
	}
	return c.AdmitAuthorizedSessionEnvelope(
		scope, intentDigest, chargeNanoTOS,
		requestAuthorization, retainUntil,
	)
}

// ApplyVerifiedPayment consumes only opaque output from the strict chain
// observer. The payment binding and pending-to-authorized request transition
// are committed atomically, so process restart or concurrent replay cannot
// authorize the request twice.
func (c *Core) ApplyVerifiedPayment(
	scope journal.Scope,
	intentDigest string,
	authorized authorization.AuthorizedPayment,
	verified payment.VerifiedObservation,
	minimumMasterSeqno uint64,
) (journal.Record, journal.PaymentRecord, journal.PaymentDisposition, error) {
	now := c.now()
	binding, err := authorized.ObservationMaterial(now)
	if err != nil {
		return journal.Record{}, journal.PaymentRecord{}, "", fmt.Errorf(
			"extract authorized payment binding: %w", err,
		)
	}
	material, err := verified.ApplicationMaterial(
		scope.Network, scope.ServiceID, scope.SessionID, scope.Operation,
		scope.RequestID, intentDigest, binding.AuthorizationID,
		binding.QuoteID, binding.Reference, minimumMasterSeqno, now,
	)
	if err != nil {
		return journal.Record{}, journal.PaymentRecord{}, "", fmt.Errorf(
			"authorize payment application: %w", err,
		)
	}
	return c.requests.ApplyPayment(journal.PaymentAdmission{
		Scope: scope, IntentDigest: material.IntentDigest,
		AuthorizationID: material.AuthorizationID,
		QuoteID:         material.QuoteID, Reference: material.Reference,
		Payer: material.Payer, Payee: material.Payee,
		AmountNanoTOS:         material.AmountNanoTOS,
		QuoteEnvelopeDigest:   material.QuoteEnvelopeDigest,
		PaymentEnvelopeDigest: material.PaymentEnvelopeDigest,
		ObservedMasterSeqno:   material.ObservedMasterSeqno,
		ObservedAt:            material.ObservedAt,
	}, now)
}

func (c *Core) admitVerifiedEnvelope(
	scope journal.Scope,
	intentDigest string,
	envelope identity.Envelope,
	now, retainUntil time.Time,
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
	}, now)
}

func (c *Core) Request(scope journal.Scope) (journal.Record, error) {
	return c.requests.Get(scope, c.now())
}

func (c *Core) Payment(scope journal.Scope) (journal.PaymentRecord, error) {
	return c.requests.GetPayment(scope, c.now())
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
	now := c.now()
	requestDeleted, requestMore, requestErr := c.requests.PruneExpired(
		now, c.limits.MaxPrunePerWrite,
	)
	nonceDeleted, nonceMore, nonceErr := c.requests.PruneNonces(
		now, c.limits.MaxPrunePerWrite,
	)
	budgetDeleted, budgetMore, budgetErr := c.requests.PruneBudgets(
		now, c.limits.MaxPrunePerWrite,
	)
	deleted = requestDeleted + nonceDeleted + budgetDeleted
	more = requestMore || nonceMore || budgetMore
	if requestErr != nil {
		err = requestErr
	} else if nonceErr != nil {
		err = nonceErr
	} else {
		err = budgetErr
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
		BudgetUsages: stats.BudgetUsages, PaymentRecords: stats.Payments,
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
