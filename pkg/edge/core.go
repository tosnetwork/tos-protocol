package edge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	DefaultCleanupInterval    = 30 * time.Second
	minCleanupInterval        = 10 * time.Millisecond
	maxCleanupInterval        = time.Hour
	minReconciliationInterval = 10 * time.Millisecond
	maxReconciliationInterval = 24 * time.Hour
	minReconciliationTimeout  = 10 * time.Millisecond
	maxReconciliationTimeout  = 10 * time.Minute
)

// CoreConfig contains only generic Edge Core state policy. Vertical runtime,
// wallet, and owner policy configuration remain outside this package.
type CoreConfig struct {
	RequestJournalPath            string
	RequestJournalLimits          journal.Limits
	CleanupInterval               time.Duration
	PaymentObserver               *payment.Observer
	PaymentReconciliationInterval time.Duration
	PaymentReconciliationTimeout  time.Duration
	PaymentReconciliationBatch    int
}

func DefaultCoreConfig(journalPath string) CoreConfig {
	return CoreConfig{
		RequestJournalPath:   journalPath,
		RequestJournalLimits: journal.DefaultLimits(),
		CleanupInterval:      DefaultCleanupInterval,
	}
}

type CoreHealth struct {
	RequestRecords                     uint64
	NonceClaims                        uint64
	BudgetUsages                       uint64
	PaymentRecords                     uint64
	ReceiptRecords                     uint64
	JournalFileBytes                   int64
	LastCleanupAt                      time.Time
	LastCleanupDeleted                 int
	LastCleanupHasMore                 bool
	LastCleanupSucceeded               bool
	LastPaymentReconciliationAt        time.Time
	LastPaymentReconciliationScanned   int
	LastPaymentReconciliationFailed    int
	LastPaymentReconciliationHasMore   bool
	LastPaymentReconciliationSucceeded bool
}

type PaymentReconciliationFailure struct {
	Scope journal.Scope
	Error string
}

// PaymentReconciliationReport is bounded by the caller's maxScan, which is
// itself capped by the journal's configured prune/write batch limit.
type PaymentReconciliationReport struct {
	Scanned     int
	Eligible    int
	Replayed    int
	Refreshed   int
	Reorganized int
	Failed      int
	HasMore     bool
	Wrapped     bool
	Failures    []PaymentReconciliationFailure
}

// Core owns durable request replay state and its bounded cleanup lifecycle.
// It intentionally has no public HTTP action handler yet.
type Core struct {
	requests                      *journal.Store
	limits                        journal.Limits
	now                           func() time.Time
	paymentObserver               *payment.Observer
	paymentReconciliationInterval time.Duration
	paymentReconciliationTimeout  time.Duration
	paymentReconciliationBatch    int
	runContext                    context.Context
	cancelRun                     context.CancelFunc

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	healthMu      sync.RWMutex
	lastCleanupAt time.Time
	lastDeleted   int
	lastMore      bool
	lastError     error

	paymentReconciliationSlot        chan struct{}
	lastPaymentReconciliationAt      time.Time
	lastPaymentReconciliationScanned int
	lastPaymentReconciliationFailed  int
	lastPaymentReconciliationMore    bool
	lastPaymentReconciliationError   error
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
	if err := validatePaymentReconciliationConfig(config); err != nil {
		return nil, err
	}
	requests, err := journal.Open(config.RequestJournalPath, config.RequestJournalLimits)
	if err != nil {
		return nil, fmt.Errorf("open Edge Core request state: %w", err)
	}
	runContext, cancelRun := context.WithCancel(context.Background())
	core := &Core{
		requests: requests, limits: config.RequestJournalLimits,
		now: now, stop: make(chan struct{}), done: make(chan struct{}),
		paymentObserver:               config.PaymentObserver,
		paymentReconciliationInterval: config.PaymentReconciliationInterval,
		paymentReconciliationTimeout:  config.PaymentReconciliationTimeout,
		paymentReconciliationBatch:    config.PaymentReconciliationBatch,
		runContext:                    runContext, cancelRun: cancelRun,
		paymentReconciliationSlot: make(chan struct{}, 1),
	}
	go core.lifecycleLoop(config.CleanupInterval)
	return core, nil
}

func (c *Core) Close() error {
	c.closeOnce.Do(func() {
		c.cancelRun()
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

// ApplyVerifiedReceipt consumes only opaque output from current
// manifest/runtime receipt authorization. Receipt uniqueness and the paid
// request terminal transition commit atomically in the journal.
func (c *Core) ApplyVerifiedReceipt(
	scope journal.Scope,
	expectedRevision uint64,
	verified authorization.VerifiedReceipt,
) (journal.Record, journal.ReceiptRecord, journal.ReceiptDisposition, error) {
	now := c.now()
	request, err := c.requests.Get(scope, now)
	if err != nil {
		return journal.Record{}, journal.ReceiptRecord{}, "", err
	}
	appliedPayment, err := c.requests.GetPayment(scope, now)
	if err != nil {
		return journal.Record{}, journal.ReceiptRecord{}, "", err
	}
	material, err := verified.ApplicationMaterial(
		authorization.ReceiptBinding{
			Network: scope.Network, ServiceID: scope.ServiceID,
			SessionID: scope.SessionID, Operation: scope.Operation,
			RequestID: scope.RequestID, IntentDigest: request.IntentDigest,
			AuthorizationID: appliedPayment.AuthorizationID,
			QuoteID:         appliedPayment.QuoteID,
		},
		now,
	)
	if err != nil {
		return journal.Record{}, journal.ReceiptRecord{}, "", fmt.Errorf(
			"authorize receipt application: %w",
			err,
		)
	}
	status, errorCode, err := receiptTerminalState(material.Status)
	if err != nil {
		return journal.Record{}, journal.ReceiptRecord{}, "", err
	}
	usage := make([]journal.ReceiptUsage, len(material.Usage))
	for index, item := range material.Usage {
		usage[index] = journal.ReceiptUsage{
			Unit: item.Unit, Quantity: item.Quantity,
		}
	}
	return c.requests.ApplyReceipt(
		journal.ReceiptAdmission{
			Scope: scope, ReceiptID: material.ReceiptID,
			IntentDigest:    material.Binding.IntentDigest,
			RuntimeKeyID:    material.RuntimeKeyID,
			AuthorizationID: material.Binding.AuthorizationID,
			QuoteID:         material.Binding.QuoteID,
			Status:          status, Usage: usage,
			ChargedNanoTOS:        material.ChargedNanoTOS,
			ResultDigest:          material.ResultDigest,
			ErrorCode:             errorCode,
			ServiceRevision:       material.ServiceRevision,
			ResourceRevision:      material.ResourceRevision,
			CompletedAt:           material.CompletedAt,
			ReceiptEnvelopeDigest: material.EnvelopeDigest,
			Envelope:              material.Envelope,
		},
		expectedRevision,
		now,
	)
}

func (c *Core) Receipt(scope journal.Scope) (journal.ReceiptRecord, error) {
	return c.requests.GetReceipt(scope, c.now())
}

// ReconcilePayment performs one strict post-application chain recheck and
// applies its opaque result against the latest durable high-water mark.
func (c *Core) ReconcilePayment(
	ctx context.Context,
	scope journal.Scope,
	observer *payment.Observer,
) (journal.PaymentRecord, journal.PaymentDisposition, error) {
	now := c.now()
	current, err := c.requests.GetPayment(scope, now)
	if err != nil {
		return journal.PaymentRecord{}, "", err
	}
	verified, err := observer.Reconcile(
		ctx, paymentReconciliationBinding(current),
		current.ObservedMasterSeqno, now,
	)
	if err != nil {
		return journal.PaymentRecord{}, "", fmt.Errorf(
			"verify payment reconciliation: %w", err,
		)
	}
	return c.applyVerifiedPaymentReconciliation(scope, verified, now)
}

// ReconcilePaymentBatch advances the durable payment scan cursor only after
// every eligible entry in the bounded page has been attempted. A process
// crash before cursor advance merely replays idempotent reconciliation.
func (c *Core) ReconcilePaymentBatch(
	ctx context.Context,
	observer *payment.Observer,
	maxScan int,
) (PaymentReconciliationReport, error) {
	if ctx == nil {
		return PaymentReconciliationReport{}, errors.New(
			"nil payment reconciliation context",
		)
	}
	if observer == nil {
		return PaymentReconciliationReport{}, errors.New(
			"nil payment reconciliation observer",
		)
	}
	select {
	case c.paymentReconciliationSlot <- struct{}{}:
		defer func() { <-c.paymentReconciliationSlot }()
	case <-ctx.Done():
		return PaymentReconciliationReport{}, ctx.Err()
	}
	now := c.now()
	scan, err := c.requests.ScanPayments(now, maxScan)
	if err != nil {
		return PaymentReconciliationReport{}, err
	}
	report := PaymentReconciliationReport{
		Scanned: scan.Scanned, Eligible: len(scan.Payments),
		HasMore: scan.HasMore, Wrapped: scan.Wrapped,
		Failures: make(
			[]PaymentReconciliationFailure, 0, len(scan.Payments),
		),
	}
	for _, current := range scan.Payments {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		binding := paymentReconciliationBinding(current)
		verified, err := observer.Reconcile(
			ctx, binding, current.ObservedMasterSeqno, now,
		)
		if err == nil {
			_, disposition, applyErr :=
				c.applyVerifiedPaymentReconciliation(
					current.Scope, verified, now,
				)
			err = applyErr
			switch disposition {
			case journal.PaymentReplay:
				report.Replayed++
			case journal.PaymentRefreshed:
				report.Refreshed++
			case journal.PaymentReorganized:
				report.Reorganized++
			case journal.PaymentApplied:
				err = errors.New(
					"payment reconciliation unexpectedly created a payment",
				)
			case "":
			default:
				err = errors.New(
					"payment reconciliation returned an unknown disposition",
				)
			}
		}
		if err != nil {
			report.Failed++
			report.Failures = append(
				report.Failures,
				PaymentReconciliationFailure{
					Scope: current.Scope,
					Error: boundedErrorMessage(err, 512),
				},
			)
		}
	}
	if err := c.requests.AdvancePaymentScanCursor(
		scan.Cursor, scan.NextCursor,
	); err != nil {
		return report, fmt.Errorf("advance payment reconciliation cursor: %w", err)
	}
	return report, nil
}

func (c *Core) applyVerifiedPaymentReconciliation(
	scope journal.Scope,
	verified payment.VerifiedReconciliation,
	now time.Time,
) (journal.PaymentRecord, journal.PaymentDisposition, error) {
	current, err := c.requests.GetPayment(scope, now)
	if err != nil {
		return journal.PaymentRecord{}, "", err
	}
	binding := paymentReconciliationBinding(current)
	material, err := verified.ApplicationMaterial(
		binding, current.ObservedMasterSeqno, now,
	)
	if err != nil {
		return journal.PaymentRecord{}, "", fmt.Errorf(
			"authorize payment reconciliation application: %w", err,
		)
	}
	switch material.Status {
	case payment.ReconciliationApplied:
		_, reconciled, disposition, err := c.requests.ApplyPayment(
			journal.PaymentAdmission{
				Scope: current.Scope, IntentDigest: binding.IntentDigest,
				AuthorizationID: binding.AuthorizationID,
				QuoteID:         binding.QuoteID, Reference: binding.Reference,
				Payer: binding.Payer, Payee: binding.Payee,
				AmountNanoTOS:         binding.AmountNanoTOS,
				QuoteEnvelopeDigest:   binding.QuoteEnvelopeDigest,
				PaymentEnvelopeDigest: binding.PaymentEnvelopeDigest,
				ObservedMasterSeqno:   material.ObservedMasterSeqno,
				ObservedAt:            material.ObservedAt,
			},
			now,
		)
		return reconciled, disposition, err
	case payment.ReconciliationReorganized:
		return c.requests.MarkPaymentReorganized(
			journal.PaymentReorganization{
				Scope:               current.Scope,
				AuthorizationID:     binding.AuthorizationID,
				QuoteID:             binding.QuoteID,
				Reference:           binding.Reference,
				ObservedMasterSeqno: material.ObservedMasterSeqno,
				ObservedAt:          material.ObservedAt,
			},
			now,
		)
	default:
		return journal.PaymentRecord{}, "", errors.New(
			"unsupported verified payment reconciliation status",
		)
	}
}

func paymentReconciliationBinding(
	record journal.PaymentRecord,
) payment.ReconciliationBinding {
	return payment.ReconciliationBinding{
		Network: record.Scope.Network, ServiceID: record.Scope.ServiceID,
		SessionID: record.Scope.SessionID, Operation: record.Scope.Operation,
		RequestID: record.Scope.RequestID, IntentDigest: record.IntentDigest,
		AuthorizationID: record.AuthorizationID, QuoteID: record.QuoteID,
		Reference: record.Reference, Payer: record.Payer, Payee: record.Payee,
		AmountNanoTOS:         record.AmountNanoTOS,
		QuoteEnvelopeDigest:   record.QuoteEnvelopeDigest,
		PaymentEnvelopeDigest: record.PaymentEnvelopeDigest,
	}
}

func boundedErrorMessage(err error, maximum int) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) <= maximum {
		return message
	}
	return strings.Clone(message[:maximum])
}

func receiptTerminalState(status string) (journal.State, string, error) {
	switch status {
	case "succeeded":
		return journal.StateSucceeded, "", nil
	case "failed":
		return journal.StateFailed, string(protocol.ErrorRuntimeFailed), nil
	case "canceled":
		return journal.StateCanceled, string(protocol.ErrorCanceled), nil
	case "timed_out":
		return journal.StateTimedOut, string(protocol.ErrorDeadlineExceeded), nil
	default:
		return "", "", errors.New("unsupported verified receipt status")
	}
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
		ReceiptRecords:   stats.Receipts,
		JournalFileBytes: stats.FileSize,
		LastCleanupAt:    c.lastCleanupAt, LastCleanupDeleted: c.lastDeleted,
		LastCleanupHasMore:               c.lastMore,
		LastCleanupSucceeded:             !c.lastCleanupAt.IsZero() && c.lastError == nil,
		LastPaymentReconciliationAt:      c.lastPaymentReconciliationAt,
		LastPaymentReconciliationScanned: c.lastPaymentReconciliationScanned,
		LastPaymentReconciliationFailed:  c.lastPaymentReconciliationFailed,
		LastPaymentReconciliationHasMore: c.lastPaymentReconciliationMore,
		LastPaymentReconciliationSucceeded: !c.lastPaymentReconciliationAt.IsZero() &&
			c.lastPaymentReconciliationError == nil &&
			c.lastPaymentReconciliationFailed == 0,
	}
	if c.lastError != nil {
		return output, fmt.Errorf("Edge Core request cleanup: %w", c.lastError)
	}
	if c.lastPaymentReconciliationError != nil {
		return output, fmt.Errorf(
			"Edge Core payment reconciliation: %w",
			c.lastPaymentReconciliationError,
		)
	}
	return output, nil
}

func (c *Core) lifecycleLoop(cleanupInterval time.Duration) {
	defer close(c.done)
	cleanupTicker := time.NewTicker(cleanupInterval)
	defer cleanupTicker.Stop()
	var reconciliationTicker *time.Ticker
	var reconciliationTicks <-chan time.Time
	if c.paymentObserver != nil {
		reconciliationTicker = time.NewTicker(c.paymentReconciliationInterval)
		reconciliationTicks = reconciliationTicker.C
		defer reconciliationTicker.Stop()
	}
	for {
		select {
		case <-cleanupTicker.C:
			_, _, _ = c.PruneNow()
		case <-reconciliationTicks:
			reconciliationContext, cancel := context.WithTimeout(
				c.runContext, c.paymentReconciliationTimeout,
			)
			report, err := c.ReconcilePaymentBatch(
				reconciliationContext,
				c.paymentObserver,
				c.paymentReconciliationBatch,
			)
			cancel()
			c.recordPaymentReconciliation(report, err)
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

func (c *Core) recordPaymentReconciliation(
	report PaymentReconciliationReport,
	err error,
) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.lastPaymentReconciliationAt = c.now().UTC()
	c.lastPaymentReconciliationScanned = report.Scanned
	c.lastPaymentReconciliationFailed = report.Failed
	c.lastPaymentReconciliationMore = report.HasMore
	c.lastPaymentReconciliationError = err
}

func validatePaymentReconciliationConfig(config CoreConfig) error {
	if config.PaymentObserver == nil {
		if config.PaymentReconciliationInterval != 0 ||
			config.PaymentReconciliationTimeout != 0 ||
			config.PaymentReconciliationBatch != 0 {
			return errors.New(
				"payment reconciliation settings require an observer",
			)
		}
		return nil
	}
	if config.PaymentReconciliationInterval < minReconciliationInterval ||
		config.PaymentReconciliationInterval > maxReconciliationInterval ||
		config.PaymentReconciliationTimeout < minReconciliationTimeout ||
		config.PaymentReconciliationTimeout > maxReconciliationTimeout ||
		config.PaymentReconciliationBatch <= 0 ||
		config.PaymentReconciliationBatch >
			config.RequestJournalLimits.MaxPrunePerWrite {
		return errors.New("invalid payment reconciliation configuration")
	}
	return nil
}
