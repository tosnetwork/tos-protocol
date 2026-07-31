package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultCleanupInterval    = 30 * time.Second
	minCleanupInterval        = 10 * time.Millisecond
	maxCleanupInterval        = time.Hour
	minReconciliationInterval = 10 * time.Millisecond
	maxReconciliationInterval = 24 * time.Hour
	minReconciliationTimeout  = 10 * time.Millisecond
	maxReconciliationTimeout  = 10 * time.Minute
	minReceiptLifetime        = time.Second
	maxReceiptLifetime        = 10 * time.Minute
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
	ExecutionRecords                   uint64
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

// CompletedInvocation contains only a defensively copied Worker output and
// the durable receipt/request state committed for it.
type CompletedInvocation struct {
	Output          []byte
	ModelRevision   string
	RuntimeRevision string
	Request         journal.Record
	Receipt         journal.ReceiptRecord
	Disposition     journal.ReceiptDisposition
}

type NonSuccessStatus string

const (
	InvocationFailed   NonSuccessStatus = "failed"
	InvocationCanceled NonSuccessStatus = "canceled"
	InvocationTimedOut NonSuccessStatus = "timed_out"
)

// TerminatedInvocation is the durable outcome of a failed, canceled, or
// timed-out paid request. Raw diagnostic text is intentionally excluded.
type TerminatedInvocation struct {
	Request     journal.Record
	Receipt     journal.ReceiptRecord
	Disposition journal.ReceiptDisposition
}

// ClaimedInvocation is the exact defensively cloned Worker request whose
// durable claim was committed with the paid request's running transition.
type ClaimedInvocation struct {
	Request     *edgev1.InvokeRequest
	State       journal.Record
	Execution   journal.ExecutionRecord
	Disposition journal.ExecutionDisposition
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

func (c *Core) Execution(scope journal.Scope) (journal.ExecutionRecord, error) {
	return c.requests.GetExecution(scope, c.now())
}

// ClaimPaidExecution validates an exact private Worker request against its
// opaque quote/payment authority and atomically binds its task and digest to
// the authorized-to-running transition. No Worker RPC is performed here.
func (c *Core) ClaimPaidExecution(
	scope journal.Scope,
	expectedRevision uint64,
	paymentAuthorization authorization.AuthorizedPayment,
	request *edgev1.InvokeRequest,
) (ClaimedInvocation, error) {
	if request == nil {
		return ClaimedInvocation{}, errors.New("nil Worker invocation request")
	}
	request = proto.Clone(request).(*edgev1.InvokeRequest)
	material, err := paymentAuthorization.ReceiptInvocationMaterial()
	if err != nil {
		return ClaimedInvocation{}, fmt.Errorf(
			"extract paid execution binding: %w",
			err,
		)
	}
	if scope.Network != material.Network ||
		scope.ServiceID != material.ServiceID ||
		scope.SessionID != material.SessionID ||
		scope.Operation != material.Operation ||
		scope.RequestID != material.RequestID ||
		request.RequestId != material.RequestID ||
		request.QuoteId != material.QuoteID ||
		request.ServiceId != material.ServiceID ||
		request.Operation != material.Operation {
		return ClaimedInvocation{}, errors.New(
			"Worker invocation does not match paid request",
		)
	}
	now := c.now().UTC()
	requestState, err := c.requests.Get(scope, now)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	if requestState.RetainUntil.After(
		now.Add(localrpc.MaximumWorkerTaskRetention),
	) {
		return ClaimedInvocation{}, errors.New(
			"request retention exceeds Worker protocol maximum",
		)
	}
	retainUntilUnixMillis := ceilUnixMillis(requestState.RetainUntil)
	if request.RetainUntilUnixMillis != 0 &&
		request.RetainUntilUnixMillis != retainUntilUnixMillis {
		return ClaimedInvocation{}, errors.New(
			"Worker invocation retention does not match request journal",
		)
	}
	request.RetainUntilUnixMillis = retainUntilUnixMillis
	request, requestDigest, err := localrpc.BindInvocationRequest(request)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	deadline := time.UnixMilli(request.DeadlineUnixMillis).UTC()
	if uint64(len(request.Payload)) > material.MaxInputBytes ||
		request.MaxOutputBytes == 0 ||
		request.MaxOutputBytes > material.MaxOutputBytes ||
		deadline.After(material.Deadline) {
		return ClaimedInvocation{}, errors.New(
			"Worker invocation expands quoted limits or deadline",
		)
	}
	state, execution, disposition, err := c.requests.ClaimExecution(
		journal.ExecutionAdmission{
			Scope: scope, IntentDigest: material.IntentDigest,
			AuthorizationID: material.AuthorizationID,
			QuoteID:         material.QuoteID, TaskID: request.TaskId,
			RequestDigest: requestDigest, Deadline: deadline,
		},
		expectedRevision,
		now,
	)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	return ClaimedInvocation{
		Request: request, State: state, Execution: execution,
		Disposition: disposition,
	}, nil
}

// CompleteSuccessfulInvocation is the only generic bridge from an opaque,
// validated private Worker result to a signed success receipt. It requires the
// exact request to remain paid and running, keeps receipt signing outside the
// Worker, and atomically applies the verified envelope through the journal.
func (c *Core) CompleteSuccessfulInvocation(
	ctx context.Context,
	scope journal.Scope,
	expectedRevision uint64,
	manifest *authorization.VerifiedManifest,
	paymentAuthorization authorization.AuthorizedPayment,
	invocation localrpc.ValidatedInvocation,
	signer authorization.ReceiptSigner,
	receiptID string,
	receiptLifetime time.Duration,
) (CompletedInvocation, error) {
	if ctx == nil {
		return CompletedInvocation{}, errors.New(
			"nil invocation completion context",
		)
	}
	if expectedRevision == 0 {
		return CompletedInvocation{}, errors.New(
			"expected revision must be positive",
		)
	}
	if receiptLifetime < minReceiptLifetime ||
		receiptLifetime > maxReceiptLifetime {
		return CompletedInvocation{}, errors.New(
			"invalid receipt envelope lifetime",
		)
	}
	material, err := paymentAuthorization.ReceiptInvocationMaterial()
	if err != nil {
		return CompletedInvocation{}, fmt.Errorf(
			"extract receipt invocation binding: %w",
			err,
		)
	}
	if scope.Network != material.Network ||
		scope.ServiceID != material.ServiceID ||
		scope.SessionID != material.SessionID ||
		scope.Operation != material.Operation ||
		scope.RequestID != material.RequestID {
		return CompletedInvocation{}, errors.New(
			"receipt invocation scope mismatch",
		)
	}
	completion, err := invocation.Completion(localrpc.InvocationBinding{
		RequestID: material.RequestID, QuoteID: material.QuoteID,
		ServiceID: material.ServiceID, Operation: material.Operation,
	})
	if err != nil {
		return CompletedInvocation{}, fmt.Errorf(
			"consume validated Worker invocation: %w",
			err,
		)
	}
	if completion.Usage.InputBytes > material.MaxInputBytes ||
		completion.Usage.OutputBytes > material.MaxOutputBytes ||
		completion.MaxOutputBytes > material.MaxOutputBytes ||
		completion.Deadline.After(material.Deadline) {
		return CompletedInvocation{}, errors.New(
			"Worker invocation expands quoted limits or deadline",
		)
	}
	now := c.now().UTC()
	if completion.CompletedAt.IsZero() ||
		completion.CompletedAt.After(now.Add(identity.MaxClockSkew)) {
		return CompletedInvocation{}, errors.New(
			"invalid Worker completion time",
		)
	}
	execution, err := c.requests.GetExecution(scope, now)
	if err != nil {
		return CompletedInvocation{}, err
	}
	if execution.IntentDigest != material.IntentDigest ||
		execution.AuthorizationID != material.AuthorizationID ||
		execution.QuoteID != material.QuoteID ||
		execution.TaskID != completion.TaskID ||
		execution.RequestDigest != completion.RequestDigest ||
		!execution.Deadline.Equal(completion.Deadline) {
		return CompletedInvocation{}, journal.ErrConflict
	}
	usage := completionReceiptUsage(completion.Usage)
	resultDigest := digestInvocationOutput(completion.Output)

	if existing, lookupErr := c.requests.GetReceipt(scope, now); lookupErr == nil {
		return c.replayCompletedInvocation(
			scope,
			existing,
			material,
			receiptID,
			usage,
			resultDigest,
			completion,
			now,
		)
	} else if !errors.Is(lookupErr, journal.ErrNotFound) {
		return CompletedInvocation{}, lookupErr
	}

	request, err := c.requests.Get(scope, now)
	if err != nil {
		return CompletedInvocation{}, err
	}
	if request.IntentDigest != material.IntentDigest {
		return CompletedInvocation{}, journal.ErrConflict
	}
	if request.Revision != expectedRevision {
		return CompletedInvocation{}, journal.ErrRevision
	}
	if request.State != journal.StateRunning {
		return CompletedInvocation{}, journal.ErrTransition
	}
	appliedPayment, err := c.requests.GetPayment(scope, now)
	if err != nil {
		return CompletedInvocation{}, err
	}
	if appliedPayment.AuthorizationID != material.AuthorizationID ||
		appliedPayment.QuoteID != material.QuoteID ||
		appliedPayment.IntentDigest != material.IntentDigest {
		return CompletedInvocation{}, journal.ErrConflict
	}
	if appliedPayment.Status == journal.PaymentStatusReorganized {
		return CompletedInvocation{}, journal.ErrPaymentReorganized
	}
	if appliedPayment.Status != journal.PaymentStatusApplied ||
		appliedPayment.AmountNanoTOS < material.PriceNanoTOS {
		return CompletedInvocation{}, errors.New(
			"receipt request has insufficient applied payment",
		)
	}
	verified, err := manifest.IssueReceipt(
		ctx,
		paymentAuthorization,
		authorization.ReceiptDraft{
			ReceiptID: receiptID, Status: "succeeded",
			Usage: usage, ChargedNanoTOS: material.PriceNanoTOS,
			ResultDigest: resultDigest, CompletedAt: completion.CompletedAt,
		},
		signer,
		now,
		now.Add(receiptLifetime),
	)
	if err != nil {
		return CompletedInvocation{}, fmt.Errorf("issue receipt: %w", err)
	}
	terminal, receipt, disposition, err := c.ApplyVerifiedReceipt(
		scope,
		expectedRevision,
		verified,
	)
	if err != nil {
		if errors.Is(err, journal.ErrConflict) ||
			errors.Is(err, journal.ErrRevision) ||
			errors.Is(err, journal.ErrTransition) {
			existing, lookupErr := c.requests.GetReceipt(scope, now)
			if lookupErr == nil {
				return c.replayCompletedInvocation(
					scope,
					existing,
					material,
					receiptID,
					usage,
					resultDigest,
					completion,
					now,
				)
			}
		}
		return CompletedInvocation{}, err
	}
	return CompletedInvocation{
		Output:          append([]byte(nil), completion.Output...),
		ModelRevision:   completion.ModelRevision,
		RuntimeRevision: completion.RuntimeRevision,
		Request:         terminal, Receipt: receipt, Disposition: disposition,
	}, nil
}

// CompleteInvocationFailure signs and atomically persists a zero-charge,
// no-result receipt for a paid request that failed, was canceled, or timed
// out. It is valid both before dispatch (authorized) and after dispatch
// (running), but never accepts caller-supplied diagnostic text or usage.
func (c *Core) CompleteInvocationFailure(
	ctx context.Context,
	scope journal.Scope,
	expectedRevision uint64,
	manifest *authorization.VerifiedManifest,
	paymentAuthorization authorization.AuthorizedPayment,
	signer authorization.ReceiptSigner,
	receiptID string,
	status NonSuccessStatus,
	receiptLifetime time.Duration,
) (TerminatedInvocation, error) {
	if ctx == nil {
		return TerminatedInvocation{}, errors.New(
			"nil invocation failure context",
		)
	}
	if expectedRevision == 0 {
		return TerminatedInvocation{}, errors.New(
			"expected revision must be positive",
		)
	}
	if receiptLifetime < minReceiptLifetime ||
		receiptLifetime > maxReceiptLifetime {
		return TerminatedInvocation{}, errors.New(
			"invalid receipt envelope lifetime",
		)
	}
	terminalState, errorCode, err := receiptTerminalState(string(status))
	if err != nil || terminalState == journal.StateSucceeded {
		return TerminatedInvocation{}, errors.New(
			"unsupported invocation failure status",
		)
	}
	material, err := paymentAuthorization.ReceiptInvocationMaterial()
	if err != nil {
		return TerminatedInvocation{}, fmt.Errorf(
			"extract receipt invocation binding: %w",
			err,
		)
	}
	if scope.Network != material.Network ||
		scope.ServiceID != material.ServiceID ||
		scope.SessionID != material.SessionID ||
		scope.Operation != material.Operation ||
		scope.RequestID != material.RequestID {
		return TerminatedInvocation{}, errors.New(
			"receipt invocation scope mismatch",
		)
	}
	now := c.now().UTC()
	if existing, lookupErr := c.requests.GetReceipt(scope, now); lookupErr == nil {
		return c.replayFailedInvocation(
			scope,
			existing,
			material,
			receiptID,
			terminalState,
			errorCode,
			now,
		)
	} else if !errors.Is(lookupErr, journal.ErrNotFound) {
		return TerminatedInvocation{}, lookupErr
	}
	if status == InvocationTimedOut && now.Before(material.Deadline) {
		return TerminatedInvocation{}, errors.New(
			"invocation deadline has not elapsed",
		)
	}
	request, err := c.requests.Get(scope, now)
	if err != nil {
		return TerminatedInvocation{}, err
	}
	if request.IntentDigest != material.IntentDigest {
		return TerminatedInvocation{}, journal.ErrConflict
	}
	if request.Revision != expectedRevision {
		return TerminatedInvocation{}, journal.ErrRevision
	}
	if request.State != journal.StateAuthorized &&
		request.State != journal.StateRunning {
		return TerminatedInvocation{}, journal.ErrTransition
	}
	if request.State == journal.StateRunning {
		execution, executionErr := c.requests.GetExecution(scope, now)
		if executionErr != nil {
			return TerminatedInvocation{}, executionErr
		}
		if execution.IntentDigest != material.IntentDigest ||
			execution.AuthorizationID != material.AuthorizationID ||
			execution.QuoteID != material.QuoteID {
			return TerminatedInvocation{}, journal.ErrConflict
		}
	}
	appliedPayment, err := c.requests.GetPayment(scope, now)
	if err != nil {
		return TerminatedInvocation{}, err
	}
	if appliedPayment.AuthorizationID != material.AuthorizationID ||
		appliedPayment.QuoteID != material.QuoteID ||
		appliedPayment.IntentDigest != material.IntentDigest {
		return TerminatedInvocation{}, journal.ErrConflict
	}
	if appliedPayment.Status == journal.PaymentStatusReorganized {
		return TerminatedInvocation{}, journal.ErrPaymentReorganized
	}
	if appliedPayment.Status != journal.PaymentStatusApplied {
		return TerminatedInvocation{}, errors.New(
			"receipt request has no applied payment",
		)
	}
	completedAt := now
	if status == InvocationTimedOut && material.Deadline.Before(completedAt) {
		completedAt = material.Deadline
	}
	verified, err := manifest.IssueReceipt(
		ctx,
		paymentAuthorization,
		authorization.ReceiptDraft{
			ReceiptID: receiptID, Status: string(status),
			Usage: []protocol.UsageItem{}, ChargedNanoTOS: 0,
			CompletedAt: completedAt,
		},
		signer,
		now,
		now.Add(receiptLifetime),
	)
	if err != nil {
		return TerminatedInvocation{}, fmt.Errorf("issue receipt: %w", err)
	}
	terminal, receipt, disposition, err := c.ApplyVerifiedReceipt(
		scope,
		expectedRevision,
		verified,
	)
	if err != nil {
		if errors.Is(err, journal.ErrConflict) ||
			errors.Is(err, journal.ErrRevision) ||
			errors.Is(err, journal.ErrTransition) {
			existing, lookupErr := c.requests.GetReceipt(scope, now)
			if lookupErr == nil {
				return c.replayFailedInvocation(
					scope,
					existing,
					material,
					receiptID,
					terminalState,
					errorCode,
					now,
				)
			}
		}
		return TerminatedInvocation{}, err
	}
	return TerminatedInvocation{
		Request: terminal, Receipt: receipt, Disposition: disposition,
	}, nil
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

func (c *Core) replayCompletedInvocation(
	scope journal.Scope,
	receipt journal.ReceiptRecord,
	material authorization.ReceiptInvocationMaterial,
	receiptID string,
	usage []protocol.UsageItem,
	resultDigest string,
	completion localrpc.InvocationCompletion,
	now time.Time,
) (CompletedInvocation, error) {
	if !sameSuccessfulCompletionReceipt(
		receipt,
		scope,
		material,
		receiptID,
		usage,
		resultDigest,
		completion.CompletedAt,
	) {
		return CompletedInvocation{}, journal.ErrConflict
	}
	request, err := c.requests.Get(scope, now)
	if err != nil {
		return CompletedInvocation{}, err
	}
	if request.State != journal.StateSucceeded ||
		request.ResultDigest != resultDigest ||
		request.ErrorCode != "" {
		return CompletedInvocation{}, fmt.Errorf(
			"%w: stored completion does not match request",
			journal.ErrCorrupt,
		)
	}
	return CompletedInvocation{
		Output:          append([]byte(nil), completion.Output...),
		ModelRevision:   completion.ModelRevision,
		RuntimeRevision: completion.RuntimeRevision,
		Request:         request, Receipt: receipt,
		Disposition: journal.ReceiptReplay,
	}, nil
}

func sameSuccessfulCompletionReceipt(
	receipt journal.ReceiptRecord,
	scope journal.Scope,
	material authorization.ReceiptInvocationMaterial,
	receiptID string,
	usage []protocol.UsageItem,
	resultDigest string,
	completedAt time.Time,
) bool {
	if receipt.Scope != scope ||
		receipt.IntentDigest != material.IntentDigest ||
		receipt.ReceiptID != receiptID ||
		receipt.AuthorizationID != material.AuthorizationID ||
		receipt.QuoteID != material.QuoteID ||
		receipt.Status != journal.StateSucceeded ||
		receipt.ChargedNanoTOS != material.PriceNanoTOS ||
		receipt.ResultDigest != resultDigest ||
		receipt.ErrorCode != "" ||
		receipt.ServiceRevision != material.ServiceRevision ||
		receipt.ResourceRevision != material.ResourceRevision ||
		!receipt.CompletedAt.Equal(completedAt.UTC()) ||
		len(receipt.Usage) != len(usage) {
		return false
	}
	for index, item := range usage {
		if receipt.Usage[index].Unit != item.Unit ||
			receipt.Usage[index].Quantity != item.Quantity {
			return false
		}
	}
	return true
}

func (c *Core) replayFailedInvocation(
	scope journal.Scope,
	receipt journal.ReceiptRecord,
	material authorization.ReceiptInvocationMaterial,
	receiptID string,
	terminalState journal.State,
	errorCode string,
	now time.Time,
) (TerminatedInvocation, error) {
	if receipt.Scope != scope ||
		receipt.IntentDigest != material.IntentDigest ||
		receipt.ReceiptID != receiptID ||
		receipt.AuthorizationID != material.AuthorizationID ||
		receipt.QuoteID != material.QuoteID ||
		receipt.Status != terminalState ||
		receipt.ChargedNanoTOS != 0 ||
		receipt.ResultDigest != "" ||
		receipt.ErrorCode != errorCode ||
		receipt.ServiceRevision != material.ServiceRevision ||
		receipt.ResourceRevision != material.ResourceRevision ||
		len(receipt.Usage) != 0 {
		return TerminatedInvocation{}, journal.ErrConflict
	}
	request, err := c.requests.Get(scope, now)
	if err != nil {
		return TerminatedInvocation{}, err
	}
	if request.State != terminalState ||
		request.ResultDigest != "" ||
		request.ErrorCode != errorCode {
		return TerminatedInvocation{}, fmt.Errorf(
			"%w: stored failure receipt does not match request",
			journal.ErrCorrupt,
		)
	}
	return TerminatedInvocation{
		Request: request, Receipt: receipt,
		Disposition: journal.ReceiptReplay,
	}, nil
}

func completionReceiptUsage(
	usage localrpc.InvocationUsage,
) []protocol.UsageItem {
	return []protocol.UsageItem{
		{Unit: "input_bytes", Quantity: usage.InputBytes},
		{Unit: "output_bytes", Quantity: usage.OutputBytes},
		{Unit: "input_tokens", Quantity: usage.InputTokens},
		{Unit: "output_tokens", Quantity: usage.OutputTokens},
		{Unit: "execution_millis", Quantity: usage.ExecutionMillis},
	}
}

func digestInvocationOutput(output []byte) string {
	digest := sha256.Sum256(output)
	return "sha256:" + hex.EncodeToString(digest[:])
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
		ReceiptRecords: stats.Receipts, ExecutionRecords: stats.Executions,
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

func ceilUnixMillis(value time.Time) int64 {
	millis := value.UnixMilli()
	if time.UnixMilli(millis).Before(value) {
		millis++
	}
	return millis
}
