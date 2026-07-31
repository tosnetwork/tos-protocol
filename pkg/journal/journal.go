// Package journal provides the durable, bounded request state owned by Edge
// Core. It does not authorize a request or execute a vertical operation.
package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	bolt "go.etcd.io/bbolt"
)

const (
	DefaultMaxRecords       = 100_000
	DefaultMaxNonces        = 200_000
	DefaultMaxBudgets       = 600_000
	DefaultMaxRecordBytes   = 32 << 10
	DefaultMaxRetention     = 48 * time.Hour
	DefaultMaxPrunePerWrite = 1_024

	maxConfiguredRecords     = 10_000_000
	maxConfiguredBudgets     = 60_000_000
	maxConfiguredRecordBytes = 1 << 20
	maxConfiguredRetention   = 365 * 24 * time.Hour
	maxAdmissionBudgets      = 6
	maxPaymentClockSkew      = 2 * time.Minute
	expiryPrefixBytes        = 12
	expiryKeyBytes           = expiryPrefixBytes + sha256.Size
)

var (
	ErrConflict           = errors.New("request ID is already bound to different intent")
	ErrCapacity           = errors.New("request journal is at capacity")
	ErrNotFound           = errors.New("request journal record not found")
	ErrExpired            = errors.New("request journal record expired")
	ErrRevision           = errors.New("request journal revision mismatch")
	ErrTransition         = errors.New("illegal request journal transition")
	ErrNonceReplay        = errors.New("signed envelope nonce was already used")
	ErrBudgetLimit        = errors.New("session or delegation budget exhausted")
	ErrPaymentReplay      = errors.New("payment authorization is already bound to another request")
	ErrPaymentReorganized = errors.New("applied payment was reorganized")
	ErrPaymentRollback    = errors.New("payment observation regressed below its high-water mark")
	ErrCorrupt            = errors.New("request journal is corrupt")

	recordsBucket         = []byte("records-v1")
	expiryBucket          = []byte("expiry-v1")
	metaBucket            = []byte("meta-v1")
	countKey              = []byte("record-count")
	expiryMarker          = []byte{1}
	noncesBucket          = []byte("nonces-v1")
	nonceExpiryBucket     = []byte("nonce-expiry-v1")
	nonceCountKey         = []byte("nonce-count")
	budgetsBucket         = []byte("budgets-v1")
	budgetExpiryBucket    = []byte("budget-expiry-v1")
	budgetClaimsBucket    = []byte("budget-claims-v1")
	budgetCountKey        = []byte("budget-count")
	paymentsBucket        = []byte("payments-v1")
	requestPaymentsBucket = []byte("request-payments-v1")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{2,127}$`)
	domainPattern = regexp.MustCompile(`^tos\.[a-z0-9.-]+$`)
)

type Limits struct {
	MaxRecords       uint64
	MaxNonces        uint64
	MaxBudgets       uint64
	MaxRecordBytes   int
	MaxRetention     time.Duration
	MaxPrunePerWrite int
	OpenTimeout      time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxRecords:       DefaultMaxRecords,
		MaxNonces:        DefaultMaxNonces,
		MaxBudgets:       DefaultMaxBudgets,
		MaxRecordBytes:   DefaultMaxRecordBytes,
		MaxRetention:     DefaultMaxRetention,
		MaxPrunePerWrite: DefaultMaxPrunePerWrite,
		OpenTimeout:      2 * time.Second,
	}
}

type Scope struct {
	Network   string `json:"network"`
	Authority string `json:"authority"`
	ServiceID string `json:"serviceId"`
	SessionID string `json:"sessionId"`
	Operation string `json:"operation"`
	RequestID string `json:"requestId"`
}

type State string

const (
	StatePending    State = "pending"
	StateAuthorized State = "authorized"
	StateRunning    State = "running"
	StateSucceeded  State = "succeeded"
	StateRejected   State = "rejected"
	StateFailed     State = "failed"
	StateCanceled   State = "canceled"
	StateTimedOut   State = "timed_out"
)

func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateRejected, StateFailed, StateCanceled, StateTimedOut:
		return true
	default:
		return false
	}
}

type Record struct {
	Version      string    `json:"version"`
	Scope        Scope     `json:"scope"`
	IntentDigest string    `json:"intentDigest"`
	State        State     `json:"state"`
	Revision     uint64    `json:"revision"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	RetainUntil  time.Time `json:"retainUntil"`
	ResultDigest string    `json:"resultDigest,omitempty"`
	ErrorCode    string    `json:"errorCode,omitempty"`
}

// Admission binds an already verified signed envelope to one idempotent
// request. Signature, manifest role, and revocation checks happen before this
// local state operation.
type Admission struct {
	Scope             Scope
	IntentDigest      string
	EnvelopeDigest    string
	Domain            string
	Nonce             string
	EnvelopeExpiresAt time.Time
	RetainUntil       time.Time
}

// UsageBudget is one cumulative session or delegation authority limit.
type UsageBudget struct {
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	GrantDigest string `json:"grantDigest"`
	MaxActions  uint64 `json:"maxActions"`
	MaxNanoTOS  uint64 `json:"maxNanoTos"`
}

// SessionAdmission extends a verified envelope admission with every
// cumulative authority budget in its session/delegation chain.
type SessionAdmission struct {
	Admission
	ClientID         string
	SessionExpiresAt time.Time
	ChargeNanoTOS    uint64
	Budgets          []UsageBudget
}

type BudgetUsage struct {
	Version     string    `json:"version"`
	Network     string    `json:"network"`
	ServiceID   string    `json:"serviceId"`
	SessionID   string    `json:"sessionId"`
	ClientID    string    `json:"clientId"`
	Kind        string    `json:"kind"`
	ID          string    `json:"id"`
	GrantDigest string    `json:"grantDigest"`
	MaxActions  uint64    `json:"maxActions"`
	MaxNanoTOS  uint64    `json:"maxNanoTos"`
	UsedActions uint64    `json:"usedActions"`
	UsedNanoTOS uint64    `json:"usedNanoTos"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	RetainUntil time.Time `json:"retainUntil"`
}

type BudgetClaim struct {
	Version       string        `json:"version"`
	Network       string        `json:"network"`
	ServiceID     string        `json:"serviceId"`
	SessionID     string        `json:"sessionId"`
	RequestID     string        `json:"requestId"`
	ClientID      string        `json:"clientId"`
	ChargeNanoTOS uint64        `json:"chargeNanoTos"`
	Budgets       []UsageBudget `json:"budgets"`
	RetainUntil   time.Time     `json:"retainUntil"`
}

type NonceClaim struct {
	Version        string    `json:"version"`
	Network        string    `json:"network"`
	Authority      string    `json:"authority"`
	ServiceID      string    `json:"serviceId"`
	SessionID      string    `json:"sessionId"`
	Operation      string    `json:"operation"`
	RequestID      string    `json:"requestId"`
	Domain         string    `json:"domain"`
	Nonce          string    `json:"nonce"`
	EnvelopeDigest string    `json:"envelopeDigest"`
	ClaimedAt      time.Time `json:"claimedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type PaymentStatus string

const (
	PaymentStatusApplied     PaymentStatus = "applied"
	PaymentStatusReorganized PaymentStatus = "reorganized"
)

// PaymentAdmission is material from a fresh opaque chain observation. The
// request must already exist in pending state with the same intent.
type PaymentAdmission struct {
	Scope                 Scope
	IntentDigest          string
	AuthorizationID       string
	QuoteID               string
	Reference             string
	Payer                 string
	Payee                 string
	AmountNanoTOS         uint64
	QuoteEnvelopeDigest   string
	PaymentEnvelopeDigest string
	ObservedMasterSeqno   uint64
	ObservedAt            time.Time
}

type PaymentReorganization struct {
	Scope               Scope
	AuthorizationID     string
	QuoteID             string
	Reference           string
	ObservedMasterSeqno uint64
	ObservedAt          time.Time
}

type PaymentRecord struct {
	Version               string        `json:"version"`
	Scope                 Scope         `json:"scope"`
	IntentDigest          string        `json:"intentDigest"`
	AuthorizationID       string        `json:"authorizationId"`
	QuoteID               string        `json:"quoteId"`
	Reference             string        `json:"reference"`
	Payer                 string        `json:"payer"`
	Payee                 string        `json:"payee"`
	AmountNanoTOS         uint64        `json:"amountNanoTos"`
	QuoteEnvelopeDigest   string        `json:"quoteEnvelopeDigest"`
	PaymentEnvelopeDigest string        `json:"paymentEnvelopeDigest"`
	Status                PaymentStatus `json:"status"`
	Revision              uint64        `json:"revision"`
	ObservedMasterSeqno   uint64        `json:"observedMasterSeqno"`
	ObservedAt            time.Time     `json:"observedAt"`
	AppliedAt             time.Time     `json:"appliedAt"`
	ReorganizedAt         time.Time     `json:"reorganizedAt,omitempty"`
	RetainUntil           time.Time     `json:"retainUntil"`
}

type BeginDisposition string

const (
	BeginCreated BeginDisposition = "created"
	BeginReplay  BeginDisposition = "replay"
)

type PaymentDisposition string

const (
	PaymentApplied     PaymentDisposition = "applied"
	PaymentReplay      PaymentDisposition = "replay"
	PaymentRefreshed   PaymentDisposition = "refreshed"
	PaymentReorganized PaymentDisposition = "reorganized"
)

type nonceDisposition uint8

const (
	nonceCreated nonceDisposition = iota + 1
	nonceReplay
)

type Stats struct {
	Records      uint64
	Nonces       uint64
	BudgetUsages uint64
	Payments     uint64
	FileSize     int64
}

type Store struct {
	db        *bolt.DB
	path      string
	limits    Limits
	closeOnce sync.Once
}

func Open(path string, limits Limits) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("request journal path must be absolute")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: limits.OpenTimeout})
	if err != nil {
		return nil, fmt.Errorf("open request journal: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict request journal permissions: %w", err)
	}
	store := &Store{db: db, path: path, limits: limits}
	if err := db.Update(store.initialize); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize request journal: %w", err)
	}
	return store, nil
}

func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.db.Close()
	})
	return err
}

func (s *Store) Begin(
	scope Scope,
	intentDigest string,
	now, retainUntil time.Time,
) (Record, BeginDisposition, error) {
	if err := scope.Validate(); err != nil {
		return Record{}, "", err
	}
	if !digestPattern.MatchString(intentDigest) {
		return Record{}, "", errors.New("intent digest must be sha256:<lowercase hex>")
	}
	now, retainUntil, err := s.validateWindow(now, retainUntil)
	if err != nil {
		return Record{}, "", err
	}
	key := scopeKey(scope)
	var output Record
	var disposition BeginDisposition
	err = s.db.Update(func(transaction *bolt.Tx) error {
		if _, _, err := s.pruneExpiredTx(transaction, now, s.limits.MaxPrunePerWrite); err != nil {
			return err
		}
		var beginErr error
		output, disposition, beginErr = s.beginTx(
			transaction, key, scope, intentDigest, now, retainUntil,
		)
		return beginErr
	})
	if err != nil {
		return Record{}, "", err
	}
	return output, disposition, nil
}

// Admit atomically claims a verified envelope nonce and creates or replays its
// idempotent request record.
func (s *Store) Admit(
	admission Admission,
	now time.Time,
) (Record, BeginDisposition, error) {
	now, err := admission.validate(s.limits, now)
	if err != nil {
		return Record{}, "", err
	}
	requestKey := scopeKey(admission.Scope)
	claim := NonceClaim{
		Version: "1", Network: admission.Scope.Network,
		Authority: admission.Scope.Authority, ServiceID: admission.Scope.ServiceID,
		SessionID: admission.Scope.SessionID, Operation: admission.Scope.Operation,
		RequestID: admission.Scope.RequestID, Domain: admission.Domain,
		Nonce: admission.Nonce, EnvelopeDigest: admission.EnvelopeDigest,
		ClaimedAt: now,
		ExpiresAt: admission.EnvelopeExpiresAt.UTC(),
	}
	var output Record
	var disposition BeginDisposition
	err = s.db.Update(func(transaction *bolt.Tx) error {
		if _, _, pruneErr := s.pruneExpiredTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		if _, _, pruneErr := s.pruneNoncesTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		nonceDisposition, claimErr := s.claimNonceTx(transaction, claim, now)
		if claimErr != nil {
			return claimErr
		}
		var beginErr error
		output, disposition, beginErr = s.beginTx(
			transaction, requestKey, admission.Scope, admission.IntentDigest,
			now, admission.RetainUntil.UTC(),
		)
		if beginErr != nil {
			return beginErr
		}
		if transaction.Bucket(budgetClaimsBucket).Get(requestKey[:]) != nil {
			return ErrConflict
		}
		if nonceDisposition == nonceReplay && disposition == BeginCreated {
			return ErrNonceReplay
		}
		return nil
	})
	if err != nil {
		return Record{}, "", err
	}
	return output, disposition, nil
}

// AdmitSession atomically claims the verified envelope nonce, creates or
// replays the request, and consumes every cumulative session/delegation
// budget. Exact request replay does not consume the budgets again.
func (s *Store) AdmitSession(
	admission SessionAdmission,
	now time.Time,
) (Record, BeginDisposition, error) {
	now, err := admission.validate(s.limits, now)
	if err != nil {
		return Record{}, "", err
	}
	requestKey := scopeKey(admission.Scope)
	claim := NonceClaim{
		Version: "1", Network: admission.Scope.Network,
		Authority: admission.Scope.Authority, ServiceID: admission.Scope.ServiceID,
		SessionID: admission.Scope.SessionID, Operation: admission.Scope.Operation,
		RequestID: admission.Scope.RequestID, Domain: admission.Domain,
		Nonce: admission.Nonce, EnvelopeDigest: admission.EnvelopeDigest,
		ClaimedAt: now, ExpiresAt: admission.EnvelopeExpiresAt.UTC(),
	}
	budgetClaim := BudgetClaim{
		Version: "1", Network: admission.Scope.Network,
		ServiceID: admission.Scope.ServiceID, SessionID: admission.Scope.SessionID,
		RequestID: admission.Scope.RequestID, ClientID: admission.ClientID,
		ChargeNanoTOS: admission.ChargeNanoTOS,
		Budgets:       append([]UsageBudget(nil), admission.Budgets...),
		RetainUntil:   admission.SessionExpiresAt.UTC(),
	}
	var output Record
	var disposition BeginDisposition
	err = s.db.Update(func(transaction *bolt.Tx) error {
		if _, _, pruneErr := s.pruneExpiredTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		if _, _, pruneErr := s.pruneNoncesTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		if _, _, pruneErr := s.pruneBudgetsTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		nonceDisposition, claimErr := s.claimNonceTx(transaction, claim, now)
		if claimErr != nil {
			return claimErr
		}
		var beginErr error
		output, disposition, beginErr = s.beginTx(
			transaction, requestKey, admission.Scope, admission.IntentDigest,
			now, admission.RetainUntil.UTC(),
		)
		if beginErr != nil {
			return beginErr
		}
		if nonceDisposition == nonceReplay && disposition == BeginCreated {
			return ErrNonceReplay
		}
		switch disposition {
		case BeginCreated:
			if transaction.Bucket(budgetClaimsBucket).Get(requestKey[:]) != nil {
				return fmt.Errorf("%w: stale request budget claim", ErrCorrupt)
			}
			for _, budget := range admission.Budgets {
				if err := s.consumeBudgetTx(
					transaction, admission, budget, now,
				); err != nil {
					return err
				}
			}
			encoded, err := s.encodeBudgetClaim(budgetClaim)
			if err != nil {
				return err
			}
			return transaction.Bucket(budgetClaimsBucket).Put(requestKey[:], encoded)
		case BeginReplay:
			encoded := transaction.Bucket(budgetClaimsBucket).Get(requestKey[:])
			if encoded == nil {
				return ErrConflict
			}
			existing, err := s.decodeBudgetClaim(encoded)
			if err != nil {
				return err
			}
			if !sameBudgetClaim(existing, budgetClaim) {
				return ErrConflict
			}
			return nil
		default:
			return fmt.Errorf("%w: invalid begin disposition", ErrCorrupt)
		}
	})
	if err != nil {
		return Record{}, "", err
	}
	return output, disposition, nil
}

// ClaimNonce records a verified envelope nonce without creating a request.
// Exact duplicate claims are rejected; callers that need idempotent request
// replay use Admit instead.
func (s *Store) ClaimNonce(claim NonceClaim, now time.Time) error {
	if err := validateNow(now); err != nil {
		return err
	}
	now = now.UTC()
	claim.Version = "1"
	claim.ClaimedAt = now
	claim.ExpiresAt = claim.ExpiresAt.UTC()
	if err := claim.validate(s.limits, now); err != nil {
		return err
	}
	return s.db.Update(func(transaction *bolt.Tx) error {
		if _, _, pruneErr := s.pruneNoncesTx(
			transaction, now, s.limits.MaxPrunePerWrite,
		); pruneErr != nil {
			return pruneErr
		}
		disposition, claimErr := s.claimNonceTx(transaction, claim, now)
		if claimErr != nil {
			return claimErr
		}
		if disposition == nonceReplay {
			return ErrNonceReplay
		}
		return nil
	})
}

func (s *Store) Get(scope Scope, now time.Time) (Record, error) {
	if err := scope.Validate(); err != nil {
		return Record{}, err
	}
	if err := validateNow(now); err != nil {
		return Record{}, err
	}
	key := scopeKey(scope)
	var output Record
	err := s.db.View(func(transaction *bolt.Tx) error {
		encoded := transaction.Bucket(recordsBucket).Get(key[:])
		if encoded == nil {
			return ErrNotFound
		}
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return err
		}
		if record.Scope != scope {
			return fmt.Errorf("%w: request key collision", ErrCorrupt)
		}
		if !record.RetainUntil.After(now.UTC()) {
			return ErrExpired
		}
		output = record
		return nil
	})
	return output, err
}

// ApplyPayment binds one globally unique payment authorization to one pending
// request and transitions that request to authorized in the same transaction.
// Exact replay never advances the request revision a second time.
func (s *Store) ApplyPayment(
	admission PaymentAdmission,
	now time.Time,
) (Record, PaymentRecord, PaymentDisposition, error) {
	now, err := admission.validate(now)
	if err != nil {
		return Record{}, PaymentRecord{}, "", err
	}
	requestKey := scopeKey(admission.Scope)
	paymentKeyValue := paymentKey(
		admission.Scope.Network,
		admission.AuthorizationID,
		admission.Reference,
	)
	var output Record
	var paymentOutput PaymentRecord
	var disposition PaymentDisposition
	err = s.db.Update(func(transaction *bolt.Tx) error {
		records := transaction.Bucket(recordsBucket)
		encodedRequest := records.Get(requestKey[:])
		if encodedRequest == nil {
			return ErrNotFound
		}
		record, err := s.decodeRecord(encodedRequest)
		if err != nil {
			return err
		}
		if record.Scope != admission.Scope {
			return fmt.Errorf("%w: request key collision", ErrCorrupt)
		}
		if !record.RetainUntil.After(now) {
			return ErrExpired
		}
		if record.IntentDigest != admission.IntentDigest {
			return ErrConflict
		}

		payments := transaction.Bucket(paymentsBucket)
		requestPayments := transaction.Bucket(requestPaymentsBucket)
		indexedPaymentKey := requestPayments.Get(requestKey[:])
		if encodedPayment := payments.Get(paymentKeyValue[:]); encodedPayment != nil {
			existing, err := s.decodePayment(encodedPayment)
			if err != nil {
				return err
			}
			if !samePaymentBinding(existing, admission) {
				if existing.Scope != admission.Scope {
					return ErrPaymentReplay
				}
				return ErrConflict
			}
			if len(indexedPaymentKey) != sha256.Size ||
				!bytes.Equal(indexedPaymentKey, paymentKeyValue[:]) {
				return fmt.Errorf("%w: missing or mismatched request payment index", ErrCorrupt)
			}
			if record.State == StatePending {
				return fmt.Errorf("%w: applied payment has pending request", ErrCorrupt)
			}
			if existing.Status == PaymentStatusReorganized {
				return ErrPaymentReorganized
			}
			if admission.ObservedMasterSeqno < existing.ObservedMasterSeqno {
				return ErrPaymentRollback
			}
			if admission.ObservedMasterSeqno == existing.ObservedMasterSeqno {
				if !admission.ObservedAt.Equal(existing.ObservedAt) {
					return ErrConflict
				}
				output, paymentOutput, disposition = record, existing, PaymentReplay
				return nil
			}
			if admission.ObservedAt.Before(existing.ObservedAt) {
				return ErrPaymentRollback
			}
			existing.ObservedMasterSeqno = admission.ObservedMasterSeqno
			existing.ObservedAt = admission.ObservedAt.UTC()
			existing.Revision++
			updated, err := s.encodePayment(existing)
			if err != nil {
				return err
			}
			if err := payments.Put(paymentKeyValue[:], updated); err != nil {
				return err
			}
			output, paymentOutput, disposition = record, existing, PaymentRefreshed
			return nil
		}
		if indexedPaymentKey != nil {
			return fmt.Errorf("%w: request payment index references missing payment", ErrCorrupt)
		}
		if record.State != StatePending {
			return ErrTransition
		}
		payment := PaymentRecord{
			Version: "1", Scope: admission.Scope,
			IntentDigest:    admission.IntentDigest,
			AuthorizationID: admission.AuthorizationID,
			QuoteID:         admission.QuoteID, Reference: admission.Reference,
			Payer: admission.Payer, Payee: admission.Payee,
			AmountNanoTOS:         admission.AmountNanoTOS,
			QuoteEnvelopeDigest:   admission.QuoteEnvelopeDigest,
			PaymentEnvelopeDigest: admission.PaymentEnvelopeDigest,
			Status:                PaymentStatusApplied, Revision: 1,
			ObservedMasterSeqno: admission.ObservedMasterSeqno,
			ObservedAt:          admission.ObservedAt.UTC(),
			AppliedAt:           now, RetainUntil: record.RetainUntil,
		}
		encodedPayment, err := s.encodePayment(payment)
		if err != nil {
			return err
		}
		if err := payments.Put(paymentKeyValue[:], encodedPayment); err != nil {
			return err
		}
		if err := requestPayments.Put(requestKey[:], paymentKeyValue[:]); err != nil {
			return err
		}
		record.State = StateAuthorized
		record.Revision++
		if now.After(record.UpdatedAt) {
			record.UpdatedAt = now
		}
		encodedRequest, err = s.encodeRecord(record)
		if err != nil {
			return err
		}
		if err := records.Put(requestKey[:], encodedRequest); err != nil {
			return err
		}
		output, paymentOutput, disposition = record, payment, PaymentApplied
		return nil
	})
	if err != nil {
		return Record{}, PaymentRecord{}, "", err
	}
	return output, paymentOutput, disposition, nil
}

func (s *Store) GetPayment(
	scope Scope,
	now time.Time,
) (PaymentRecord, error) {
	if err := scope.Validate(); err != nil {
		return PaymentRecord{}, err
	}
	if err := validateNow(now); err != nil {
		return PaymentRecord{}, err
	}
	requestKey := scopeKey(scope)
	var output PaymentRecord
	err := s.db.View(func(transaction *bolt.Tx) error {
		paymentKeyBytes := transaction.Bucket(requestPaymentsBucket).Get(requestKey[:])
		if paymentKeyBytes == nil {
			return ErrNotFound
		}
		if len(paymentKeyBytes) != sha256.Size {
			return fmt.Errorf("%w: invalid request payment index", ErrCorrupt)
		}
		encoded := transaction.Bucket(paymentsBucket).Get(paymentKeyBytes)
		if encoded == nil {
			return fmt.Errorf("%w: request payment is missing", ErrCorrupt)
		}
		payment, err := s.decodePayment(encoded)
		if err != nil {
			return err
		}
		if payment.Scope != scope {
			return fmt.Errorf("%w: request payment scope mismatch", ErrCorrupt)
		}
		if !payment.RetainUntil.After(now.UTC()) {
			return ErrExpired
		}
		output = payment
		return nil
	})
	return output, err
}

// MarkPaymentReorganized records a verified chain reorganization. It does not
// guess refund or completion policy, but subsequent paid dispatch is blocked.
func (s *Store) MarkPaymentReorganized(
	reorganization PaymentReorganization,
	now time.Time,
) (PaymentRecord, PaymentDisposition, error) {
	now, err := reorganization.validate(now)
	if err != nil {
		return PaymentRecord{}, "", err
	}
	requestKey := scopeKey(reorganization.Scope)
	paymentKeyValue := paymentKey(
		reorganization.Scope.Network,
		reorganization.AuthorizationID,
		reorganization.Reference,
	)
	var output PaymentRecord
	var disposition PaymentDisposition
	err = s.db.Update(func(transaction *bolt.Tx) error {
		indexedPaymentKey := transaction.Bucket(requestPaymentsBucket).Get(requestKey[:])
		if len(indexedPaymentKey) != sha256.Size ||
			!bytes.Equal(indexedPaymentKey, paymentKeyValue[:]) {
			return ErrNotFound
		}
		payments := transaction.Bucket(paymentsBucket)
		encoded := payments.Get(paymentKeyValue[:])
		if encoded == nil {
			return fmt.Errorf("%w: indexed payment is missing", ErrCorrupt)
		}
		payment, err := s.decodePayment(encoded)
		if err != nil {
			return err
		}
		if payment.Scope != reorganization.Scope ||
			payment.AuthorizationID != reorganization.AuthorizationID ||
			payment.QuoteID != reorganization.QuoteID ||
			payment.Reference != reorganization.Reference {
			return ErrConflict
		}
		if !payment.RetainUntil.After(now) {
			return ErrExpired
		}
		if reorganization.ObservedMasterSeqno < payment.ObservedMasterSeqno ||
			reorganization.ObservedAt.Before(payment.ObservedAt) {
			return ErrPaymentRollback
		}
		if payment.Status == PaymentStatusReorganized {
			if reorganization.ObservedMasterSeqno == payment.ObservedMasterSeqno &&
				reorganization.ObservedAt.Equal(payment.ObservedAt) {
				output, disposition = payment, PaymentReplay
				return nil
			}
			payment.ObservedMasterSeqno = reorganization.ObservedMasterSeqno
			payment.ObservedAt = reorganization.ObservedAt.UTC()
			payment.Revision++
			disposition = PaymentRefreshed
		} else {
			payment.Status = PaymentStatusReorganized
			payment.ObservedMasterSeqno = reorganization.ObservedMasterSeqno
			payment.ObservedAt = reorganization.ObservedAt.UTC()
			payment.ReorganizedAt = now
			payment.Revision++
			disposition = PaymentReorganized
		}
		updated, err := s.encodePayment(payment)
		if err != nil {
			return err
		}
		if err := payments.Put(paymentKeyValue[:], updated); err != nil {
			return err
		}
		output = payment
		return nil
	})
	if err != nil {
		return PaymentRecord{}, "", err
	}
	return output, disposition, nil
}

func (s *Store) Transition(
	scope Scope,
	expectedRevision uint64,
	next State,
	resultDigest, errorCode string,
	now time.Time,
) (Record, error) {
	if err := scope.Validate(); err != nil {
		return Record{}, err
	}
	if expectedRevision == 0 {
		return Record{}, errors.New("expected revision must be positive")
	}
	if err := validateNow(now); err != nil {
		return Record{}, err
	}
	if err := validateOutcome(next, resultDigest, errorCode); err != nil {
		return Record{}, err
	}
	now = now.UTC()
	key := scopeKey(scope)
	var output Record
	err := s.db.Update(func(transaction *bolt.Tx) error {
		records := transaction.Bucket(recordsBucket)
		encoded := records.Get(key[:])
		if encoded == nil {
			return ErrNotFound
		}
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return err
		}
		if record.Scope != scope {
			return fmt.Errorf("%w: request key collision", ErrCorrupt)
		}
		if !record.RetainUntil.After(now) {
			return ErrExpired
		}
		if record.Revision != expectedRevision {
			return ErrRevision
		}
		if !canTransition(record.State, next) {
			return ErrTransition
		}
		if record.State == StateAuthorized && next == StateRunning {
			if err := s.ensurePaymentRunnableTx(transaction, key); err != nil {
				return err
			}
		}
		record.State = next
		record.Revision++
		if now.After(record.UpdatedAt) {
			record.UpdatedAt = now
		}
		record.ResultDigest = resultDigest
		record.ErrorCode = errorCode
		encoded, err = s.encodeRecord(record)
		if err != nil {
			return err
		}
		if err := records.Put(key[:], encoded); err != nil {
			return err
		}
		output = record
		return nil
	})
	return output, err
}

func (s *Store) ensurePaymentRunnableTx(
	transaction *bolt.Tx,
	requestKey [32]byte,
) error {
	paymentKeyBytes := transaction.Bucket(requestPaymentsBucket).Get(requestKey[:])
	if paymentKeyBytes == nil {
		return nil
	}
	if len(paymentKeyBytes) != sha256.Size {
		return fmt.Errorf("%w: invalid request payment index", ErrCorrupt)
	}
	encoded := transaction.Bucket(paymentsBucket).Get(paymentKeyBytes)
	if encoded == nil {
		return fmt.Errorf("%w: request payment is missing", ErrCorrupt)
	}
	payment, err := s.decodePayment(encoded)
	if err != nil {
		return err
	}
	if payment.Status == PaymentStatusReorganized {
		return ErrPaymentReorganized
	}
	if payment.Status != PaymentStatusApplied {
		return fmt.Errorf("%w: invalid request payment status", ErrCorrupt)
	}
	return nil
}

func (s *Store) beginTx(
	transaction *bolt.Tx,
	key [32]byte,
	scope Scope,
	intentDigest string,
	now, retainUntil time.Time,
) (Record, BeginDisposition, error) {
	records := transaction.Bucket(recordsBucket)
	if encoded := records.Get(key[:]); encoded != nil {
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return Record{}, "", err
		}
		if record.Scope != scope {
			return Record{}, "", fmt.Errorf("%w: request key collision", ErrCorrupt)
		}
		if !record.RetainUntil.After(now) {
			expiries := transaction.Bucket(expiryBucket)
			recordExpiryKey := expiryKey(record.RetainUntil, key)
			if !bytes.Equal(expiries.Get(recordExpiryKey), expiryMarker) {
				return Record{}, "", fmt.Errorf("%w: missing expiry index", ErrCorrupt)
			}
			if err := expiries.Delete(recordExpiryKey); err != nil {
				return Record{}, "", err
			}
			if err := records.Delete(key[:]); err != nil {
				return Record{}, "", err
			}
			if err := s.deletePaymentForRequestTx(transaction, key); err != nil {
				return Record{}, "", err
			}
			if err := transaction.Bucket(budgetClaimsBucket).Delete(key[:]); err != nil {
				return Record{}, "", err
			}
			count, err := readCount(transaction)
			if err != nil {
				return Record{}, "", err
			}
			if count == 0 {
				return Record{}, "", fmt.Errorf("%w: record count underflow", ErrCorrupt)
			}
			if err := writeCount(transaction, count-1); err != nil {
				return Record{}, "", err
			}
		} else {
			if record.IntentDigest != intentDigest {
				return Record{}, "", ErrConflict
			}
			return record, BeginReplay, nil
		}
	}
	count, err := readCount(transaction)
	if err != nil {
		return Record{}, "", err
	}
	if count >= s.limits.MaxRecords {
		return Record{}, "", ErrCapacity
	}
	record := Record{
		Version: "1", Scope: scope, IntentDigest: intentDigest,
		State: StatePending, Revision: 1,
		CreatedAt: now, UpdatedAt: now, RetainUntil: retainUntil,
	}
	encoded, err := s.encodeRecord(record)
	if err != nil {
		return Record{}, "", err
	}
	if err := records.Put(key[:], encoded); err != nil {
		return Record{}, "", err
	}
	if err := transaction.Bucket(expiryBucket).Put(
		expiryKey(retainUntil, key), expiryMarker,
	); err != nil {
		return Record{}, "", err
	}
	if err := writeCount(transaction, count+1); err != nil {
		return Record{}, "", err
	}
	return record, BeginCreated, nil
}

func (s *Store) deletePaymentForRequestTx(
	transaction *bolt.Tx,
	requestKey [32]byte,
) error {
	requestPayments := transaction.Bucket(requestPaymentsBucket)
	paymentKeyBytes := requestPayments.Get(requestKey[:])
	if paymentKeyBytes == nil {
		return nil
	}
	if len(paymentKeyBytes) != sha256.Size {
		return fmt.Errorf("%w: invalid request payment index", ErrCorrupt)
	}
	payments := transaction.Bucket(paymentsBucket)
	encoded := payments.Get(paymentKeyBytes)
	if encoded == nil {
		return fmt.Errorf("%w: request payment index references missing payment", ErrCorrupt)
	}
	payment, err := s.decodePayment(encoded)
	if err != nil {
		return err
	}
	if scopeKey(payment.Scope) != requestKey {
		return fmt.Errorf("%w: request payment index scope mismatch", ErrCorrupt)
	}
	if err := payments.Delete(paymentKeyBytes); err != nil {
		return err
	}
	return requestPayments.Delete(requestKey[:])
}

func (s *Store) claimNonceTx(
	transaction *bolt.Tx,
	claim NonceClaim,
	now time.Time,
) (nonceDisposition, error) {
	key := nonceKey(claim)
	nonces := transaction.Bucket(noncesBucket)
	if encoded := nonces.Get(key[:]); encoded != nil {
		existing, err := s.decodeNonce(encoded)
		if err != nil {
			return 0, err
		}
		if !sameNonceKey(existing, claim) {
			return 0, fmt.Errorf("%w: nonce key collision", ErrCorrupt)
		}
		if !existing.ExpiresAt.After(now) {
			expiries := transaction.Bucket(nonceExpiryBucket)
			existingExpiryKey := expiryKey(existing.ExpiresAt, key)
			if !bytes.Equal(expiries.Get(existingExpiryKey), expiryMarker) {
				return 0, fmt.Errorf("%w: missing nonce expiry index", ErrCorrupt)
			}
			if err := expiries.Delete(existingExpiryKey); err != nil {
				return 0, err
			}
			if err := nonces.Delete(key[:]); err != nil {
				return 0, err
			}
			count, err := readNonceCount(transaction)
			if err != nil {
				return 0, err
			}
			if count == 0 {
				return 0, fmt.Errorf("%w: nonce count underflow", ErrCorrupt)
			}
			if err := writeNonceCount(transaction, count-1); err != nil {
				return 0, err
			}
		} else {
			if !sameNonceBinding(existing, claim) {
				return 0, ErrNonceReplay
			}
			return nonceReplay, nil
		}
	}
	count, err := readNonceCount(transaction)
	if err != nil {
		return 0, err
	}
	if count >= s.limits.MaxNonces {
		return 0, ErrCapacity
	}
	encoded, err := s.encodeNonce(claim)
	if err != nil {
		return 0, err
	}
	if err := nonces.Put(key[:], encoded); err != nil {
		return 0, err
	}
	if err := transaction.Bucket(nonceExpiryBucket).Put(
		expiryKey(claim.ExpiresAt, key), expiryMarker,
	); err != nil {
		return 0, err
	}
	if err := writeNonceCount(transaction, count+1); err != nil {
		return 0, err
	}
	return nonceCreated, nil
}

func (s *Store) consumeBudgetTx(
	transaction *bolt.Tx,
	admission SessionAdmission,
	budget UsageBudget,
	now time.Time,
) error {
	key := budgetKey(
		admission.Scope.Network, admission.Scope.ServiceID,
		admission.Scope.SessionID, budget.Kind, budget.ID,
	)
	budgets := transaction.Bucket(budgetsBucket)
	if encoded := budgets.Get(key[:]); encoded != nil {
		usage, err := s.decodeBudgetUsage(encoded)
		if err != nil {
			return err
		}
		if !sameBudgetAuthority(usage, admission, budget) {
			return ErrConflict
		}
		if usage.UsedActions >= usage.MaxActions ||
			admission.ChargeNanoTOS > usage.MaxNanoTOS-usage.UsedNanoTOS {
			return ErrBudgetLimit
		}
		usage.UsedActions++
		usage.UsedNanoTOS += admission.ChargeNanoTOS
		if now.After(usage.UpdatedAt) {
			usage.UpdatedAt = now
		}
		updated, err := s.encodeBudgetUsage(usage)
		if err != nil {
			return err
		}
		return budgets.Put(key[:], updated)
	}
	count, err := readBudgetCount(transaction)
	if err != nil {
		return err
	}
	if count >= s.limits.MaxBudgets {
		return ErrCapacity
	}
	if admission.ChargeNanoTOS > budget.MaxNanoTOS {
		return ErrBudgetLimit
	}
	usage := BudgetUsage{
		Version: "1", Network: admission.Scope.Network,
		ServiceID: admission.Scope.ServiceID, SessionID: admission.Scope.SessionID,
		ClientID: admission.ClientID, Kind: budget.Kind, ID: budget.ID,
		GrantDigest: budget.GrantDigest,
		MaxActions:  budget.MaxActions, MaxNanoTOS: budget.MaxNanoTOS,
		UsedActions: 1, UsedNanoTOS: admission.ChargeNanoTOS,
		CreatedAt: now, UpdatedAt: now,
		RetainUntil: admission.SessionExpiresAt.UTC(),
	}
	encoded, err := s.encodeBudgetUsage(usage)
	if err != nil {
		return err
	}
	if err := budgets.Put(key[:], encoded); err != nil {
		return err
	}
	if err := transaction.Bucket(budgetExpiryBucket).Put(
		expiryKey(usage.RetainUntil, key), expiryMarker,
	); err != nil {
		return err
	}
	return writeBudgetCount(transaction, count+1)
}

// PruneExpired removes at most maxDelete records. more reports whether the
// oldest remaining expiry is already due, allowing a caller to continue in
// bounded batches.
func (s *Store) PruneExpired(now time.Time, maxDelete int) (deleted int, more bool, err error) {
	if err := validateNow(now); err != nil {
		return 0, false, err
	}
	if maxDelete <= 0 || maxDelete > s.limits.MaxPrunePerWrite {
		return 0, false, errors.New("prune batch exceeds configured limit")
	}
	err = s.db.Update(func(transaction *bolt.Tx) error {
		var pruneErr error
		deleted, more, pruneErr = s.pruneExpiredTx(transaction, now.UTC(), maxDelete)
		return pruneErr
	})
	return deleted, more, err
}

func (s *Store) PruneNonces(now time.Time, maxDelete int) (deleted int, more bool, err error) {
	if err := validateNow(now); err != nil {
		return 0, false, err
	}
	if maxDelete <= 0 || maxDelete > s.limits.MaxPrunePerWrite {
		return 0, false, errors.New("nonce prune batch exceeds configured limit")
	}
	err = s.db.Update(func(transaction *bolt.Tx) error {
		var pruneErr error
		deleted, more, pruneErr = s.pruneNoncesTx(transaction, now.UTC(), maxDelete)
		return pruneErr
	})
	return deleted, more, err
}

func (s *Store) PruneBudgets(now time.Time, maxDelete int) (deleted int, more bool, err error) {
	if err := validateNow(now); err != nil {
		return 0, false, err
	}
	if maxDelete <= 0 || maxDelete > s.limits.MaxPrunePerWrite {
		return 0, false, errors.New("budget prune batch exceeds configured limit")
	}
	err = s.db.Update(func(transaction *bolt.Tx) error {
		var pruneErr error
		deleted, more, pruneErr = s.pruneBudgetsTx(
			transaction, now.UTC(), maxDelete,
		)
		return pruneErr
	})
	return deleted, more, err
}

func (s *Store) Stats() (Stats, error) {
	var output Stats
	err := s.db.View(func(transaction *bolt.Tx) error {
		count, err := readCount(transaction)
		if err != nil {
			return err
		}
		output.Records = count
		nonceCount, err := readNonceCount(transaction)
		if err != nil {
			return err
		}
		output.Nonces = nonceCount
		budgetCount, err := readBudgetCount(transaction)
		if err != nil {
			return err
		}
		output.BudgetUsages = budgetCount
		output.Payments = uint64(transaction.Bucket(paymentsBucket).Stats().KeyN)
		return nil
	})
	if err != nil {
		return Stats{}, err
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return Stats{}, err
	}
	output.FileSize = info.Size()
	return output, nil
}

func (s *Store) initialize(transaction *bolt.Tx) error {
	records, err := transaction.CreateBucketIfNotExists(recordsBucket)
	if err != nil {
		return err
	}
	expiries, err := transaction.CreateBucketIfNotExists(expiryBucket)
	if err != nil {
		return err
	}
	nonces, err := transaction.CreateBucketIfNotExists(noncesBucket)
	if err != nil {
		return err
	}
	nonceExpiries, err := transaction.CreateBucketIfNotExists(nonceExpiryBucket)
	if err != nil {
		return err
	}
	budgets, err := transaction.CreateBucketIfNotExists(budgetsBucket)
	if err != nil {
		return err
	}
	budgetExpiries, err := transaction.CreateBucketIfNotExists(budgetExpiryBucket)
	if err != nil {
		return err
	}
	if _, err := transaction.CreateBucketIfNotExists(budgetClaimsBucket); err != nil {
		return err
	}
	payments, err := transaction.CreateBucketIfNotExists(paymentsBucket)
	if err != nil {
		return err
	}
	requestPayments, err := transaction.CreateBucketIfNotExists(requestPaymentsBucket)
	if err != nil {
		return err
	}
	meta, err := transaction.CreateBucketIfNotExists(metaBucket)
	if err != nil {
		return err
	}
	if err := initializeCount(meta, countKey, uint64(records.Stats().KeyN), "record"); err != nil {
		return err
	}
	if expiries.Stats().KeyN != records.Stats().KeyN {
		return fmt.Errorf("%w: expiry index count mismatch", ErrCorrupt)
	}
	if err := initializeCount(meta, nonceCountKey, uint64(nonces.Stats().KeyN), "nonce"); err != nil {
		return err
	}
	if nonceExpiries.Stats().KeyN != nonces.Stats().KeyN {
		return fmt.Errorf("%w: nonce expiry index count mismatch", ErrCorrupt)
	}
	if err := initializeCount(meta, budgetCountKey, uint64(budgets.Stats().KeyN), "budget"); err != nil {
		return err
	}
	if budgetExpiries.Stats().KeyN != budgets.Stats().KeyN {
		return fmt.Errorf("%w: budget expiry index count mismatch", ErrCorrupt)
	}
	if payments.Stats().KeyN != requestPayments.Stats().KeyN ||
		payments.Stats().KeyN > records.Stats().KeyN {
		return fmt.Errorf("%w: payment index count mismatch", ErrCorrupt)
	}
	return nil
}

func (s *Store) pruneExpiredTx(
	transaction *bolt.Tx,
	now time.Time,
	maxDelete int,
) (deleted int, more bool, err error) {
	records := transaction.Bucket(recordsBucket)
	expiries := transaction.Bucket(expiryBucket)
	cursor := expiries.Cursor()
	cutoff := expiryPrefix(now)
	for key, marker := cursor.First(); key != nil; key, marker = cursor.Next() {
		if len(key) != expiryKeyBytes {
			return deleted, false, fmt.Errorf("%w: invalid expiry key", ErrCorrupt)
		}
		if !bytes.Equal(marker, expiryMarker) {
			return deleted, false, fmt.Errorf("%w: invalid expiry marker", ErrCorrupt)
		}
		if bytes.Compare(key[:expiryPrefixBytes], cutoff[:]) > 0 {
			break
		}
		if deleted >= maxDelete {
			more = true
			break
		}
		recordKey := key[expiryPrefixBytes:]
		encoded := records.Get(recordKey)
		if encoded == nil {
			return deleted, false, fmt.Errorf("%w: expiry references missing record", ErrCorrupt)
		}
		record, err := s.decodeRecord(encoded)
		if err != nil {
			return deleted, false, err
		}
		expectedKey := expiryKey(record.RetainUntil, array32(recordKey))
		if !bytes.Equal(expectedKey, key) || record.RetainUntil.After(now) {
			return deleted, false, fmt.Errorf("%w: expiry index mismatch", ErrCorrupt)
		}
		if err := records.Delete(recordKey); err != nil {
			return deleted, false, err
		}
		if err := s.deletePaymentForRequestTx(
			transaction, array32(recordKey),
		); err != nil {
			return deleted, false, err
		}
		if err := transaction.Bucket(budgetClaimsBucket).Delete(recordKey); err != nil {
			return deleted, false, err
		}
		if err := cursor.Delete(); err != nil {
			return deleted, false, err
		}
		deleted++
	}
	if deleted != 0 {
		count, err := readCount(transaction)
		if err != nil {
			return deleted, false, err
		}
		if uint64(deleted) > count {
			return deleted, false, fmt.Errorf("%w: record count underflow", ErrCorrupt)
		}
		if err := writeCount(transaction, count-uint64(deleted)); err != nil {
			return deleted, false, err
		}
	}
	return deleted, more, nil
}

func (s *Store) pruneNoncesTx(
	transaction *bolt.Tx,
	now time.Time,
	maxDelete int,
) (deleted int, more bool, err error) {
	nonces := transaction.Bucket(noncesBucket)
	expiries := transaction.Bucket(nonceExpiryBucket)
	cursor := expiries.Cursor()
	cutoff := expiryPrefix(now)
	for key, marker := cursor.First(); key != nil; key, marker = cursor.Next() {
		if len(key) != expiryKeyBytes {
			return deleted, false, fmt.Errorf("%w: invalid nonce expiry key", ErrCorrupt)
		}
		if !bytes.Equal(marker, expiryMarker) {
			return deleted, false, fmt.Errorf("%w: invalid nonce expiry marker", ErrCorrupt)
		}
		if bytes.Compare(key[:expiryPrefixBytes], cutoff[:]) > 0 {
			break
		}
		if deleted >= maxDelete {
			more = true
			break
		}
		nonceKeyBytes := key[expiryPrefixBytes:]
		encoded := nonces.Get(nonceKeyBytes)
		if encoded == nil {
			return deleted, false, fmt.Errorf("%w: expiry references missing nonce", ErrCorrupt)
		}
		claim, err := s.decodeNonce(encoded)
		if err != nil {
			return deleted, false, err
		}
		expectedKey := expiryKey(claim.ExpiresAt, array32(nonceKeyBytes))
		if !bytes.Equal(expectedKey, key) || claim.ExpiresAt.After(now) {
			return deleted, false, fmt.Errorf("%w: nonce expiry index mismatch", ErrCorrupt)
		}
		if err := nonces.Delete(nonceKeyBytes); err != nil {
			return deleted, false, err
		}
		if err := cursor.Delete(); err != nil {
			return deleted, false, err
		}
		deleted++
	}
	if deleted != 0 {
		count, err := readNonceCount(transaction)
		if err != nil {
			return deleted, false, err
		}
		if uint64(deleted) > count {
			return deleted, false, fmt.Errorf("%w: nonce count underflow", ErrCorrupt)
		}
		if err := writeNonceCount(transaction, count-uint64(deleted)); err != nil {
			return deleted, false, err
		}
	}
	return deleted, more, nil
}

func (s *Store) pruneBudgetsTx(
	transaction *bolt.Tx,
	now time.Time,
	maxDelete int,
) (deleted int, more bool, err error) {
	budgets := transaction.Bucket(budgetsBucket)
	expiries := transaction.Bucket(budgetExpiryBucket)
	cursor := expiries.Cursor()
	cutoff := expiryPrefix(now)
	for key, marker := cursor.First(); key != nil; key, marker = cursor.Next() {
		if len(key) != expiryKeyBytes {
			return deleted, false, fmt.Errorf("%w: invalid budget expiry key", ErrCorrupt)
		}
		if !bytes.Equal(marker, expiryMarker) {
			return deleted, false, fmt.Errorf("%w: invalid budget expiry marker", ErrCorrupt)
		}
		if bytes.Compare(key[:expiryPrefixBytes], cutoff[:]) > 0 {
			break
		}
		if deleted >= maxDelete {
			more = true
			break
		}
		budgetKeyBytes := key[expiryPrefixBytes:]
		encoded := budgets.Get(budgetKeyBytes)
		if encoded == nil {
			return deleted, false, fmt.Errorf("%w: expiry references missing budget", ErrCorrupt)
		}
		usage, err := s.decodeBudgetUsage(encoded)
		if err != nil {
			return deleted, false, err
		}
		expectedKey := expiryKey(usage.RetainUntil, array32(budgetKeyBytes))
		if !bytes.Equal(expectedKey, key) || usage.RetainUntil.After(now) {
			return deleted, false, fmt.Errorf("%w: budget expiry index mismatch", ErrCorrupt)
		}
		if err := budgets.Delete(budgetKeyBytes); err != nil {
			return deleted, false, err
		}
		if err := cursor.Delete(); err != nil {
			return deleted, false, err
		}
		deleted++
	}
	if deleted != 0 {
		count, err := readBudgetCount(transaction)
		if err != nil {
			return deleted, false, err
		}
		if uint64(deleted) > count {
			return deleted, false, fmt.Errorf("%w: budget count underflow", ErrCorrupt)
		}
		if err := writeBudgetCount(transaction, count-uint64(deleted)); err != nil {
			return deleted, false, err
		}
	}
	return deleted, more, nil
}

func (s *Store) encodeRecord(record Record) ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if record.RetainUntil.Sub(record.CreatedAt) > s.limits.MaxRetention {
		return nil, fmt.Errorf("%w: record retention exceeds configured limit", ErrCorrupt)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(encoded) > s.limits.MaxRecordBytes {
		return nil, errors.New("request journal record exceeds byte limit")
	}
	return encoded, nil
}

func (s *Store) decodeRecord(encoded []byte) (Record, error) {
	if len(encoded) == 0 || len(encoded) > s.limits.MaxRecordBytes {
		return Record{}, fmt.Errorf("%w: invalid record size", ErrCorrupt)
	}
	var record Record
	if err := jsonstrict.Decode(encoded, &record); err != nil {
		return Record{}, fmt.Errorf("%w: decode record: %v", ErrCorrupt, err)
	}
	if err := record.validate(); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if record.RetainUntil.Sub(record.CreatedAt) > s.limits.MaxRetention {
		return Record{}, fmt.Errorf("%w: record retention exceeds configured limit", ErrCorrupt)
	}
	return record, nil
}

func (s *Store) encodeNonce(claim NonceClaim) ([]byte, error) {
	if err := claim.validateStored(s.limits); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	encoded, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	if len(encoded) > s.limits.MaxRecordBytes {
		return nil, errors.New("nonce claim exceeds byte limit")
	}
	return encoded, nil
}

func (s *Store) decodeNonce(encoded []byte) (NonceClaim, error) {
	if len(encoded) == 0 || len(encoded) > s.limits.MaxRecordBytes {
		return NonceClaim{}, fmt.Errorf("%w: invalid nonce claim size", ErrCorrupt)
	}
	var claim NonceClaim
	if err := jsonstrict.Decode(encoded, &claim); err != nil {
		return NonceClaim{}, fmt.Errorf("%w: decode nonce claim: %v", ErrCorrupt, err)
	}
	if err := claim.validateStored(s.limits); err != nil {
		return NonceClaim{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return claim, nil
}

func (s *Store) encodeBudgetUsage(usage BudgetUsage) ([]byte, error) {
	if err := usage.validateStored(s.limits); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	encoded, err := json.Marshal(usage)
	if err != nil {
		return nil, err
	}
	if len(encoded) > s.limits.MaxRecordBytes {
		return nil, errors.New("budget usage exceeds byte limit")
	}
	return encoded, nil
}

func (s *Store) decodeBudgetUsage(encoded []byte) (BudgetUsage, error) {
	if len(encoded) == 0 || len(encoded) > s.limits.MaxRecordBytes {
		return BudgetUsage{}, fmt.Errorf("%w: invalid budget usage size", ErrCorrupt)
	}
	var usage BudgetUsage
	if err := jsonstrict.Decode(encoded, &usage); err != nil {
		return BudgetUsage{}, fmt.Errorf("%w: decode budget usage: %v", ErrCorrupt, err)
	}
	if err := usage.validateStored(s.limits); err != nil {
		return BudgetUsage{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return usage, nil
}

func (s *Store) encodeBudgetClaim(claim BudgetClaim) ([]byte, error) {
	if err := claim.validateStored(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	encoded, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	if len(encoded) > s.limits.MaxRecordBytes {
		return nil, errors.New("budget claim exceeds byte limit")
	}
	return encoded, nil
}

func (s *Store) decodeBudgetClaim(encoded []byte) (BudgetClaim, error) {
	if len(encoded) == 0 || len(encoded) > s.limits.MaxRecordBytes {
		return BudgetClaim{}, fmt.Errorf("%w: invalid budget claim size", ErrCorrupt)
	}
	var claim BudgetClaim
	if err := jsonstrict.Decode(encoded, &claim); err != nil {
		return BudgetClaim{}, fmt.Errorf("%w: decode budget claim: %v", ErrCorrupt, err)
	}
	if err := claim.validateStored(); err != nil {
		return BudgetClaim{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return claim, nil
}

func (s *Store) encodePayment(payment PaymentRecord) ([]byte, error) {
	if err := payment.validateStored(s.limits); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	encoded, err := json.Marshal(payment)
	if err != nil {
		return nil, err
	}
	if len(encoded) > s.limits.MaxRecordBytes {
		return nil, errors.New("payment record exceeds byte limit")
	}
	return encoded, nil
}

func (s *Store) decodePayment(encoded []byte) (PaymentRecord, error) {
	if len(encoded) == 0 || len(encoded) > s.limits.MaxRecordBytes {
		return PaymentRecord{}, fmt.Errorf("%w: invalid payment record size", ErrCorrupt)
	}
	var payment PaymentRecord
	if err := jsonstrict.Decode(encoded, &payment); err != nil {
		return PaymentRecord{}, fmt.Errorf("%w: decode payment record: %v", ErrCorrupt, err)
	}
	if err := payment.validateStored(s.limits); err != nil {
		return PaymentRecord{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return payment, nil
}

func (l Limits) validate() error {
	if l.MaxRecords == 0 || l.MaxRecords > maxConfiguredRecords ||
		l.MaxNonces == 0 || l.MaxNonces > maxConfiguredRecords ||
		l.MaxBudgets == 0 || l.MaxBudgets > maxConfiguredBudgets ||
		l.MaxRecordBytes < 1_024 || l.MaxRecordBytes > maxConfiguredRecordBytes ||
		l.MaxRetention <= 0 || l.MaxRetention > maxConfiguredRetention ||
		l.MaxPrunePerWrite <= 0 || uint64(l.MaxPrunePerWrite) > l.MaxRecords ||
		l.OpenTimeout <= 0 || l.OpenTimeout > time.Minute {
		return errors.New("invalid request journal limits")
	}
	return nil
}

func (a Admission) validate(limits Limits, now time.Time) (time.Time, error) {
	if err := validateNow(now); err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	if err := a.Scope.Validate(); err != nil {
		return time.Time{}, err
	}
	if !digestPattern.MatchString(a.IntentDigest) {
		return time.Time{}, errors.New("intent digest must be sha256:<lowercase hex>")
	}
	if !digestPattern.MatchString(a.EnvelopeDigest) {
		return time.Time{}, errors.New("envelope digest must be sha256:<lowercase hex>")
	}
	if err := validateDomainAndNonce(a.Domain, a.Nonce); err != nil {
		return time.Time{}, err
	}
	expiresAt := a.EnvelopeExpiresAt.UTC()
	retainUntil := a.RetainUntil.UTC()
	if !expiresAt.After(now) || expiresAt.Sub(now) > limits.MaxRetention {
		return time.Time{}, errors.New("invalid envelope nonce retention window")
	}
	if retainUntil.Before(expiresAt) || !retainUntil.After(now) ||
		retainUntil.Sub(now) > limits.MaxRetention {
		return time.Time{}, errors.New("request retention must cover the envelope nonce")
	}
	return now, nil
}

func (a SessionAdmission) validate(limits Limits, now time.Time) (time.Time, error) {
	now, err := a.Admission.validate(limits, now)
	if err != nil {
		return time.Time{}, err
	}
	if err := bounded("client ID", a.ClientID, 1, 512); err != nil {
		return time.Time{}, err
	}
	sessionExpiresAt := a.SessionExpiresAt.UTC()
	if !sessionExpiresAt.After(now) ||
		sessionExpiresAt.Sub(now) > limits.MaxRetention ||
		a.RetainUntil.UTC().Before(sessionExpiresAt) {
		return time.Time{}, errors.New("request retention must cover the session budget")
	}
	if len(a.Budgets) == 0 || len(a.Budgets) > maxAdmissionBudgets {
		return time.Time{}, errors.New("session admission budgets are not bounded")
	}
	seen := make(map[string]struct{}, len(a.Budgets))
	for index, budget := range a.Budgets {
		if err := budget.validate(); err != nil {
			return time.Time{}, fmt.Errorf("budgets[%d]: %w", index, err)
		}
		if index == 0 && (budget.Kind != "session" || budget.ID != a.Scope.SessionID) {
			return time.Time{}, errors.New("first admission budget must bind the session")
		}
		key := budget.Kind + "\x00" + budget.ID
		if _, duplicate := seen[key]; duplicate {
			return time.Time{}, errors.New("duplicate session admission budget")
		}
		seen[key] = struct{}{}
		if a.ChargeNanoTOS > budget.MaxNanoTOS {
			return time.Time{}, ErrBudgetLimit
		}
	}
	return now, nil
}

func (a PaymentAdmission) validate(now time.Time) (time.Time, error) {
	if err := validateNow(now); err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	if err := validatePaymentBinding(
		a.Scope, a.IntentDigest, a.AuthorizationID, a.QuoteID,
		a.Reference, a.Payer, a.Payee, a.QuoteEnvelopeDigest,
		a.PaymentEnvelopeDigest, a.ObservedMasterSeqno, a.ObservedAt,
	); err != nil {
		return time.Time{}, err
	}
	if a.ObservedAt.UTC().After(now.Add(maxPaymentClockSkew)) {
		return time.Time{}, errors.New("payment observation is excessively future-dated")
	}
	return now, nil
}

func (r PaymentReorganization) validate(now time.Time) (time.Time, error) {
	if err := validateNow(now); err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	if err := r.Scope.Validate(); err != nil {
		return time.Time{}, err
	}
	if err := validatePaymentReference(
		r.AuthorizationID, r.QuoteID, r.Reference,
		r.ObservedMasterSeqno, r.ObservedAt,
	); err != nil {
		return time.Time{}, err
	}
	if r.ObservedAt.UTC().After(now.Add(maxPaymentClockSkew)) {
		return time.Time{}, errors.New("payment reorganization is excessively future-dated")
	}
	return now, nil
}

func validatePaymentBinding(
	scope Scope,
	intentDigest, authorizationID, quoteID, reference, payer, payee string,
	quoteEnvelopeDigest, paymentEnvelopeDigest string,
	observedMasterSeqno uint64,
	observedAt time.Time,
) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if !digestPattern.MatchString(intentDigest) ||
		!digestPattern.MatchString(quoteEnvelopeDigest) ||
		!digestPattern.MatchString(paymentEnvelopeDigest) {
		return errors.New("invalid payment binding digest")
	}
	if err := validatePaymentReference(
		authorizationID, quoteID, reference,
		observedMasterSeqno, observedAt,
	); err != nil {
		return err
	}
	if err := bounded("payment payer", payer, 1, 512); err != nil {
		return err
	}
	return bounded("payment payee", payee, 1, 512)
}

func validatePaymentReference(
	authorizationID, quoteID, reference string,
	observedMasterSeqno uint64,
	observedAt time.Time,
) error {
	if err := bounded("payment authorization ID", authorizationID, 8, 128); err != nil {
		return err
	}
	if err := bounded("payment quote ID", quoteID, 8, 128); err != nil {
		return err
	}
	if err := bounded("payment reference", reference, 1, 512); err != nil {
		return err
	}
	if observedMasterSeqno == 0 || observedAt.IsZero() ||
		observedAt.Year() < 1970 || observedAt.Year() > 9999 {
		return errors.New("invalid payment observation position")
	}
	return nil
}

func (p PaymentRecord) validateStored(limits Limits) error {
	if p.Version != "1" {
		return errors.New("unsupported payment record version")
	}
	if err := validatePaymentBinding(
		p.Scope, p.IntentDigest, p.AuthorizationID, p.QuoteID,
		p.Reference, p.Payer, p.Payee, p.QuoteEnvelopeDigest,
		p.PaymentEnvelopeDigest, p.ObservedMasterSeqno, p.ObservedAt,
	); err != nil {
		return err
	}
	if p.Revision == 0 || p.AppliedAt.IsZero() || p.RetainUntil.IsZero() ||
		!p.RetainUntil.After(p.AppliedAt) ||
		!p.RetainUntil.After(p.ObservedAt) ||
		p.RetainUntil.Sub(p.AppliedAt) > limits.MaxRetention {
		return errors.New("invalid payment record time or revision")
	}
	switch p.Status {
	case PaymentStatusApplied:
		if !p.ReorganizedAt.IsZero() {
			return errors.New("applied payment has a reorganization timestamp")
		}
	case PaymentStatusReorganized:
		if p.ReorganizedAt.IsZero() ||
			p.ReorganizedAt.Before(p.AppliedAt) ||
			!p.RetainUntil.After(p.ReorganizedAt) {
			return errors.New("invalid payment reorganization time")
		}
	default:
		return errors.New("invalid payment status")
	}
	return nil
}

func (b UsageBudget) validate() error {
	switch b.Kind {
	case "session", "delegation":
	default:
		return errors.New("invalid budget kind")
	}
	if err := bounded("budget ID", b.ID, 8, 128); err != nil {
		return err
	}
	if !digestPattern.MatchString(b.GrantDigest) {
		return errors.New("invalid budget grant digest")
	}
	if b.MaxActions == 0 {
		return errors.New("budget maxActions must be nonzero")
	}
	return nil
}

func (u BudgetUsage) validateStored(limits Limits) error {
	if u.Version != "1" {
		return errors.New("unsupported budget usage version")
	}
	if err := (Scope{
		Network: u.Network, Authority: u.ClientID, ServiceID: u.ServiceID,
		SessionID: u.SessionID, Operation: "budget", RequestID: "budget-usage",
	}).Validate(); err != nil {
		return err
	}
	if err := (UsageBudget{
		Kind: u.Kind, ID: u.ID, GrantDigest: u.GrantDigest,
		MaxActions: u.MaxActions, MaxNanoTOS: u.MaxNanoTOS,
	}).validate(); err != nil {
		return err
	}
	if u.UsedActions == 0 || u.UsedActions > u.MaxActions ||
		u.UsedNanoTOS > u.MaxNanoTOS {
		return errors.New("invalid cumulative budget usage")
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() || u.RetainUntil.IsZero() ||
		u.UpdatedAt.Before(u.CreatedAt) ||
		!u.RetainUntil.After(u.UpdatedAt) ||
		u.RetainUntil.Sub(u.CreatedAt) > limits.MaxRetention {
		return errors.New("invalid budget usage time ordering")
	}
	return nil
}

func (c BudgetClaim) validateStored() error {
	if c.Version != "1" {
		return errors.New("unsupported budget claim version")
	}
	if err := (Scope{
		Network: c.Network, Authority: c.ClientID, ServiceID: c.ServiceID,
		SessionID: c.SessionID, Operation: "budget", RequestID: c.RequestID,
	}).Validate(); err != nil {
		return err
	}
	if c.RetainUntil.IsZero() {
		return errors.New("invalid budget claim retention")
	}
	if c.RetainUntil.Year() < 1970 || c.RetainUntil.Year() > 9999 {
		return errors.New("invalid budget claim retention year")
	}
	if len(c.Budgets) == 0 || len(c.Budgets) > maxAdmissionBudgets {
		return errors.New("invalid budget claim list")
	}
	seen := make(map[string]struct{}, len(c.Budgets))
	for _, budget := range c.Budgets {
		if err := budget.validate(); err != nil {
			return err
		}
		if c.ChargeNanoTOS > budget.MaxNanoTOS {
			return errors.New("budget claim exceeds authority")
		}
		key := budget.Kind + "\x00" + budget.ID
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate budget claim authority")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (n NonceClaim) validate(limits Limits, now time.Time) error {
	if err := n.validateStored(limits); err != nil {
		return err
	}
	if !n.ExpiresAt.After(now) {
		return errors.New("nonce claim is already expired")
	}
	return nil
}

func (n NonceClaim) validateStored(limits Limits) error {
	if n.Version != "1" {
		return errors.New("unsupported nonce claim version")
	}
	scope := Scope{
		Network: n.Network, Authority: n.Authority, ServiceID: n.ServiceID,
		SessionID: n.SessionID, Operation: n.Operation, RequestID: n.RequestID,
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateDomainAndNonce(n.Domain, n.Nonce); err != nil {
		return err
	}
	if !digestPattern.MatchString(n.EnvelopeDigest) {
		return errors.New("invalid signed envelope digest")
	}
	if n.ClaimedAt.IsZero() || n.ExpiresAt.IsZero() ||
		!n.ExpiresAt.After(n.ClaimedAt) ||
		n.ExpiresAt.Sub(n.ClaimedAt) > limits.MaxRetention {
		return errors.New("invalid nonce claim time ordering")
	}
	return nil
}

func (s Scope) Validate() error {
	for name, value := range map[string]string{
		"network": s.Network, "authority": s.Authority,
	} {
		if err := bounded(name, value, 1, 512); err != nil {
			return err
		}
	}
	if !idPattern.MatchString(s.ServiceID) {
		return errors.New("invalid service ID")
	}
	if err := bounded("session ID", s.SessionID, 8, 128); err != nil {
		return err
	}
	if err := bounded("operation", s.Operation, 1, 128); err != nil {
		return err
	}
	if err := bounded("request ID", s.RequestID, 8, 128); err != nil {
		return err
	}
	return nil
}

func (r Record) validate() error {
	if r.Version != "1" {
		return errors.New("unsupported record version")
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if !digestPattern.MatchString(r.IntentDigest) || r.Revision == 0 {
		return errors.New("invalid record digest or revision")
	}
	if !validState(r.State) {
		return errors.New("invalid record state")
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.RetainUntil.IsZero() ||
		r.UpdatedAt.Before(r.CreatedAt) || !r.RetainUntil.After(r.UpdatedAt) {
		return errors.New("invalid record time ordering")
	}
	return validateOutcome(r.State, r.ResultDigest, r.ErrorCode)
}

func (s *Store) validateWindow(now, retainUntil time.Time) (time.Time, time.Time, error) {
	if err := validateNow(now); err != nil {
		return time.Time{}, time.Time{}, err
	}
	now = now.UTC()
	retainUntil = retainUntil.UTC()
	if !retainUntil.After(now) || retainUntil.Sub(now) > s.limits.MaxRetention {
		return time.Time{}, time.Time{}, errors.New("invalid request journal retention window")
	}
	return now, retainUntil, nil
}

func validateNow(now time.Time) error {
	if now.IsZero() || now.Year() < 1970 || now.Year() > 9999 {
		return errors.New("invalid request journal time")
	}
	return nil
}

func validState(state State) bool {
	switch state {
	case StatePending, StateAuthorized, StateRunning, StateSucceeded,
		StateRejected, StateFailed, StateCanceled, StateTimedOut:
		return true
	default:
		return false
	}
}

func canTransition(current, next State) bool {
	switch current {
	case StatePending:
		return next == StateAuthorized || next == StateRejected ||
			next == StateFailed || next == StateCanceled || next == StateTimedOut
	case StateAuthorized:
		return next == StateRunning || next == StateFailed ||
			next == StateCanceled || next == StateTimedOut
	case StateRunning:
		return next == StateSucceeded || next == StateFailed ||
			next == StateCanceled || next == StateTimedOut
	default:
		return false
	}
}

func validateOutcome(state State, resultDigest, errorCode string) error {
	switch state {
	case StateSucceeded:
		if !digestPattern.MatchString(resultDigest) || errorCode != "" {
			return errors.New("successful state requires only a result digest")
		}
	case StateRejected, StateFailed, StateTimedOut:
		if resultDigest != "" || bounded("error code", errorCode, 1, 128) != nil {
			return errors.New("failed state requires only a bounded error code")
		}
	case StateCanceled:
		if resultDigest != "" {
			return errors.New("canceled state must not contain a result digest")
		}
		if errorCode != "" {
			if err := bounded("error code", errorCode, 1, 128); err != nil {
				return err
			}
		}
	case StatePending, StateAuthorized, StateRunning:
		if resultDigest != "" || errorCode != "" {
			return errors.New("nonterminal state must not contain an outcome")
		}
	default:
		return errors.New("invalid request journal state")
	}
	return nil
}

func bounded(name, value string, minimum, maximum int) error {
	if len(value) < minimum || len(value) > maximum || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s has invalid length or content", name)
	}
	return nil
}

func validateDomainAndNonce(domain, nonce string) error {
	if len(domain) < 5 || len(domain) > 128 || !domainPattern.MatchString(domain) {
		return errors.New("invalid signed envelope domain")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(decoded) != 16 {
		return errors.New("invalid signed envelope nonce")
	}
	return nil
}

func scopeKey(scope Scope) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte("TOS-EDGE-JOURNAL-SCOPE-V1"))
	for _, value := range []string{
		scope.Network, scope.Authority, scope.ServiceID,
		scope.SessionID, scope.Operation, scope.RequestID,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hasher.Write(length[:])
		hasher.Write([]byte(value))
	}
	var output [32]byte
	copy(output[:], hasher.Sum(nil))
	return output
}

func nonceKey(claim NonceClaim) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte("TOS-EDGE-JOURNAL-NONCE-V1"))
	for _, value := range []string{
		claim.Network, claim.Authority, claim.ServiceID, claim.Nonce,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hasher.Write(length[:])
		hasher.Write([]byte(value))
	}
	var output [32]byte
	copy(output[:], hasher.Sum(nil))
	return output
}

func sameNonceKey(left, right NonceClaim) bool {
	return left.Network == right.Network &&
		left.Authority == right.Authority &&
		left.ServiceID == right.ServiceID &&
		left.Nonce == right.Nonce
}

func sameNonceBinding(left, right NonceClaim) bool {
	return sameNonceKey(left, right) &&
		left.SessionID == right.SessionID &&
		left.Operation == right.Operation &&
		left.RequestID == right.RequestID &&
		left.Domain == right.Domain &&
		left.EnvelopeDigest == right.EnvelopeDigest &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

func paymentKey(
	network, authorizationID, reference string,
) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte("TOS-EDGE-JOURNAL-PAYMENT-V1"))
	for _, value := range []string{network, authorizationID, reference} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hasher.Write(length[:])
		hasher.Write([]byte(value))
	}
	var output [32]byte
	copy(output[:], hasher.Sum(nil))
	return output
}

func samePaymentBinding(
	record PaymentRecord,
	admission PaymentAdmission,
) bool {
	return record.Scope == admission.Scope &&
		record.IntentDigest == admission.IntentDigest &&
		record.AuthorizationID == admission.AuthorizationID &&
		record.QuoteID == admission.QuoteID &&
		record.Reference == admission.Reference &&
		record.Payer == admission.Payer &&
		record.Payee == admission.Payee &&
		record.AmountNanoTOS == admission.AmountNanoTOS &&
		record.QuoteEnvelopeDigest == admission.QuoteEnvelopeDigest &&
		record.PaymentEnvelopeDigest == admission.PaymentEnvelopeDigest
}

func budgetKey(
	network, serviceID, sessionID, kind, id string,
) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte("TOS-EDGE-JOURNAL-BUDGET-V1"))
	for _, value := range []string{
		network, serviceID, sessionID, kind, id,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hasher.Write(length[:])
		hasher.Write([]byte(value))
	}
	var output [32]byte
	copy(output[:], hasher.Sum(nil))
	return output
}

func sameBudgetAuthority(
	usage BudgetUsage,
	admission SessionAdmission,
	budget UsageBudget,
) bool {
	return usage.Network == admission.Scope.Network &&
		usage.ServiceID == admission.Scope.ServiceID &&
		usage.SessionID == admission.Scope.SessionID &&
		usage.ClientID == admission.ClientID &&
		usage.Kind == budget.Kind &&
		usage.ID == budget.ID &&
		usage.GrantDigest == budget.GrantDigest &&
		usage.MaxActions == budget.MaxActions &&
		usage.MaxNanoTOS == budget.MaxNanoTOS &&
		usage.RetainUntil.Equal(admission.SessionExpiresAt.UTC())
}

func sameBudgetClaim(left, right BudgetClaim) bool {
	if left.Version != right.Version ||
		left.Network != right.Network ||
		left.ServiceID != right.ServiceID ||
		left.SessionID != right.SessionID ||
		left.RequestID != right.RequestID ||
		left.ClientID != right.ClientID ||
		left.ChargeNanoTOS != right.ChargeNanoTOS ||
		!left.RetainUntil.Equal(right.RetainUntil) ||
		len(left.Budgets) != len(right.Budgets) {
		return false
	}
	for index := range left.Budgets {
		if left.Budgets[index] != right.Budgets[index] {
			return false
		}
	}
	return true
}

func expiryPrefix(value time.Time) [expiryPrefixBytes]byte {
	var output [expiryPrefixBytes]byte
	value = value.UTC()
	binary.BigEndian.PutUint64(output[:8], uint64(value.Unix()))
	binary.BigEndian.PutUint32(output[8:], uint32(value.Nanosecond()))
	return output
}

func expiryKey(retainUntil time.Time, recordKey [32]byte) []byte {
	prefix := expiryPrefix(retainUntil)
	output := make([]byte, expiryKeyBytes)
	copy(output[:expiryPrefixBytes], prefix[:])
	copy(output[expiryPrefixBytes:], recordKey[:])
	return output
}

func array32(value []byte) [32]byte {
	var output [32]byte
	copy(output[:], value)
	return output
}

func readCount(transaction *bolt.Tx) (uint64, error) {
	return readNamedCount(transaction, countKey, "record")
}

func writeCount(transaction *bolt.Tx, count uint64) error {
	return writeNamedCount(transaction, countKey, count)
}

func readNonceCount(transaction *bolt.Tx) (uint64, error) {
	return readNamedCount(transaction, nonceCountKey, "nonce")
}

func writeNonceCount(transaction *bolt.Tx, count uint64) error {
	return writeNamedCount(transaction, nonceCountKey, count)
}

func readBudgetCount(transaction *bolt.Tx) (uint64, error) {
	return readNamedCount(transaction, budgetCountKey, "budget")
}

func writeBudgetCount(transaction *bolt.Tx, count uint64) error {
	return writeNamedCount(transaction, budgetCountKey, count)
}

func readNamedCount(transaction *bolt.Tx, key []byte, name string) (uint64, error) {
	encoded := transaction.Bucket(metaBucket).Get(key)
	if len(encoded) != 8 {
		return 0, fmt.Errorf("%w: invalid %s count", ErrCorrupt, name)
	}
	return binary.BigEndian.Uint64(encoded), nil
}

func writeNamedCount(transaction *bolt.Tx, key []byte, count uint64) error {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], count)
	return transaction.Bucket(metaBucket).Put(key, encoded[:])
}

func initializeCount(
	meta *bolt.Bucket,
	key []byte,
	actual uint64,
	name string,
) error {
	encoded := meta.Get(key)
	if encoded == nil {
		var value [8]byte
		binary.BigEndian.PutUint64(value[:], actual)
		return meta.Put(key, value[:])
	}
	if len(encoded) != 8 || binary.BigEndian.Uint64(encoded) != actual {
		return fmt.Errorf("%w: %s count mismatch", ErrCorrupt, name)
	}
	return nil
}
