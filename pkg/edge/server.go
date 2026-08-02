// Package edge provides the public, generic Edge Core HTTP surface. The
// bootstrap serves discovery only and intentionally has no invocation route.
package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/nilcheck"
	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	readinessCheckTimeout = 8 * time.Second
	readinessCacheTTL     = time.Second
	receiptAccessTimeout  = 5 * time.Second
	maxReceiptDocument    = 2 << 20

	// SignedEnvelopeMediaType is the public JSON representation of a signed
	// TOS protocol envelope. Receipt delivery returns no journal metadata.
	SignedEnvelopeMediaType = "application/vnd.tos.signed-envelope+json"
)

var errReadinessProbeBusy = errors.New("readiness probe already in progress")

// ReadinessChecker represents an external startup dependency. It must make no
// authorization decision; readiness is only an operational availability
// signal and is always rechecked by the real request path.
type ReadinessChecker interface {
	CheckReady(context.Context) error
}

// ReceiptDeliveryAuthorizer authenticates one receipt read before durable
// state is consulted. Implementations must derive the returned scope from
// current session/client authority rather than trusting request parameters.
// The public server invokes it with a short bounded context and hides all
// authorization failures behind the same unavailable response.
type ReceiptDeliveryAuthorizer interface {
	AuthorizeReceiptAccess(context.Context, *http.Request, string) (journal.Scope, error)
}

// ReceiptSource returns an already validated durable receipt for an exact
// authorized scope. *Core implements this interface.
type ReceiptSource interface {
	Receipt(journal.Scope) (journal.ReceiptRecord, error)
}

// ActionStatusAuthorizer authenticates a read of one durable action. The
// implementation must bind the path action ID to the returned request scope;
// discovery metadata is never sufficient authorization.
type ActionStatusAuthorizer interface {
	AuthorizeActionStatus(
		context.Context,
		*http.Request,
		string,
	) (journal.Scope, error)
}

// PaidActionHTTPAuthorizer parses and authenticates one bounded public action
// request. The returned opaque value must come from PaidActionAuthorizer;
// discovery fields alone cannot implement this boundary.
type PaidActionHTTPAuthorizer interface {
	AuthorizePaidAction(
		context.Context,
		*http.Request,
	) (authorization.AuthorizedPaidAction, error)
}

type ServerDependencies struct {
	Core                    *Core
	ChainReadiness          ReadinessChecker
	ReceiptSignerReadiness  ReadinessChecker
	ProfileReadiness        ReadinessChecker
	ReceiptAuthorizer       ReceiptDeliveryAuthorizer
	ReceiptSource           ReceiptSource
	ActionStatusAuthorizer  ActionStatusAuthorizer
	PaidActionAuthorizer    PaidActionHTTPAuthorizer
	PaymentObserver         *payment.Observer
	ProfilePlan             *ProfileInvocationPlan
	Worker                  *localrpc.WorkerClient
	ReceiptSigner           authorization.ReceiptSigner
	PaidActionRetention     time.Duration
	ReceiptLifetime         time.Duration
	PaidActionMaxConcurrent int
	PaidActionErrorReporter PaidActionErrorReporter
}

// PaidActionErrorReporter receives server-side diagnostics for failures that
// are deliberately collapsed to generic public HTTP errors. Implementations
// must not return these diagnostics to unauthenticated callers.
type PaidActionErrorReporter interface {
	ReportPaidActionError(context.Context, string, error)
}

type readinessGate struct {
	checker ReadinessChecker
	mu      sync.Mutex
	running bool
	checked time.Time
	err     error
}

func newReadinessGate(checker ReadinessChecker) *readinessGate {
	if nilcheck.IsNil(checker) {
		return nil
	}
	return &readinessGate{checker: checker}
}

func (gate *readinessGate) check(ctx context.Context, now time.Time) error {
	gate.mu.Lock()
	if !gate.checked.IsZero() && now.Sub(gate.checked) >= 0 &&
		now.Sub(gate.checked) < readinessCacheTTL {
		err := gate.err
		gate.mu.Unlock()
		return err
	}
	if gate.running {
		gate.mu.Unlock()
		return errReadinessProbeBusy
	}
	gate.running = true
	gate.mu.Unlock()

	err := callReadinessChecker(gate.checker, ctx)
	gate.mu.Lock()
	gate.running = false
	gate.checked = now
	gate.err = err
	gate.mu.Unlock()
	return err
}

func callReadinessChecker(
	checker ReadinessChecker,
	ctx context.Context,
) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("readiness checker panicked")
		}
	}()
	return checker.CheckReady(ctx)
}

type Server struct {
	descriptor           []byte
	descriptorExpiresAt  time.Time
	catalog              []byte
	now                  func() time.Time
	core                 *Core
	chainReadiness       *readinessGate
	receiptReadiness     *readinessGate
	workerReadiness      *readinessGate
	profileReadiness     *readinessGate
	receiptAuthorizer    ReceiptDeliveryAuthorizer
	receiptSource        ReceiptSource
	actionStatusAuth     ActionStatusAuthorizer
	paidActionAuthorizer PaidActionHTTPAuthorizer
	paymentObserver      *payment.Observer
	profilePlan          *ProfileInvocationPlan
	worker               *localrpc.WorkerClient
	receiptSigner        authorization.ReceiptSigner
	paidActionRetention  time.Duration
	receiptLifetime      time.Duration
	paidActionSlots      chan struct{}
	paidActionErrors     PaidActionErrorReporter
	network              string
	serviceID            string
}

func NewServer(descriptor protocol.ServiceDescriptor, catalog ard.Catalog, now time.Time) (*Server, error) {
	return newServer(descriptor, catalog, now, ServerDependencies{})
}

func NewServerWithCore(
	descriptor protocol.ServiceDescriptor,
	catalog ard.Catalog,
	now time.Time,
	core *Core,
) (*Server, error) {
	if core == nil {
		return nil, errors.New("nil Edge Core")
	}
	return newServer(descriptor, catalog, now, ServerDependencies{Core: core})
}

func NewServerWithDependencies(
	descriptor protocol.ServiceDescriptor,
	catalog ard.Catalog,
	now time.Time,
	dependencies ServerDependencies,
) (*Server, error) {
	return newServer(descriptor, catalog, now, dependencies)
}

func newServer(
	descriptor protocol.ServiceDescriptor,
	catalog ard.Catalog,
	now time.Time,
	dependencies ServerDependencies,
) (*Server, error) {
	for _, dependency := range []any{
		dependencies.ChainReadiness,
		dependencies.ReceiptSignerReadiness,
		dependencies.ProfileReadiness,
		dependencies.ReceiptAuthorizer,
		dependencies.ReceiptSource,
		dependencies.ActionStatusAuthorizer,
		dependencies.PaidActionAuthorizer,
		dependencies.ReceiptSigner,
		dependencies.PaidActionErrorReporter,
	} {
		if dependency != nil && nilcheck.IsNil(dependency) {
			return nil, errors.New("typed-nil Edge server dependency")
		}
	}
	receiptAuthorizerConfigured := !nilcheck.IsNil(dependencies.ReceiptAuthorizer)
	receiptSourceConfigured := !nilcheck.IsNil(dependencies.ReceiptSource)
	actionStatusConfigured := !nilcheck.IsNil(dependencies.ActionStatusAuthorizer)
	paidAuthorizerConfigured := !nilcheck.IsNil(dependencies.PaidActionAuthorizer)
	chainReadinessConfigured := !nilcheck.IsNil(dependencies.ChainReadiness)
	receiptReadinessConfigured := !nilcheck.IsNil(dependencies.ReceiptSignerReadiness)
	profileReadinessConfigured := !nilcheck.IsNil(dependencies.ProfileReadiness)
	receiptSignerConfigured := !nilcheck.IsNil(dependencies.ReceiptSigner)
	if receiptAuthorizerConfigured != receiptSourceConfigured {
		return nil, errors.New("partial receipt delivery dependencies")
	}
	if actionStatusConfigured && dependencies.Core == nil {
		return nil, errors.New("action status requires Edge Core")
	}
	paidConfigured := paidAuthorizerConfigured ||
		dependencies.PaymentObserver != nil || dependencies.ProfilePlan != nil ||
		profileReadinessConfigured ||
		dependencies.Worker != nil || receiptSignerConfigured ||
		dependencies.PaidActionRetention != 0 ||
		dependencies.ReceiptLifetime != 0 ||
		dependencies.PaidActionMaxConcurrent != 0
	if paidConfigured && (dependencies.Core == nil ||
		!chainReadinessConfigured ||
		!receiptReadinessConfigured ||
		!profileReadinessConfigured ||
		!paidAuthorizerConfigured ||
		dependencies.PaymentObserver == nil || dependencies.ProfilePlan == nil ||
		dependencies.Worker == nil || !receiptSignerConfigured ||
		dependencies.PaidActionRetention <= 0 ||
		dependencies.PaidActionRetention > localrpc.MaximumWorkerTaskRetention ||
		dependencies.ReceiptLifetime < minReceiptLifetime ||
		dependencies.ReceiptLifetime > maxReceiptLifetime ||
		dependencies.PaidActionMaxConcurrent <= 0 ||
		dependencies.PaidActionMaxConcurrent > MaxPaidActionConcurrent) {
		return nil, errors.New("invalid or partial paid-action dependencies")
	}
	if err := descriptor.Validate(now); err != nil {
		return nil, err
	}
	if err := catalog.Validate(ard.DefaultLimits()); err != nil {
		return nil, err
	}
	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	catalogJSON, err := json.Marshal(catalog)
	if err != nil {
		return nil, err
	}
	if len(descriptorJSON) > 256<<10 {
		return nil, errors.New("descriptor exceeds byte limit")
	}
	server := &Server{
		descriptor:           descriptorJSON,
		descriptorExpiresAt:  descriptor.ExpiresAt,
		catalog:              catalogJSON,
		now:                  time.Now,
		core:                 dependencies.Core,
		chainReadiness:       newReadinessGate(dependencies.ChainReadiness),
		receiptReadiness:     newReadinessGate(dependencies.ReceiptSignerReadiness),
		receiptAuthorizer:    dependencies.ReceiptAuthorizer,
		receiptSource:        dependencies.ReceiptSource,
		actionStatusAuth:     dependencies.ActionStatusAuthorizer,
		paidActionAuthorizer: dependencies.PaidActionAuthorizer,
		paymentObserver:      dependencies.PaymentObserver,
		profilePlan:          dependencies.ProfilePlan,
		worker:               dependencies.Worker,
		receiptSigner:        dependencies.ReceiptSigner,
		paidActionRetention:  dependencies.PaidActionRetention,
		receiptLifetime:      dependencies.ReceiptLifetime,
		paidActionErrors:     dependencies.PaidActionErrorReporter,
		network:              descriptor.Network,
		serviceID:            descriptor.ServiceID,
	}
	if paidConfigured {
		server.workerReadiness = newReadinessGate(dependencies.Worker)
		server.profileReadiness = newReadinessGate(dependencies.ProfileReadiness)
		server.paidActionSlots = make(
			chan struct{}, dependencies.PaidActionMaxConcurrent,
		)
	}
	return server, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		if !s.writeLiveness(writer) {
			return
		}
		writeDocument(
			writer, []byte(`{"status":"ok"}`),
			"application/json", "no-store", http.StatusOK,
		)
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		if !s.writeCoreReadiness(writer) {
			return
		}
		var readinessContext context.Context
		var cancelReadiness context.CancelFunc
		if s.chainReadiness != nil || s.receiptReadiness != nil ||
			s.workerReadiness != nil || s.profileReadiness != nil {
			readinessContext, cancelReadiness = context.WithTimeout(
				request.Context(), readinessCheckTimeout,
			)
			defer cancelReadiness()
		}
		if s.chainReadiness != nil {
			err := s.chainReadiness.check(readinessContext, s.now())
			if err != nil {
				writeDocument(
					writer,
					[]byte(`{"status":"degraded","component":"tos-chain"}`),
					"application/json", "no-store", http.StatusServiceUnavailable,
				)
				return
			}
		}
		if s.receiptReadiness != nil {
			err := s.receiptReadiness.check(readinessContext, s.now())
			if err != nil {
				writeDocument(
					writer,
					[]byte(`{"status":"degraded","component":"receipt-signer"}`),
					"application/json", "no-store", http.StatusServiceUnavailable,
				)
				return
			}
		}
		if s.workerReadiness != nil {
			err := s.workerReadiness.check(readinessContext, s.now())
			if err != nil {
				writeDocument(
					writer,
					[]byte(`{"status":"degraded","component":"worker"}`),
					"application/json", "no-store", http.StatusServiceUnavailable,
				)
				return
			}
		}
		if s.profileReadiness != nil {
			err := s.profileReadiness.check(readinessContext, s.now())
			if err != nil {
				writeDocument(
					writer,
					[]byte(`{"status":"degraded","component":"profile"}`),
					"application/json", "no-store", http.StatusServiceUnavailable,
				)
				return
			}
		}
		writeDocument(
			writer, []byte(`{"status":"ready"}`),
			"application/json", "no-store", http.StatusOK,
		)
	})
	mux.HandleFunc("GET /.well-known/tos-service.json", func(writer http.ResponseWriter, _ *http.Request) {
		if !s.descriptorExpiresAt.After(s.now()) {
			writeDocument(
				writer, []byte(`{"error":"service descriptor expired"}`),
				"application/json", "no-store", http.StatusServiceUnavailable,
			)
			return
		}
		writeDocument(
			writer, s.descriptor, ard.TOSServiceDescriptorMediaType,
			"public, max-age=60, must-revalidate", http.StatusOK,
		)
	})
	mux.HandleFunc("GET /.well-known/ai-catalog.json", func(writer http.ResponseWriter, _ *http.Request) {
		writeDocument(
			writer, s.catalog, "application/json",
			"public, max-age=60, must-revalidate", http.StatusOK,
		)
	})
	if s.receiptAuthorizer != nil && s.receiptSource != nil {
		mux.HandleFunc("GET /tos/v1/receipts/{receiptId}", s.deliverReceipt)
	}
	if s.paidActionAuthorizer != nil && s.paidActionSlots != nil {
		mux.HandleFunc("POST /tos/v1/actions", s.processPaidAction)
	}
	if s.actionStatusAuth != nil && s.core != nil {
		mux.HandleFunc("GET /tos/v1/actions/{actionId}", s.deliverActionStatus)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(writer, request)
	})
}

func (s *Server) deliverReceipt(writer http.ResponseWriter, request *http.Request) {
	receiptID := request.PathValue("receiptId")
	if !validPublicReceiptID(receiptID) {
		writeReceiptUnavailable(writer)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), receiptAccessTimeout)
	defer cancel()
	authorizedRequest := request.Clone(ctx)
	scope, err := authorizeReceiptAccess(
		ctx, s.receiptAuthorizer, authorizedRequest, receiptID,
	)
	if err != nil || scope.Validate() != nil || scope.Network != s.network ||
		scope.ServiceID != s.serviceID {
		writeReceiptUnavailable(writer)
		return
	}
	receipt, err := readReceipt(s.receiptSource, scope)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) || errors.Is(err, journal.ErrExpired) {
			writeReceiptUnavailable(writer)
			return
		}
		writeDocument(
			writer, []byte(`{"error":"receipt delivery unavailable"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return
	}
	if receipt.Scope != scope || receipt.ReceiptID != receiptID {
		writeDocument(
			writer, []byte(`{"error":"receipt delivery unavailable"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return
	}
	fingerprint, err := receipt.Envelope.Fingerprint()
	if err != nil || fingerprint != receipt.ReceiptEnvelopeDigest {
		writeDocument(
			writer, []byte(`{"error":"receipt delivery unavailable"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return
	}
	document, err := json.Marshal(receipt.Envelope)
	if err != nil || len(document) == 0 || len(document) > maxReceiptDocument {
		writeDocument(
			writer, []byte(`{"error":"receipt delivery unavailable"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return
	}
	writeDocument(
		writer, document, SignedEnvelopeMediaType, "no-store", http.StatusOK,
	)
}

func authorizeReceiptAccess(
	ctx context.Context,
	authorizer ReceiptDeliveryAuthorizer,
	request *http.Request,
	receiptID string,
) (scope journal.Scope, err error) {
	defer func() {
		if recover() != nil {
			scope = journal.Scope{}
			err = errors.New("receipt authorizer panicked")
		}
	}()
	return authorizer.AuthorizeReceiptAccess(ctx, request, receiptID)
}

func readReceipt(
	source ReceiptSource,
	scope journal.Scope,
) (receipt journal.ReceiptRecord, err error) {
	defer func() {
		if recover() != nil {
			receipt = journal.ReceiptRecord{}
			err = errors.New("receipt source panicked")
		}
	}()
	return source.Receipt(scope)
}

func validPublicReceiptID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character == 0 {
			return false
		}
	}
	return true
}

func writeReceiptUnavailable(writer http.ResponseWriter) {
	writeDocument(
		writer, []byte(`{"error":"receipt unavailable"}`),
		"application/json", "no-store", http.StatusNotFound,
	)
}

func (s *Server) writeLiveness(writer http.ResponseWriter) bool {
	if s.core == nil {
		return true
	}
	if _, err := s.core.Liveness(); err != nil {
		writeDocument(
			writer,
			[]byte(`{"status":"degraded","component":"request-journal"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return false
	}
	return true
}

func (s *Server) writeCoreReadiness(writer http.ResponseWriter) bool {
	if s.core == nil {
		return true
	}
	if _, err := s.core.Health(); err != nil {
		writeDocument(
			writer,
			[]byte(`{"status":"degraded","component":"edge-core"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return false
	}
	return true
}

func writeDocument(
	writer http.ResponseWriter,
	document []byte,
	contentType, cacheControl string,
	status int,
) {
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Cache-Control", cacheControl)
	writer.WriteHeader(status)
	_, _ = writer.Write(document)
}

func NewHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}
