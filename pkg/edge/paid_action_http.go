package edge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	MaxPaidActionConcurrent     = 8
	DefaultPaidActionConcurrent = 4
	maxPaidActionRequestBytes   = int64(20 << 20)
	maxPaidActionResponseBytes  = 24 << 20
	PaidActionResultMediaType   = "application/vnd.tos.action-result+json"
)

var errPaidActionRequestTooLarge = errors.New(
	"paid-action request exceeds byte limit",
)

// JSONPaidActionAuthorizer is the strict base-v0.1 JSON ingress adapter. The
// intent is base64 in JSON because its exact canonical bytes, not a permissive
// JSON re-encoding, are committed by the signed quote.
type JSONPaidActionAuthorizer struct {
	authorizer *authorization.PaidActionAuthorizer
	now        func() time.Time
}

type paidActionDocument struct {
	Version              string              `json:"version"`
	Intent               []byte              `json:"intent"`
	SessionGrant         identity.Envelope   `json:"sessionGrant"`
	Quote                identity.Envelope   `json:"quote"`
	Delegations          []identity.Envelope `json:"delegations,omitempty"`
	PaymentAuthorization identity.Envelope   `json:"paymentAuthorization"`
}

type paidActionResult struct {
	Version string             `json:"version"`
	Status  string             `json:"status"`
	Output  []byte             `json:"output,omitempty"`
	Receipt *identity.Envelope `json:"receipt,omitempty"`
}

func NewJSONPaidActionAuthorizer(
	authorizer *authorization.PaidActionAuthorizer,
) (*JSONPaidActionAuthorizer, error) {
	if authorizer == nil {
		return nil, errors.New("nil paid-action authorizer")
	}
	return &JSONPaidActionAuthorizer{
		authorizer: authorizer,
		now:        time.Now,
	}, nil
}

func (a *JSONPaidActionAuthorizer) AuthorizePaidAction(
	ctx context.Context,
	request *http.Request,
) (authorization.AuthorizedPaidAction, error) {
	if a == nil || a.authorizer == nil || a.now == nil {
		return authorization.AuthorizedPaidAction{}, errors.New(
			"invalid JSON paid-action authorizer",
		)
	}
	if ctx == nil || request == nil || request.Body == nil {
		return authorization.AuthorizedPaidAction{}, errors.New(
			"invalid paid-action HTTP request",
		)
	}
	if err := ctx.Err(); err != nil {
		return authorization.AuthorizedPaidAction{}, err
	}
	data, err := io.ReadAll(io.LimitReader(
		request.Body, maxPaidActionRequestBytes+1,
	))
	if err != nil || int64(len(data)) > maxPaidActionRequestBytes {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) ||
			int64(len(data)) > maxPaidActionRequestBytes {
			return authorization.AuthorizedPaidAction{},
				errPaidActionRequestTooLarge
		}
		return authorization.AuthorizedPaidAction{}, errors.New(
			"read paid-action request",
		)
	}
	var document paidActionDocument
	if err := jsonstrict.Decode(data, &document); err != nil {
		return authorization.AuthorizedPaidAction{}, errors.New(
			"invalid paid-action JSON document",
		)
	}
	if document.Version != protocol.BaseEnvelopeVersion ||
		len(document.Intent) == 0 ||
		len(document.Intent) > protocol.MaxRequestIntentBytes ||
		len(document.Delegations) > protocol.MaxDelegationDepth+1 {
		return authorization.AuthorizedPaidAction{}, errors.New(
			"invalid paid-action document bounds",
		)
	}
	return a.authorizer.Authorize(
		ctx,
		authorization.PaidActionCredentials{
			SessionGrant:         document.SessionGrant,
			Quote:                document.Quote,
			Delegations:          document.Delegations,
			PaymentAuthorization: document.PaymentAuthorization,
		},
		document.Intent,
		a.now().UTC(),
	)
}

func (s *Server) processPaidAction(
	writer http.ResponseWriter,
	request *http.Request,
) {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	charset := strings.ToLower(parameters["charset"])
	if err != nil || mediaType != "application/json" ||
		(len(parameters) > 1 || (len(parameters) == 1 && charset != "utf-8")) ||
		request.Header.Get("Content-Encoding") != "" ||
		request.URL.RawQuery != "" {
		writeDocument(
			writer, []byte(`{"error":"invalid paid action"}`),
			"application/json", "no-store", http.StatusBadRequest,
		)
		return
	}
	if request.ContentLength > maxPaidActionRequestBytes {
		writeDocument(
			writer, []byte(`{"error":"paid action too large"}`),
			"application/json", "no-store", http.StatusRequestEntityTooLarge,
		)
		return
	}
	select {
	case s.paidActionSlots <- struct{}{}:
		defer func() { <-s.paidActionSlots }()
	default:
		writer.Header().Set("Retry-After", "1")
		writeDocument(
			writer, []byte(`{"error":"paid action capacity exhausted"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return
	}
	request.Body = http.MaxBytesReader(
		writer, request.Body, maxPaidActionRequestBytes,
	)
	authorized, err := callPaidActionAuthorizer(
		request.Context(), s.paidActionAuthorizer, request,
	)
	if err != nil {
		if errors.Is(err, errPaidActionRequestTooLarge) {
			writeDocument(
				writer, []byte(`{"error":"paid action too large"}`),
				"application/json", "no-store", http.StatusRequestEntityTooLarge,
			)
			return
		}
		writeDocument(
			writer, []byte(`{"error":"paid action unauthorized"}`),
			"application/json", "no-store", http.StatusUnauthorized,
		)
		return
	}
	known, err := s.core.HasAuthorizedPaidAction(authorized)
	if err != nil {
		writePaidActionUnavailable(writer)
		return
	}
	if !known && !s.paidActionReady(request.Context()) {
		writePaidActionUnavailable(writer)
		return
	}
	resolution, processErr := s.callProcessAuthorizedPaidAction(
		request.Context(), authorized, s.paymentObserver, s.profilePlan,
		s.worker, s.receiptSigner, s.paidActionRetention,
		s.receiptLifetime,
	)
	if !resolution.valid {
		writeDocument(
			writer, []byte(`{"error":"paid action unavailable"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return
	}
	disposition, err := resolution.Disposition()
	if err != nil {
		writeDocument(
			writer, []byte(`{"error":"paid action unavailable"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return
	}
	if processErr != nil && disposition != ExecutionResolutionUncertain {
		writePaidActionUnavailable(writer)
		return
	}
	result := paidActionResult{
		Version: protocol.BaseEnvelopeVersion,
		Status:  string(disposition),
	}
	statusCode := http.StatusAccepted
	switch disposition {
	case ExecutionResolutionSucceeded:
		completed, completionErr := resolution.CompletedInvocation()
		if completionErr != nil {
			writePaidActionUnavailable(writer)
			return
		}
		result.Output = append([]byte(nil), completed.Output...)
		envelope := clonePublicEnvelope(completed.Receipt.Envelope)
		result.Receipt = &envelope
		statusCode = http.StatusOK
	case ExecutionResolutionFailed,
		ExecutionResolutionCanceled,
		ExecutionResolutionTimedOut:
		terminated, terminationErr := resolution.TerminatedInvocation()
		if terminationErr != nil {
			writePaidActionUnavailable(writer)
			return
		}
		envelope := clonePublicEnvelope(terminated.Receipt.Envelope)
		result.Receipt = &envelope
		statusCode = http.StatusOK
	case ExecutionResolutionUncertain,
		ExecutionResolutionNotFound,
		ExecutionResolutionAccepted,
		ExecutionResolutionRunning:
	default:
		writePaidActionUnavailable(writer)
		return
	}
	// A valid uncertain resolution remains useful even when its private RPC
	// returned an error; returning 202 prevents callers from treating it as
	// permission to submit another action.
	document, err := json.Marshal(result)
	if err != nil || len(document) > maxPaidActionResponseBytes {
		writePaidActionUnavailable(writer)
		return
	}
	writeDocument(
		writer, document, PaidActionResultMediaType,
		"no-store", statusCode,
	)
}

func (s *Server) paidActionReady(ctx context.Context) bool {
	if s == nil || ctx == nil || s.chainReadiness == nil ||
		s.receiptReadiness == nil || s.workerReadiness == nil ||
		s.profileReadiness == nil {
		return false
	}
	probeContext, cancel := context.WithTimeout(ctx, readinessCheckTimeout)
	defer cancel()
	now := s.now()
	for _, gate := range []*readinessGate{
		s.chainReadiness, s.receiptReadiness, s.workerReadiness,
		s.profileReadiness,
	} {
		if gate.check(probeContext, now) != nil {
			return false
		}
	}
	return true
}

func (s *Server) callProcessAuthorizedPaidAction(
	ctx context.Context,
	action authorization.AuthorizedPaidAction,
	observer *payment.Observer,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
	signer authorization.ReceiptSigner,
	taskRetention time.Duration,
	receiptLifetime time.Duration,
) (resolution ExecutionResolution, err error) {
	defer func() {
		if recover() != nil {
			resolution = ExecutionResolution{}
			err = errors.New("paid-action processing panicked")
		}
	}()
	return s.core.ProcessAuthorizedPaidAction(
		ctx, action, observer, plan, worker, signer, taskRetention,
		receiptLifetime,
	)
}

func callPaidActionAuthorizer(
	ctx context.Context,
	authorizer PaidActionHTTPAuthorizer,
	request *http.Request,
) (authorized authorization.AuthorizedPaidAction, err error) {
	defer func() {
		if recover() != nil {
			authorized = authorization.AuthorizedPaidAction{}
			err = errors.New("paid-action authorizer panicked")
		}
	}()
	return authorizer.AuthorizePaidAction(ctx, request)
}

func clonePublicEnvelope(envelope identity.Envelope) identity.Envelope {
	envelope.Payload = append([]byte(nil), envelope.Payload...)
	return envelope
}

func writePaidActionUnavailable(writer http.ResponseWriter) {
	writeDocument(
		writer, []byte(`{"error":"paid action unavailable"}`),
		"application/json", "no-store", http.StatusServiceUnavailable,
	)
}
