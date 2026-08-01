package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	ActionStatusMediaType = "application/vnd.tos.action-status+json"
	actionStatusTimeout   = 5 * time.Second
	maxActionStatusBytes  = 2 << 20
)

type publicActionStatus struct {
	Version  string             `json:"version"`
	ActionID string             `json:"actionId"`
	Status   journal.State      `json:"status"`
	Receipt  *identity.Envelope `json:"receipt,omitempty"`
}

func (s *Server) deliverActionStatus(
	writer http.ResponseWriter,
	request *http.Request,
) {
	actionID := request.PathValue("actionId")
	if !validPublicActionID(actionID) || request.URL.RawQuery != "" {
		writeActionUnavailable(writer)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), actionStatusTimeout)
	defer cancel()
	authorizedRequest := request.Clone(ctx)
	scope, err := authorizeActionStatus(
		ctx, s.actionStatusAuth, authorizedRequest, actionID,
	)
	if err != nil || scope.Validate() != nil || scope.Network != s.network ||
		scope.ServiceID != s.serviceID || scope.RequestID != actionID {
		writeActionUnavailable(writer)
		return
	}
	record, err := s.core.Request(scope)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) ||
			errors.Is(err, journal.ErrExpired) {
			writeActionUnavailable(writer)
			return
		}
		writeActionStatusUnavailable(writer)
		return
	}
	if record.Scope != scope || record.State == "" {
		writeActionStatusUnavailable(writer)
		return
	}
	result := publicActionStatus{
		Version:  protocol.BaseEnvelopeVersion,
		ActionID: actionID,
		Status:   record.State,
	}
	if record.State.Terminal() {
		_, paymentErr := s.core.Payment(scope)
		switch {
		case paymentErr == nil:
		case errors.Is(paymentErr, journal.ErrNotFound),
			errors.Is(paymentErr, journal.ErrExpired):
			break
		default:
			writeActionStatusUnavailable(writer)
			return
		}
		if paymentErr == nil {
			receipt, receiptErr := s.core.Receipt(scope)
			if receiptErr != nil || receipt.Scope != scope ||
				!validPublicReceiptID(receipt.ReceiptID) {
				writeActionStatusUnavailable(writer)
				return
			}
			fingerprint, fingerprintErr := receipt.Envelope.Fingerprint()
			if fingerprintErr != nil || fingerprint != receipt.ReceiptEnvelopeDigest {
				writeActionStatusUnavailable(writer)
				return
			}
			envelope := clonePublicEnvelope(receipt.Envelope)
			result.Receipt = &envelope
		}
	}
	document, err := json.Marshal(result)
	if err != nil || len(document) == 0 || len(document) > maxActionStatusBytes {
		writeActionStatusUnavailable(writer)
		return
	}
	writeDocument(
		writer, document, ActionStatusMediaType, "no-store", http.StatusOK,
	)
}

func authorizeActionStatus(
	ctx context.Context,
	authorizer ActionStatusAuthorizer,
	request *http.Request,
	actionID string,
) (scope journal.Scope, err error) {
	defer func() {
		if recover() != nil {
			scope = journal.Scope{}
			err = errors.New("action status authorizer panicked")
		}
	}()
	return authorizer.AuthorizeActionStatus(ctx, request, actionID)
}

func validPublicActionID(value string) bool {
	return validPublicReceiptID(value)
}

func writeActionUnavailable(writer http.ResponseWriter) {
	writeDocument(
		writer, []byte(`{"error":"action unavailable"}`),
		"application/json", "no-store", http.StatusNotFound,
	)
}

func writeActionStatusUnavailable(writer http.ResponseWriter) {
	writeDocument(
		writer, []byte(`{"error":"action status unavailable"}`),
		"application/json", "no-store", http.StatusServiceUnavailable,
	)
}
