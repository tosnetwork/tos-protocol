package protocol

import (
	"errors"
	"fmt"
	"time"
)

const (
	BaseEnvelopeVersion = "0.1"
	MaxQuoteLifetime    = 24 * time.Hour
)

type Quote struct {
	Version          string    `json:"version"`
	QuoteID          string    `json:"quoteId"`
	RequestID        string    `json:"requestId"`
	SessionID        string    `json:"sessionId"`
	ServiceID        string    `json:"serviceId"`
	ProfileID        string    `json:"profileId"`
	Operation        string    `json:"operation"`
	IntentDigest     string    `json:"intentDigest"`
	ServiceRevision  string    `json:"serviceRevision"`
	ResourceRevision string    `json:"resourceRevision"`
	Network          string    `json:"network"`
	Payee            string    `json:"payee"`
	Settlement       string    `json:"settlement"`
	PriceNanoTOS     uint64    `json:"priceNanoTos"`
	MaxInputBytes    uint64    `json:"maxInputBytes"`
	MaxOutputBytes   uint64    `json:"maxOutputBytes"`
	IssuedAt         time.Time `json:"issuedAt"`
	Deadline         time.Time `json:"deadline"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type PaymentAuthorization struct {
	Version         string    `json:"version"`
	AuthorizationID string    `json:"authorizationId"`
	QuoteID         string    `json:"quoteId"`
	RequestID       string    `json:"requestId"`
	Network         string    `json:"network"`
	Payer           string    `json:"payer"`
	Payee           string    `json:"payee"`
	MaxNanoTOS      uint64    `json:"maxNanoTos"`
	Reference       string    `json:"reference"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type Receipt struct {
	Version          string      `json:"version"`
	ReceiptID        string      `json:"receiptId"`
	RequestID        string      `json:"requestId"`
	QuoteID          string      `json:"quoteId"`
	AuthorizationID  string      `json:"authorizationId"`
	ServiceID        string      `json:"serviceId"`
	Status           string      `json:"status"`
	Usage            []UsageItem `json:"usage"`
	ChargedNanoTOS   uint64      `json:"chargedNanoTos"`
	ResultDigest     string      `json:"resultDigest,omitempty"`
	ServiceRevision  string      `json:"serviceRevision"`
	ResourceRevision string      `json:"resourceRevision"`
	CompletedAt      time.Time   `json:"completedAt"`
}

type UsageItem struct {
	Unit     string `json:"unit"`
	Quantity uint64 `json:"quantity"`
}

func (q Quote) Validate(now time.Time) error {
	if q.Version != BaseEnvelopeVersion {
		return errors.New("unsupported quote version")
	}
	if err := validateCorrelationIDs(q.QuoteID, q.RequestID, q.SessionID); err != nil {
		return err
	}
	if !serviceIDPattern.MatchString(q.ServiceID) || !serviceIDPattern.MatchString(q.ProfileID) {
		return errors.New("invalid quote service or profile")
	}
	if err := boundedString("operation", q.Operation, 1, 128); err != nil {
		return err
	}
	if !digestPattern.MatchString(q.IntentDigest) {
		return errors.New("quote intent digest must be sha256:<lowercase hex>")
	}
	if err := boundedString("serviceRevision", q.ServiceRevision, 1, 128); err != nil {
		return err
	}
	if err := boundedString("resourceRevision", q.ResourceRevision, 1, 256); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"network": q.Network, "payee": q.Payee, "settlement": q.Settlement,
	} {
		if err := boundedString(name, value, 1, 512); err != nil {
			return err
		}
	}
	if q.MaxInputBytes == 0 || q.MaxOutputBytes == 0 {
		return errors.New("quote resource bounds are required")
	}
	if q.IssuedAt.IsZero() || q.IssuedAt.After(now.Add(MaxClockSkewForReceipts)) ||
		!q.Deadline.After(now) || !q.ExpiresAt.After(now) ||
		!q.ExpiresAt.After(q.IssuedAt) || q.ExpiresAt.After(q.Deadline) {
		return errors.New("invalid quote time bounds")
	}
	if q.Deadline.Sub(q.IssuedAt) > MaxQuoteLifetime {
		return errors.New("quote deadline exceeds maximum lifetime")
	}
	return nil
}

func (p PaymentAuthorization) Validate(quote Quote, now time.Time) error {
	if err := quote.Validate(now); err != nil {
		return fmt.Errorf("invalid quote: %w", err)
	}
	if p.Version != BaseEnvelopeVersion {
		return errors.New("unsupported payment authorization version")
	}
	if err := validateCorrelationIDs(p.AuthorizationID, p.QuoteID, p.RequestID); err != nil {
		return err
	}
	if p.QuoteID != quote.QuoteID || p.RequestID != quote.RequestID {
		return errors.New("payment authorization does not bind the quote")
	}
	if p.Network != quote.Network || p.Payee != quote.Payee || p.Reference != quote.Settlement {
		return errors.New("payment authorization destination mismatch")
	}
	if p.MaxNanoTOS < quote.PriceNanoTOS {
		return errors.New("payment authorization is below quoted price")
	}
	for name, value := range map[string]string{
		"network": p.Network, "payer": p.Payer, "payee": p.Payee, "reference": p.Reference,
	} {
		if err := boundedString(name, value, 1, 512); err != nil {
			return err
		}
	}
	if !p.ExpiresAt.After(now) || p.ExpiresAt.After(quote.ExpiresAt) {
		return errors.New("invalid payment authorization expiry")
	}
	return nil
}

func (r Receipt) Validate(quote Quote, authorization PaymentAuthorization) error {
	if r.Version != BaseEnvelopeVersion {
		return errors.New("unsupported receipt version")
	}
	if err := validateCorrelationIDs(r.ReceiptID, r.RequestID, r.QuoteID, r.AuthorizationID); err != nil {
		return err
	}
	if r.RequestID != quote.RequestID || r.QuoteID != quote.QuoteID ||
		r.AuthorizationID != authorization.AuthorizationID || r.ServiceID != quote.ServiceID {
		return errors.New("receipt correlation binding mismatch")
	}
	switch r.Status {
	case "succeeded", "failed", "canceled", "timed_out":
	default:
		return errors.New("invalid receipt status")
	}
	if r.ChargedNanoTOS > authorization.MaxNanoTOS {
		return errors.New("receipt charge exceeds authorization")
	}
	if r.Status == "succeeded" && r.ResultDigest == "" {
		return errors.New("successful receipt requires a result digest")
	}
	if r.ResultDigest != "" && !digestPattern.MatchString(r.ResultDigest) {
		return errors.New("receipt result digest must be sha256:<lowercase hex>")
	}
	if r.ServiceRevision != quote.ServiceRevision || r.ResourceRevision != quote.ResourceRevision {
		return errors.New("receipt revision binding mismatch")
	}
	if r.CompletedAt.IsZero() || r.CompletedAt.Before(quote.IssuedAt) ||
		r.CompletedAt.After(quote.Deadline.Add(MaxClockSkewForReceipts)) {
		return errors.New("invalid receipt completion time")
	}
	if r.Usage == nil {
		return errors.New("receipt usage must be an array")
	}
	if len(r.Usage) > 32 {
		return errors.New("too many receipt usage units")
	}
	seenUnits := make(map[string]struct{}, len(r.Usage))
	for index, usage := range r.Usage {
		if err := boundedString(fmt.Sprintf("usage[%d].unit", index), usage.Unit, 1, 64); err != nil {
			return err
		}
		if _, duplicate := seenUnits[usage.Unit]; duplicate {
			return errors.New("duplicate receipt usage unit")
		}
		seenUnits[usage.Unit] = struct{}{}
	}
	return nil
}

const MaxClockSkewForReceipts = 2 * time.Minute

func validateCorrelationIDs(values ...string) error {
	for _, value := range values {
		if len(value) < 8 || len(value) > 128 {
			return errors.New("correlation IDs must contain 8..128 bytes")
		}
	}
	return nil
}
