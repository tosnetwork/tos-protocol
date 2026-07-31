package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestQuotePaymentReceiptBindings(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	quote := Quote{
		Version:          BaseEnvelopeVersion,
		QuoteID:          "quote-0001",
		RequestID:        "request-0001",
		SessionID:        "session-0001",
		ServiceID:        "edge.example.ai",
		ProfileID:        "tos.ai.inference",
		Operation:        "generate",
		IntentDigest:     "sha256:" + strings.Repeat("b", 64),
		ServiceRevision:  "service-1",
		ResourceRevision: "model-1",
		Network:          "testnet",
		Payee:            "payee",
		Settlement:       "service-actor-request",
		PriceNanoTOS:     100,
		MaxInputBytes:    1024,
		MaxOutputBytes:   1024,
		IssuedAt:         now,
		Deadline:         now.Add(time.Minute),
		ExpiresAt:        now.Add(30 * time.Second),
	}
	if err := quote.Validate(now); err != nil {
		t.Fatal(err)
	}
	authorization := PaymentAuthorization{
		Version:         BaseEnvelopeVersion,
		AuthorizationID: "authorization-0001",
		QuoteID:         quote.QuoteID,
		RequestID:       quote.RequestID,
		Network:         "testnet",
		Payer:           "payer",
		Payee:           "payee",
		MaxNanoTOS:      100,
		Reference:       "service-actor-request",
		ExpiresAt:       now.Add(25 * time.Second),
	}
	if err := authorization.Validate(quote, now); err != nil {
		t.Fatal(err)
	}
	wrongDestination := authorization
	wrongDestination.Payee = "attacker"
	if err := wrongDestination.Validate(quote, now); err == nil {
		t.Fatal("payment authorization with substituted payee accepted")
	}
	receipt := Receipt{
		Version:          BaseEnvelopeVersion,
		ReceiptID:        "receipt-0001",
		RequestID:        quote.RequestID,
		QuoteID:          quote.QuoteID,
		AuthorizationID:  authorization.AuthorizationID,
		ServiceID:        quote.ServiceID,
		Status:           "succeeded",
		Usage:            []UsageItem{},
		ChargedNanoTOS:   100,
		ResultDigest:     "sha256:" + strings.Repeat("a", 64),
		ServiceRevision:  quote.ServiceRevision,
		ResourceRevision: quote.ResourceRevision,
		CompletedAt:      now.Add(50 * time.Second),
	}
	if err := receipt.Validate(quote, authorization); err != nil {
		t.Fatal(err)
	}
	receipt.ChargedNanoTOS = 101
	if err := receipt.Validate(quote, authorization); err == nil {
		t.Fatal("overcharge accepted")
	}
}

func TestQuoteRejectsLifetimeFromIssuedAt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	quote := Quote{
		Version: BaseEnvelopeVersion, QuoteID: "quote-0001", RequestID: "request-0001",
		SessionID: "session-0001", ServiceID: "edge.example.ai",
		ProfileID: "tos.ai.inference", Operation: "generate",
		IntentDigest:    "sha256:" + strings.Repeat("b", 64),
		ServiceRevision: "service-1", ResourceRevision: "model-1",
		Network: "testnet", Payee: "payee", Settlement: "reference",
		MaxInputBytes: 1, MaxOutputBytes: 1, IssuedAt: now.Add(-time.Hour),
		Deadline: now.Add(MaxQuoteLifetime), ExpiresAt: now.Add(time.Second),
	}
	if err := quote.Validate(now); err == nil {
		t.Fatal("quote lifetime measured only from validation time")
	}
}

func TestReceiptRejectsRevisionAndUsageConfusion(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	quote := Quote{
		Version: BaseEnvelopeVersion, QuoteID: "quote-0001", RequestID: "request-0001",
		SessionID: "session-0001",
		ServiceID: "edge.example.ai", ProfileID: "tos.ai.inference", Operation: "generate",
		IntentDigest:    "sha256:" + strings.Repeat("b", 64),
		ServiceRevision: "service-1", ResourceRevision: "model-1", MaxInputBytes: 1,
		Network: "testnet", Payee: "payee", Settlement: "reference",
		MaxOutputBytes: 1, IssuedAt: now, Deadline: now.Add(time.Minute),
		ExpiresAt: now.Add(time.Second),
	}
	authorization := PaymentAuthorization{
		Version: BaseEnvelopeVersion, AuthorizationID: "authorization-0001",
		QuoteID: quote.QuoteID, RequestID: quote.RequestID, Network: "testnet",
		Payer: "payer", Payee: "payee", Reference: "reference",
		ExpiresAt: now.Add(time.Second),
	}
	receipt := Receipt{
		Version: BaseEnvelopeVersion, ReceiptID: "receipt-0001", RequestID: quote.RequestID,
		QuoteID: quote.QuoteID, AuthorizationID: authorization.AuthorizationID,
		ServiceID: quote.ServiceID, Status: "failed", ServiceRevision: "wrong",
		ResourceRevision: quote.ResourceRevision, Usage: []UsageItem{}, CompletedAt: now,
	}
	if err := receipt.Validate(quote, authorization); err == nil {
		t.Fatal("mismatched revision accepted")
	}
	receipt.ServiceRevision = quote.ServiceRevision
	receipt.Usage = []UsageItem{{Unit: "tokens", Quantity: 1}, {Unit: "tokens", Quantity: 2}}
	if err := receipt.Validate(quote, authorization); err == nil {
		t.Fatal("duplicate usage unit accepted")
	}
}
