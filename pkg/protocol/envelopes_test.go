package protocol

import (
	"testing"
	"time"
)

func TestQuotePaymentReceiptBindings(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	quote := Quote{
		Version:          BaseEnvelopeVersion,
		QuoteID:          "quote-0001",
		RequestID:        "request-0001",
		ServiceID:        "edge.example.ai",
		ProfileID:        "tos.ai.inference",
		Operation:        "generate",
		ServiceRevision:  "service-1",
		ResourceRevision: "model-1",
		PriceNanoTOS:     100,
		MaxInputBytes:    1024,
		MaxOutputBytes:   1024,
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
		ExpiresAt:       now.Add(45 * time.Second),
	}
	if err := authorization.Validate(quote, now); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		Version:          BaseEnvelopeVersion,
		ReceiptID:        "receipt-0001",
		RequestID:        quote.RequestID,
		QuoteID:          quote.QuoteID,
		AuthorizationID:  authorization.AuthorizationID,
		ServiceID:        quote.ServiceID,
		Status:           "succeeded",
		ChargedNanoTOS:   100,
		ResultDigest:     "sha256:result",
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
