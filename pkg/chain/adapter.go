package chain

import (
	"context"
	"time"
)

// Adapter is the small chain-authoritative interface consumed by Edge Core.
// Implementations may use JSON-RPC, lite-server, or supported ADNL/RLDP APIs,
// but must not access validator-private databases.
type Adapter interface {
	ResolveService(context.Context, ServiceReference) (ServiceState, error)
	ObservePayment(context.Context, PaymentReference) (PaymentState, error)
}

type ServiceReference struct {
	Network   string
	Address   string
	ServiceID string
}

type ServiceState struct {
	Active              bool
	Controller          string
	ManifestDigest      string
	CodeHash            string
	ObservedMasterSeqno uint64
	ObservedAt          time.Time
}

type PaymentReference struct {
	Network         string
	AuthorizationID string
	QuoteID         string
	RequestID       string
	Reference       string
}

type PaymentState struct {
	Confirmed           bool
	Finalized           bool
	AmountNanoTOS       uint64
	Payer               string
	Payee               string
	ObservedMasterSeqno uint64
	ObservedAt          time.Time
}
