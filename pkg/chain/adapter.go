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
	Network   string
	Address   string
	ServiceID string
	Active    bool
	Finalized bool
	// ControllerPublicKey is the current manifest-signing key resolved from
	// authoritative chain state. It is not automatically the Service Actor
	// response-attestor key.
	Controller          string
	ControllerPublicKey []byte
	// ManifestDigest is the canonical tos.manifest.v1 value commitment.
	ManifestDigest       string
	RevokedRuntimeKeyIDs []string
	// CodeHash identifies the decoded registration/service contract and is
	// checked against the authorization resolver's local allowlist.
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
	// Payer, Payee, and AmountNanoTOS are the already authenticated payment
	// expectations. Supplying them lets a stateless chain adapter return an
	// exact negative observation without retaining an unbounded
	// process-local transaction cache.
	Payer         string
	Payee         string
	AmountNanoTOS uint64
	// Comment, when non-empty, is the exact inbound internal-message comment
	// expected for this transaction. It binds a finalized transfer to a
	// purpose-specific application commitment rather than only to parties and
	// amount.
	Comment            string
	MinimumMasterSeqno uint64
}

type PaymentState struct {
	Network             string
	AuthorizationID     string
	QuoteID             string
	RequestID           string
	Reference           string
	Confirmed           bool
	Finalized           bool
	Reorganized         bool
	AmountNanoTOS       uint64
	Payer               string
	Payee               string
	Comment             string
	ObservedMasterSeqno uint64
	ObservedAt          time.Time
}
