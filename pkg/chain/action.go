package chain

import "context"

const ChainActionVersion = "1"

// ActionKind identifies a purpose-specific TOS transaction requested from a
// private key-custody sidecar. The current chain-backed ATOS Authority uses
// ActionKindAnchor. The economic action kinds reserve stable wire names for a
// future contract-backed escrow driver; merely publishing an anchor with one
// of those names is not equivalent to economic escrow or settlement.
type ActionKind string

const (
	ActionKindAnchor        ActionKind = "anchor"
	ActionKindEscrowReserve ActionKind = "escrow_reserve"
	ActionKindEscrowRelease ActionKind = "escrow_release"
	ActionKindSettlement    ActionKind = "settlement"
)

// Action is an idempotent transaction intent. ActionID is derived from all
// stable semantic fields by the caller. ExpiresUnixMillis is a local freshness
// window and is deliberately excluded from that identity: a retry may refresh
// it, but must not change any other field. A publisher must return the original
// transaction for the same ActionID, reject any stable-field substitution, and
// never publish a second transaction merely because the freshness window was
// extended.
type Action struct {
	Version           string     `json:"version"`
	ActionID          string     `json:"actionId"`
	Network           string     `json:"network"`
	Kind              ActionKind `json:"kind"`
	CommitmentKind    string     `json:"commitmentKind"`
	ObjectID          string     `json:"objectId"`
	Digest            string     `json:"digest"`
	Payer             string     `json:"payer"`
	Payee             string     `json:"payee"`
	AmountNanoTOS     uint64     `json:"amountNanoTOS"`
	Comment           string     `json:"comment"`
	ExpiresUnixMillis int64      `json:"expiresUnixMillis"`
}

// ActionReceipt names the exact finalized transaction candidate returned by
// the key-custody sidecar. The caller must independently observe this exact
// reference through quorum-backed TOS chain readers before accepting it.
type ActionReceipt struct {
	Version        string     `json:"version"`
	ActionID       string     `json:"actionId"`
	Network        string     `json:"network"`
	Kind           ActionKind `json:"kind"`
	CommitmentKind string     `json:"commitmentKind"`
	ObjectID       string     `json:"objectId"`
	Digest         string     `json:"digest"`
	Reference      string     `json:"reference"`
	Payer          string     `json:"payer"`
	Payee          string     `json:"payee"`
	AmountNanoTOS  uint64     `json:"amountNanoTOS"`
	Comment        string     `json:"comment"`
}

// ActionPublisher is a private key-custody boundary. It may submit a TOS
// transaction, but it is not trusted to declare that transaction finalized or
// semantically correct. Chain-backed callers independently verify its receipt.
type ActionPublisher interface {
	CheckReady(context.Context) error
	Publish(context.Context, Action) (ActionReceipt, error)
	Close() error
}

// ActionResolver is the read-only counterpart required for lost-response
// recovery. It looks up the original receipt by the deterministic ActionID
// and verifies every stable field against action. It must never publish a
// transaction. found=false is an authoritative absence from the configured
// publisher journal; transport or journal availability failures are errors.
type ActionResolver interface {
	Resolve(context.Context, Action) (receipt ActionReceipt, found bool, err error)
}
