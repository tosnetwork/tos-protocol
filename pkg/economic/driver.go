// Package economic defines the economically enforceable TOS contract boundary
// used by ATOS Verified execution. It is deliberately separate from generic
// commitment anchoring: a finalized data anchor is not escrow.
package economic

import (
	"context"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

type TrustMode string

const (
	TrustModeVerified TrustMode = "verified"
	TrustModeNative   TrustMode = "native"
)

type ReserveEscrowRequest struct {
	EscrowID       string
	Creator        string
	Agent          string
	Verifier       string
	BudgetNanoTOS  uint64
	DeadlineUnix   uint64
	PolicyHash     string
	PermissionHash string
}

type AcceptEscrowRequest struct {
	EscrowID        string
	ContractAddress string
	ExpectedAgent   string
}

type CommitResultRequest struct {
	EscrowID        string
	ContractAddress string
	ResultHash      string
	EvidenceHash    string
}

type ReleaseEscrowRequest struct {
	EscrowID        string
	ContractAddress string
	BudgetNanoTOS   uint64
	ReasonCode      string
	ReleaseDigest   string
}

type SettleProviderRequest struct {
	EscrowID        string
	ContractAddress string
	BudgetNanoTOS   uint64
	ResultHash      string
	EvidenceHash    string
	PayoutNanoTOS   uint64
}

type RefundPrincipalRequest struct {
	EscrowID        string
	ContractAddress string
	BudgetNanoTOS   uint64
	DisputeHash     string
	ReleaseDigest   string
}

type OpenDisputeRequest struct {
	EscrowID        string
	ContractAddress string
	DisputeHash     string
}

type ResolveDisputeRequest struct {
	EscrowID        string
	ContractAddress string
	BudgetNanoTOS   uint64
	PayoutNanoTOS   uint64
}

type Result struct {
	State               chain.TaskEscrowState
	ContractReference   string
	TransitionReference string
	AgentPaidNanoTOS    uint64
	CreatorPaidNanoTOS  uint64
	ActionID            string
}

type Driver interface {
	Network() string
	Supports(TrustMode) bool
	CheckReady(context.Context) error
	ReserveEscrow(context.Context, ReserveEscrowRequest) (Result, error)
	ResolveEscrow(context.Context, ReserveEscrowRequest) (Result, bool, error)
	AcceptEscrow(context.Context, AcceptEscrowRequest) (Result, error)
	CommitResult(context.Context, CommitResultRequest) (Result, error)
	ReleaseEscrow(context.Context, ReleaseEscrowRequest) (Result, error)
	SettleProvider(context.Context, SettleProviderRequest) (Result, error)
	RefundPrincipal(context.Context, RefundPrincipalRequest) (Result, error)
	OpenDispute(context.Context, OpenDisputeRequest) (Result, error)
	ResolveDispute(context.Context, ResolveDisputeRequest) (Result, error)
	ReadEconomicState(context.Context, string) (chain.TaskEscrowState, error)
	Close() error
}

// SettlementResolver is the read-only terminal recovery boundary used by
// proof production. Typed absence or an unavailable publisher journal fails
// closed; it never authorizes Publish.
type SettlementResolver interface {
	ResolveSettlement(context.Context, SettleProviderRequest) (Result, error)
}

// ReleaseResolver is the read-only terminal recovery boundary for a refund.
// It resolves the deterministic release ActionID from the enrolled publisher
// journal and independently observes the chain transition; absence never
// authorizes another mutation.
type ReleaseResolver interface {
	ResolveRelease(context.Context, RefundPrincipalRequest) (Result, error)
}
