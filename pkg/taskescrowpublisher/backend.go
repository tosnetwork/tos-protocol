// Package taskescrowpublisher implements the private key-custody sidecar used
// by the ATOS TaskEscrow economic driver. The sidecar may submit transactions,
// but tos-protocol remains responsible for independent quorum/finality checks.
package taskescrowpublisher

import (
	"context"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

// PreparedAction is durable recovery metadata captured before key custody is
// asked to sign or submit anything.
type PreparedAction struct {
	ContractAddress string `json:"contractAddress"`
	BaselineLT      uint64 `json:"baselineLt,omitempty"`
	BaselineHash    string `json:"baselineHash,omitempty"`
	PreparedAt      int64  `json:"preparedAtUnixMillis"`
}

// Backend owns the key-custody-specific transaction construction and
// submission path. It must return a candidate transaction reference only;
// callers independently verify the exact transition on TOS.
type Backend interface {
	CheckReady(context.Context) error
	Prepare(context.Context, chain.TaskEscrowAction) (PreparedAction, error)
	Publish(context.Context, chain.TaskEscrowAction, PreparedAction, bool) (chain.TaskEscrowActionReceipt, error)
	Close() error
}

// Clock is injectable so expiry/recovery behaviour can be tested without
// weakening production wall-clock checks.
type Clock func() time.Time
