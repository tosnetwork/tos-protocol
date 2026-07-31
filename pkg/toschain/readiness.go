package toschain

import (
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
)

// ReadinessSnapshot is a current strict-majority view used by process
// readiness checks. It is diagnostic state, not authorization by itself.
type ReadinessSnapshot struct {
	Network             string
	ObservedMasterSeqno uint64
	ObservedAt          time.Time
	QuorumEndpoints     int
}

// Readiness verifies that a strict majority agrees on a recent finalized
// masterchain position. Callers supply time explicitly to keep tests and
// operational probes deterministic.
func (a *Adapter) Readiness(
	ctx context.Context,
	now time.Time,
) (ReadinessSnapshot, error) {
	if a == nil || ctx == nil || now.IsZero() {
		return ReadinessSnapshot{}, errors.New("invalid TOS chain readiness request")
	}
	if err := ctx.Err(); err != nil {
		return ReadinessSnapshot{}, err
	}
	observation, nodes, err := a.consensus(ctx)
	if err != nil {
		return ReadinessSnapshot{}, err
	}
	now = now.UTC()
	if observation.observedAt.After(now.Add(identity.MaxClockSkew)) ||
		!observation.observedAt.Add(a.readinessAge).After(now) {
		return ReadinessSnapshot{}, errors.New("TOS chain consensus is stale or from the future")
	}
	return ReadinessSnapshot{
		Network: a.network, ObservedMasterSeqno: observation.seqno,
		ObservedAt: observation.observedAt, QuorumEndpoints: len(nodes),
	}, nil
}

// CheckReady implements the generic Edge readiness boundary.
func (a *Adapter) CheckReady(ctx context.Context) error {
	_, err := a.Readiness(ctx, time.Now())
	return err
}
