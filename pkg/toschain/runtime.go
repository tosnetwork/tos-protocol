package toschain

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
)

// Runtime is the production composition consumed by Edge startup code. One
// quorum adapter backs all three trust decisions, while each higher-level
// verifier retains its own exact binding, freshness, and finality policy.
type Runtime struct {
	Chain      *Adapter
	Authority  *authorization.ChainResolver
	ClientKeys authorization.ClientKeyResolver
	Payments   *payment.Observer
}

// CheckServiceReady verifies both recent chain progress and the configured
// service authority/code commitment. It is an operational check only; request
// authorization must still repeat all exact bindings at admission time.
func (runtime *Runtime) CheckServiceReady(
	ctx context.Context,
	reference authorization.Reference,
	now time.Time,
) (ReadinessSnapshot, error) {
	if runtime == nil || runtime.Chain == nil || runtime.Authority == nil ||
		ctx == nil || now.IsZero() {
		return ReadinessSnapshot{}, errors.New("invalid TOS service readiness request")
	}
	authority, err := runtime.Authority.ResolveAuthority(ctx, reference)
	if err != nil {
		return ReadinessSnapshot{}, fmt.Errorf("resolve ready TOS service authority: %w", err)
	}
	now = now.UTC()
	if !authority.Active || authority.ObservedMasterSeqno < reference.MinimumMasterSeqno ||
		authority.ObservedAt.IsZero() ||
		authority.ObservedAt.After(now.Add(identity.MaxClockSkew)) ||
		!authority.ObservedAt.Add(runtime.Chain.readinessAge).After(now) {
		return ReadinessSnapshot{}, errors.New("TOS service authority is not current")
	}
	return ReadinessSnapshot{
		Network:             runtime.Chain.network,
		ObservedMasterSeqno: authority.ObservedMasterSeqno,
		ObservedAt:          authority.ObservedAt,
		QuorumEndpoints:     runtime.Chain.quorum,
	}, nil
}

// NewRuntime assembles live authority, client-key, and payment resolution.
// allowedServiceCodeHashes must come from reviewed deployment artifacts, not
// from a value learned dynamically from the same untrusted request.
func NewRuntime(
	chainConfig Config,
	allowedServiceCodeHashes []string,
	paymentPolicy payment.Policy,
) (*Runtime, error) {
	adapter, err := New(chainConfig)
	if err != nil {
		return nil, err
	}
	authority, err := authorization.NewChainResolver(
		adapter,
		authorization.DefaultChainResolverPolicy(allowedServiceCodeHashes),
	)
	if err != nil {
		return nil, fmt.Errorf("configure TOS authority resolver: %w", err)
	}
	payments, err := payment.NewObserver(adapter, paymentPolicy)
	if err != nil {
		return nil, fmt.Errorf("configure TOS payment observer: %w", err)
	}
	return &Runtime{
		Chain: adapter, Authority: authority, ClientKeys: adapter, Payments: payments,
	}, nil
}
