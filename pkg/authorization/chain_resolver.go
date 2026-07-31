package authorization

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

const (
	DefaultChainQueryTimeout = 5 * time.Second
	MaxAllowedServiceCodes   = 32

	minChainQueryTimeout = 10 * time.Millisecond
	maxChainQueryTimeout = 30 * time.Second
)

// ChainServiceReader is the narrow read-only portion of chain.Adapter needed
// for authority resolution.
type ChainServiceReader interface {
	ResolveService(context.Context, chain.ServiceReference) (chain.ServiceState, error)
}

type ChainResolverPolicy struct {
	QueryTimeout      time.Duration
	RequireFinalized  bool
	AllowedCodeHashes []string
}

func DefaultChainResolverPolicy(allowedCodeHashes []string) ChainResolverPolicy {
	return ChainResolverPolicy{
		QueryTimeout:      DefaultChainQueryTimeout,
		RequireFinalized:  true,
		AllowedCodeHashes: append([]string(nil), allowedCodeHashes...),
	}
}

// ChainResolver converts a contract-aware chain adapter result into the
// generic authorization snapshot. It is stateless and retains no service
// cache, so the reader must return a current canonical chain view.
type ChainResolver struct {
	reader            ChainServiceReader
	queryTimeout      time.Duration
	requireFinalized  bool
	allowedCodeHashes map[string]struct{}
}

func NewChainResolver(
	reader ChainServiceReader,
	policy ChainResolverPolicy,
) (*ChainResolver, error) {
	if reader == nil {
		return nil, errors.New("nil chain service reader")
	}
	if policy.QueryTimeout < minChainQueryTimeout ||
		policy.QueryTimeout > maxChainQueryTimeout {
		return nil, errors.New("invalid chain authority query timeout")
	}
	if len(policy.AllowedCodeHashes) == 0 ||
		len(policy.AllowedCodeHashes) > MaxAllowedServiceCodes {
		return nil, errors.New("chain authority requires a bounded code-hash allowlist")
	}
	allowed := make(map[string]struct{}, len(policy.AllowedCodeHashes))
	for _, codeHash := range policy.AllowedCodeHashes {
		if err := bounded("service code hash", codeHash, 1, 512); err != nil ||
			strings.TrimSpace(codeHash) != codeHash {
			return nil, errors.New("invalid allowed service code hash")
		}
		if _, duplicate := allowed[codeHash]; duplicate {
			return nil, errors.New("duplicate allowed service code hash")
		}
		allowed[codeHash] = struct{}{}
	}
	return &ChainResolver{
		reader: reader, queryTimeout: policy.QueryTimeout,
		requireFinalized:  policy.RequireFinalized,
		allowedCodeHashes: allowed,
	}, nil
}

func (r *ChainResolver) ResolveAuthority(
	ctx context.Context,
	reference Reference,
) (AuthoritySnapshot, error) {
	if r == nil || r.reader == nil {
		return AuthoritySnapshot{}, errors.New("invalid chain authority resolver")
	}
	if ctx == nil {
		return AuthoritySnapshot{}, errors.New("nil chain authority context")
	}
	if err := reference.validate(); err != nil {
		return AuthoritySnapshot{}, err
	}
	queryContext, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()
	state, err := r.reader.ResolveService(queryContext, chain.ServiceReference{
		Network: reference.Network, Address: reference.Address,
		ServiceID: reference.ServiceID,
	})
	if err != nil {
		return AuthoritySnapshot{}, fmt.Errorf("read chain service authority: %w", err)
	}
	if state.Network != reference.Network ||
		state.Address != reference.Address ||
		state.ServiceID != reference.ServiceID {
		return AuthoritySnapshot{}, errors.New("chain service response reference mismatch")
	}
	if r.requireFinalized && !state.Finalized {
		return AuthoritySnapshot{}, errors.New("chain service authority is not finalized")
	}
	if _, allowed := r.allowedCodeHashes[state.CodeHash]; !allowed {
		return AuthoritySnapshot{}, errors.New("chain service code hash is not allowed")
	}
	return AuthoritySnapshot{
		Active: state.Active, Network: state.Network,
		ServiceID: state.ServiceID, Controller: state.Controller,
		ControllerPublicKey: append([]byte(nil), state.ControllerPublicKey...),
		ManifestDigest:      state.ManifestDigest,
		RevokedRuntimeKeyIDs: append(
			[]string(nil), state.RevokedRuntimeKeyIDs...,
		),
		ObservedMasterSeqno: state.ObservedMasterSeqno,
		ObservedAt:          state.ObservedAt,
	}, nil
}
