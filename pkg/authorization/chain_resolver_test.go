package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

const testServiceCodeHash = "sha256:service-actor-v1"

type chainReaderFunc func(
	context.Context,
	chain.ServiceReference,
) (chain.ServiceState, error)

func (f chainReaderFunc) ResolveService(
	ctx context.Context,
	reference chain.ServiceReference,
) (chain.ServiceState, error) {
	return f(ctx, reference)
}

func fixtureServiceState(
	fixture authFixture,
	reference Reference,
) chain.ServiceState {
	return chain.ServiceState{
		Network: reference.Network, Address: reference.Address,
		ServiceID: reference.ServiceID, Active: true, Finalized: true,
		Controller: fixture.snapshot.Controller,
		ControllerPublicKey: append(
			[]byte(nil), fixture.snapshot.ControllerPublicKey...,
		),
		ManifestDigest: fixture.snapshot.ManifestDigest,
		RevokedRuntimeKeyIDs: append(
			[]string(nil), fixture.snapshot.RevokedRuntimeKeyIDs...,
		),
		CodeHash: testServiceCodeHash, ObservedMasterSeqno: 100,
		ObservedAt: fixture.now.Add(-time.Second),
	}
}

func newTestChainResolver(
	t *testing.T,
	reader ChainServiceReader,
) *ChainResolver {
	t.Helper()
	resolver, err := NewChainResolver(
		reader,
		DefaultChainResolverPolicy([]string{testServiceCodeHash}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestChainResolverCompletesManifestAuthorizationBoundary(t *testing.T) {
	fixture := newAuthFixture(t)
	reference := Reference{
		Network:            fixture.manifest.Network,
		Address:            "tos:test:service-actor",
		ServiceID:          fixture.manifest.ServiceID,
		MinimumMasterSeqno: 99,
	}
	expectedState := fixtureServiceState(fixture, reference)
	resolver := newTestChainResolver(t, chainReaderFunc(func(
		_ context.Context,
		received chain.ServiceReference,
	) (chain.ServiceState, error) {
		if received.Network != reference.Network ||
			received.Address != reference.Address ||
			received.ServiceID != reference.ServiceID {
			t.Fatalf("unexpected service reference: %#v", received)
		}
		return expectedState, nil
	}))
	if _, err := newTestVerifier(t).ResolveAndVerifyManifest(
		context.Background(), resolver, reference,
		fixture.manifestEnvelope, fixture.now,
	); err != nil {
		t.Fatal(err)
	}
}

func TestChainResolverRejectsSubstitutionFinalityCodeAndRollback(t *testing.T) {
	fixture := newAuthFixture(t)
	reference := Reference{
		Network:            fixture.manifest.Network,
		Address:            "tos:test:service-actor",
		ServiceID:          fixture.manifest.ServiceID,
		MinimumMasterSeqno: 100,
	}
	valid := fixtureServiceState(fixture, reference)
	tests := []struct {
		name   string
		mutate func(*chain.ServiceState)
	}{
		{
			name: "address substitution",
			mutate: func(state *chain.ServiceState) {
				state.Address = "tos:test:another-service"
			},
		},
		{
			name: "unfinalized",
			mutate: func(state *chain.ServiceState) {
				state.Finalized = false
			},
		},
		{
			name: "wrong code",
			mutate: func(state *chain.ServiceState) {
				state.CodeHash = "sha256:unknown-contract"
			},
		},
		{
			name: "masterchain rollback",
			mutate: func(state *chain.ServiceState) {
				state.ObservedMasterSeqno = 99
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := valid
			test.mutate(&state)
			resolver := newTestChainResolver(t, chainReaderFunc(func(
				context.Context,
				chain.ServiceReference,
			) (chain.ServiceState, error) {
				return state, nil
			}))
			if _, err := newTestVerifier(t).ResolveAndVerifyManifest(
				context.Background(), resolver, reference,
				fixture.manifestEnvelope, fixture.now,
			); err == nil {
				t.Fatal("invalid chain authority accepted")
			}
		})
	}
}

func TestChainResolverEnforcesTimeoutAndPropagatesCancellation(t *testing.T) {
	policy := DefaultChainResolverPolicy([]string{testServiceCodeHash})
	policy.QueryTimeout = 10 * time.Millisecond
	resolver, err := NewChainResolver(
		chainReaderFunc(func(
			ctx context.Context,
			_ chain.ServiceReference,
		) (chain.ServiceState, error) {
			<-ctx.Done()
			return chain.ServiceState{}, ctx.Err()
		}),
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	reference := Reference{
		Network: "testnet", Address: "tos:test:service-actor",
		ServiceID: "edge.example.ai",
	}
	if _, err := resolver.ResolveAuthority(
		context.Background(), reference,
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveAuthority(
		ctx, reference,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestChainResolverContainsReaderPanic(t *testing.T) {
	resolver := newTestChainResolver(t, chainReaderFunc(func(
		context.Context,
		chain.ServiceReference,
	) (chain.ServiceState, error) {
		panic("mock chain reader secret")
	}))
	_, err := resolver.ResolveAuthority(context.Background(), Reference{
		Network: "testnet", Address: "tos:test:service-actor",
		ServiceID: "edge.example.ai",
	})
	if err == nil || !strings.Contains(err.Error(), "chain service reader panicked") ||
		strings.Contains(err.Error(), "mock chain reader secret") {
		t.Fatalf("chain reader panic was not safely converted: %v", err)
	}
}

func TestChainResolverRejectsCancellationLateReaderSuccess(t *testing.T) {
	fixture := newAuthFixture(t)
	reference := Reference{
		Network: fixture.manifest.Network, Address: "tos:test:service-actor",
		ServiceID: fixture.manifest.ServiceID,
	}
	ctx, cancel := context.WithCancel(context.Background())
	resolver := newTestChainResolver(t, chainReaderFunc(func(
		context.Context,
		chain.ServiceReference,
	) (chain.ServiceState, error) {
		cancel()
		return fixtureServiceState(fixture, reference), nil
	}))
	if _, err := resolver.ResolveAuthority(ctx, reference); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation-late chain success accepted: %v", err)
	}
}

func TestChainResolverDefensivelyCopiesAuthorityState(t *testing.T) {
	fixture := newAuthFixture(t)
	reference := Reference{
		Network:   fixture.manifest.Network,
		Address:   "tos:test:service-actor",
		ServiceID: fixture.manifest.ServiceID,
	}
	state := fixtureServiceState(fixture, reference)
	state.RevokedRuntimeKeyIDs = []string{"runtime-key-old"}
	resolver := newTestChainResolver(t, chainReaderFunc(func(
		context.Context,
		chain.ServiceReference,
	) (chain.ServiceState, error) {
		return state, nil
	}))
	snapshot, err := resolver.ResolveAuthority(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	state.ControllerPublicKey[0] ^= 1
	state.RevokedRuntimeKeyIDs[0] = "changed-key"
	if snapshot.ControllerPublicKey[0] !=
		fixture.snapshot.ControllerPublicKey[0] {
		t.Fatal("controller public key aliases adapter memory")
	}
	if snapshot.RevokedRuntimeKeyIDs[0] != "runtime-key-old" {
		t.Fatal("revocation list aliases adapter memory")
	}
}

func TestChainResolverPolicyIsStrictAndBounded(t *testing.T) {
	reader := chainReaderFunc(func(
		context.Context,
		chain.ServiceReference,
	) (chain.ServiceState, error) {
		return chain.ServiceState{}, nil
	})
	tests := []ChainResolverPolicy{
		DefaultChainResolverPolicy(nil),
		DefaultChainResolverPolicy([]string{"duplicate", "duplicate"}),
		DefaultChainResolverPolicy([]string{" leading-space"}),
	}
	tooMany := make([]string, MaxAllowedServiceCodes+1)
	for index := range tooMany {
		tooMany[index] = "code-" + strings.Repeat("x", index+1)
	}
	tests = append(tests, DefaultChainResolverPolicy(tooMany))
	for index, policy := range tests {
		if _, err := NewChainResolver(reader, policy); err == nil {
			t.Fatalf("invalid policy %d accepted", index)
		}
	}
	var typedNil chainReaderFunc
	if resolver, err := NewChainResolver(
		typedNil, DefaultChainResolverPolicy([]string{testServiceCodeHash}),
	); err == nil || resolver != nil {
		t.Fatal("typed-nil chain reader accepted")
	}
}
