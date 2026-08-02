package authorization

import (
	"context"
	"errors"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

func safeResolveAuthority(
	resolver Resolver,
	ctx context.Context,
	reference Reference,
) (snapshot AuthoritySnapshot, err error) {
	defer func() {
		if recover() != nil {
			snapshot = AuthoritySnapshot{}
			err = errors.New("authority resolver panicked")
		}
	}()
	return resolver.ResolveAuthority(ctx, reference)
}

func safeResolveClientKey(
	resolver ClientKeyResolver,
	ctx context.Context,
	reference ClientKeyReference,
) (snapshot ClientKeySnapshot, err error) {
	defer func() {
		if recover() != nil {
			snapshot = ClientKeySnapshot{}
			err = errors.New("client-key resolver panicked")
		}
	}()
	return resolver.ResolveClientKey(ctx, reference)
}

func safeResolveService(
	reader ChainServiceReader,
	ctx context.Context,
	reference chain.ServiceReference,
) (state chain.ServiceState, err error) {
	defer func() {
		if recover() != nil {
			state = chain.ServiceState{}
			err = errors.New("chain service reader panicked")
		}
	}()
	return reader.ResolveService(ctx, reference)
}
