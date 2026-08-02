package payment

import (
	"context"
	"errors"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

func safeObservePayment(
	resolver Resolver,
	ctx context.Context,
	reference chain.PaymentReference,
) (state chain.PaymentState, err error) {
	defer func() {
		if recover() != nil {
			state = chain.PaymentState{}
			err = errors.New("payment resolver panicked")
		}
	}()
	return resolver.ObservePayment(ctx, reference)
}
