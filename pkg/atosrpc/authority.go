package atosrpc

import (
	"context"
	"errors"
	"strings"
)

type localAuthority struct {
	network string
}

func NewLocalAuthority(network string) Authority {
	network = strings.TrimSpace(network)
	if network == "" {
		network = "tos-local"
	}
	if network != "tos-local" && !strings.HasPrefix(network, "tos-dev-") {
		// The bundled authority is deliberately incapable of claiming a
		// production TOS network reference.
		network = "tos-local"
	}
	return &localAuthority{network: network}
}

func (a *localAuthority) Network() string { return a.network }

func (a *localAuthority) Supports(mode TrustMode) bool {
	return mode == TrustModeManaged
}

func (a *localAuthority) CheckReady(ctx context.Context) error {
	if a == nil || strings.TrimSpace(a.network) == "" {
		return errors.New("invalid local authority")
	}
	if ctx == nil {
		return errors.New("nil local authority context")
	}
	return ctx.Err()
}

func (a *localAuthority) Close() error { return nil }

func (a *localAuthority) Commit(_ context.Context, kind, id, digest string) (NetworkReference, error) {
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(id) == "" || strings.TrimSpace(digest) == "" {
		return NetworkReference{}, errors.New("invalid local commitment")
	}
	return NetworkReference{
		Network:   a.network,
		Reference: "atosrpc:" + kind + ":" + id + ":" + digest,
		Finalized: false,
	}, nil
}
