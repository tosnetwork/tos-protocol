package chainactionpublisher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

// CommandBackend delegates key custody to an owner-controlled executable.
// The executable receives `check-ready` or `publish`, with the action JSON on
// stdin for publish, and must be idempotent by ActionID.
type CommandBackend struct {
	path string
	args []string
}

func NewCommandBackend(path string, args []string) (*CommandBackend, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("backend command must be absolute and clean")
	}
	return &CommandBackend{path: path, args: append([]string(nil), args...)}, nil
}
func (b *CommandBackend) CheckReady(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, b.path, append(b.args, "check-ready")...)
	return cmd.Run()
}
func (b *CommandBackend) Publish(ctx context.Context, a chain.Action, recovering bool) (chain.ActionReceipt, error) {
	mode := "publish"
	if recovering {
		mode = "recover"
	}
	raw, _ := json.Marshal(a)
	cmd := exec.CommandContext(ctx, b.path, append(b.args, mode)...)
	cmd.Stdin = bytes.NewReader(raw)
	out, err := cmd.Output()
	if err != nil || len(out) > 1<<20 {
		return chain.ActionReceipt{}, errors.New("chain action backend failed")
	}
	var receipt chain.ActionReceipt
	if jsonstrict.Decode(out, &receipt) != nil {
		return chain.ActionReceipt{}, errors.New("chain action backend returned invalid receipt")
	}
	return receipt, nil
}
func (*CommandBackend) Close() error { return nil }
