package toschain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
)

type consensusObservation struct {
	seqno      uint64
	observedAt time.Time
}

type consensusResult struct {
	Type           string `json:"@type"`
	ConsensusBlock uint64 `json:"consensus_block"`
	Timestamp      int64  `json:"timestamp"`
	LastBlockUtime int64  `json:"last_block_utime"`
}

type consensusVote struct {
	ConsensusBlock uint64 `json:"consensus_block"`
	LastBlockUtime int64  `json:"last_block_utime"`
}

type quorumValue[T any] struct {
	node  *rpcNode
	value T
	err   error
}

func (a *Adapter) consensus(ctx context.Context) (consensusObservation, []*rpcNode, error) {
	result, nodes, err := quorumRead(ctx, a.nodes, a.quorum, func(
		ctx context.Context,
		node *rpcNode,
	) (consensusVote, error) {
		var value consensusResult
		if err := node.client.Call(ctx, "getConsensusBlock", struct{}{}, &value); err != nil {
			return consensusVote{}, err
		}
		if value.Type != "ext.blocks.consensusBlock" || value.ConsensusBlock == 0 ||
			value.Timestamp <= 0 || value.LastBlockUtime <= 0 ||
			value.LastBlockUtime > value.Timestamp+int64(identity.MaxClockSkew/time.Second) {
			return consensusVote{}, errors.New("invalid TOS consensus-block response")
		}
		// timestamp is when this particular process first observed the block
		// and can legitimately differ by one second across nodes. Finality
		// quorum is over the block seqno and its chain-authored unix time.
		return consensusVote{
			ConsensusBlock: value.ConsensusBlock,
			LastBlockUtime: value.LastBlockUtime,
		}, nil
	})
	if err != nil {
		return consensusObservation{}, nil, fmt.Errorf("resolve TOS consensus quorum: %w", err)
	}
	return consensusObservation{
		seqno:      result.ConsensusBlock,
		observedAt: time.Unix(result.LastBlockUtime, 0).UTC(),
	}, nodes, nil
}

func quorumRead[T any](
	ctx context.Context,
	nodes []*rpcNode,
	quorum int,
	read func(context.Context, *rpcNode) (T, error),
) (T, []*rpcNode, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, nil, err
	}
	results := make(chan quorumValue[T], len(nodes))
	for _, node := range nodes {
		node := node
		go func() {
			value, err := read(ctx, node)
			results <- quorumValue[T]{node: node, value: value, err: err}
		}()
	}
	type group struct {
		value T
		nodes []*rpcNode
	}
	groups := make(map[string]*group, len(nodes))
	failures := 0
	for range nodes {
		result := <-results
		if result.err != nil {
			failures++
			continue
		}
		key, err := quorumKey(result.value)
		if err != nil {
			failures++
			continue
		}
		current := groups[key]
		if current == nil {
			current = &group{value: result.value}
			groups[key] = current
		}
		current.nodes = append(current.nodes, result.node)
	}
	if err := ctx.Err(); err != nil {
		return zero, nil, err
	}
	for _, candidate := range groups {
		if len(candidate.nodes) >= quorum {
			return candidate.value, candidate.nodes, nil
		}
	}
	return zero, nil, fmt.Errorf(
		"quorum not reached: %d value groups and %d endpoint errors",
		len(groups), failures,
	)
}

func quorumKey(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
