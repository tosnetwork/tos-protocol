// Package economic is the deterministic aggregator half of the agent economy
// metrics profile (tos-service-spec docs/AGENT_ECONOMY_METRICS_V1.md).
//
// The profile draws a line the spec draws for it: a verification and attribution
// layer authenticates finalized chain evidence -- escrow deployment, funding,
// Receipt, stablecoin transfer, release outcome, and the historical Registry
// facts that decide whether a released payment may be attributed to the Agent
// its Quote names -- and emits already-verified job records. That layer needs a
// chain. This package is the other half: given those records, it computes the
// exact-asset statistics deterministically, so two indexers observing the same
// finalized interval produce the same values. It reads no chain and holds no
// authority; the finalized state is the authority, and this is a replaceable
// projection of it.
//
// Everything here is pure computation over the supplied evidence. What it does
// not do -- scan finalized transactions, authenticate the terminal chain,
// resolve attribution against archived Registry history, or export a protobuf
// API -- is named in the roadmap as belonging to the verification layer or to a
// later slice, and is not stubbed here.
package economic

import (
	"errors"
	"math/big"
	"regexp"
)

// atomicPattern matches a canonical unsigned atomic-unit amount: zero, or a
// positive integer with no leading zero, no sign, and no separators. One value
// has one encoding, because two encodings of one amount are two inputs to one
// sum.
var atomicPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// maxU256 is the exclusive upper bound on every aggregate amount. The spec
// requires aggregates to stay below 2^256 and any overflow to invalidate the
// report, never to saturate or wrap.
var maxU256 = new(big.Int).Lsh(big.NewInt(1), 256)

// ErrAmountOverflow reports an aggregate that reached or passed 2^256.
var ErrAmountOverflow = errors.New("aggregate amount reached the 2^256 bound")

// parseAtomic validates and parses one canonical unsigned atomic amount. A value
// at or above 2^256 is rejected at the door, so no single input can carry a sum
// past the bound on its own.
func parseAtomic(value string) (*big.Int, error) {
	if !atomicPattern.MatchString(value) {
		return nil, errors.New("amount is not a canonical unsigned atomic value")
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, errors.New("amount is not a base-10 integer")
	}
	if parsed.Sign() < 0 || parsed.Cmp(maxU256) >= 0 {
		return nil, ErrAmountOverflow
	}
	return parsed, nil
}

// sum256 accumulates canonical unsigned atomic amounts under the 2^256 bound.
// It is the only place amounts are added, so the bound is enforced in exactly
// one place rather than at every call site.
type sum256 struct {
	total *big.Int
}

func newSum256() *sum256 { return &sum256{total: new(big.Int)} }

// add folds one canonical amount into the running total, failing closed if the
// input is malformed or the total would reach the bound.
func (s *sum256) add(value string) error {
	parsed, err := parseAtomic(value)
	if err != nil {
		return err
	}
	next := new(big.Int).Add(s.total, parsed)
	if next.Cmp(maxU256) >= 0 {
		return ErrAmountOverflow
	}
	s.total = next
	return nil
}

// string returns the canonical decimal encoding of the total: no leading zero,
// no sign, "0" for an empty sum.
func (s *sum256) string() string { return s.total.String() }

// equalSum reports whether a total equals the sum of parts, the identity the
// value metrics must satisfy (settled cash flow equals the attributed,
// unattributed, and attribution-unresolved parts). It is a self-check against a
// bucketing mistake, not a metric.
func equalSum(total *sum256, parts ...*sum256) bool {
	combined := new(big.Int)
	for _, part := range parts {
		combined.Add(combined, part.total)
	}
	return combined.Cmp(total.total) == 0
}
