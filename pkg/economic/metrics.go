package economic

import (
	"errors"
	"math/big"
	"sort"
)

// Window is a half-open finalized-time interval [From, To). Every windowed
// metric selects a job by the one finalized time that metric is defined over --
// acceptance, funding, or terminal -- so the same job can enter one series and
// not another.
type Window struct {
	From uint64
	To   uint64
}

// Validate enforces a non-empty, ordered window.
func (w Window) Validate() error {
	if w.To <= w.From {
		return errors.New("window end must be after its start")
	}
	return nil
}

func (w Window) contains(unix uint64) bool {
	return unix >= w.From && unix < w.To
}

// NetworkMetrics is the network-level projection for one asset bucket over one
// window. Amounts are canonical unsigned atomic strings; a nil rate or latency
// is the spec's null -- a rate with no denominator, or a percentile with no
// samples, is absent, never zero.
type NetworkMetrics struct {
	Asset  AssetIdentity
	Window Window

	// Value.
	SettledCashFlowAtomic                    string
	GrossAgentValueAtomic                    string
	SettledProviderReceiptsAtomic            string
	UnattributedReleasedValueAtomic          string
	AttributionUnresolvedReleasedValueAtomic string

	// Counts.
	AcceptedJobCount                   uint64
	FundedJobCount                     uint64
	ReleasedEscrowCount                uint64
	AttributedSettledJobCount          uint64
	RefundedJobCount                   uint64
	UniqueBuyerWalletCount             uint64
	UniqueQuoteNamedProviderAgentCount uint64
	UniqueAttributedProviderAgentCount uint64

	// Rates, integer parts-per-million, null when the denominator is zero.
	TerminalReleaseRatePPM *uint32
	RefundRatePPM          *uint32

	// Settlement latency in seconds over funding-to-terminal durations of jobs
	// terminal in the window, null when there are no such jobs.
	MedianSettlementSeconds *uint64
	P95SettlementSeconds    *uint64
}

// AggregateNetwork computes the network-level metrics for each exact asset over
// one window. Output is one entry per asset, ordered by asset key, so the same
// evidence always produces the same sequence.
//
// The input is the set of verified jobs the verification layer emitted. Jobs are
// rejected for being malformed or for sharing an identifier, because two records
// of one job are duplicate terminal evidence, which the spec requires be refused
// rather than resolved by arrival order.
func AggregateNetwork(jobs []VerifiedJob, window Window) ([]NetworkMetrics, error) {
	if err := window.Validate(); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(jobs))
	buckets := make(map[string][]VerifiedJob)
	var order []string
	for _, job := range jobs {
		if err := job.Validate(); err != nil {
			return nil, err
		}
		if _, duplicate := seen[job.JobID]; duplicate {
			return nil, errors.New("two records name the same job")
		}
		seen[job.JobID] = struct{}{}
		key := job.Asset.key()
		if _, known := buckets[key]; !known {
			order = append(order, key)
		}
		buckets[key] = append(buckets[key], job)
	}
	sort.Strings(order)

	metrics := make([]NetworkMetrics, 0, len(order))
	for _, key := range order {
		bucket, err := aggregateBucket(buckets[key], window)
		if err != nil {
			return nil, err
		}
		metrics = append(metrics, bucket)
	}
	return metrics, nil
}

func aggregateBucket(jobs []VerifiedJob, window Window) (NetworkMetrics, error) {
	result := NetworkMetrics{Asset: jobs[0].Asset, Window: window}

	settled := newSum256()
	gross := newSum256()
	unattributed := newSum256()
	unresolved := newSum256()

	buyerWallets := newStringSet()
	namedProviders := newStringSet()
	attributedProviders := newStringSet()
	var durations []uint64

	for _, job := range jobs {
		// Membership in the "seen this window" set is the union of the three
		// finalized times, which the unique-participant counts are defined over.
		if window.contains(job.AcceptanceTime) ||
			window.contains(job.FundingTime) ||
			(job.TerminalTime != 0 && window.contains(job.TerminalTime)) {
			buyerWallets.add(job.BuyerWallet)
			namedProviders.add(job.ProviderAgentID)
		}

		if window.contains(job.AcceptanceTime) {
			if err := incr(&result.AcceptedJobCount); err != nil {
				return NetworkMetrics{}, err
			}
		}
		if window.contains(job.FundingTime) {
			if err := incr(&result.FundedJobCount); err != nil {
				return NetworkMetrics{}, err
			}
		}

		if !job.isTerminal() || !window.contains(job.TerminalTime) {
			continue
		}
		// Terminal in the window: this is where value, terminal counts, rates,
		// and settlement latency are measured.
		durations = append(durations, job.TerminalTime-job.FundingTime)

		switch job.Outcome {
		case OutcomeReleased:
			if err := incr(&result.ReleasedEscrowCount); err != nil {
				return NetworkMetrics{}, err
			}
			if err := settled.add(job.Amount); err != nil {
				return NetworkMetrics{}, err
			}
			switch job.Attribution {
			case AttributionAttributed:
				if err := gross.add(job.Amount); err != nil {
					return NetworkMetrics{}, err
				}
				if err := incr(&result.AttributedSettledJobCount); err != nil {
					return NetworkMetrics{}, err
				}
				attributedProviders.add(job.ProviderAgentID)
			case AttributionUnattributed:
				if err := unattributed.add(job.Amount); err != nil {
					return NetworkMetrics{}, err
				}
			case AttributionUnresolved:
				if err := unresolved.add(job.Amount); err != nil {
					return NetworkMetrics{}, err
				}
			}
		case OutcomeRefunded:
			if err := incr(&result.RefundedJobCount); err != nil {
				return NetworkMetrics{}, err
			}
		}
	}

	// The identity the value buckets must satisfy: released cash flow is exactly
	// its attributed, unattributed, and attribution-unresolved parts.
	if !equalSum(settled, gross, unattributed, unresolved) {
		return NetworkMetrics{}, errors.New("released value does not partition into its attribution buckets")
	}

	result.SettledCashFlowAtomic = settled.string()
	result.GrossAgentValueAtomic = gross.string()
	// In fixed-price V1 provider receipts equal gross Agent value.
	result.SettledProviderReceiptsAtomic = gross.string()
	result.UnattributedReleasedValueAtomic = unattributed.string()
	result.AttributionUnresolvedReleasedValueAtomic = unresolved.string()

	result.UniqueBuyerWalletCount = buyerWallets.size()
	result.UniqueQuoteNamedProviderAgentCount = namedProviders.size()
	result.UniqueAttributedProviderAgentCount = attributedProviders.size()

	terminalTotal := result.ReleasedEscrowCount + result.RefundedJobCount
	result.TerminalReleaseRatePPM = ratePPM(result.ReleasedEscrowCount, terminalTotal)
	result.RefundRatePPM = ratePPM(result.RefundedJobCount, terminalTotal)

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	result.MedianSettlementSeconds = median(durations)
	result.P95SettlementSeconds = p95(durations)

	return result, nil
}

// ratePPM is floor(numerator * 1_000_000 / denominator) in integer
// parts-per-million, or null when the denominator is zero. The multiplication
// is done in arbitrary precision so a large count cannot overflow it before the
// divide; for these rates the numerator never exceeds the denominator, so the
// result is at most 1_000_000 and fits a uint32.
func ratePPM(numerator, denominator uint64) *uint32 {
	if denominator == 0 {
		return nil
	}
	scaled := new(big.Int).Mul(new(big.Int).SetUint64(numerator), big.NewInt(1_000_000))
	scaled.Quo(scaled, new(big.Int).SetUint64(denominator))
	value := uint32(scaled.Uint64())
	return &value
}

// median returns the floor of the middle of a sorted slice: the central value
// for odd length, the floor of the mean of the two central values for even
// length, computed so two large durations cannot overflow their sum.
func median(sorted []uint64) *uint64 {
	n := len(sorted)
	if n == 0 {
		return nil
	}
	if n%2 == 1 {
		value := sorted[n/2]
		return &value
	}
	low := sorted[n/2-1]
	high := sorted[n/2]
	value := low/2 + high/2 + (low%2+high%2)/2
	return &value
}

// p95 returns the nearest-rank 95th percentile: the sorted value at one-based
// rank ceil(0.95 * n).
func p95(sorted []uint64) *uint64 {
	n := len(sorted)
	if n == 0 {
		return nil
	}
	rank := (95*n + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	value := sorted[rank-1]
	return &value
}

// incr adds one to a count, failing closed rather than wrapping. A count derived
// from a bounded slice cannot reach this, but the spec requires overflow to be
// rejected, not assumed impossible.
func incr(count *uint64) error {
	if *count == ^uint64(0) {
		return errors.New("count overflowed")
	}
	*count++
	return nil
}
