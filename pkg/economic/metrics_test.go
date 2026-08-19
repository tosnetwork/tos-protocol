package economic

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the frozen metrics vector")

func hexOf(seed byte) string {
	body := make([]byte, 64)
	for i := range body {
		body[i] = "0123456789abcdef"[seed%16]
	}
	body[0] = "0123456789abcdef"[(seed/16)%16]
	body[1] = "0123456789abcdef"[seed%16]
	return string(body)
}

func testAsset() AssetIdentity {
	return AssetIdentity{
		NetworkID:       "tos-local",
		MasterWorkchain: 0,
		MasterAccountID: strings.Repeat("a", 64),
		MasterCodeHash:  "tvm-cell-sha256:" + strings.Repeat("b", 64),
		WalletCodeHash:  "tvm-cell-sha256:" + strings.Repeat("c", 64),
		Decimals:        6,
	}
}

func job(seed, provider, buyer byte, outcome Outcome, attribution Attribution, amount string, funding, terminal uint64) VerifiedJob {
	j := VerifiedJob{
		JobID:             "sha256:" + hexOf(seed),
		Asset:             testAsset(),
		BuyerWallet:       hexOf(buyer),
		ProviderAgentID:   "agent_" + hexOf(provider),
		CapabilityID:      "cap_" + hexOf(1),
		CapabilityVersion: "1.0.0",
		Outcome:           outcome,
		Attribution:       attribution,
		Amount:            amount,
		AcceptanceTime:    funding - 10,
		FundingTime:       funding,
		TerminalTime:      terminal,
	}
	return j
}

// happyJobs is the fixture the value, count, rate, and latency assertions share.
// Window is [1000, 2000).
func happyJobs() []VerifiedJob {
	return []VerifiedJob{
		job(1, 10, 20, OutcomeReleased, AttributionAttributed, "100", 1100, 1200),
		job(2, 10, 21, OutcomeReleased, AttributionAttributed, "50", 1000, 1300),
		job(3, 11, 20, OutcomeReleased, AttributionUnattributed, "30", 1100, 1400),
		job(4, 12, 22, OutcomeReleased, AttributionUnresolved, "20", 1000, 1500),
		job(5, 13, 23, OutcomeRefunded, AttributionNone, "10", 1000, 1600),
	}
}

func onlyBucket(t *testing.T, jobs []VerifiedJob, window Window) NetworkMetrics {
	t.Helper()
	metrics, err := AggregateNetwork(jobs, window)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(metrics) != 1 {
		t.Fatalf("expected one asset bucket, got %d", len(metrics))
	}
	return metrics[0]
}

func TestAggregateValueAndIdentity(t *testing.T) {
	m := onlyBucket(t, happyJobs(), Window{From: 1000, To: 2000})
	if m.SettledCashFlowAtomic != "200" {
		t.Fatalf("settled cash flow = %q, want 200", m.SettledCashFlowAtomic)
	}
	if m.GrossAgentValueAtomic != "150" || m.SettledProviderReceiptsAtomic != "150" {
		t.Fatalf("gross/receipts = %q/%q, want 150/150", m.GrossAgentValueAtomic, m.SettledProviderReceiptsAtomic)
	}
	if m.UnattributedReleasedValueAtomic != "30" || m.AttributionUnresolvedReleasedValueAtomic != "20" {
		t.Fatalf("unattributed/unresolved = %q/%q, want 30/20", m.UnattributedReleasedValueAtomic, m.AttributionUnresolvedReleasedValueAtomic)
	}
}

func TestAggregateCounts(t *testing.T) {
	m := onlyBucket(t, happyJobs(), Window{From: 1000, To: 2000})
	// Acceptance times are funding-10: only the jobs funded at 1100 accept
	// inside the window; those funded at 1000 accept at 990, outside it.
	if m.AcceptedJobCount != 2 {
		t.Fatalf("accepted = %d, want 2", m.AcceptedJobCount)
	}
	if m.FundedJobCount != 5 {
		t.Fatalf("funded = %d, want 5", m.FundedJobCount)
	}
	if m.ReleasedEscrowCount != 4 || m.AttributedSettledJobCount != 2 || m.RefundedJobCount != 1 {
		t.Fatalf("released/attributed/refunded = %d/%d/%d, want 4/2/1",
			m.ReleasedEscrowCount, m.AttributedSettledJobCount, m.RefundedJobCount)
	}
	if m.UniqueBuyerWalletCount != 4 {
		t.Fatalf("unique buyers = %d, want 4", m.UniqueBuyerWalletCount)
	}
	if m.UniqueQuoteNamedProviderAgentCount != 4 || m.UniqueAttributedProviderAgentCount != 1 {
		t.Fatalf("named/attributed providers = %d/%d, want 4/1",
			m.UniqueQuoteNamedProviderAgentCount, m.UniqueAttributedProviderAgentCount)
	}
}

func TestAggregateRatesAndLatency(t *testing.T) {
	m := onlyBucket(t, happyJobs(), Window{From: 1000, To: 2000})
	// released/(released+refunded) = 4/5 = 800000 ppm; refund = 1/5 = 200000.
	if m.TerminalReleaseRatePPM == nil || *m.TerminalReleaseRatePPM != 800000 {
		t.Fatalf("release rate = %v, want 800000", m.TerminalReleaseRatePPM)
	}
	if m.RefundRatePPM == nil || *m.RefundRatePPM != 200000 {
		t.Fatalf("refund rate = %v, want 200000", m.RefundRatePPM)
	}
	// funding-to-terminal durations: 100,300,300,500,600 -> median 300, p95 600.
	if m.MedianSettlementSeconds == nil || *m.MedianSettlementSeconds != 300 {
		t.Fatalf("median = %v, want 300", m.MedianSettlementSeconds)
	}
	if m.P95SettlementSeconds == nil || *m.P95SettlementSeconds != 600 {
		t.Fatalf("p95 = %v, want 600", m.P95SettlementSeconds)
	}
}

// A rate with no terminal jobs is null, not zero, and a percentile with no
// samples is null too.
func TestZeroDenominatorIsNull(t *testing.T) {
	// One job that never reached a terminal outcome.
	open := job(1, 10, 20, OutcomeNone, AttributionNone, "", 1000, 0)
	m := onlyBucket(t, []VerifiedJob{open}, Window{From: 1000, To: 2000})
	if m.TerminalReleaseRatePPM != nil || m.RefundRatePPM != nil {
		t.Fatal("a rate with no terminal jobs was not null")
	}
	if m.MedianSettlementSeconds != nil || m.P95SettlementSeconds != nil {
		t.Fatal("a percentile with no samples was not null")
	}
	if m.SettledCashFlowAtomic != "0" {
		t.Fatalf("settled cash flow with no releases = %q, want 0", m.SettledCashFlowAtomic)
	}
}

// The even-length median is the floor of the mean of the two central values.
func TestEvenMedianFloors(t *testing.T) {
	jobs := []VerifiedJob{
		job(1, 10, 20, OutcomeReleased, AttributionAttributed, "1", 1000, 1003), // dur 3
		job(2, 10, 21, OutcomeReleased, AttributionAttributed, "1", 1000, 1004), // dur 4
	}
	m := onlyBucket(t, jobs, Window{From: 1000, To: 2000})
	if m.MedianSettlementSeconds == nil || *m.MedianSettlementSeconds != 3 {
		t.Fatalf("median of {3,4} = %v, want floor 3", m.MedianSettlementSeconds)
	}
}

// The 95th percentile is the nearest-rank value at ceil(0.95*n).
func TestP95NearestRank(t *testing.T) {
	var jobs []VerifiedJob
	// Twenty durations 10,20,...,200; ceil(0.95*20)=19 -> 19th value = 190.
	for i := 1; i <= 20; i++ {
		jobs = append(jobs, job(byte(i), 10, 20, OutcomeReleased, AttributionAttributed, "1", 1000, uint64(1000+i*10)))
	}
	m := onlyBucket(t, jobs, Window{From: 1000, To: 3000})
	if m.P95SettlementSeconds == nil || *m.P95SettlementSeconds != 190 {
		t.Fatalf("p95 = %v, want 190", m.P95SettlementSeconds)
	}
}

// The window is half-open: a terminal at exactly To is excluded, at From
// included.
func TestWindowIsHalfOpen(t *testing.T) {
	atFrom := job(1, 10, 20, OutcomeReleased, AttributionAttributed, "5", 900, 1000)
	atTo := job(2, 10, 21, OutcomeReleased, AttributionAttributed, "7", 1500, 2000)
	m := onlyBucket(t, []VerifiedJob{atFrom, atTo}, Window{From: 1000, To: 2000})
	// Only the terminal at 1000 counts; the one at 2000 is the next window's.
	if m.ReleasedEscrowCount != 1 || m.SettledCashFlowAtomic != "5" {
		t.Fatalf("half-open boundary wrong: released=%d value=%q", m.ReleasedEscrowCount, m.SettledCashFlowAtomic)
	}
}

// Two assets never share a bucket, and the output is ordered by asset.
func TestPerAssetSeparation(t *testing.T) {
	a := job(1, 10, 20, OutcomeReleased, AttributionAttributed, "100", 1000, 1100)
	b := job(2, 10, 21, OutcomeReleased, AttributionAttributed, "1", 1000, 1100)
	b.Asset.MasterAccountID = strings.Repeat("f", 64) // a different asset
	metrics, err := AggregateNetwork([]VerifiedJob{a, b}, Window{From: 1000, To: 2000})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected two asset buckets, got %d", len(metrics))
	}
	// Ordered by asset key: "aaaa..." sorts before "ffff...".
	if metrics[0].SettledCashFlowAtomic != "100" || metrics[1].SettledCashFlowAtomic != "1" {
		t.Fatalf("assets were summed or misordered: %q then %q",
			metrics[0].SettledCashFlowAtomic, metrics[1].SettledCashFlowAtomic)
	}
}

// An aggregate that would reach 2^256 invalidates the report.
func TestOverflowInvalidates(t *testing.T) {
	huge := strings.Repeat("9", 78) // ~10^78, above 2^256 (~1.16e77)
	j := job(1, 10, 20, OutcomeReleased, AttributionAttributed, huge, 1000, 1100)
	if _, err := AggregateNetwork([]VerifiedJob{j}, Window{From: 1000, To: 2000}); err == nil {
		t.Fatal("an amount above the 2^256 bound was accepted")
	}
}

// Two records of one job are duplicate terminal evidence and are refused.
func TestDuplicateJobRefused(t *testing.T) {
	j := job(1, 10, 20, OutcomeReleased, AttributionAttributed, "1", 1000, 1100)
	if _, err := AggregateNetwork([]VerifiedJob{j, j}, Window{From: 1000, To: 2000}); err == nil {
		t.Fatal("a duplicate job was accepted")
	}
}

func TestMalformedInputsRefused(t *testing.T) {
	cases := map[string]func(*VerifiedJob){
		"bad job id":         func(j *VerifiedJob) { j.JobID = "nope" },
		"unordered times":    func(j *VerifiedJob) { j.TerminalTime = j.FundingTime - 1 },
		"released no attr":   func(j *VerifiedJob) { j.Attribution = AttributionNone },
		"refund with attr":   func(j *VerifiedJob) { j.Outcome = OutcomeRefunded; j.Attribution = AttributionAttributed },
		"terminal no amount": func(j *VerifiedJob) { j.Amount = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			j := job(1, 10, 20, OutcomeReleased, AttributionAttributed, "1", 1000, 1100)
			mutate(&j)
			if _, err := AggregateNetwork([]VerifiedJob{j}, Window{From: 1000, To: 2000}); err == nil {
				t.Fatalf("a job with %q was accepted", name)
			}
		})
	}
}

func TestWindowMustBeOrdered(t *testing.T) {
	if _, err := AggregateNetwork(nil, Window{From: 2000, To: 1000}); err == nil {
		t.Fatal("an inverted window was accepted")
	}
}

// A frozen input->output vector. It is a regression anchor and the seed of the
// cross-implementation vector the spec's acceptance requires; the canonical
// snake-case envelope and set digests are a later slice, so this freezes the Go
// projection rather than the wire form.
func TestFrozenVector(t *testing.T) {
	metrics, err := AggregateNetwork(happyJobs(), Window{From: 1000, To: 2000})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	encoded, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("testdata", "network-metrics.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector: %v (run with -update to create it)", err)
	}
	if string(committed) != string(encoded) {
		t.Fatal("the frozen metrics vector changed; if intended, re-run with -update and review the diff")
	}
}
