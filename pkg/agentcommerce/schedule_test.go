package agentcommerce

import (
	"strings"
	"testing"
)

func TestScheduleTakeoverAndDependencyCycleFailClosed(t *testing.T) {
	entry := EngagementScheduleEntry{SchemaVersion: 1, ScheduleEntryID: "schedule:1", AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64), ExecutionObligationID: "work:one",
		ExecutionID: "sha256:" + strings.Repeat("2", 64), State: ScheduleQueued, StateRevision: 1, DispatchGeneration: 1,
		DeadlineUnix: 2_000_000_000, ComputeUnits: 1, MemoryBytes: 1, ConcurrencyUnits: 1, CancelClass: "safe",
		PreemptClass: "safe", IrreversibleBoundary: "before-delivery", WriterGeneration: 3}
	ready, err := TransitionScheduleEntry(entry, ScheduleReady, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TransitionScheduleEntry(ready, ScheduleDispatched, 2, 2); err == nil {
		t.Fatal("stale writer dispatched work")
	}
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	edges := []PortfolioDependency{
		{SchemaVersion: 1, UpstreamAgreementDigest: a, UpstreamObligationID: "one", DownstreamAgreementDigest: b, DownstreamObligationID: "two", DependencyType: "requires", DependencyClass: "blocking", FailurePropagation: "cancel", EvidenceDrivenReleaseRequired: true},
		{SchemaVersion: 1, UpstreamAgreementDigest: b, UpstreamObligationID: "two", DownstreamAgreementDigest: a, DownstreamObligationID: "one", DependencyType: "requires", DependencyClass: "blocking", FailurePropagation: "cancel", EvidenceDrivenReleaseRequired: true},
	}
	if err := ValidatePortfolioDependencies(edges); err == nil {
		t.Fatal("blocking cycle was accepted")
	}
	edges[1].DependencyClass = "informational"
	if err := ValidatePortfolioDependencies(edges); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyScheduleEntryLoadsWithoutInventingObligationIdentity(t *testing.T) {
	entry := EngagementScheduleEntry{SchemaVersion: 1, ScheduleEntryID: "schedule:legacy", AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64),
		ExecutionID: "sha256:" + strings.Repeat("2", 64), State: ScheduleAmbiguous, StateRevision: 2, DispatchGeneration: 1,
		DeadlineUnix: 2_100_000_000, ConcurrencyUnits: 1, CancelClass: "manual", PreemptClass: "drain",
		IrreversibleBoundary: "unknown-start", WriterGeneration: 1}
	if err := ValidateScheduleEntry(entry); err != nil {
		t.Fatalf("legacy schedule state should load conservatively: %v", err)
	}
	entry.SchemaVersion = 2
	if err := ValidateScheduleEntry(entry); err == nil {
		t.Fatal("new schedule state omitted its exact execution obligation")
	}
}
