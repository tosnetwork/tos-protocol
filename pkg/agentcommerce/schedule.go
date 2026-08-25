package agentcommerce

import (
	"errors"
	"sort"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type EngagementScheduleState string

const (
	ScheduleQueued     EngagementScheduleState = "queued"
	ScheduleReady      EngagementScheduleState = "ready"
	ScheduleDispatched EngagementScheduleState = "dispatched"
	ScheduleRunning    EngagementScheduleState = "running"
	ScheduleDraining   EngagementScheduleState = "draining"
	ScheduleSucceeded  EngagementScheduleState = "succeeded"
	ScheduleFailed     EngagementScheduleState = "failed"
	ScheduleCancelled  EngagementScheduleState = "cancelled"
	ScheduleAmbiguous  EngagementScheduleState = "ambiguous"
)

type EngagementScheduleEntry struct {
	SchemaVersion         uint16                  `json:"schema_version"`
	ScheduleEntryID       string                  `json:"schedule_entry_id"`
	AgreementBodyDigest   string                  `json:"agreement_body_digest"`
	ExecutionObligationID string                  `json:"execution_obligation_id"`
	ExecutionID           string                  `json:"execution_id"`
	State                 EngagementScheduleState `json:"state"`
	StateRevision         uint64                  `json:"state_revision"`
	DispatchGeneration    uint64                  `json:"dispatch_generation"`
	NotBeforeUnix         uint64                  `json:"not_before_unix,omitempty"`
	DeadlineUnix          uint64                  `json:"deadline_unix"`
	ComputeUnits          uint64                  `json:"compute_units"`
	MemoryBytes           uint64                  `json:"memory_bytes"`
	ConcurrencyUnits      uint32                  `json:"concurrency_units"`
	CancelClass           string                  `json:"cancel_class"`
	PreemptClass          string                  `json:"preempt_class"`
	IrreversibleBoundary  string                  `json:"irreversible_boundary"`
	WriterGeneration      uint64                  `json:"writer_generation"`
}

type PortfolioDependency struct {
	SchemaVersion                 uint16 `json:"schema_version"`
	UpstreamAgreementDigest       string `json:"upstream_agreement_digest"`
	UpstreamObligationID          string `json:"upstream_obligation_id"`
	DownstreamAgreementDigest     string `json:"downstream_agreement_digest"`
	DownstreamObligationID        string `json:"downstream_obligation_id"`
	DependencyType                string `json:"dependency_type"`
	DependencyClass               string `json:"dependency_class"`
	FailurePropagation            string `json:"failure_propagation"`
	EvidenceDrivenReleaseRequired bool   `json:"evidence_driven_release_required"`
}

func ValidateScheduleEntry(entry EngagementScheduleEntry) error {
	if (entry.SchemaVersion != 1 && entry.SchemaVersion != 2) || !boundedIdentifier(entry.ScheduleEntryID, 256) ||
		!canonicalDigestPattern.MatchString(entry.AgreementBodyDigest) ||
		(entry.SchemaVersion == 2 && !boundedIdentifier(entry.ExecutionObligationID, 128)) ||
		(entry.SchemaVersion == 1 && entry.ExecutionObligationID != "" && !boundedIdentifier(entry.ExecutionObligationID, 128)) ||
		!canonicalDigestPattern.MatchString(entry.ExecutionID) ||
		entry.StateRevision == 0 || entry.DispatchGeneration == 0 || entry.DeadlineUnix == 0 ||
		entry.NotBeforeUnix > entry.DeadlineUnix || entry.ConcurrencyUnits == 0 ||
		!canonicalLowerToken(entry.CancelClass) || !canonicalLowerToken(entry.PreemptClass) ||
		!boundedIdentifier(entry.IrreversibleBoundary, 256) || entry.WriterGeneration == 0 {
		return errors.New("engagement schedule entry is invalid")
	}
	switch entry.State {
	case ScheduleQueued, ScheduleReady, ScheduleDispatched, ScheduleRunning, ScheduleDraining,
		ScheduleSucceeded, ScheduleFailed, ScheduleCancelled, ScheduleAmbiguous:
		return nil
	default:
		return errors.New("engagement schedule state is unknown")
	}
}

func TransitionScheduleEntry(current EngagementScheduleEntry, target EngagementScheduleState,
	dispatchGeneration, writerGeneration uint64) (EngagementScheduleEntry, error) {
	if err := ValidateScheduleEntry(current); err != nil || writerGeneration < current.WriterGeneration || dispatchGeneration < current.DispatchGeneration {
		return EngagementScheduleEntry{}, errors.New("schedule transition is stale")
	}
	allowed := map[EngagementScheduleState]map[EngagementScheduleState]bool{
		ScheduleQueued:     {ScheduleReady: true, ScheduleCancelled: true},
		ScheduleReady:      {ScheduleDispatched: true, ScheduleCancelled: true},
		ScheduleDispatched: {ScheduleRunning: true, ScheduleAmbiguous: true, ScheduleCancelled: true},
		ScheduleRunning:    {ScheduleDraining: true, ScheduleSucceeded: true, ScheduleFailed: true, ScheduleAmbiguous: true},
		ScheduleDraining:   {ScheduleSucceeded: true, ScheduleFailed: true, ScheduleAmbiguous: true},
		ScheduleAmbiguous:  {ScheduleRunning: true, ScheduleSucceeded: true, ScheduleFailed: true},
	}
	if !allowed[current.State][target] {
		return EngagementScheduleEntry{}, errors.New("schedule transition is not permitted")
	}
	updated := current
	updated.State, updated.StateRevision = target, current.StateRevision+1
	updated.DispatchGeneration, updated.WriterGeneration = dispatchGeneration, writerGeneration
	return updated, ValidateScheduleEntry(updated)
}

func ValidatePortfolioDependencies(dependencies []PortfolioDependency) error {
	if len(dependencies) > 4096 {
		return errors.New("portfolio dependency graph is unbounded")
	}
	edges := make(map[string][]string)
	seen := make(map[string]bool)
	for _, dependency := range dependencies {
		if dependency.SchemaVersion != 1 || !canonicalDigestPattern.MatchString(dependency.UpstreamAgreementDigest) ||
			!canonicalDigestPattern.MatchString(dependency.DownstreamAgreementDigest) || !boundedIdentifier(dependency.UpstreamObligationID, 128) ||
			!boundedIdentifier(dependency.DownstreamObligationID, 128) || !canonicalLowerToken(dependency.DependencyType) ||
			(dependency.DependencyClass != "blocking" && dependency.DependencyClass != "informational") ||
			!canonicalLowerToken(dependency.FailurePropagation) {
			return errors.New("portfolio dependency is invalid")
		}
		canonical, err := codec.Marshal(dependency)
		if err != nil {
			return err
		}
		digest, _ := codec.Digest("tos.portfolio-dependency.v1", canonical)
		if seen[digest] {
			return errors.New("portfolio dependency is duplicated")
		}
		seen[digest] = true
		if dependency.DependencyClass == "blocking" {
			from := dependency.UpstreamAgreementDigest + "\x00" + dependency.UpstreamObligationID
			to := dependency.DownstreamAgreementDigest + "\x00" + dependency.DownstreamObligationID
			edges[from] = append(edges[from], to)
		}
	}
	for node := range edges {
		sort.Strings(edges[node])
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var cycle func(string) bool
	cycle = func(node string) bool {
		if visiting[node] {
			return true
		}
		if visited[node] {
			return false
		}
		visiting[node] = true
		for _, next := range edges[node] {
			if cycle(next) {
				return true
			}
		}
		delete(visiting, node)
		visited[node] = true
		return false
	}
	for node := range edges {
		if cycle(node) {
			return errors.New("blocking portfolio dependency cycle")
		}
	}
	return nil
}
