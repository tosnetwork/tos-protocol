package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/taskescrowpublisher"
)

type enrollmentBackend struct {
	readyErr error
	checked  bool
}

func (b *enrollmentBackend) CheckReady(context.Context) error {
	b.checked = true
	return b.readyErr
}
func (*enrollmentBackend) EnrollmentBinding() string { return "backend-binding-v1" }
func (*enrollmentBackend) Prepare(context.Context, chain.TaskEscrowAction) (taskescrowpublisher.PreparedAction, error) {
	return taskescrowpublisher.PreparedAction{}, errors.New("not used")
}
func (*enrollmentBackend) Publish(context.Context, chain.TaskEscrowAction, taskescrowpublisher.PreparedAction, bool) (chain.TaskEscrowActionReceipt, error) {
	return chain.TaskEscrowActionReceipt{}, errors.New("not used")
}
func (*enrollmentBackend) Close() error { return nil }

func TestInitializeJournalChecksBackendBeforeCreatingState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "journal.db")
	config := startupConfig{
		Network: "tos-test", StatePath: statePath, JournalIdentity: "journal-test",
		Policy: taskescrowpublisher.PublisherPolicy{
			AllowedCreators:     []string{"0:" + repeatHex("11")},
			AllowedAgents:       []string{"0:" + repeatHex("22")},
			AllowedCodeHashes:   []string{"sha256:" + repeatHex("33")},
			AllowedPolicyHashes: []string{"sha256:" + repeatHex("44")},
			MaxBudgetNanoTOS:    1, MaxFundingNanoTOS: 1,
		},
	}
	// Negative control: model an enrolled executable that supports wallet ls
	// but has no versioned agent-task capability command. The permanent journal
	// must not exist after this failure.
	backend := &enrollmentBackend{readyErr: errors.New("query tosctl TaskEscrow capabilities: unknown subcommand capabilities")}
	if err := initializeJournal(context.Background(), config, backend); err == nil {
		t.Fatal("unready backend was enrolled")
	}
	if !backend.checked {
		t.Fatal("backend readiness was not checked")
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed readiness created journal: %v", err)
	}

	backend.readyErr = nil
	if err := initializeJournal(context.Background(), config, backend); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("ready backend did not create journal: %v", err)
	}
}

func repeatHex(pair string) string {
	value := ""
	for range 32 {
		value += pair
	}
	return value
}
