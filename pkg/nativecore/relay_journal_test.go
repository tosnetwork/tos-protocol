package nativecore

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func journalTestIntent(actionHash string) RelayIntent {
	return RelayIntent{ActionHash: actionHash, Destination: "0:destination", QueryID: 7,
		BodyHash: "sha256:body", StateInitHash: "sha256:state-init", FundingNanoTOS: MinimumRelayFundingNanoTOS}
}

func TestFileRelayJournalIsDurableAndConflictSafe(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	intent := journalTestIntent("sha256:first")
	complete, existing, err := first.Begin("request-1", intent)
	if err != nil || complete || existing != "" {
		t.Fatalf("first begin = (%v, %q, %v)", complete, existing, err)
	}
	second, _ := NewFileRelayJournal(directory)
	complete, existing, err = second.Begin("request-1", intent)
	if err != nil || complete || existing != "sha256:first" {
		t.Fatalf("pending restart = (%v, %q, %v)", complete, existing, err)
	}
	different := intent
	different.FundingNanoTOS++
	if _, _, err := second.Begin("request-1", different); err == nil {
		t.Fatal("idempotency key accepted different semantics")
	}
	if err := first.Complete("request-1", intent); err != nil {
		t.Fatal(err)
	}
	third, _ := NewFileRelayJournal(filepath.Clean(directory))
	complete, existing, err = third.Begin("request-1", intent)
	if err != nil || !complete || existing != "sha256:first" {
		t.Fatalf("completed restart = (%v, %q, %v)", complete, existing, err)
	}
}

func TestFileRelayJournalFencesConcurrentBroadcasters(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journals := make([]*FileRelayJournal, 2)
	for i := range journals {
		journal, err := NewFileRelayJournal(directory)
		if err != nil {
			t.Fatal(err)
		}
		journals[i] = journal
	}
	type outcome struct {
		existing string
		err      error
	}
	outcomes := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := range journals {
		go func(j *FileRelayJournal) {
			start.Wait()
			_, existing, err := j.Begin("race", journalTestIntent("sha256:action"))
			outcomes <- outcome{existing: existing, err: err}
		}(journals[i])
	}
	start.Done()
	first, second := <-outcomes, <-outcomes
	if first.err != nil || second.err != nil {
		t.Fatalf("race outcomes: %+v %+v", first, second)
	}
	if (first.existing == "") == (second.existing == "") {
		t.Fatalf("exactly one broadcaster must own the new intent: %+v %+v", first, second)
	}
}
