package toschain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointStoreSurvivesRestartAndRejectsRegression(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "checkpoint")
	first, err := newCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.checkAndAdvance(42); err != nil {
		t.Fatal(err)
	}
	second, err := newCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.checkAndAdvance(41); err == nil {
		t.Fatal("checkpoint regression accepted after restart")
	}
	if err := second.checkAndAdvance(43); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := second.checkAndAdvance(44); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
}
