package taskescrowpublisher

import (
	"io"
	"os"
	"testing"
)

func TestTaskEscrowTosctlRPCURLMergesLegacyAndNewFields(t *testing.T) {
	if _, err := taskEscrowTosctlRPCURL([]byte(`{"chain_rpc":{"url":"http://chain-a","urls":["http://chain-b"]}}`)); err == nil {
		t.Fatal("contradictory legacy/new endpoints accepted")
	}
	got, err := taskEscrowTosctlRPCURL([]byte(`{"chain_rpc":{"url":" http://chain-a ","urls":["http://chain-a"]}}`))
	if err != nil || got != "http://chain-a" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err = taskEscrowTosctlRPCURL([]byte(`{"chain_rpc":{"urls":[{"url":"http://chain-a","api_key":"secret"}]}}`)); err == nil {
		t.Fatal("keyed endpoint accepted by recovery path")
	}
}

func TestPinnedTaskEscrowConfigSurvivesSourceReplacement(t *testing.T) {
	raw := []byte(`{"chain_rpc":{"url":"http://chain-a"}}`)
	file, err := pinnedTaskEscrowConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("snapshot=%s err=%v", got, err)
	}
	if _, err = os.Stat(file.Name()); !os.IsNotExist(err) {
		t.Fatalf("pinned snapshot remained path-addressable: %v", err)
	}
}
