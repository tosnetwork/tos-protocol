package executiongate

import "testing"

func TestNewFromChainFailsClosedWithoutAuthorityConfiguration(t *testing.T) {
	if _, err := NewFromChain(ChainConfig{}); err == nil {
		t.Fatal("empty chain configuration created an execution Gate")
	}
}
