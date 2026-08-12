package chainactionpublisher

import (
	"bytes"
	"testing"
)

func TestChainLimitedBufferBoundsMemoryBeforeProcessExit(t *testing.T) {
	buffer := chainLimitedBuffer{limit: 32}
	payload := bytes.Repeat([]byte("x"), 4096)
	written, err := buffer.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(payload) || !buffer.overflow || len(buffer.Bytes()) != buffer.limit {
		t.Fatalf("written=%d overflow=%v retained=%d", written, buffer.overflow, len(buffer.Bytes()))
	}
	for range 100 {
		if _, err := buffer.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if len(buffer.Bytes()) != buffer.limit {
		t.Fatalf("overflow grew retained output to %d", len(buffer.Bytes()))
	}
}
