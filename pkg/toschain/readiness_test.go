package toschain

import (
	"testing"
	"time"
)

func TestValidateObservationTimeFailsClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	adapter := &Adapter{readinessAge: DefaultReadinessMaxAge}
	for _, test := range []struct {
		name       string
		observedAt time.Time
		wantError  bool
	}{
		{name: "fresh", observedAt: now.Add(-time.Minute)},
		{name: "old boundary is stale", observedAt: now.Add(-DefaultReadinessMaxAge), wantError: true},
		{name: "future boundary allowed", observedAt: now.Add(maxClockSkew)},
		{name: "too far future", observedAt: now.Add(maxClockSkew + time.Second), wantError: true},
		{name: "zero", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := adapter.validateObservationTime(consensusObservation{seqno: 1, observedAt: test.observedAt}, now)
			if (err != nil) != test.wantError {
				t.Fatalf("validateObservationTime error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
