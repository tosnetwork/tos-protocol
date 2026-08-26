package toschain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestConsensusRejectsStaleAndFutureTimeAtEveryReadBoundary(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, test := range []struct {
		name      string
		chainTime time.Time
		wantError bool
	}{
		{name: "fresh", chainTime: now.Add(-time.Minute)},
		{name: "stale", chainTime: now.Add(-DefaultReadinessMaxAge), wantError: true},
		{name: "future", chainTime: now.Add(maxClockSkew + time.Second), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			servers := make([]*httptest.Server, 0, 3)
			for range 3 {
				server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					var call struct {
						ID uint64 `json:"id"`
					}
					if err := json.NewDecoder(request.Body).Decode(&call); err != nil {
						http.Error(response, "bad request", http.StatusBadRequest)
						return
					}
					response.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
						"result": map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": 42,
							"timestamp": test.chainTime.Unix(), "last_block_utime": test.chainTime.Unix()}})
				}))
				servers = append(servers, server)
			}
			defer func() {
				for _, server := range servers {
					server.Close()
				}
			}()
			endpoints := make([]string, 0, len(servers))
			for _, server := range servers {
				endpoints = append(endpoints, server.URL)
			}
			adapter, err := New(Config{Network: "tos:freshness-test", Endpoints: endpoints, Quorum: 2,
				ReadinessMaxAge: DefaultReadinessMaxAge, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = adapter.consensus(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("consensus error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
