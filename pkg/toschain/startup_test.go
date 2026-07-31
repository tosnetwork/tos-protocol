package toschain

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStartupConfigBuildsBoundedRuntime(t *testing.T) {
	servers := []*httptest.Server{
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
		fakeRPCServer(t, fakeRPCBehavior{}),
	}
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()
	endpoints := make([]string, len(servers))
	for index := range servers {
		endpoints[index] = servers[index].URL
	}
	runtime, err := (StartupConfig{
		Version: StartupConfigVersion, Network: "tos-test",
		Endpoints: endpoints, Quorum: 2,
		AllowedServiceCodeHashes: []string{codeHashPrefix + strings.Repeat("11", 32)},
	}).BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Chain.readinessAge != DefaultReadinessMaxAge ||
		runtime.Chain.clientKeyLease != DefaultClientKeyLease {
		t.Fatalf("startup defaults not applied: %#v", runtime.Chain)
	}
}

func TestStartupConfigRejectsUnsafeBounds(t *testing.T) {
	base := StartupConfig{
		Version: StartupConfigVersion, Network: "tos-test",
		Endpoints: []string{"https://one", "https://two", "https://three"}, Quorum: 2,
		AllowedServiceCodeHashes: []string{codeHashPrefix + strings.Repeat("11", 32)},
	}
	tests := []struct {
		name   string
		mutate func(*StartupConfig)
	}{
		{"version", func(config *StartupConfig) { config.Version = "2" }},
		{"query timeout", func(config *StartupConfig) { config.QueryTimeoutMillis = 30_001 }},
		{"client lease", func(config *StartupConfig) { config.ClientKeyLeaseSeconds = 3_601 }},
		{"readiness age", func(config *StartupConfig) { config.ReadinessMaxAgeSeconds = 3_601 }},
		{"payment timeout", func(config *StartupConfig) { config.PaymentQueryTimeoutMillis = 60_001 }},
		{"payment age", func(config *StartupConfig) { config.PaymentMaxObservationAgeSeconds = 3_601 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if _, err := config.BuildRuntime(); err == nil {
				t.Fatal("unsafe startup configuration accepted")
			}
		})
	}
}
