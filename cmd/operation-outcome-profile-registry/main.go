package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type document struct {
	Schema   string                               `json:"schema"`
	Version  uint16                               `json:"version"`
	Profiles []commerce.OutcomeAssertionProfileV1 `json:"profiles"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: operation-outcome-profile-registry OUTPUT")
	}
	registry := commerce.OutcomeAssertionProfileRegistryV1()
	profiles := make([]commerce.OutcomeAssertionProfileV1, 0, len(registry))
	for _, profile := range registry {
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ProfileURI < profiles[j].ProfileURI })
	raw, err := json.MarshalIndent(document{Schema: "tos.operation-outcome-assertion-profile-registry.v1", Version: 1, Profiles: profiles}, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("encode registry: %v", err))
	}
	if err := os.WriteFile(os.Args[1], append(raw, '\n'), 0o644); err != nil {
		panic(fmt.Sprintf("write registry: %v", err))
	}
}
