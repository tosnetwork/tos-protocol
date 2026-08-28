package main

import (
	"encoding/json"
	"fmt"
	"os"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: operation-outcome-error-registry OUTPUT")
		os.Exit(2)
	}
	encoded, err := json.MarshalIndent(commerce.OutcomeErrorRegistryV1(), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
