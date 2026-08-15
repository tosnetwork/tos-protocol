// Command native-vector-reference reproduces frozen registration values using
// the independent conformance encoder. It never imports pkg/nativecore.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
)

func main() {
	vectorsPath := flag.String("vectors", "pkg/nativecore/testdata/native_registry_v1_vectors.json", "frozen vector JSON")
	flag.Parse()
	raw, err := os.ReadFile(*vectorsPath)
	if err != nil {
		fail(err)
	}
	vectors, err := referencecodec.Decode(raw)
	if err != nil {
		fail(err)
	}
	agent, err := referencecodec.ComputeAgent(vectors)
	if err != nil {
		fail(err)
	}
	capability, err := referencecodec.ComputeCapability(vectors)
	if err != nil {
		fail(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]referencecodec.Result{
		"agent_registration": agent, "capability_registration": capability,
	}); err != nil {
		fail(err)
	}
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
