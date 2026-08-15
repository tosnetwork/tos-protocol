// Command native-gate-c-check resolves deployed Native Registry objects
// through the production quorum and typed-state decoder.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/encoding/protojson"
)

type endpointsFlag []string

func (e *endpointsFlag) String() string { return strings.Join(*e, ",") }
func (e *endpointsFlag) Set(value string) error {
	if strings.TrimSpace(value) != value || value == "" {
		return errors.New("invalid endpoint")
	}
	*e = append(*e, value)
	return nil
}

func main() {
	var endpoints endpointsFlag
	var objects string
	var network, genesisRoot, genesisFile, codePath, codeHash, checkpoint, output string
	var workchain int
	flag.Var(&endpoints, "endpoint", "JSON-RPC URL; repeat three or more times")
	flag.StringVar(&objects, "objects", "", "comma-separated Agent or Capability IDs")
	flag.StringVar(&network, "network", "", "Native network ID")
	flag.StringVar(&genesisRoot, "genesis-root", "", "sha256:<hex> genesis root")
	flag.StringVar(&genesisFile, "genesis-file", "", "sha256:<hex> genesis file")
	flag.StringVar(&codePath, "code-base64", "", "path to the frozen code BOC Base64")
	flag.StringVar(&codeHash, "code-hash", "", "tvm-cell-sha256:<hex> code hash")
	flag.StringVar(&checkpoint, "checkpoint", "", "absolute durable checkpoint path")
	flag.StringVar(&output, "output", "", "optional JSON evidence output path")
	flag.IntVar(&workchain, "workchain", 0, "Registry workchain")
	flag.Parse()

	if len(endpoints) < 3 || objects == "" || network == "" || genesisRoot == "" ||
		genesisFile == "" || codePath == "" || codeHash == "" || checkpoint == "" {
		fatal(errors.New("all network, release, checkpoint, and object flags are required"))
	}
	seenEndpoints := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if _, exists := seenEndpoints[endpoint]; exists {
			fatal(fmt.Errorf("duplicate endpoint %q", endpoint))
		}
		seenEndpoints[endpoint] = struct{}{}
	}
	objectIDs := strings.Split(objects, ",")
	seenObjects := make(map[string]struct{}, len(objectIDs))
	for i, objectID := range objectIDs {
		objectIDs[i] = strings.TrimSpace(objectID)
		if objectIDs[i] == "" {
			fatal(errors.New("object IDs must not be empty"))
		}
		if _, exists := seenObjects[objectIDs[i]]; exists {
			fatal(fmt.Errorf("duplicate object ID %q", objectIDs[i]))
		}
		seenObjects[objectIDs[i]] = struct{}{}
	}
	code, err := os.ReadFile(codePath)
	if err != nil {
		fatal(err)
	}
	domain := &nativev1.NetworkDomain{
		NetworkId: network, GenesisRootHash: genesisRoot, GenesisFileHash: genesisFile,
	}
	locator, err := nativecore.NewLocator(domain, int32(workchain),
		strings.Join(strings.Fields(string(code)), ""), codeHash)
	if err != nil {
		fatal(err)
	}
	chain, err := toschain.New(toschain.Config{
		Network: network, Endpoints: endpoints, Quorum: len(endpoints)/2 + 1,
	})
	if err != nil {
		fatal(err)
	}
	resolver, err := toschain.NewSimplifiedNativeResolver(chain, locator, checkpoint)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := resolver.CheckReady(ctx); err != nil {
		fatal(err)
	}

	type resolvedObject struct {
		ObjectID string          `json:"object_id"`
		Found    bool            `json:"found"`
		State    json.RawMessage `json:"state"`
	}
	result := struct {
		Schema            string           `json:"schema"`
		AcceptanceProfile string           `json:"acceptance_profile"`
		GeneratedAt       string           `json:"generated_at"`
		Network           string           `json:"network"`
		GenesisRootHash   string           `json:"genesis_root_hash"`
		GenesisFileHash   string           `json:"genesis_file_hash"`
		RegistryWorkchain int              `json:"registry_workchain"`
		ExpectedCodeHash  string           `json:"expected_code_hash"`
		Endpoints         []string         `json:"endpoints"`
		Quorum            int              `json:"quorum"`
		Objects           []resolvedObject `json:"objects"`
	}{
		Schema:            "tos.service.gate-c.quorum-check.v1",
		AcceptanceProfile: "operator-designated-initial-public-testnet",
		Network:           network,
		GenesisRootHash:   genesisRoot,
		GenesisFileHash:   genesisFile,
		RegistryWorkchain: workchain,
		ExpectedCodeHash:  codeHash,
		Endpoints:         endpoints,
		Quorum:            len(endpoints)/2 + 1,
	}
	for _, objectID := range objectIDs {
		state, found, finalizedAt, err := resolver.ResolveFinalizedState(ctx, objectID, "")
		if err != nil {
			fatal(fmt.Errorf("resolve %s: %w", objectID, err))
		}
		encoded, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(state)
		if err != nil {
			fatal(err)
		}
		var stateDocument map[string]any
		if err := json.Unmarshal(encoded, &stateDocument); err != nil {
			fatal(err)
		}
		stateDocument["finalized_at"] = finalizedAt.Format(time.RFC3339)
		encoded, err = json.Marshal(stateDocument)
		if err != nil {
			fatal(err)
		}
		result.Objects = append(result.Objects, resolvedObject{objectID, found, encoded})
	}
	result.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fatal(err)
	}
	if output == "" {
		fmt.Println(string(encoded))
		return
	}
	if err := os.WriteFile(output, append(encoded, '\n'), 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "native-gate-c-check:", err)
	os.Exit(1)
}
