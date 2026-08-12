// tos-verified-proof verifies a canonical tos_verified_v1 package. The CLI
// intentionally has no mutation/publisher dependency. Production deployments
// provide a quorum observer through the library; --offline performs structural,
// digest and signature checks but cannot return VALID.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tosnetwork/tos-protocol/pkg/verifiedproof"
)

func main() {
	jsonOutput := flag.Bool("json", false, "emit machine-readable JSON")
	network := flag.String("network", "", "required TOS network identity")
	domain := flag.String("domain", "", "required gateway trust domain")
	flag.Parse()
	if flag.NArg() != 2 || flag.Arg(0) != "verify" {
		fmt.Fprintln(os.Stderr, "usage: tos-verified-proof [--json] --network ID --domain DOMAIN verify PACKAGE.cbor")
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := (verifiedproof.Verifier{Network: *network, GatewayDomain: *domain}).VerifyBytes(context.Background(), data)
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(result)
	} else if result.Valid {
		fmt.Printf("VALID %s %s quote=%s job=%s escrow=%s outcome=%s signer=%s\n", result.Version, result.PackageDigest, result.QuoteID, result.JobID, result.EscrowID, result.Outcome, result.ExecutionSignerID)
	} else {
		fmt.Printf("INVALID (%d failures)\n", len(result.Failures))
		for _, f := range result.Failures {
			fmt.Printf("%s %s: %s\n", f.Code, f.Field, f.Message)
		}
	}
	if !result.Valid {
		os.Exit(1)
	}
}
