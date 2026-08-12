// tos-verified-proof verifies a canonical tos_verified_v1 package. The CLI
// intentionally has no mutation/publisher dependency. Production deployments
// provide a quorum observer through the library; --offline performs structural,
// digest and signature checks but cannot return VALID.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/verifiedproof"
)

func main() {
	jsonOutput := flag.Bool("json", false, "emit machine-readable JSON")
	network := flag.String("network", "", "required TOS network identity")
	domain := flag.String("domain", "", "required gateway trust domain")
	observerCommand := flag.String("observer-command", "", "absolute read-only quorum observer executable")
	protocolURL := flag.String("protocol-url", "", "read-only tos-protocol RPC URL")
	protocolTokenFile := flag.String("protocol-token-file", "", "file containing the tos-protocol bearer token")
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
	var observer verifiedproof.Observer
	if *protocolURL != "" {
		if *protocolTokenFile == "" {
			fmt.Fprintln(os.Stderr, "--protocol-token-file is required with --protocol-url")
			os.Exit(2)
		}
		tokenBytes, e := os.ReadFile(*protocolTokenFile)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		observer, e = verifiedproof.NewProtocolObserver(*protocolURL, strings.TrimSpace(string(tokenBytes)))
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
	} else if *observerCommand != "" {
		if (*observerCommand)[0] != '/' {
			fmt.Fprintln(os.Stderr, "--observer-command must be absolute")
			os.Exit(2)
		}
		observer = commandObserver{path: *observerCommand}
	}
	result := (verifiedproof.Verifier{Network: *network, GatewayDomain: *domain, Observer: observer}).VerifyBytes(context.Background(), data)
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

type commandObserver struct{ path string }

func (o commandObserver) call(ctx context.Context, request any, response any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	body, e := json.Marshal(request)
	if e != nil {
		return e
	}
	cmd := exec.CommandContext(ctx, o.path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: 2 << 20}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("observer failed: %w: %s", e, stderr.String())
	}
	dec := json.NewDecoder(io.LimitReader(&stdout, 2<<20))
	dec.DisallowUnknownFields()
	if e = dec.Decode(response); e != nil {
		return fmt.Errorf("decode observer response: %w", e)
	}
	return nil
}
func (o commandObserver) Observe(ctx context.Context, r verifiedproof.EvidenceRequest) (verifiedproof.EvidenceObservation, error) {
	var out verifiedproof.EvidenceObservation
	e := o.call(ctx, map[string]any{"version": "tos_verified_observer_v1", "operation": "observe", "request": r}, &out)
	return out, e
}
func (o commandObserver) ResolveSigner(ctx context.Context, p verifiedproof.Package) (verifiedproof.SignerObservation, error) {
	var out verifiedproof.SignerObservation
	e := o.call(ctx, map[string]any{"version": "tos_verified_observer_v1", "operation": "resolve_signer", "package": p}, &out)
	return out, e
}

type limitedWriter struct {
	w        io.Writer
	n        int64
	overflow bool
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		l.overflow = true
		return len(p), errors.New("observer output exceeds limit")
	}
	n, e := l.w.Write(p)
	l.n -= int64(n)
	return n, e
}
