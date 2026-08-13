// Command tos-phase4d-gate performs the read-only, fail-closed production
// acceptance audit for ATOS Verified mode. It has no publisher dependency and
// cannot submit an economic mutation.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/productiongate"
	"github.com/tosnetwork/tos-protocol/pkg/verifiedproof"
)

func main() {
	manifestPath := flag.String("manifest", "", "absolute path to the read-only Phase 4D manifest")
	protocolTokenFile := flag.String("protocol-token-file", "", "owner-only file containing a read-only verifier token")
	allowLoopback := flag.Bool("allow-loopback", false, "allow plaintext loopback probes for local acceptance only")
	timeout := flag.Duration("timeout", 2*time.Minute, "overall audit timeout")
	flag.Parse()
	if flag.NArg() != 0 || *manifestPath == "" || *protocolTokenFile == "" || *timeout <= 0 || *timeout > 10*time.Minute {
		fmt.Fprintln(os.Stderr, "usage: tos-phase4d-gate --manifest /absolute/manifest.json --protocol-token-file /absolute/token [--allow-loopback]")
		os.Exit(2)
	}
	if err := productiongate.ValidateManifestTrust(*manifestPath, *allowLoopback); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	manifest, err := productiongate.Load(*manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	token, err := readSecret(*protocolTokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	httpClient := &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	observer, err := verifiedproof.NewProtocolObserverWithHTTPClient(httpClient, manifest.ProtocolObserverURL, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	auditor := productiongate.Auditor{
		HTTPClient:    httpClient,
		AllowLoopback: *allowLoopback,
		VerifyProof: func(ctx context.Context, proof []byte, manifest productiongate.Manifest) error {
			parsed, err := verifiedproof.Parse(proof)
			if err != nil {
				return err
			}
			if err := verifyReviewedEscrowCodeHash(parsed.Escrow.ContractCodeHash, manifest.EscrowCodeHashes); err != nil {
				return err
			}
			result := (verifiedproof.Verifier{Network: manifest.Network, GatewayDomain: manifest.GatewayDomain, Observer: observer}).VerifyBytes(ctx, proof)
			if result.Valid {
				return nil
			}
			encoded, marshalErr := json.Marshal(result.Failures)
			if marshalErr != nil {
				return errors.New("portable proof is invalid")
			}
			return fmt.Errorf("portable proof is invalid: %s", encoded)
		},
	}
	report := auditor.Audit(ctx, manifest)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !report.Passed {
		os.Exit(1)
	}
}

func verifyReviewedEscrowCodeHash(codeHash string, reviewed []string) error {
	if !slices.Contains(reviewed, codeHash) {
		return errors.New("portable proof TaskEscrow code hash is not in the reviewed deployment allowlist")
	}
	return nil
}

func readSecret(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("protocol token path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("protocol token must be a regular owner-only file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return "", errors.New("protocol token must be owned by the gate process account")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("protocol token changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return "", errors.New("protocol token is unavailable or oversized")
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("protocol token must contain one non-empty line")
	}
	return token, nil
}
