// tos-verified-proof verifies a canonical tos_verified_v1 package. The CLI
// intentionally has no mutation/publisher dependency. Production deployments
// provide a quorum observer through the library; --offline performs structural,
// digest and signature checks but cannot return VALID.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/verifiedproof"
)

func main() {
	jsonOutput := flag.Bool("json", false, "emit machine-readable JSON")
	network := flag.String("network", "", "required TOS network identity")
	domain := flag.String("domain", "", "required gateway trust domain")
	observerCommand := flag.String("observer-command", "", "absolute read-only quorum observer executable")
	observerCommandSHA256 := flag.String("observer-command-sha256", "", "required sha256:<hex> digest pin for --observer-command")
	protocolURL := flag.String("protocol-url", "", "read-only tos-protocol RPC URL")
	protocolTokenFile := flag.String("protocol-token-file", "", "file containing the tos-protocol bearer token")
	flag.Parse()
	if flag.NArg() != 2 || flag.Arg(0) != "verify" {
		fmt.Fprintln(os.Stderr, "usage: tos-verified-proof [--json] --network ID --domain DOMAIN verify PACKAGE.cbor")
		os.Exit(2)
	}
	if strings.TrimSpace(*network) == "" || strings.TrimSpace(*domain) == "" {
		fmt.Fprintln(os.Stderr, "--network and --domain are required trust pins")
		os.Exit(2)
	}
	if *protocolURL != "" && *observerCommand != "" {
		fmt.Fprintln(os.Stderr, "choose exactly one live observer: --protocol-url or --observer-command")
		os.Exit(2)
	}
	if *protocolURL == "" && *protocolTokenFile != "" {
		fmt.Fprintln(os.Stderr, "--protocol-token-file requires --protocol-url")
		os.Exit(2)
	}
	if *observerCommand == "" && *observerCommandSHA256 != "" {
		fmt.Fprintln(os.Stderr, "--observer-command-sha256 requires --observer-command")
		os.Exit(2)
	}
	data, err := readBoundedFile(flag.Arg(1), 1<<20)
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
		tokenBytes, e := readSecretFile(*protocolTokenFile, 64<<10)
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
		if !validSHA256Pin(*observerCommandSHA256) {
			fmt.Fprintln(os.Stderr, "--observer-command-sha256=sha256:<64 lowercase hex> is required with --observer-command")
			os.Exit(2)
		}
		observer = commandObserver{path: *observerCommand, digest: *observerCommandSHA256}
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

type commandObserver struct {
	path   string
	digest string
}

func (o commandObserver) call(ctx context.Context, request any, response any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	body, e := json.Marshal(request)
	if e != nil {
		return e
	}
	executable, e := openVerifiedObserverCommand(o.path, o.digest)
	if e != nil {
		return e
	}
	defer executable.Close()
	execPath := o.path
	extraFiles := []*os.File(nil)
	if runtime.GOOS == "linux" {
		execPath = "/proc/self/fd/3"
		extraFiles = []*os.File{executable}
	}
	cmd := exec.CommandContext(ctx, execPath)
	cmd.ExtraFiles = extraFiles
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: 2 << 20}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("observer failed: %w: %s", e, stderr.String())
	}
	return decodeObserverResponse(io.LimitReader(&stdout, 2<<20), response)
}

func decodeObserverResponse(reader io.Reader, response any) error {
	dec := json.NewDecoder(reader)
	dec.DisallowUnknownFields()
	if err := dec.Decode(response); err != nil {
		return fmt.Errorf("decode observer response: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode observer response: trailing data: %w", err)
	}
	return nil
}

func validSHA256Pin(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[len("sha256:"):] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func openVerifiedObserverCommand(path, expectedDigest string) (*os.File, error) {
	if !validSHA256Pin(expectedDigest) {
		return nil, errors.New("valid observer command SHA-256 pin is required")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("observer command is not a regular executable file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		file.Close()
		return nil, errors.New("observer command changed while it was opened")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || os.Geteuid() == 0 || info.Mode().Perm()&0o022 != 0 {
		file.Close()
		return nil, errors.New("observer command must be root-owned, non-group-writable, and used by an unprivileged verifier")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		directoryInfo, directoryErr := os.Lstat(directory)
		if directoryErr != nil {
			file.Close()
			return nil, errors.New("observer command path contains an untrusted directory")
		}
		directoryStat, statOK := directoryInfo.Sys().(*syscall.Stat_t)
		if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o022 != 0 || !statOK || directoryStat.Uid != 0 {
			file.Close()
			return nil, errors.New("observer command path contains an untrusted directory")
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		file.Close()
		return nil, err
	}
	actual := fmt.Sprintf("sha256:%x", hash.Sum(nil))
	if actual != expectedDigest {
		file.Close()
		return nil, errors.New("observer command SHA-256 does not match the configured pin")
	}
	if _, err = file.Seek(0, 0); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid file size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBounded(file, limit)
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid file size limit")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return data, nil
}

func readSecretFile(path string, limit int64) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret file must be a regular, non-symlink file with no group or world permissions")
	}
	stat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("secret file must be owned by the verifier service account")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		return nil, errors.New("secret file changed while it was opened")
	}
	return readBounded(file, limit)
}
func (o commandObserver) Observe(ctx context.Context, r verifiedproof.EvidenceRequest) (verifiedproof.EvidenceObservation, error) {
	var out verifiedproof.EvidenceObservation
	e := o.call(ctx, map[string]any{"version": "tos_verified_observer_v2", "operation": "observe", "request": r}, &out)
	return out, e
}
func (o commandObserver) ResolveSigner(ctx context.Context, p verifiedproof.Package, effectiveReceiptUnixNanos int64) (verifiedproof.SignerObservation, error) {
	var out verifiedproof.SignerObservation
	e := o.call(ctx, map[string]any{"version": "tos_verified_observer_v2", "operation": "resolve_signer", "package": p, "effective_receipt_unix_nanos": effectiveReceiptUnixNanos}, &out)
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
