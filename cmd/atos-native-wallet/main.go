// Command atos-native-wallet reviews and signs atos_native_v1 action JSON.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativewallet"
	"google.golang.org/protobuf/encoding/protojson"
)

type pathsFlag []string

func (p *pathsFlag) String() string { return fmt.Sprint([]string(*p)) }
func (p *pathsFlag) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
	var authorityPaths, counterpartyPaths pathsFlag
	actionPath := flag.String("action", "", "absolute path to NativeActionV1 JSON")
	outputPath := flag.String("output", "", "optional output path; stdout when empty")
	flag.Var(&authorityPaths, "authority-key", "owner-private Ed25519 seed file; repeat for multisig")
	flag.Var(&counterpartyPaths, "counterparty-key", "owner-private acceptance/new-policy seed file; repeat for multisig")
	flag.Parse()

	action, err := loadAction(*actionPath)
	if err != nil {
		fail(err)
	}
	review, built, err := nativewallet.ReviewAction(action)
	if err != nil {
		fail(err)
	}
	reviewJSON, _ := json.MarshalIndent(review, "", "  ")
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", reviewJSON)
	_, _ = fmt.Fprintf(os.Stderr, "Type the complete action hash to sign: ")
	if err := nativewallet.ConfirmHash(bufio.NewReader(os.Stdin), review.ActionHash); err != nil {
		fail(err)
	}

	authority, err := loadKeys(authorityPaths)
	if err != nil {
		fail(err)
	}
	defer closeKeys(authority)
	counterparty, err := loadKeys(counterpartyPaths)
	if err != nil {
		fail(err)
	}
	defer closeKeys(counterparty)
	if len(authority) == 0 {
		fail(errors.New("at least one authority key is required"))
	}
	authoritySignatures, err := nativewallet.Sign(built, authority)
	if err != nil {
		fail(err)
	}
	var counterpartySignatures []*nativev1.SignatureV1
	if len(counterparty) != 0 {
		counterpartySignatures, err = nativewallet.Sign(built, counterparty)
		if err != nil {
			fail(err)
		}
	}
	submission := &nativev1.SignedNativeActionV1{Action: action,
		AuthoritySignatures: authoritySignatures, CounterpartySignatures: counterpartySignatures}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}).Marshal(submission)
	if err != nil {
		fail(err)
	}
	encoded = append(encoded, '\n')
	if *outputPath == "" {
		if _, err := os.Stdout.Write(encoded); err != nil {
			fail(err)
		}
		return
	}
	if !filepath.IsAbs(*outputPath) || filepath.Clean(*outputPath) != *outputPath {
		fail(errors.New("output path must be absolute and clean"))
	}
	output, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail(err)
	}
	if _, err := output.Write(encoded); err != nil {
		_ = output.Close()
		fail(err)
	}
	if err := output.Close(); err != nil {
		fail(err)
	}
}

func loadAction(path string) (*nativev1.NativeActionV1, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("action path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errors.New("action JSON must be a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var action nativev1.NativeActionV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &action); err != nil {
		return nil, err
	}
	return &action, nil
}

func loadKeys(paths []string) ([]*nativewallet.Key, error) {
	keys := make([]*nativewallet.Key, 0, len(paths))
	for _, path := range paths {
		key, err := nativewallet.LoadKey(path)
		if err != nil {
			closeKeys(keys)
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func closeKeys(keys []*nativewallet.Key) {
	for _, key := range keys {
		key.Close()
	}
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
