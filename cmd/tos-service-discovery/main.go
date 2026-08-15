// Command tos-service-discovery uses only the public derived Capability API.
// It never reads or edits a gateway catalog directory.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const maxManifestBytes = 1 << 20

type connectionFlags struct {
	gateway, caller, caFile, serverName string
	insecure                            bool
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: tos-service-discovery <publish|list|search|get> [flags]"))
	}
	var err error
	switch os.Args[1] {
	case "publish":
		err = publish(os.Args[2:])
	case "list":
		err = list(os.Args[2:])
	case "search":
		err = search(os.Args[2:])
	case "get":
		err = get(os.Args[2:])
	default:
		err = errors.New("unknown discovery command")
	}
	if err != nil {
		fail(err)
	}
}

func addConnectionFlags(set *flag.FlagSet) *connectionFlags {
	flags := &connectionFlags{}
	set.StringVar(&flags.gateway, "gateway", "", "Native gateway base URL")
	set.StringVar(&flags.caller, "caller-id", "", "bounded discovery caller ID")
	set.BoolVar(&flags.insecure, "insecure", false, "allow plaintext HTTP (loopback development only)")
	set.StringVar(&flags.caFile, "ca-file", "", "optional private CA PEM")
	set.StringVar(&flags.serverName, "server-name", "", "optional TLS server name")
	return flags
}

func openClient(flags *connectionFlags) (*nativeclient.Client, error) {
	token := os.Getenv("TOS_SERVICE_TOKEN")
	if flags == nil || flags.gateway == "" || flags.caller == "" || len(flags.caller) > 256 || token == "" {
		return nil, errors.New("--gateway, --caller-id, and TOS_SERVICE_TOKEN are required")
	}
	return nativeclient.New(nativeclient.Config{BaseURL: flags.gateway, BearerToken: token,
		Insecure: flags.insecure, CAFile: flags.caFile, ServerName: flags.serverName})
}

func requestContext(caller, idempotency string) (*nativev1.RequestContext, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("generate discovery request identity")
	}
	return &nativev1.RequestContext{RequestId: hex.EncodeToString(nonce[:]), CallerId: caller,
		IdempotencyKey: idempotency, DeadlineUnixMillis: time.Now().Add(30 * time.Second).UnixMilli()}, nil
}

func publish(arguments []string) error {
	set := flag.NewFlagSet("publish", flag.ContinueOnError)
	connection := addConnectionFlags(set)
	capability := set.String("capability-id", "", "finalized Capability ID")
	manifest := set.String("manifest-cbor", "", "absolute canonical manifest CBOR path")
	retry := set.String("idempotency-key", "", "durable publication retry key")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || *capability == "" || *retry == "" || len(*retry) > 256 {
		return errors.New("invalid manifest publication flags")
	}
	raw, err := readBoundedRegular(*manifest, maxManifestBytes)
	if err != nil {
		return err
	}
	client, err := openClient(connection)
	if err != nil {
		return err
	}
	defer client.Close()
	request, err := requestContext(connection.caller, *retry)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := client.PublishSoftwareWorkManifest(ctx, &nativev1.PublishSoftwareWorkManifestRequest{
		Context: request, CapabilityId: *capability, CanonicalCbor: raw})
	if err != nil {
		return err
	}
	return printProto(response)
}

func list(arguments []string) error {
	set := flag.NewFlagSet("list", flag.ContinueOnError)
	connection := addConnectionFlags(set)
	pageSize := set.Uint("page-size", 20, "page size (maximum 100)")
	after := set.String("after-capability-id", "", "local continuation Capability ID")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || *pageSize > 100 {
		return errors.New("invalid Capability listing flags")
	}
	client, contextValue, cancel, request, err := discoveryCall(connection, "")
	if err != nil {
		return err
	}
	defer client.Close()
	defer cancel()
	response, err := client.ListCapabilities(contextValue, &nativev1.ListCapabilitiesRequest{
		Context: request, PageSize: uint32(*pageSize), AfterCapabilityId: *after})
	if err != nil {
		return err
	}
	return printProto(response)
}

func search(arguments []string) error {
	set := flag.NewFlagSet("search", flag.ContinueOnError)
	connection := addConnectionFlags(set)
	query := set.String("query", "", "bounded local search query")
	pageSize := set.Uint("page-size", 20, "page size (maximum 100)")
	after := set.String("after-capability-id", "", "local continuation Capability ID")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || *query == "" || len(*query) > 128 || *pageSize > 100 {
		return errors.New("invalid Capability search flags")
	}
	client, contextValue, cancel, request, err := discoveryCall(connection, "")
	if err != nil {
		return err
	}
	defer client.Close()
	defer cancel()
	response, err := client.SearchCapabilities(contextValue, &nativev1.SearchCapabilitiesRequest{
		Context: request, Query: *query,
		PageSize: uint32(*pageSize), AfterCapabilityId: *after})
	if err != nil {
		return err
	}
	return printProto(response)
}

func get(arguments []string) error {
	set := flag.NewFlagSet("get", flag.ContinueOnError)
	connection := addConnectionFlags(set)
	digest := set.String("manifest-digest", "", "SHA-256 manifest digest")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || *digest == "" {
		return errors.New("invalid manifest retrieval flags")
	}
	client, contextValue, cancel, request, err := discoveryCall(connection, "")
	if err != nil {
		return err
	}
	defer client.Close()
	defer cancel()
	response, err := client.GetSoftwareWorkManifest(contextValue, &nativev1.GetSoftwareWorkManifestRequest{
		Context: request, ManifestDigest: *digest})
	if err != nil {
		return err
	}
	return printProto(response)
}

func discoveryCall(flags *connectionFlags, retry string) (*nativeclient.Client, context.Context, context.CancelFunc, *nativev1.RequestContext, error) {
	client, err := openClient(flags)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	request, err := requestContext(flags.caller, retry)
	if err != nil {
		_ = client.Close()
		return nil, nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	return client, ctx, cancel, request, nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("manifest path must be absolute and clean")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("manifest must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("manifest changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("manifest changed outside its size bound")
	}
	return raw, nil
}

func printProto(message proto.Message) error {
	if message == nil {
		return errors.New("gateway returned an empty response")
	}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}).Marshal(message)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = os.Stdout.Write(raw)
	return err
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
