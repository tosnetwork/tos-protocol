// Command tos-service-material creates the public, signed bootstrap documents
// for one service deployment. It emits no private key material and never
// contacts a chain; the operator must commit the reported manifest digest to
// the service Agent Account before publishing the documents.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
	"github.com/tosnetwork/tos-protocol/pkg/receiptsigner"
)

type output struct {
	ManifestDigest       string                     `json:"manifestDigest"`
	ManifestEnvelope     identity.Envelope          `json:"manifestEnvelope"`
	Descriptor           protocol.ServiceDescriptor `json:"descriptor"`
	Catalog              ard.Catalog                `json:"catalog"`
	Controller           string                     `json:"controller"`
	AuthenticateKeyID    string                     `json:"authenticateKeyId"`
	AuthenticatePublic   string                     `json:"authenticatePublicKey"`
	QuoteKeyID           string                     `json:"quoteKeyId"`
	QuotePublic          string                     `json:"quotePublicKey"`
	ReceiptKeyID         string                     `json:"receiptKeyId"`
	ReceiptPublic        string                     `json:"receiptPublicKey"`
	ManifestCanonicalSHA string                     `json:"manifestCanonicalSha256"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("tos-service-material", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var serviceID, network, account, displayName, publicURL, ardIdentifier string
	var manifestID, revision, profileDigest string
	var authenticateKeyID, quoteKeyID, receiptKeyID string
	var controllerSeed, authenticateSeed, quoteSeed, receiptSeed string
	var lifetime time.Duration
	flags.StringVar(&serviceID, "service-id", "", "stable service ID")
	flags.StringVar(&network, "network", "", "TOS network ID")
	flags.StringVar(&account, "agent-account", "", "service Agent Account raw address")
	flags.StringVar(&displayName, "display-name", "", "public service display name")
	flags.StringVar(&publicURL, "public-url", "", "public HTTPS origin")
	flags.StringVar(&ardIdentifier, "ard-identifier", "", "ARD resource identifier")
	flags.StringVar(&manifestID, "manifest-id", "", "unique manifest ID")
	flags.StringVar(&revision, "revision", "", "deployment revision")
	flags.StringVar(&profileDigest, "profile-digest", "", "sha256 profile artifact digest")
	flags.StringVar(&authenticateKeyID, "authenticate-key-id", "", "authenticate signer key ID")
	flags.StringVar(&quoteKeyID, "quote-key-id", "", "quote signer key ID")
	flags.StringVar(&receiptKeyID, "receipt-key-id", "", "receipt signer key ID")
	flags.StringVar(&controllerSeed, "controller-seed", "", "private controller seed file")
	flags.StringVar(&authenticateSeed, "authenticate-seed", "", "private authenticate seed file")
	flags.StringVar(&quoteSeed, "quote-seed", "", "private quote seed file")
	flags.StringVar(&receiptSeed, "receipt-seed", "", "private receipt seed file")
	flags.DurationVar(&lifetime, "lifetime", 20*time.Hour, "document validity (maximum 24h)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if len(flags.Args()) != 0 || serviceID == "" || network == "" || account == "" ||
		displayName == "" || publicURL == "" || ardIdentifier == "" ||
		manifestID == "" || revision == "" || profileDigest == "" ||
		authenticateKeyID == "" || quoteKeyID == "" || receiptKeyID == "" ||
		controllerSeed == "" || authenticateSeed == "" || quoteSeed == "" || receiptSeed == "" ||
		lifetime <= 0 || lifetime > protocol.MaxManifestLifetime {
		return errors.New("complete bounded service material flags are required")
	}
	origin, err := url.Parse(publicURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" ||
		origin.User != nil || origin.Path != "" || origin.RawQuery != "" ||
		origin.Fragment != "" {
		return errors.New("public URL must be an HTTPS origin without path, query, or fragment")
	}
	controller, err := receiptsigner.LoadPrivateKey(controllerSeed)
	if err != nil {
		return errors.New("load controller seed")
	}
	defer zero(controller)
	authenticate, err := receiptsigner.LoadPrivateKey(authenticateSeed)
	if err != nil {
		return errors.New("load authenticate seed")
	}
	defer zero(authenticate)
	quote, err := receiptsigner.LoadPrivateKey(quoteSeed)
	if err != nil {
		return errors.New("load quote seed")
	}
	defer zero(quote)
	receipt, err := receiptsigner.LoadPrivateKey(receiptSeed)
	if err != nil {
		return errors.New("load receipt seed")
	}
	defer zero(receipt)

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(lifetime)
	profile := protocol.ProfileReference{
		ID: "tos.ai.text-generation", Version: "0.1.0",
		MediaType: "application/vnd.tos.ai.text-generation+json",
		URL:       publicURL + "/profiles/tos.ai.text-generation/0.1",
		Digest:    profileDigest,
	}
	controllerPublic := controller.Public().(ed25519.PublicKey)
	controllerID := "ed25519:" + hex.EncodeToString(controllerPublic)
	manifest := protocol.ServiceManifest{
		Version: protocol.ManifestVersion, ManifestID: manifestID,
		ServiceID: serviceID, Controller: controllerID, Network: network,
		Revision: revision, IssuedAt: now, ExpiresAt: expires,
		RuntimeKeys: []protocol.RuntimeKey{
			runtimeKey(authenticateKeyID, authenticate, protocol.RuntimeRoleAuthenticate, now, expires),
			runtimeKey(quoteKeyID, quote, protocol.RuntimeRoleQuote, now, expires),
			runtimeKey(receiptKeyID, receipt, protocol.RuntimeRoleReceipt, now, expires),
		},
		Endpoints: []protocol.ServiceEndpoint{{
			Transport: "https", Audience: "authenticated", URL: publicURL + "/tos/v1/actions",
		}},
		Profiles: []protocol.ProfileReference{profile},
	}
	if err := manifest.Validate(now); err != nil {
		return fmt.Errorf("validate service manifest: %w", err)
	}
	envelope, err := identity.SignCanonical(
		controller, protocol.ServiceManifestDomain, controllerID,
		manifest, now, expires,
	)
	if err != nil {
		return fmt.Errorf("sign service manifest: %w", err)
	}
	digest, err := codec.Digest(protocol.ServiceManifestDomain, manifest)
	if err != nil {
		return err
	}
	descriptor := protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion, ServiceID: serviceID,
		DisplayName: displayName, Controller: account, Network: network,
		Revision: manifest.Revision, ExpiresAt: expires, Profiles: []protocol.ProfileReference{profile},
		ARDIdentifier: ardIdentifier,
	}
	if err := descriptor.Validate(now); err != nil {
		return fmt.Errorf("validate service descriptor: %w", err)
	}
	catalogDocument := fmt.Sprintf(`{"specVersion":"1.0","entries":[{"identifier":%q,"displayName":%q,"type":"application/vnd.tos.service+json","url":%q}]}`,
		ardIdentifier, displayName, publicURL+"/.well-known/tos-service.json")
	catalog, err := ard.DecodeCatalog(
		strings.NewReader(catalogDocument), ard.DefaultLimits(),
	)
	if err != nil {
		return fmt.Errorf("build ARD catalog: %w", err)
	}
	canonical, err := codec.Marshal(manifest)
	if err != nil {
		return err
	}
	canonicalHash := sha256.Sum256(canonical)
	result := output{
		ManifestDigest: digest, ManifestEnvelope: envelope, Descriptor: descriptor,
		Catalog: catalog, Controller: controllerID,
		AuthenticateKeyID: authenticateKeyID, AuthenticatePublic: publicKey(authenticate),
		QuoteKeyID: quoteKeyID, QuotePublic: publicKey(quote),
		ReceiptKeyID: receiptKeyID, ReceiptPublic: publicKey(receipt),
		ManifestCanonicalSHA: "sha256:" + hex.EncodeToString(canonicalHash[:]),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func runtimeKey(id string, key ed25519.PrivateKey, role string, start, end time.Time) protocol.RuntimeKey {
	return protocol.RuntimeKey{
		KeyID: id, Algorithm: "Ed25519", PublicKey: publicKey(key),
		Roles: []string{role}, NotBefore: start, NotAfter: end,
	}
}

func publicKey(key ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
