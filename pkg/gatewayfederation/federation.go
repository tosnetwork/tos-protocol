// Package gatewayfederation combines authority-neutral discovery responses
// from independent Gateways. It never promotes search ranking, availability,
// or a Gateway response into canonical Native state.
package gatewayfederation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

type Client interface {
	SearchCapabilities(context.Context, *nativev1.SearchCapabilitiesRequest) (*nativev1.SearchCapabilitiesResponse, error)
	GetSoftwareWorkManifest(context.Context, *nativev1.GetSoftwareWorkManifestRequest) (*nativev1.GetSoftwareWorkManifestResponse, error)
}

type Gateway struct {
	ID     string
	Client Client
}

type Config struct {
	Network           *nativev1.NetworkDomain
	RegistryCodeHash  string
	PerGatewayTimeout time.Duration
	MaxGateways       int
	MaxResults        int
}

type Federation struct{ config Config }

type Candidate struct {
	GatewayID string
	Result    *nativev1.CapabilitySearchResultV1
}

type Failure struct {
	GatewayID string
	Err       error
}

func New(config Config) (*Federation, error) {
	if config.Network == nil || config.Network.NetworkId == "" ||
		!digest(config.Network.GenesisRootHash, "sha256:") ||
		!digest(config.Network.GenesisFileHash, "sha256:") ||
		!digest(config.RegistryCodeHash, "tvm-cell-sha256:") {
		return nil, errors.New("invalid Gateway federation authority domain")
	}
	if config.PerGatewayTimeout == 0 {
		config.PerGatewayTimeout = 10 * time.Second
	}
	if config.MaxGateways == 0 {
		config.MaxGateways = 8
	}
	if config.MaxResults == 0 {
		config.MaxResults = config.MaxGateways * 100
	}
	if config.PerGatewayTimeout < time.Second || config.PerGatewayTimeout > 30*time.Second ||
		config.MaxGateways < 2 || config.MaxGateways > 32 || config.MaxResults < 1 || config.MaxResults > 3200 {
		return nil, errors.New("invalid Gateway federation bounds")
	}
	config.Network = proto.Clone(config.Network).(*nativev1.NetworkDomain)
	return &Federation{config: config}, nil
}

type searchResult struct {
	id       string
	response *nativev1.SearchCapabilitiesResponse
	err      error
}

// Search queries every configured Gateway independently. A partial result is
// useful only as discovery: consumers still resolve the selected Capability
// from finalized TOS state before purchase.
func (f *Federation) Search(ctx context.Context, gateways []Gateway, request *nativev1.SearchCapabilitiesRequest) ([]Candidate, []Failure, error) {
	if f == nil || ctx == nil || request == nil || request.Context == nil || len(gateways) < 2 || len(gateways) > f.config.MaxGateways {
		return nil, nil, errors.New("invalid federated Capability search")
	}
	if request.PageSize == 0 || request.PageSize > 100 {
		return nil, nil, errors.New("federated search page size is outside bounds")
	}
	if err := validateGateways(gateways); err != nil {
		return nil, nil, err
	}
	results := make(chan searchResult, len(gateways))
	for _, gateway := range gateways {
		gateway := gateway
		go func() {
			call, cancel := context.WithTimeout(ctx, f.config.PerGatewayTimeout)
			defer cancel()
			response, err := gateway.Client.SearchCapabilities(call,
				proto.Clone(request).(*nativev1.SearchCapabilitiesRequest))
			results <- searchResult{id: gateway.ID, response: response, err: err}
		}()
	}
	candidates := make([]Candidate, 0)
	failures := make([]Failure, 0)
	successes := 0
	for range gateways {
		result := <-results
		if result.err != nil || result.response == nil {
			if result.err == nil {
				result.err = errors.New("Gateway returned no search response")
			}
			failures = append(failures, Failure{result.id, result.err})
			continue
		}
		if len(result.response.Results) > int(request.PageSize) {
			failures = append(failures, Failure{result.id, errors.New("Gateway search response exceeds bounds")})
			continue
		}
		valid := make([]Candidate, 0, len(result.response.Results))
		for _, candidate := range result.response.Results {
			if err := f.validateCandidate(candidate); err != nil {
				valid = nil
				failures = append(failures, Failure{result.id, err})
				break
			}
			valid = append(valid, Candidate{result.id, proto.Clone(candidate).(*nativev1.CapabilitySearchResultV1)})
		}
		if valid == nil {
			continue
		}
		successes++
		candidates = append(candidates, valid...)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		leftID, rightID := left.Result.Capability.GetCapability().CapabilityId, right.Result.Capability.GetCapability().CapabilityId
		if leftID != rightID {
			return leftID < rightID
		}
		if left.Result.CapabilityVersion != right.Result.CapabilityVersion {
			return left.Result.CapabilityVersion < right.Result.CapabilityVersion
		}
		return left.GatewayID < right.GatewayID
	})
	sort.Slice(failures, func(i, j int) bool { return failures[i].GatewayID < failures[j].GatewayID })
	if successes == 0 {
		return nil, failures, errors.New("all Gateway searches failed closed")
	}
	if len(candidates) > f.config.MaxResults {
		return nil, failures, errors.New("federated search aggregate exceeds configured bound")
	}
	return candidates, failures, nil
}

func (f *Federation) validateCandidate(result *nativev1.CapabilitySearchResultV1) error {
	if result == nil || result.Capability == nil || !proto.Equal(result.Capability.Network, f.config.Network) ||
		!digest(result.Capability.TvmStateHash, "tvm-cell-sha256:") || result.Capability.Reference == nil ||
		result.Capability.Reference.FinalizedCheckpoint == 0 ||
		result.Capability.Reference.ContractCodeHash != f.config.RegistryCodeHash ||
		!digest(result.Capability.Reference.TransactionHash, "sha256:") || result.Capability.GetCapability() == nil ||
		result.Capability.GetCapability().Tombstoned || result.CapabilityVersion == "" ||
		!digest(result.ManifestDigest, "sha256:") {
		return errors.New("Gateway returned an invalid finalized Capability candidate")
	}
	active := false
	for _, version := range result.Capability.GetCapability().Versions {
		if version != nil && version.Version == result.CapabilityVersion &&
			version.ManifestDigest == result.ManifestDigest && !version.Revoked {
			active = true
		}
	}
	if !active {
		return errors.New("Gateway search projection conflicts with Capability state")
	}
	return nil
}

// FetchManifest tries every Gateway and returns the first exact
// content-addressed object. Invalid or unavailable responses are isolated.
func (f *Federation) FetchManifest(ctx context.Context, gateways []Gateway, request *nativev1.GetSoftwareWorkManifestRequest) ([]byte, string, []Failure, error) {
	if f == nil || ctx == nil || request == nil || request.Context == nil || !digest(request.ManifestDigest, "sha256:") ||
		len(gateways) < 2 || len(gateways) > f.config.MaxGateways {
		return nil, "", nil, errors.New("invalid federated manifest retrieval")
	}
	if err := validateGateways(gateways); err != nil {
		return nil, "", nil, err
	}
	failures := make([]Failure, 0)
	for _, gateway := range gateways {
		call, cancel := context.WithTimeout(ctx, f.config.PerGatewayTimeout)
		response, err := gateway.Client.GetSoftwareWorkManifest(call,
			proto.Clone(request).(*nativev1.GetSoftwareWorkManifestRequest))
		cancel()
		if err == nil && response != nil && response.ManifestDigest == request.ManifestDigest &&
			len(response.CanonicalCbor) > 0 && len(response.CanonicalCbor) <= 1<<20 && sha(response.CanonicalCbor) == request.ManifestDigest {
			return append([]byte(nil), response.CanonicalCbor...), gateway.ID, failures, nil
		}
		if err == nil {
			err = errors.New("Gateway manifest bytes do not match requested digest")
		}
		failures = append(failures, Failure{gateway.ID, err})
	}
	return nil, "", failures, errors.New("manifest is unavailable from every Gateway")
}

func validateGateways(gateways []Gateway) error {
	seen := make(map[string]struct{}, len(gateways))
	for _, gateway := range gateways {
		if gateway.Client == nil || gateway.ID == "" || len(gateway.ID) > 128 || strings.TrimSpace(gateway.ID) != gateway.ID {
			return errors.New("invalid Gateway federation member")
		}
		if _, exists := seen[gateway.ID]; exists {
			return errors.New("duplicate Gateway federation member")
		}
		seen[gateway.ID] = struct{}{}
	}
	return nil
}

func sha(value []byte) string {
	hash := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func digest(value, prefix string) bool {
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value[len(prefix):])
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}

func (f Failure) Error() string { return fmt.Sprintf("%s: %v", f.GatewayID, f.Err) }
