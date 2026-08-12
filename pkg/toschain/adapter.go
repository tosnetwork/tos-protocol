// Package toschain implements the production, quorum-backed TOS chain
// boundary consumed by tos-protocol authorization and payment components.
// It reads only public JSON-RPC state and never opens validator databases.
package toschain

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/xssnick/tonutils-go/address"
)

const (
	DefaultQueryTimeout     = 5 * time.Second
	DefaultMaxResponseBytes = int64(4 << 20)
	DefaultClientKeyLease   = 5 * time.Minute
	DefaultReadinessMaxAge  = 2 * time.Minute

	maxEndpoints       = 8
	maxQueryTimeout    = 30 * time.Second
	maxResponseBytes   = int64(16 << 20)
	maxClientKeyLease  = time.Hour
	maxReadinessAge    = time.Hour
	controllerPrefix   = "ed25519:"
	manifestHashPrefix = "sha256:"
	codeHashPrefix     = "tvm-cell-sha256:"
)

var (
	networkPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	serviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

// Config describes a bounded set of independently operated TOS JSON-RPC
// observers. Quorum must be a strict majority, preventing two conflicting
// observations from both being accepted.
type Config struct {
	Network          string
	Endpoints        []string
	Quorum           int
	QueryTimeout     time.Duration
	MaxResponseBytes int64
	ClientKeyLease   time.Duration
	ReadinessMaxAge  time.Duration
}

type rpcNode struct {
	client *chain.Client
}

// Adapter is stateless with respect to request-controlled chain data. It has
// no transaction, account, or key cache, so adversarial references cannot
// cause process RSS to grow without bound.
type Adapter struct {
	network        string
	nodes          []*rpcNode
	quorum         int
	clientKeyLease time.Duration
	readinessAge   time.Duration
}

func New(config Config) (*Adapter, error) {
	if !networkPattern.MatchString(config.Network) {
		return nil, errors.New("invalid TOS chain network")
	}
	if len(config.Endpoints) < 3 || len(config.Endpoints) > maxEndpoints {
		return nil, errors.New("TOS chain endpoint count is outside bounds")
	}
	if config.Quorum <= len(config.Endpoints)/2 || config.Quorum > len(config.Endpoints) {
		return nil, errors.New("TOS chain quorum must be a strict endpoint majority")
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = DefaultQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if config.ClientKeyLease == 0 {
		config.ClientKeyLease = DefaultClientKeyLease
	}
	if config.ReadinessMaxAge == 0 {
		config.ReadinessMaxAge = DefaultReadinessMaxAge
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maxQueryTimeout ||
		config.MaxResponseBytes <= 0 || config.MaxResponseBytes > maxResponseBytes ||
		config.ClientKeyLease <= 0 || config.ClientKeyLease > maxClientKeyLease ||
		config.ReadinessMaxAge <= 0 || config.ReadinessMaxAge > maxReadinessAge {
		return nil, errors.New("invalid bounded TOS chain adapter policy")
	}

	nodes := make([]*rpcNode, 0, len(config.Endpoints))
	seenEndpoints := make(map[string]struct{}, len(config.Endpoints))
	seenAuthorities := make(map[string]struct{}, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		if endpoint == "" || len(endpoint) > 2048 {
			return nil, errors.New("invalid TOS JSON-RPC endpoint")
		}
		if _, duplicate := seenEndpoints[endpoint]; duplicate {
			return nil, errors.New("duplicate TOS JSON-RPC endpoint")
		}
		parsedEndpoint, err := url.Parse(endpoint)
		if err != nil || (parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https") ||
			parsedEndpoint.Host == "" || parsedEndpoint.User != nil ||
			parsedEndpoint.RawQuery != "" || parsedEndpoint.Fragment != "" {
			return nil, errors.New("invalid TOS JSON-RPC endpoint URL")
		}
		if parsedEndpoint.Scheme == "http" && !loopbackHost(parsedEndpoint.Hostname()) {
			return nil, errors.New("remote TOS JSON-RPC endpoints require HTTPS")
		}
		authority, err := canonicalAuthority(parsedEndpoint)
		if err != nil {
			return nil, errors.New("invalid TOS JSON-RPC endpoint authority")
		}
		if _, duplicate := seenAuthorities[authority]; duplicate {
			return nil, errors.New("TOS JSON-RPC endpoints must use unique authorities")
		}
		seenEndpoints[endpoint] = struct{}{}
		seenAuthorities[authority] = struct{}{}
		client, err := chain.NewClient(endpoint, config.QueryTimeout, config.MaxResponseBytes)
		if err != nil {
			return nil, fmt.Errorf("configure TOS JSON-RPC endpoint: %w", err)
		}
		nodes = append(nodes, &rpcNode{client: client})
	}
	return &Adapter{
		network: config.Network, nodes: nodes, quorum: config.Quorum,
		clientKeyLease: config.ClientKeyLease, readinessAge: config.ReadinessMaxAge,
	}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func canonicalAuthority(endpoint *url.URL) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(endpoint.Hostname(), "."))
	if host == "" {
		return "", errors.New("empty endpoint host")
	}
	port := endpoint.Port()
	if port == "" {
		if endpoint.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port), nil
}

func (a *Adapter) ResolveService(
	ctx context.Context,
	reference chain.ServiceReference,
) (chain.ServiceState, error) {
	if a == nil || ctx == nil {
		return chain.ServiceState{}, errors.New("invalid TOS service authority request")
	}
	if reference.Network != a.network || !serviceIDPattern.MatchString(reference.ServiceID) {
		return chain.ServiceState{}, errors.New("TOS service authority reference does not match adapter")
	}
	account, err := requireCanonicalAddress(reference.Address)
	if err != nil {
		return chain.ServiceState{}, fmt.Errorf("invalid service Agent Account: %w", err)
	}
	state, observation, err := a.resolveAgentAccount(ctx, account, reference.ServiceID, true)
	if err != nil {
		return chain.ServiceState{}, err
	}
	return chain.ServiceState{
		Network: a.network, Address: account, ServiceID: reference.ServiceID,
		Active: true, Finalized: true,
		Controller:          state.controllerID,
		ControllerPublicKey: append([]byte(nil), state.controllerKey...),
		ManifestDigest:      state.manifestDigest,
		CodeHash:            state.codeHash,
		ObservedMasterSeqno: observation.seqno,
		ObservedAt:          observation.observedAt,
	}, nil
}

func (a *Adapter) ResolveClientKey(
	ctx context.Context,
	reference authorization.ClientKeyReference,
) (authorization.ClientKeySnapshot, error) {
	if a == nil || ctx == nil {
		return authorization.ClientKeySnapshot{}, errors.New("invalid TOS client-key request")
	}
	if reference.Network != a.network || !serviceIDPattern.MatchString(reference.ServiceID) {
		return authorization.ClientKeySnapshot{}, errors.New("TOS client-key reference does not match adapter")
	}
	account, expectedKey, err := parseAgentClientKeyID(reference.KeyID)
	if err != nil {
		return authorization.ClientKeySnapshot{}, err
	}
	state, observation, err := a.resolveAgentAccount(ctx, account, reference.ServiceID, false)
	if err != nil {
		return authorization.ClientKeySnapshot{}, err
	}
	if observation.seqno < reference.MinimumMasterSeqno {
		return authorization.ClientKeySnapshot{}, errors.New("TOS client-key observation is below high-water mark")
	}
	if !ed25519.PublicKey(expectedKey).Equal(ed25519.PublicKey(state.controllerKey)) {
		return authorization.ClientKeySnapshot{}, errors.New("requested client key is not the current Agent Account controller")
	}
	return authorization.ClientKeySnapshot{
		Network: a.network, ServiceID: reference.ServiceID,
		KeyID: reference.KeyID, Principal: account,
		PublicKey:           append(ed25519.PublicKey(nil), state.controllerKey...),
		NotBefore:           observation.observedAt.Add(-identity.MaxClockSkew),
		NotAfter:            observation.observedAt.Add(a.clientKeyLease),
		ObservedMasterSeqno: observation.seqno,
		ObservedAt:          observation.observedAt,
	}, nil
}

// FormatAgentClientKeyID creates a self-describing client key reference. It
// allows a service to authenticate any number of independently owned Agent
// Accounts without a request-driven server-side address map or cache.
func FormatAgentClientKeyID(account string, key []byte) (string, error) {
	canonical, err := requireCanonicalAddress(account)
	if err != nil {
		return "", err
	}
	if len(key) != ed25519.PublicKeySize || allZero(key) {
		return "", errors.New("invalid Agent Account client public key")
	}
	parts := strings.Split(canonical, ":")
	return "tos:agent-key:v1:" + parts[0] + ":" + parts[1] + ":" +
		hex.EncodeToString(key), nil
}

func parseAgentClientKeyID(value string) (string, []byte, error) {
	if len(value) > 256 || strings.TrimSpace(value) != value {
		return "", nil, errors.New("invalid Agent Account client key ID")
	}
	parts := strings.Split(value, ":")
	if len(parts) != 6 || parts[0] != "tos" || parts[1] != "agent-key" || parts[2] != "v1" {
		return "", nil, errors.New("unsupported Agent Account client key ID")
	}
	account := parts[3] + ":" + parts[4]
	if _, err := requireCanonicalAddress(account); err != nil {
		return "", nil, err
	}
	key, err := hex.DecodeString(parts[5])
	if err != nil || len(key) != ed25519.PublicKeySize ||
		parts[5] != strings.ToLower(parts[5]) || allZero(key) {
		return "", nil, errors.New("invalid Agent Account client public key")
	}
	return account, key, nil
}

func controllerID(key []byte) string {
	return controllerPrefix + hex.EncodeToString(key)
}

func normalizeAddress(value string) (string, error) {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return "", errors.New("invalid TOS address")
	}
	parsed, err := address.ParseAddr(value)
	if err != nil {
		parsed, err = address.ParseRawAddr(value)
	}
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 {
		return "", errors.New("invalid standard TOS address")
	}
	return parsed.StringRaw(), nil
}

func requireCanonicalAddress(value string) (string, error) {
	normalized, err := normalizeAddress(value)
	if err != nil {
		return "", err
	}
	if value != normalized {
		return "", errors.New("TOS chain references must use raw canonical addresses")
	}
	return normalized, nil
}

// CanonicalAddress validates that value is an exact raw standard TOS address
// and returns that canonical value. It is exposed for components that need to
// construct independently verifiable chain expectations before querying the
// adapter.
func CanonicalAddress(value string) (string, error) {
	return requireCanonicalAddress(value)
}

// NormalizeAddress accepts either a user-friendly or raw standard TOS address
// and returns its raw canonical representation. It is intended for trusted
// tool output; protocol inputs must continue to use CanonicalAddress so that
// alternative textual encodings cannot enter signed or hashed structures.
func NormalizeAddress(value string) (string, error) {
	return normalizeAddress(strings.TrimSpace(value))
}

var (
	_ chain.Adapter                   = (*Adapter)(nil)
	_ authorization.ClientKeyResolver = (*Adapter)(nil)
)
