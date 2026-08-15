// Package toschain implements finalized, quorum-backed Native Registry reads.
package toschain

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/chain"
	"github.com/xssnick/tonutils-go/address"
)

const (
	DefaultQueryTimeout     = 5 * time.Second
	DefaultMaxResponseBytes = int64(4 << 20)
	DefaultReadinessMaxAge  = 2 * time.Minute
	maxEndpoints            = 8
	maxQueryTimeout         = 30 * time.Second
	maxResponseBytes        = int64(16 << 20)
	maxReadinessAge         = time.Hour
	maxClockSkew            = 2 * time.Minute
)

var networkPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Config struct {
	Network          string
	Endpoints        []string
	Quorum           int
	QueryTimeout     time.Duration
	MaxResponseBytes int64
	ReadinessMaxAge  time.Duration
}

type rpcNode struct{ client *chain.Client }

type Adapter struct {
	network      string
	nodes        []*rpcNode
	quorum       int
	readinessAge time.Duration
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
	if config.ReadinessMaxAge == 0 {
		config.ReadinessMaxAge = DefaultReadinessMaxAge
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maxQueryTimeout || config.MaxResponseBytes <= 0 || config.MaxResponseBytes > maxResponseBytes || config.ReadinessMaxAge <= 0 || config.ReadinessMaxAge > maxReadinessAge {
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
		parsed, err := url.Parse(endpoint)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("invalid TOS JSON-RPC endpoint URL")
		}
		if parsed.Scheme == "http" && !loopbackHost(parsed.Hostname()) {
			return nil, errors.New("remote TOS JSON-RPC endpoints require HTTPS")
		}
		authority, err := canonicalAuthority(parsed)
		if err != nil {
			return nil, errors.New("invalid TOS JSON-RPC endpoint authority")
		}
		if _, duplicate := seenAuthorities[authority]; duplicate {
			return nil, errors.New("TOS JSON-RPC endpoints must use unique authorities")
		}
		client, err := chain.NewClient(endpoint, config.QueryTimeout, config.MaxResponseBytes)
		if err != nil {
			return nil, fmt.Errorf("configure TOS JSON-RPC endpoint: %w", err)
		}
		seenEndpoints[endpoint], seenAuthorities[authority] = struct{}{}, struct{}{}
		nodes = append(nodes, &rpcNode{client: client})
	}
	return &Adapter{network: config.Network, nodes: nodes, quorum: config.Quorum, readinessAge: config.ReadinessMaxAge}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	value := net.ParseIP(host)
	return value != nil && value.IsLoopback()
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

func CanonicalAddress(value string) (string, error) {
	normalized, err := normalizeAddress(value)
	if err != nil {
		return "", err
	}
	if value != normalized {
		return "", errors.New("TOS chain references must use raw canonical addresses")
	}
	return normalized, nil
}

func NormalizeAddress(value string) (string, error) {
	return normalizeAddress(strings.TrimSpace(value))
}
