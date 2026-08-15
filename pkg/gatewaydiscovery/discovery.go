// Package gatewaydiscovery validates the authority-neutral ATOS Gateway
// locator. Discovery never resolves or vouches for protocol state.
package gatewaydiscovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

const (
	Schema           = "atos.gateway-discovery.v1"
	Protocol         = "atos_native_v1"
	MaxDocumentBytes = 64 << 10
)

type Network struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}
type Services struct {
	NativeConnect     string `json:"native_connect"`
	A2AJSONRPC        string `json:"a2a_jsonrpc,omitempty"`
	MCPStreamableHTTP string `json:"mcp_streamable_http,omitempty"`
}
type Limits struct {
	MaxRequestBytes  int `json:"max_request_bytes"`
	MaxResponseBytes int `json:"max_response_bytes"`
}
type Document struct {
	Schema               string   `json:"schema"`
	Protocol             string   `json:"protocol"`
	Network              Network  `json:"network"`
	RegistryCodeHash     string   `json:"registry_code_hash"`
	Services             Services `json:"services"`
	Limits               Limits   `json:"limits"`
	ExpiresAtUnixSeconds int64    `json:"expires_at_unix_seconds"`
}
type Expected struct{ NetworkID, GenesisRootHash, GenesisFileHash, RegistryCodeHash string }

func Decode(raw []byte, expected Expected, now time.Time, allowLoopbackHTTP bool) (Document, error) {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes {
		return Document{}, errors.New("Gateway discovery document is outside size bounds")
	}
	var d Document
	if err := jsonstrict.Decode(raw, &d); err != nil {
		return Document{}, fmt.Errorf("decode Gateway discovery: %w", err)
	}
	if d.Schema != Schema || d.Protocol != Protocol || d.Network.NetworkID != expected.NetworkID ||
		d.Network.GenesisRootHash != expected.GenesisRootHash || d.Network.GenesisFileHash != expected.GenesisFileHash ||
		d.RegistryCodeHash != expected.RegistryCodeHash {
		return Document{}, errors.New("Gateway discovery authority domain mismatch")
	}
	if d.Limits.MaxRequestBytes <= 0 || d.Limits.MaxRequestBytes > 64<<20 || d.Limits.MaxResponseBytes <= 0 || d.Limits.MaxResponseBytes > 64<<20 ||
		d.ExpiresAtUnixSeconds <= now.Unix() || d.ExpiresAtUnixSeconds > now.Add(24*time.Hour).Unix() {
		return Document{}, errors.New("Gateway discovery limits or expiry are invalid")
	}
	for _, endpoint := range []string{d.Services.NativeConnect, d.Services.A2AJSONRPC, d.Services.MCPStreamableHTTP} {
		if endpoint == "" {
			continue
		}
		if err := validateServiceURL(endpoint, allowLoopbackHTTP); err != nil {
			return Document{}, err
		}
	}
	if d.Services.NativeConnect == "" {
		return Document{}, errors.New("Gateway discovery omits Native Connect service")
	}
	return d, nil
}

func validateServiceURL(value string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(value)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("invalid Gateway discovery service URL")
	}
	if u.Scheme == "http" && (!allowLoopbackHTTP || !loopbackName(u.Hostname())) {
		return errors.New("Gateway discovery service requires HTTPS")
	}
	return nil
}

type FetchConfig struct {
	Origin            string
	Expected          Expected
	AllowLoopbackHTTP bool
	Timeout           time.Duration
	Now               func() time.Time
}

func Fetch(ctx context.Context, c FetchConfig) (Document, error) {
	if ctx == nil {
		return Document{}, errors.New("missing Gateway discovery context")
	}
	origin, err := url.Parse(strings.TrimRight(c.Origin, "/"))
	if err != nil || origin == nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return Document{}, errors.New("invalid Gateway discovery origin")
	}
	if err := validateServiceURL(origin.String(), c.AllowLoopbackHTTP); err != nil {
		return Document{}, err
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return Document{}, errors.New("invalid Gateway discovery timeout")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	transport := &http.Transport{Proxy: nil, DialContext: pinnedDialer(origin.Hostname(), origin.Port(), origin.Scheme, c.AllowLoopbackHTTP), TLSHandshakeTimeout: c.Timeout}
	client := &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.String()+"/.well-known/atos-native.json", nil)
	if err != nil {
		return Document{}, err
	}
	response, err := client.Do(req)
	if err != nil {
		return Document{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return Document{}, errors.New("Gateway discovery response is not JSON success")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxDocumentBytes+1))
	if err != nil || len(raw) > MaxDocumentBytes {
		return Document{}, errors.New("read bounded Gateway discovery response")
	}
	return Decode(raw, c.Expected, c.Now(), c.AllowLoopbackHTTP)
}

func pinnedDialer(host, explicitPort, scheme string, allowLoopback bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("resolve Gateway discovery origin")
		}
		port := explicitPort
		if port == "" {
			if scheme == "http" {
				port = "80"
			} else {
				port = "443"
			}
		}
		var last error
		for _, candidate := range addresses {
			ip := candidate.IP
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				if !(allowLoopback && ip.IsLoopback() && loopbackName(host)) {
					continue
				}
			}
			connection, dialErr := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			last = dialErr
		}
		if last != nil {
			return nil, last
		}
		return nil, errors.New("Gateway discovery origin resolves only to disallowed addresses")
	}
}

func loopbackName(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
