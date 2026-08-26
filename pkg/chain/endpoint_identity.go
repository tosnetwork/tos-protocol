package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"
)

// EndpointAuthorityDigest binds operator provenance to the exact configured
// JSON-RPC origin and path without exposing that URL in relay evidence. It is
// an owner-configuration identity, not a TLS certificate or chain proof.
func EndpointAuthorityDigest(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid JSON-RPC endpoint identity")
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return "", errors.New("invalid JSON-RPC endpoint host")
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	identity := scheme + "://" + net.JoinHostPort(host, port) + path
	digest := sha256.Sum256([]byte("TOS-CHAIN-ENDPOINT-AUTHORITY-V1\x00" + identity))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (c *Client) EndpointAuthorityDigest() (string, error) {
	if c == nil {
		return "", errors.New("JSON-RPC client is unavailable")
	}
	return EndpointAuthorityDigest(c.endpoint)
}
