package agentcommerce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type ContentRetrievalPolicy struct {
	SchemaVersion          uint16   `json:"schema_version"`
	AllowedOrigins         []string `json:"allowed_origins"`
	MaxRedirects           uint8    `json:"max_redirects"`
	MaxConnections         uint16   `json:"max_connections"`
	MaxResponseHeaderBytes uint32   `json:"max_response_header_bytes"`
	MaxCompressedBytes     uint64   `json:"max_compressed_bytes"`
	MaxDecodedBytes        uint64   `json:"max_decoded_bytes"`
	TimeoutMillis          uint32   `json:"timeout_millis"`
}

type ContentFetchRequest struct {
	CandidateURL  string `json:"candidate_url"`
	ContentDigest string `json:"content_digest"`
	ContentSize   uint64 `json:"content_size"`
}

type OriginCredential struct {
	Origin string
	Name   string
	Value  string
}

type HostResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// SecureContentRetriever treats every locator as hostile. The fixed policy,
// not an Intent or model, chooses reachable origins and credentials.
type SecureContentRetriever struct {
	Policy     ContentRetrievalPolicy
	Resolver   HostResolver
	Dialer     *net.Dialer
	Credential *OriginCredential
}

func (retriever SecureContentRetriever) Fetch(ctx context.Context, request ContentFetchRequest) ([]byte, error) {
	if err := validateRetrievalPolicy(retriever.Policy); err != nil || !canonicalDigestPattern.MatchString(request.ContentDigest) ||
		request.ContentSize == 0 || request.ContentSize > retriever.Policy.MaxDecodedBytes {
		return nil, errors.New("content retrieval request or policy is invalid")
	}
	candidate, err := url.Parse(request.CandidateURL)
	if err != nil {
		return nil, errors.New("content locator is invalid")
	}
	allowed := make(map[string]struct{}, len(retriever.Policy.AllowedOrigins))
	for _, origin := range retriever.Policy.AllowedOrigins {
		allowed[origin] = struct{}{}
	}
	resolver := retriever.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := retriever.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: time.Duration(retriever.Policy.TimeoutMillis) * time.Millisecond}
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: int(retriever.Policy.MaxConnections),
		MaxIdleConnsPerHost: int(retriever.Policy.MaxConnections), MaxResponseHeaderBytes: int64(retriever.Policy.MaxResponseHeaderBytes),
		ResponseHeaderTimeout: time.Duration(retriever.Policy.TimeoutMillis) * time.Millisecond}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("retrieval address is invalid")
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 || len(ips) > 16 {
			return nil, errors.New("retrieval DNS result is unavailable or unbounded")
		}
		for _, resolved := range ips {
			if !publicRetrievalIP(resolved.IP) {
				return nil, errors.New("retrieval DNS resolved to a non-public address")
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
	redirects := 0
	client := &http.Client{Transport: transport, Timeout: time.Duration(retriever.Policy.TimeoutMillis) * time.Millisecond,
		CheckRedirect: func(next *http.Request, prior []*http.Request) error {
			redirects++
			if redirects > int(retriever.Policy.MaxRedirects) {
				return errors.New("content retrieval exceeded redirect limit")
			}
			if err := validateRetrievalURL(next.URL, allowed); err != nil {
				return err
			}
			// Go may copy custom headers across redirects. A credential is an
			// origin capability, so even another allowed origin must not receive
			// it unless it is the exact configured credential origin.
			if retriever.Credential != nil && originOf(next.URL) != retriever.Credential.Origin {
				next.Header.Del(retriever.Credential.Name)
			}
			return nil
		}}
	defer transport.CloseIdleConnections()
	if err := validateRetrievalURL(candidate, allowed); err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.String(), nil)
	if err != nil {
		return nil, errors.New("create content retrieval request")
	}
	httpRequest.Header.Set("Accept-Encoding", "identity")
	if credential := retriever.Credential; credential != nil {
		if credential.Origin != originOf(candidate) || !validHeaderName(credential.Name) || credential.Value == "" || len(credential.Value) > 4096 {
			return nil, errors.New("retrieval credential is not bound to this origin")
		}
		httpRequest.Header.Set(credential.Name, credential.Value)
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("retrieve content: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > int64(retriever.Policy.MaxCompressedBytes) ||
		response.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("content response status, encoding, or size is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(retriever.Policy.MaxCompressedBytes)+1))
	if err != nil || uint64(len(body)) > retriever.Policy.MaxCompressedBytes || uint64(len(body)) != request.ContentSize {
		return nil, errors.New("content response has the wrong bounded size")
	}
	digest := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(digest[:]) != request.ContentDigest {
		return nil, errors.New("content response digest mismatch")
	}
	return body, nil
}

func validateRetrievalPolicy(policy ContentRetrievalPolicy) error {
	if policy.SchemaVersion != 1 || len(policy.AllowedOrigins) == 0 || len(policy.AllowedOrigins) > 64 ||
		policy.MaxRedirects > 3 || policy.MaxConnections == 0 || policy.MaxConnections > 16 ||
		policy.MaxResponseHeaderBytes == 0 || policy.MaxResponseHeaderBytes > 256<<10 || policy.MaxCompressedBytes == 0 ||
		policy.MaxDecodedBytes == 0 || policy.MaxCompressedBytes > policy.MaxDecodedBytes || policy.MaxDecodedBytes > MaxIntentContentBytes ||
		policy.TimeoutMillis < 100 || policy.TimeoutMillis > 60_000 || !sort.StringsAreSorted(policy.AllowedOrigins) {
		return errors.New("content retrieval policy is invalid")
	}
	for index, origin := range policy.AllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			index > 0 && policy.AllowedOrigins[index-1] == origin {
			return errors.New("content retrieval origin is not canonical HTTPS")
		}
	}
	return nil
}

func validateRetrievalURL(candidate *url.URL, allowed map[string]struct{}) error {
	if candidate == nil || candidate.Scheme != "https" || candidate.Host == "" || candidate.User != nil || candidate.Fragment != "" {
		return errors.New("content locator is not canonical HTTPS")
	}
	if _, ok := allowed[originOf(candidate)]; !ok {
		return errors.New("content locator origin is not owner-allowed")
	}
	return nil
}

func originOf(value *url.URL) string { return value.Scheme + "://" + value.Host }

func publicRetrievalIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > 128 || strings.EqualFold(value, "host") || strings.EqualFold(value, "cookie") {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character == '-') {
			return false
		}
	}
	return true
}
