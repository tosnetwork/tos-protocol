package registry

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
)

const federationLinkRelation = "ard-registry"

type FederationConfig struct {
	Roots              []string
	AllowedOrigins     []string
	MaxSources         int
	MaxDepth           int
	MaxRedirects       int
	MaxCompressedBytes int64
	MaxDecodedBytes    int64
	MinimumTTL         time.Duration
	MaximumTTL         time.Duration
	// AllowPrivateOrigins is for explicitly private operator federations and
	// local tests. Public Registry deployments must leave it false.
	AllowPrivateOrigins bool
	Resolver            *net.Resolver
}

func DefaultFederationConfig() FederationConfig {
	return FederationConfig{
		MaxSources: 64, MaxDepth: 3, MaxRedirects: 3,
		MaxCompressedBytes: 2 << 20, MaxDecodedBytes: 2 << 20,
		MinimumTTL: time.Minute, MaximumTTL: time.Hour,
	}
}

type FederationStatus struct {
	Generation uint64
	Sources    int
	ExpiresAt  time.Time
	LastError  string
}

// Federation maintains one cached, atomically replaceable crawl generation.
// Roots and every redirect/peer must match an explicit origin allowlist.
type Federation struct {
	index   *Index
	client  *http.Client
	config  FederationConfig
	origins map[string]struct{}
	mu      sync.Mutex
	status  FederationStatus
}

func NewFederation(index *Index, client *http.Client, config FederationConfig) (*Federation, error) {
	if index == nil || client == nil || config.MaxSources <= 0 || config.MaxSources > 4096 ||
		config.MaxDepth < 0 || config.MaxDepth > 16 || config.MaxRedirects < 0 || config.MaxRedirects > 16 ||
		config.MaxCompressedBytes <= 0 || config.MaxDecodedBytes <= 0 ||
		config.MaxCompressedBytes > 64<<20 || config.MaxDecodedBytes > 64<<20 ||
		config.MinimumTTL <= 0 || config.MaximumTTL < config.MinimumTTL || config.MaximumTTL > 24*time.Hour ||
		len(config.Roots) == 0 || len(config.Roots) > config.MaxSources || len(config.AllowedOrigins) == 0 ||
		len(config.AllowedOrigins) > 4096 {
		return nil, errors.New("invalid ARD federation configuration")
	}
	origins := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, raw := range config.AllowedOrigins {
		parsed, err := canonicalFederationURL(raw)
		if err != nil || parsed.Path != "/" || parsed.RawQuery != "" {
			return nil, errors.New("invalid ARD federation allowed origin")
		}
		origins[parsed.Scheme+"://"+parsed.Host] = struct{}{}
	}
	for _, root := range config.Roots {
		parsed, err := canonicalFederationURL(root)
		if err != nil {
			return nil, err
		}
		if _, ok := origins[parsed.Scheme+"://"+parsed.Host]; !ok {
			return nil, errors.New("ARD federation root origin is not allowed")
		}
	}
	clone := *client
	transport, err := federationTransport(client.Transport, config)
	if err != nil {
		return nil, err
	}
	clone.Transport = transport
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &Federation{index: index, client: &clone, config: config, origins: origins}, nil
}

type crawlItem struct {
	url   string
	depth int
}

// Refresh crawls a complete bounded generation. Any fetch, parse, quota, or
// index error preserves the prior generation unchanged.
func (f *Federation) Refresh(ctx context.Context, now time.Time) error {
	if f == nil || ctx == nil || now.IsZero() {
		return errors.New("invalid ARD federation refresh")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := make([]crawlItem, 0, f.config.MaxSources)
	for _, root := range f.config.Roots {
		queue = append(queue, crawlItem{url: root})
	}
	visited := make(map[string]struct{}, f.config.MaxSources)
	inputs := make([]CatalogInput, 0, f.config.MaxSources)
	expiresAt := now.Add(f.config.MaximumTTL)
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return f.fail(err)
		}
		item := queue[0]
		queue = queue[1:]
		parsed, err := canonicalFederationURL(item.url)
		if err != nil || !f.allowed(parsed) {
			return f.fail(errors.New("ARD federation source is not allowed"))
		}
		canonical := parsed.String()
		if _, exists := visited[canonical]; exists {
			continue
		}
		if len(visited) >= f.config.MaxSources {
			return f.fail(errors.New("ARD federation source limit exceeded"))
		}
		visited[canonical] = struct{}{}
		catalog, peers, expiry, err := f.fetch(ctx, parsed, now)
		if err != nil {
			return f.fail(err)
		}
		inputs = append(inputs, CatalogInput{Source: canonical, Catalog: catalog})
		if expiry.Before(expiresAt) {
			expiresAt = expiry
		}
		if item.depth == f.config.MaxDepth && len(peers) != 0 {
			return f.fail(errors.New("ARD federation depth limit exceeded"))
		}
		for _, peer := range peers {
			peerURL, peerErr := canonicalFederationURL(peer)
			if peerErr != nil || !f.allowed(peerURL) {
				return f.fail(errors.New("ARD federation peer is not allowed"))
			}
			canonicalPeer := peerURL.String()
			if _, exists := visited[canonicalPeer]; exists || queuedFederationURL(queue, canonicalPeer) {
				continue
			}
			if len(queue)+len(visited) >= f.config.MaxSources {
				return f.fail(errors.New("ARD federation source limit exceeded"))
			}
			queue = append(queue, crawlItem{url: canonicalPeer, depth: item.depth + 1})
		}
	}
	if err := f.index.ReplaceCatalogs(inputs); err != nil {
		return f.fail(err)
	}
	f.status.Generation++
	f.status.Sources = len(inputs)
	f.status.ExpiresAt = expiresAt
	f.status.LastError = ""
	return nil
}

func queuedFederationURL(queue []crawlItem, value string) bool {
	for _, item := range queue {
		if item.url == value {
			return true
		}
	}
	return false
}

// Expire removes a stale cached generation. Network requests are never made
// from a search request path.
func (f *Federation) Expire(now time.Time) (bool, error) {
	if f == nil || now.IsZero() {
		return false, errors.New("invalid ARD federation expiry")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.ExpiresAt.IsZero() || now.Before(f.status.ExpiresAt) {
		return false, nil
	}
	if err := f.index.ReplaceCatalogs(nil); err != nil {
		return false, err
	}
	f.status.Generation++
	f.status.Sources = 0
	f.status.ExpiresAt = time.Time{}
	return true, nil
}

func (f *Federation) Status() FederationStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *Federation) fail(err error) error {
	f.status.LastError = "refresh_failed"
	return fmt.Errorf("refresh ARD federation: %w", err)
}

func (f *Federation) allowed(parsed *url.URL) bool {
	_, ok := f.origins[parsed.Scheme+"://"+parsed.Host]
	return ok
}

func (f *Federation) fetch(ctx context.Context, start *url.URL, now time.Time) (ard.Catalog, []string, time.Time, error) {
	current := start
	for redirects := 0; ; redirects++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return ard.Catalog{}, nil, time.Time{}, err
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Accept-Encoding", "gzip")
		response, err := f.client.Do(request)
		if err != nil {
			return ard.Catalog{}, nil, time.Time{}, err
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			_ = response.Body.Close()
			if redirects >= f.config.MaxRedirects {
				return ard.Catalog{}, nil, time.Time{}, errors.New("ARD federation redirect limit exceeded")
			}
			next, err := current.Parse(response.Header.Get("Location"))
			if err != nil || !f.allowed(next) {
				return ard.Catalog{}, nil, time.Time{}, errors.New("ARD federation redirect is not allowed")
			}
			current = next
			continue
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return ard.Catalog{}, nil, time.Time{}, fmt.Errorf("ARD federation source returned %d", response.StatusCode)
		}
		mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" || len(parameters) != 0 {
			return ard.Catalog{}, nil, time.Time{}, errors.New("ARD federation source has invalid Content-Type")
		}
		body, err := boundedFederationBody(response, f.config.MaxCompressedBytes, f.config.MaxDecodedBytes)
		if err != nil {
			return ard.Catalog{}, nil, time.Time{}, err
		}
		catalog, err := ard.DecodeCatalog(strings.NewReader(string(body)), ard.DefaultLimits())
		if err != nil {
			return ard.Catalog{}, nil, time.Time{}, err
		}
		peers, err := federationLinks(current, response.Header.Values("Link"))
		if err != nil {
			return ard.Catalog{}, nil, time.Time{}, err
		}
		for _, peer := range peers {
			parsed, parseErr := canonicalFederationURL(peer)
			if parseErr != nil || !f.allowed(parsed) {
				return ard.Catalog{}, nil, time.Time{}, errors.New("ARD federation peer is not allowed")
			}
		}
		return catalog, peers, now.Add(f.cacheTTL(response.Header.Get("Cache-Control"))), nil
	}
}

func boundedFederationBody(response *http.Response, compressedLimit, decodedLimit int64) ([]byte, error) {
	compressed := io.LimitReader(response.Body, compressedLimit+1)
	var reader io.Reader = compressed
	switch strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding"))) {
	case "":
	case "gzip":
		archive, err := gzip.NewReader(compressed)
		if err != nil {
			return nil, errors.New("invalid ARD federation gzip body")
		}
		defer archive.Close()
		reader = archive
	default:
		return nil, errors.New("unsupported ARD federation content encoding")
	}
	data, err := io.ReadAll(io.LimitReader(reader, decodedLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > decodedLimit {
		return nil, errors.New("ARD federation decoded byte limit exceeded")
	}
	return data, nil
}

func (f *Federation) cacheTTL(value string) time.Duration {
	ttl := f.config.MinimumTTL
	for _, directive := range strings.Split(value, ",") {
		parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "max-age") {
			seconds, err := strconv.ParseInt(strings.Trim(parts[1], `"`), 10, 64)
			if err == nil && seconds > 0 && seconds <= int64(f.config.MaximumTTL/time.Second) {
				ttl = time.Duration(seconds) * time.Second
			}
		}
	}
	if ttl < f.config.MinimumTTL {
		return f.config.MinimumTTL
	}
	if ttl > f.config.MaximumTTL {
		return f.config.MaximumTTL
	}
	return ttl
}

func canonicalFederationURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, errors.New("ARD federation URL exceeds limit")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, errors.New("ARD federation URL must be an absolute HTTPS URL")
	}
	if parsed.RawPath != "" {
		return nil, errors.New("ARD federation URL contains noncanonical escaping")
	}
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Path == "" {
		parsed.Path = "/"
	} else {
		parsed.Path = strings.TrimSuffix(path.Clean(parsed.Path), "/")
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.RawPath = ""
	return parsed, nil
}

func federationTransport(base http.RoundTripper, config FederationConfig) (*http.Transport, error) {
	var transport *http.Transport
	switch value := base.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = value.Clone()
	default:
		return nil, errors.New("ARD federation requires an inspectable HTTP transport")
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.MaxConnsPerHost = 16
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid ARD federation dial address")
		}
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 || len(addresses) > 32 {
			return nil, errors.New("resolve ARD federation origin")
		}
		for _, address := range addresses {
			if !config.AllowPrivateOrigins && unsafeFederationIP(address.IP) {
				return nil, errors.New("ARD federation origin resolved to disallowed address space")
			}
		}
		var lastErr error
		for _, resolved := range addresses {
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
	return transport, nil
}

func unsafeFederationIP(value net.IP) bool {
	return value == nil || value.IsUnspecified() || value.IsLoopback() || value.IsPrivate() ||
		value.IsLinkLocalUnicast() || value.IsLinkLocalMulticast() || value.IsMulticast()
}

func federationLinks(base *url.URL, values []string) ([]string, error) {
	var output []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			end := strings.Index(part, ">")
			if !strings.HasPrefix(part, "<") || end < 2 || !strings.Contains(strings.ToLower(part[end+1:]), `rel="`+federationLinkRelation+`"`) {
				continue
			}
			if len(output) >= 256 {
				return nil, errors.New("too many ARD federation links")
			}
			next, err := base.Parse(part[1:end])
			if err != nil {
				return nil, errors.New("invalid ARD federation link")
			}
			output = append(output, next.String())
		}
	}
	return output, nil
}
