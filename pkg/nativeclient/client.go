// Package nativeclient provides the public, authority-neutral Connect client
// used by Native SDKs. It transports signed objects but never signs, rewrites,
// or treats a gateway acknowledgement as finalized state.
package nativeclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1/tosservicev1connect"
)

const (
	defaultTimeout = 30 * time.Second
	defaultLimit   = 16 << 20
)

type Config struct {
	BaseURL         string
	BearerToken     string
	Timeout         time.Duration
	MaxMessageBytes int
	Insecure        bool
	ServerName      string
	CAFile          string
	ClientCertFile  string
	ClientKeyFile   string
}

type Client struct {
	token      string
	timeout    time.Duration
	httpClient *http.Client
	native     tosservicev1connect.NativeServiceClient
	discovery  tosservicev1connect.CapabilityDiscoveryServiceClient
	dns        tosservicev1connect.DNSAliasServiceClient
}

func New(config Config) (*Client, error) {
	config.BaseURL = strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	config.BearerToken = strings.TrimSpace(config.BearerToken)
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") || config.BearerToken == "" {
		return nil, errors.New("Native gateway URL and bearer token are invalid")
	}
	if parsed.Scheme == "http" && !config.Insecure {
		return nil, errors.New("plaintext Native gateway requires explicit insecure mode")
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Timeout <= 0 || config.Timeout > 15*time.Minute {
		return nil, errors.New("invalid Native gateway timeout")
	}
	if config.MaxMessageBytes == 0 {
		config.MaxMessageBytes = defaultLimit
	}
	if config.MaxMessageBytes <= 0 || config.MaxMessageBytes > 64<<20 {
		return nil, errors.New("invalid Native gateway message limit")
	}
	if (config.ClientCertFile == "") != (config.ClientKeyFile == "") {
		return nil, errors.New("Native gateway client certificate and key must be configured together")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if parsed.Scheme == "https" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.ServerName}
		if config.CAFile != "" {
			pem, err := os.ReadFile(config.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read Native gateway CA: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("Native gateway CA contains no valid certificate")
			}
			tlsConfig.RootCAs = pool
		}
		if config.ClientCertFile != "" {
			certificate, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load Native gateway client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
		transport.TLSClientConfig = tlsConfig
	}
	httpClient := &http.Client{Transport: transport}
	options := []connect.ClientOption{
		connect.WithReadMaxBytes(config.MaxMessageBytes),
		connect.WithSendMaxBytes(config.MaxMessageBytes),
	}
	return &Client{token: config.BearerToken, timeout: config.Timeout, httpClient: httpClient,
		native:    tosservicev1connect.NewNativeServiceClient(httpClient, config.BaseURL, options...),
		discovery: tosservicev1connect.NewCapabilityDiscoveryServiceClient(httpClient, config.BaseURL, options...),
		dns:       tosservicev1connect.NewDNSAliasServiceClient(httpClient, config.BaseURL, options...)}, nil
}

func (c *Client) ListCapabilities(ctx context.Context, request *nativev1.ListCapabilitiesRequest) (*nativev1.ListCapabilitiesResponse, error) {
	if c == nil || c.discovery == nil || request == nil {
		return nil, errors.New("invalid Capability listing request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	response, err := c.discovery.ListCapabilities(callCtx, authorized(c, request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) SearchCapabilities(ctx context.Context, request *nativev1.SearchCapabilitiesRequest) (*nativev1.SearchCapabilitiesResponse, error) {
	if c == nil || c.discovery == nil || request == nil {
		return nil, errors.New("invalid Capability search request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	response, err := c.discovery.SearchCapabilities(callCtx, authorized(c, request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) PublishSoftwareWorkManifest(ctx context.Context, request *nativev1.PublishSoftwareWorkManifestRequest) (*nativev1.PublishSoftwareWorkManifestResponse, error) {
	if c == nil || c.discovery == nil || request == nil {
		return nil, errors.New("invalid software-work manifest publication request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	response, err := c.discovery.PublishSoftwareWorkManifest(callCtx, authorized(c, request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) GetSoftwareWorkManifest(ctx context.Context, request *nativev1.GetSoftwareWorkManifestRequest) (*nativev1.GetSoftwareWorkManifestResponse, error) {
	if c == nil || c.discovery == nil || request == nil {
		return nil, errors.New("invalid software-work manifest retrieval request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	response, err := c.discovery.GetSoftwareWorkManifest(callCtx, authorized(c, request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) RequestQuoteProposal(ctx context.Context, request *nativev1.RequestQuoteProposalRequest) (*nativev1.RequestQuoteProposalResponse, error) {
	if c == nil || c.discovery == nil || request == nil {
		return nil, errors.New("invalid Quote Proposal request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	response, err := c.discovery.RequestQuoteProposal(callCtx, authorized(c, request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func authorized[T any](c *Client, message *T) *connect.Request[T] {
	request := connect.NewRequest(message)
	request.Header().Set("Authorization", "Bearer "+c.token)
	return request
}

func (c *Client) SubmitNativeAction(ctx context.Context, request *nativev1.SubmitNativeActionRequest) (*nativev1.SubmitNativeActionResponse, error) {
	if c == nil || c.native == nil || request == nil {
		return nil, errors.New("invalid Native submission request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	req := connect.NewRequest(request)
	req.Header().Set("Authorization", "Bearer "+c.token)
	response, err := c.native.SubmitNativeAction(callCtx, req)
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) ResolveNativeState(ctx context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	if c == nil || c.native == nil || request == nil {
		return nil, errors.New("invalid Native resolution request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	req := connect.NewRequest(request)
	req.Header().Set("Authorization", "Bearer "+c.token)
	response, err := c.native.ResolveNativeState(callCtx, req)
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

// ResolveDNSAlias resolves a human-readable discovery alias into a fully
// verified Native object identity. Callers must use NativeObjectId (and the
// returned finalized state) as authority; the input name is display metadata.
func (c *Client) ResolveDNSAlias(ctx context.Context, request *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
	if c == nil || c.dns == nil || request == nil {
		return nil, errors.New("invalid DNS alias resolution request")
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	response, err := c.dns.ResolveDNSAlias(callCtx, authorized(c, request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, c.timeout)
}

func (c *Client) Close() error {
	if c != nil && c.httpClient != nil {
		if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	return nil
}
