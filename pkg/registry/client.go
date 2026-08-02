package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/ard"
)

const MaxClientResponseBytes = 2 << 20

// Client is the stable bounded Go client for the pinned ARD Registry surface.
// It uses one fixed registry origin and never follows discovery metadata as a
// request destination.
type Client struct {
	base   *url.URL
	client *http.Client
}

func NewClient(baseURL string, client *http.Client) (*Client, error) {
	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Scheme != "https" && !localHTTP(parsed)) ||
		client == nil || len(baseURL) > 2048 {
		return nil, errors.New("invalid Registry client configuration")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	fixedClient := *client
	fixedClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{base: parsed, client: &fixedClient}, nil
}

func (c *Client) Search(ctx context.Context, request SearchRequest) (SearchResponse, error) {
	if c == nil || ctx == nil {
		return SearchResponse{}, errors.New("invalid Registry search")
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > maxSearchBodyBytes {
		return SearchResponse{}, errors.New("invalid Registry search")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("search"), bytes.NewReader(body))
	if err != nil {
		return SearchResponse{}, errors.New("create Registry search request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	var response SearchResponse
	if err := c.do(httpRequest, &response); err != nil {
		return SearchResponse{}, err
	}
	if len(response.Results) > DefaultLimits().MaxPageSize || len(response.PageToken) > 4096 {
		return SearchResponse{}, errors.New("Registry search response exceeds limit")
	}
	for _, result := range response.Results {
		if result.Score < 0 || result.Score > 100 || result.Source == "" || len(result.Source) > 2048 ||
			result.Entry.Validate(ard.DefaultLimits()) != nil {
			return SearchResponse{}, errors.New("invalid Registry search response")
		}
	}
	return response, nil
}

func (c *Client) List(ctx context.Context, request ListRequest) (ListResponse, error) {
	if c == nil || ctx == nil || len(request.Filter) > DefaultLimits().MaxQueryBytes ||
		len(request.OrderBy) > 256 || len(request.PageToken) > 4096 ||
		request.PageSize < 0 || request.PageSize > DefaultLimits().MaxPageSize {
		return ListResponse{}, errors.New("invalid Registry list")
	}
	query := make(url.Values)
	if request.Filter != "" {
		query.Set("filter", request.Filter)
	}
	if request.OrderBy != "" {
		query.Set("orderBy", request.OrderBy)
	}
	if request.PageSize != 0 {
		query.Set("pageSize", strconv.Itoa(request.PageSize))
	}
	if request.PageToken != "" {
		query.Set("pageToken", request.PageToken)
	}
	endpoint := c.endpoint("agents")
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ListResponse{}, errors.New("create Registry list request")
	}
	var response ListResponse
	if err := c.do(httpRequest, &response); err != nil {
		return ListResponse{}, err
	}
	if len(response.Items) > DefaultLimits().MaxPageSize || response.Total < len(response.Items) ||
		response.Total > DefaultLimits().MaxEntries || len(response.PageToken) > 4096 {
		return ListResponse{}, errors.New("Registry list response exceeds limit")
	}
	for _, entry := range response.Items {
		if entry.Validate(ard.DefaultLimits()) != nil {
			return ListResponse{}, errors.New("invalid Registry list response")
		}
	}
	return response, nil
}

func (c *Client) do(request *http.Request, output interface{}) error {
	response, err := c.client.Do(request)
	if err != nil {
		return errors.New("Registry transport failed")
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, MaxClientResponseBytes+1))
	if readErr != nil || len(data) > MaxClientResponseBytes || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Registry response rejected")
	}
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" || len(parameters) != 0 {
		return errors.New("Registry response media type rejected")
	}
	if err := jsonstrict.Decode(data, output); err != nil {
		return errors.New("invalid Registry response")
	}
	if err := request.Context().Err(); err != nil {
		return err
	}
	return nil
}

func (c *Client) endpoint(path string) string {
	copy := *c.base
	copy.Path += "/" + path
	return copy.String()
}

func localHTTP(value *url.URL) bool {
	if value.Scheme != "http" {
		return false
	}
	host := value.Hostname()
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}
