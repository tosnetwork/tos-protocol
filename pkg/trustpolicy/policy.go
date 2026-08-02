package trustpolicy

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
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

const (
	MaxPolicyBodyBytes  = 64 << 10
	MaxPolicyAttributes = 32
	MaxPolicyEvidence   = 32
	MaxPolicyConcurrent = 128
)

type DecisionInput struct {
	WorkloadID     string            `json:"workloadId"`
	ServiceID      string            `json:"serviceId"`
	Operation      string            `json:"operation"`
	ArtifactDigest string            `json:"artifactDigest,omitempty"`
	Evidence       []string          `json:"evidence,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

type Decision struct {
	Allow     bool      `json:"allow"`
	Revision  string    `json:"revision"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Evaluator interface {
	Evaluate(context.Context, DecisionInput, time.Time) (Decision, error)
}

type OPAClient struct {
	endpoint string
	token    string
	client   *http.Client
	gate     chan struct{}
}

func NewOPAClient(endpoint, bearerToken string, client *http.Client, maximumConcurrent int) (*OPAClient, error) {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) || client == nil ||
		!validSecret(bearerToken) || maximumConcurrent <= 0 || maximumConcurrent > MaxPolicyConcurrent {
		return nil, errors.New("invalid policy adapter configuration")
	}
	fixedClient := *client
	fixedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &OPAClient{endpoint: parsed.String(), token: bearerToken, client: &fixedClient, gate: make(chan struct{}, maximumConcurrent)}, nil
}

func (c *OPAClient) Evaluate(ctx context.Context, input DecisionInput, now time.Time) (Decision, error) {
	if c == nil || ctx == nil || now.IsZero() || validateDecisionInput(input) != nil {
		return Decision{}, errors.New("policy decision rejected")
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	default:
		return Decision{}, errors.New("policy adapter capacity exhausted")
	}
	body, err := json.Marshal(struct {
		Input DecisionInput `json:"input"`
	}{Input: input})
	if err != nil || len(body) > MaxPolicyBodyBytes {
		return Decision{}, errors.New("policy decision rejected")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Decision{}, errors.New("policy decision rejected")
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return Decision{}, errors.New("policy adapter unavailable")
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, MaxPolicyBodyBytes+1))
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if readErr != nil || len(data) > MaxPolicyBodyBytes || response.StatusCode != http.StatusOK ||
		mediaErr != nil || mediaType != "application/json" || len(parameters) != 0 {
		return Decision{}, errors.New("policy adapter response rejected")
	}
	var output struct {
		Result Decision `json:"result"`
	}
	if jsonstrict.Decode(data, &output) != nil || !validBoundedID(output.Result.Revision, 256) ||
		!output.Result.ExpiresAt.After(now) || output.Result.ExpiresAt.After(now.Add(24*time.Hour)) {
		return Decision{}, errors.New("policy adapter response rejected")
	}
	return output.Result, nil
}

// StaticEvaluator is useful for disconnected terminals and tests. It compares
// exact immutable tuples and never grants based on partial matches.
type StaticEvaluator struct {
	rules    map[string]bool
	revision string
	ttl      time.Duration
}

type StaticRule struct {
	Input DecisionInput
	Allow bool
}

func NewStaticEvaluator(rules []StaticRule, revision string, ttl time.Duration) (*StaticEvaluator, error) {
	if len(rules) == 0 || len(rules) > 4096 || !validBoundedID(revision, 256) || ttl <= 0 || ttl > 24*time.Hour {
		return nil, errors.New("invalid static policy")
	}
	compiled := make(map[string]bool, len(rules))
	for _, rule := range rules {
		input, allow := rule.Input, rule.Allow
		if validateDecisionInput(input) != nil || len(input.Evidence) != 0 || len(input.Attributes) != 0 {
			return nil, errors.New("static policy requires scalar inputs")
		}
		key := decisionKey(input)
		if _, duplicate := compiled[key]; duplicate {
			return nil, errors.New("static policy contains a duplicate rule")
		}
		compiled[key] = allow
	}
	return &StaticEvaluator{rules: compiled, revision: revision, ttl: ttl}, nil
}

func (s *StaticEvaluator) Evaluate(ctx context.Context, input DecisionInput, now time.Time) (Decision, error) {
	if s == nil || ctx == nil || now.IsZero() || validateDecisionInput(input) != nil {
		return Decision{}, errors.New("policy decision rejected")
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	allow, found := s.rules[decisionKey(input)]
	return Decision{Allow: found && allow, Revision: s.revision, ExpiresAt: now.Add(s.ttl).UTC()}, nil
}

func validateDecisionInput(input DecisionInput) error {
	if !validBoundedID(input.WorkloadID, 512) || !validBoundedID(input.ServiceID, 256) ||
		!validBoundedID(input.Operation, 128) || (input.ArtifactDigest != "" && !validDigest(input.ArtifactDigest)) ||
		len(input.Evidence) > MaxPolicyEvidence || len(input.Attributes) > MaxPolicyAttributes {
		return errors.New("invalid policy input")
	}
	seen := make(map[string]struct{}, len(input.Evidence))
	for _, digest := range input.Evidence {
		if !validDigest(digest) {
			return errors.New("invalid policy input")
		}
		if _, duplicate := seen[digest]; duplicate {
			return errors.New("invalid policy input")
		}
		seen[digest] = struct{}{}
	}
	for key, value := range input.Attributes {
		if !validBoundedID(key, 128) || len(value) > 1024 || strings.ContainsRune(value, '\x00') {
			return errors.New("invalid policy input")
		}
	}
	return nil
}

func decisionKey(input DecisionInput) string {
	return strings.Join([]string{input.WorkloadID, input.ServiceID, input.Operation, input.ArtifactDigest}, "\x00")
}

func isLoopbackHTTP(value *url.URL) bool {
	if value.Scheme != "http" {
		return false
	}
	host := value.Hostname()
	parsed := net.ParseIP(host)
	return host == "localhost" || (parsed != nil && parsed.IsLoopback())
}

func validSecret(value string) bool {
	if len(value) == 0 || len(value) > 8192 {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == '\x7f' {
			return false
		}
	}
	return true
}
