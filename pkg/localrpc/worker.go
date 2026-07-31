package localrpc

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"connectrpc.com/connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/gen/tos/edge/v1/edgev1connect"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultWorkerControlTimeout        = 5 * time.Second
	DefaultWorkerMaxInvocationDuration = 15 * time.Minute
	DefaultWorkerMaxMessageBytes       = 2 << 20

	maxWorkerControlTimeout     = time.Minute
	maxWorkerInvocationDuration = 24 * time.Hour
	maxWorkerMessageBytes       = 16 << 20
	maxWorkerCapabilities       = 128
	maxWorkerResources          = 128
	maxWorkerReadiness          = 64
	maxWorkerResourceLimits     = 64
	maxWorkerAttributes         = 64
	maxWorkerPriorities         = 6
)

var workerServiceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{2,127}$`)

// WorkerClientConfig is the fail-closed private boundary from Edge Core to a
// vertical worker. Public Edge traffic should normally allow only
// PRIORITY_EXTERNAL_SERVICE.
type WorkerClientConfig struct {
	SocketPath            string
	ControlTimeout        time.Duration
	MaxInvocationDuration time.Duration
	MaxMessageBytes       int
	AllowedPriorities     []edgev1.Priority
}

func DefaultWorkerClientConfig(socketPath string) WorkerClientConfig {
	return WorkerClientConfig{
		SocketPath:            socketPath,
		ControlTimeout:        DefaultWorkerControlTimeout,
		MaxInvocationDuration: DefaultWorkerMaxInvocationDuration,
		MaxMessageBytes:       DefaultWorkerMaxMessageBytes,
		AllowedPriorities: []edgev1.Priority{
			edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
		},
	}
}

// WorkerClient validates both sides of the private RPC contract. It performs
// no retries: Edge Core and the durable request journal own idempotency.
type WorkerClient struct {
	rpc                   edgev1connect.WorkerServiceClient
	controlTimeout        time.Duration
	maxInvocationDuration time.Duration
	maxMessageBytes       int
	allowedPriorities     map[edgev1.Priority]struct{}
	now                   func() time.Time
}

// InvocationBinding is the immutable public request/quote scope repeated by
// Edge Core before it consumes a private Worker result.
type InvocationBinding struct {
	RequestID string
	QuoteID   string
	ServiceID string
	Operation string
}

type InvocationUsage struct {
	InputBytes      uint64
	OutputBytes     uint64
	InputTokens     uint64
	OutputTokens    uint64
	ExecutionMillis uint64
}

// InvocationCompletion is a defensive copy of a result that crossed the
// validated private Worker RPC boundary.
type InvocationCompletion struct {
	Binding         InvocationBinding
	Output          []byte
	Usage           InvocationUsage
	MaxOutputBytes  uint64
	Deadline        time.Time
	ModelRevision   string
	RuntimeRevision string
	CompletedAt     time.Time
}

// ValidatedInvocation is opaque so an unvalidated protobuf response cannot be
// substituted into receipt issuance.
type ValidatedInvocation struct {
	valid           bool
	binding         InvocationBinding
	output          []byte
	usage           InvocationUsage
	maxOutputBytes  uint64
	deadline        time.Time
	modelRevision   string
	runtimeRevision string
	completedAt     time.Time
}

// Completion repeats the expected immutable binding and returns defensive
// result bytes only after the private RPC response passed every client check.
func (v ValidatedInvocation) Completion(
	binding InvocationBinding,
) (InvocationCompletion, error) {
	if !v.valid {
		return InvocationCompletion{}, errors.New(
			"invalid validated Worker invocation",
		)
	}
	if binding != v.binding {
		return InvocationCompletion{}, errors.New(
			"validated Worker invocation binding mismatch",
		)
	}
	return InvocationCompletion{
		Binding:         binding,
		Output:          append([]byte(nil), v.output...),
		Usage:           v.usage,
		MaxOutputBytes:  v.maxOutputBytes,
		Deadline:        v.deadline,
		ModelRevision:   v.modelRevision,
		RuntimeRevision: v.runtimeRevision,
		CompletedAt:     v.completedAt,
	}, nil
}

func NewWorkerClient(config WorkerClientConfig) (*WorkerClient, error) {
	return newWorkerClient(config, time.Now)
}

func newWorkerClient(
	config WorkerClientConfig,
	now func() time.Time,
) (*WorkerClient, error) {
	if config.ControlTimeout <= 0 ||
		config.ControlTimeout > maxWorkerControlTimeout ||
		config.MaxInvocationDuration <= 0 ||
		config.MaxInvocationDuration > maxWorkerInvocationDuration ||
		config.MaxMessageBytes <= 0 ||
		config.MaxMessageBytes > maxWorkerMessageBytes ||
		now == nil {
		return nil, errors.New("invalid worker client configuration")
	}
	allowed, err := validateAllowedPriorities(config.AllowedPriorities)
	if err != nil {
		return nil, err
	}
	httpClient, err := httpClient(
		config.SocketPath,
		config.ControlTimeout,
		config.MaxInvocationDuration,
	)
	if err != nil {
		return nil, err
	}
	rpc := edgev1connect.NewWorkerServiceClient(
		httpClient,
		"http://unix",
		connect.WithReadMaxBytes(config.MaxMessageBytes),
		connect.WithSendMaxBytes(config.MaxMessageBytes),
	)
	return &WorkerClient{
		rpc: rpc, controlTimeout: config.ControlTimeout,
		maxInvocationDuration: config.MaxInvocationDuration,
		maxMessageBytes:       config.MaxMessageBytes,
		allowedPriorities:     allowed,
		now:                   now,
	}, nil
}

func (c *WorkerClient) Health(
	ctx context.Context,
) (*edgev1.HealthResponse, error) {
	callContext, cancel, err := c.controlContext(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	defer cancel()
	response, err := c.rpc.Health(
		callContext,
		connect.NewRequest(&edgev1.HealthRequest{}),
	)
	if err != nil {
		return nil, fmt.Errorf("worker Health: %w", err)
	}
	if err := validateHealthResponse(response.Msg); err != nil {
		return nil, fmt.Errorf("validate worker Health response: %w", err)
	}
	return proto.Clone(response.Msg).(*edgev1.HealthResponse), nil
}

func (c *WorkerClient) GetCapabilities(
	ctx context.Context,
) (*edgev1.GetCapabilitiesResponse, error) {
	callContext, cancel, err := c.controlContext(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	defer cancel()
	response, err := c.rpc.GetCapabilities(
		callContext,
		connect.NewRequest(&edgev1.GetCapabilitiesRequest{}),
	)
	if err != nil {
		return nil, fmt.Errorf("worker GetCapabilities: %w", err)
	}
	if err := validateCapabilitiesResponse(response.Msg); err != nil {
		return nil, fmt.Errorf("validate worker GetCapabilities response: %w", err)
	}
	return proto.Clone(response.Msg).(*edgev1.GetCapabilitiesResponse), nil
}

func (c *WorkerClient) Quote(
	ctx context.Context,
	request *edgev1.QuoteRequest,
) (*edgev1.QuoteResponse, error) {
	if c == nil {
		return nil, errors.New("nil worker client")
	}
	request = cloneQuoteRequest(request)
	now := c.now().UTC()
	if err := c.validateQuoteRequest(request, now); err != nil {
		return nil, err
	}
	requestDeadline := time.UnixMilli(request.DeadlineUnixMillis)
	callContext, cancel, err := c.controlContext(ctx, requestDeadline)
	if err != nil {
		return nil, err
	}
	defer cancel()
	response, err := c.rpc.Quote(
		callContext,
		connect.NewRequest(request),
	)
	if err != nil {
		return nil, fmt.Errorf("worker Quote: %w", err)
	}
	if err := validateQuoteResponse(response.Msg, request, now); err != nil {
		return nil, fmt.Errorf("validate worker Quote response: %w", err)
	}
	return proto.Clone(response.Msg).(*edgev1.QuoteResponse), nil
}

func (c *WorkerClient) Invoke(
	ctx context.Context,
	request *edgev1.InvokeRequest,
) (ValidatedInvocation, error) {
	if c == nil {
		return ValidatedInvocation{}, errors.New("nil worker client")
	}
	request = cloneInvokeRequest(request)
	now := c.now().UTC()
	if err := c.validateInvokeRequest(request, now); err != nil {
		return ValidatedInvocation{}, err
	}
	deadline := time.UnixMilli(request.DeadlineUnixMillis)
	callContext, cancel, err := boundedContext(ctx, deadline)
	if err != nil {
		return ValidatedInvocation{}, err
	}
	defer cancel()
	response, err := c.rpc.Invoke(
		callContext,
		connect.NewRequest(request),
	)
	if err != nil {
		return ValidatedInvocation{}, fmt.Errorf("worker Invoke: %w", err)
	}
	if err := validateInvokeResponse(response.Msg, request); err != nil {
		return ValidatedInvocation{}, fmt.Errorf(
			"validate worker Invoke response: %w",
			err,
		)
	}
	completedAt := c.now().UTC()
	return ValidatedInvocation{
		valid: true,
		binding: InvocationBinding{
			RequestID: request.RequestId, QuoteID: request.QuoteId,
			ServiceID: request.ServiceId, Operation: request.Operation,
		},
		output: append([]byte(nil), response.Msg.Output...),
		usage: InvocationUsage{
			InputBytes:      response.Msg.Usage.InputBytes,
			OutputBytes:     response.Msg.Usage.OutputBytes,
			InputTokens:     response.Msg.Usage.InputTokens,
			OutputTokens:    response.Msg.Usage.OutputTokens,
			ExecutionMillis: response.Msg.Usage.ExecutionMillis,
		},
		maxOutputBytes:  request.MaxOutputBytes,
		deadline:        deadline.UTC(),
		modelRevision:   response.Msg.ModelRevision,
		runtimeRevision: response.Msg.RuntimeRevision,
		completedAt:     completedAt,
	}, nil
}

func (c *WorkerClient) Cancel(
	ctx context.Context,
	requestID string,
) (bool, error) {
	if c == nil {
		return false, errors.New("nil worker client")
	}
	if err := validateWorkerID("request ID", requestID); err != nil {
		return false, err
	}
	callContext, cancel, err := c.controlContext(ctx, time.Time{})
	if err != nil {
		return false, err
	}
	defer cancel()
	response, err := c.rpc.Cancel(
		callContext,
		connect.NewRequest(&edgev1.CancelRequest{RequestId: requestID}),
	)
	if err != nil {
		return false, fmt.Errorf("worker Cancel: %w", err)
	}
	if response.Msg == nil {
		return false, errors.New("worker Cancel returned an empty response")
	}
	return response.Msg.Accepted, nil
}

func (c *WorkerClient) controlContext(
	ctx context.Context,
	requestDeadline time.Time,
) (context.Context, context.CancelFunc, error) {
	if c == nil {
		return nil, nil, errors.New("nil worker client")
	}
	if ctx == nil {
		return nil, nil, errors.New("nil worker context")
	}
	deadline := c.now().Add(c.controlTimeout)
	if !requestDeadline.IsZero() && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	callContext, cancel := context.WithDeadline(ctx, deadline)
	return callContext, cancel, nil
}

func boundedContext(
	ctx context.Context,
	deadline time.Time,
) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil worker context")
	}
	callContext, cancel := context.WithDeadline(ctx, deadline)
	return callContext, cancel, nil
}

func (c *WorkerClient) validateQuoteRequest(
	request *edgev1.QuoteRequest,
	now time.Time,
) error {
	if request == nil {
		return errors.New("nil worker Quote request")
	}
	if err := validateWorkerID("request ID", request.RequestId); err != nil {
		return err
	}
	if err := validateWorkerSelector(
		request.ServiceId, request.Operation, request.Model,
	); err != nil {
		return err
	}
	if request.InputBytes > uint64(c.maxMessageBytes) ||
		request.MaxOutputBytes == 0 ||
		request.MaxOutputBytes > uint64(c.maxMessageBytes) {
		return errors.New("worker Quote byte limits exceed local policy")
	}
	if err := c.validatePriority(request.Priority); err != nil {
		return err
	}
	if err := validateWorkerDeadline(
		request.DeadlineUnixMillis, now, c.maxInvocationDuration,
	); err != nil {
		return err
	}
	return validateWorkerResourceLimits(request.RequestedLimits)
}

func (c *WorkerClient) validateInvokeRequest(
	request *edgev1.InvokeRequest,
	now time.Time,
) error {
	if request == nil {
		return errors.New("nil worker Invoke request")
	}
	if err := validateWorkerID("request ID", request.RequestId); err != nil {
		return err
	}
	if err := validateWorkerID("quote ID", request.QuoteId); err != nil {
		return err
	}
	if err := validateWorkerSelector(
		request.ServiceId, request.Operation, request.Model,
	); err != nil {
		return err
	}
	if len(request.Payload) > c.maxMessageBytes ||
		request.MaxOutputBytes == 0 ||
		request.MaxOutputBytes > uint64(c.maxMessageBytes) {
		return errors.New("worker Invoke byte limits exceed local policy")
	}
	if err := c.validatePriority(request.Priority); err != nil {
		return err
	}
	return validateWorkerDeadline(
		request.DeadlineUnixMillis, now, c.maxInvocationDuration,
	)
}

func (c *WorkerClient) validatePriority(priority edgev1.Priority) error {
	if _, allowed := c.allowedPriorities[priority]; !allowed {
		return errors.New("worker priority is not allowed by Edge policy")
	}
	return nil
}

func validateAllowedPriorities(
	values []edgev1.Priority,
) (map[edgev1.Priority]struct{}, error) {
	if len(values) == 0 || len(values) > maxWorkerPriorities {
		return nil, errors.New("worker allowed priorities must be bounded and nonempty")
	}
	output := make(map[edgev1.Priority]struct{}, len(values))
	for _, value := range values {
		if value < edgev1.Priority_PRIORITY_EMERGENCY ||
			value > edgev1.Priority_PRIORITY_BACKGROUND {
			return nil, errors.New("invalid worker priority policy")
		}
		if _, duplicate := output[value]; duplicate {
			return nil, errors.New("duplicate worker priority policy")
		}
		output[value] = struct{}{}
	}
	return output, nil
}

func validateHealthResponse(response *edgev1.HealthResponse) error {
	if response == nil {
		return errors.New("empty response")
	}
	if err := boundedWorkerString("health status", response.Status, 1, 512); err != nil {
		return err
	}
	if err := boundedWorkerString("worker version", response.Version, 1, 128); err != nil {
		return err
	}
	if len(response.Readiness) > maxWorkerReadiness {
		return errors.New("worker readiness list exceeds limit")
	}
	seen := make(map[string]struct{}, len(response.Readiness))
	for _, component := range response.Readiness {
		if component == nil {
			return errors.New("nil worker readiness component")
		}
		if err := boundedWorkerString("readiness ID", component.Id, 1, 128); err != nil {
			return err
		}
		if component.Status < edgev1.ReadinessStatus_READINESS_STATUS_READY ||
			component.Status > edgev1.ReadinessStatus_READINESS_STATUS_DRAINING {
			return errors.New("invalid worker readiness status")
		}
		if _, duplicate := seen[component.Id]; duplicate {
			return errors.New("duplicate worker readiness component")
		}
		seen[component.Id] = struct{}{}
		if component.Revision != "" {
			if err := boundedWorkerString(
				"readiness revision", component.Revision, 1, 512,
			); err != nil {
				return err
			}
		}
		if component.ReasonCode != "" {
			if err := boundedWorkerString(
				"readiness reason code", component.ReasonCode, 1, 128,
			); err != nil {
				return err
			}
		}
		if err := validateWorkerEvidence(component.Evidence); err != nil {
			return err
		}
	}
	return nil
}

func validateCapabilitiesResponse(
	response *edgev1.GetCapabilitiesResponse,
) error {
	if response == nil {
		return errors.New("empty response")
	}
	if err := boundedWorkerString(
		"capacity revision", response.CapacityRevision, 1, 512,
	); err != nil {
		return err
	}
	if len(response.Capabilities) > maxWorkerCapabilities ||
		len(response.Resources) > maxWorkerResources {
		return errors.New("worker capability or resource list exceeds limit")
	}
	seen := make(map[string]struct{}, len(response.Capabilities))
	for _, capability := range response.Capabilities {
		if capability == nil {
			return errors.New("nil worker capability")
		}
		if err := validateWorkerSelector(
			capability.ServiceId, capability.Operation, capability.Model,
		); err != nil {
			return err
		}
		for name, value := range map[string]string{
			"model digest":     capability.ModelDigest,
			"runtime":          capability.Runtime,
			"runtime revision": capability.RuntimeRevision,
		} {
			if err := boundedWorkerString(name, value, 1, 512); err != nil {
				return err
			}
		}
		if capability.MaxInputBytes == 0 || capability.MaxOutputBytes == 0 {
			return errors.New("worker capability has zero byte limit")
		}
		key := capability.ServiceId + "\x00" + capability.Operation + "\x00" + capability.Model
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate worker capability")
		}
		seen[key] = struct{}{}
		if _, err := validateAllowedPriorities(capability.AcceptedPriorities); err != nil {
			return fmt.Errorf("invalid capability priorities: %w", err)
		}
		if err := validateWorkerResourceLimits(capability.AdmissionLimits); err != nil {
			return err
		}
	}
	resourceIDs := make(map[string]struct{}, len(response.Resources))
	for _, resource := range response.Resources {
		if resource == nil {
			return errors.New("nil worker resource")
		}
		if err := boundedWorkerString("resource ID", resource.Id, 1, 128); err != nil {
			return err
		}
		if resource.ResourceClass < edgev1.ResourceClass_RESOURCE_CLASS_COMPUTE ||
			resource.ResourceClass > edgev1.ResourceClass_RESOURCE_CLASS_OTHER ||
			resource.Unit < edgev1.ResourceUnit_RESOURCE_UNIT_COUNT ||
			resource.Unit > edgev1.ResourceUnit_RESOURCE_UNIT_BITS_PER_SECOND ||
			resource.OwnerReserved > resource.Total ||
			resource.AvailableExternal > resource.Total-resource.OwnerReserved {
			return errors.New("invalid worker resource claim")
		}
		if len(resource.Attributes) > maxWorkerAttributes {
			return errors.New("worker resource attributes exceed limit")
		}
		if err := boundedWorkerString(
			"resource revision", resource.Revision, 1, 512,
		); err != nil {
			return err
		}
		for key, value := range resource.Attributes {
			if err := boundedWorkerString(
				"resource attribute key", key, 1, 128,
			); err != nil {
				return err
			}
			if err := boundedWorkerString(
				"resource attribute value", value, 1, 512,
			); err != nil {
				return err
			}
		}
		if err := validateWorkerEvidence(resource.Evidence); err != nil {
			return err
		}
		if _, duplicate := resourceIDs[resource.Id]; duplicate {
			return errors.New("duplicate worker resource")
		}
		resourceIDs[resource.Id] = struct{}{}
	}
	return nil
}

func validateWorkerEvidence(value *edgev1.ClaimEvidence) error {
	if value == nil {
		return nil
	}
	if value.Level < edgev1.EvidenceLevel_EVIDENCE_LEVEL_DECLARED ||
		value.Level > edgev1.EvidenceLevel_EVIDENCE_LEVEL_CRYPTOGRAPHICALLY_PROVEN {
		return errors.New("invalid worker evidence level")
	}
	if err := boundedWorkerString("evidence issuer", value.Issuer, 1, 512); err != nil {
		return err
	}
	if value.CollectedUnixMillis <= 0 ||
		value.ExpiresUnixMillis <= value.CollectedUnixMillis {
		return errors.New("invalid worker evidence validity")
	}
	if value.Digest != "" {
		if err := boundedWorkerString("evidence digest", value.Digest, 1, 512); err != nil {
			return err
		}
	}
	if value.Reference != "" {
		if err := boundedWorkerString(
			"evidence reference", value.Reference, 1, 2_048,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateQuoteResponse(
	response *edgev1.QuoteResponse,
	request *edgev1.QuoteRequest,
	now time.Time,
) error {
	if response == nil {
		return errors.New("empty response")
	}
	if err := validateWorkerID("quote ID", response.QuoteId); err != nil {
		return err
	}
	if response.RequestId != request.RequestId {
		return errors.New("worker Quote response request binding mismatch")
	}
	expires := time.UnixMilli(response.ExpiresUnixMillis)
	if !expires.After(now) ||
		expires.After(time.UnixMilli(request.DeadlineUnixMillis)) {
		return errors.New("worker Quote response has invalid expiry")
	}
	for name, value := range map[string]string{
		"capacity revision": response.CapacityRevision,
		"model revision":    response.ModelRevision,
		"runtime revision":  response.RuntimeRevision,
	} {
		if err := boundedWorkerString(name, value, 1, 512); err != nil {
			return err
		}
	}
	return validateWorkerResourceLimits(response.CommittedLimits)
}

func validateInvokeResponse(
	response *edgev1.InvokeResponse,
	request *edgev1.InvokeRequest,
) error {
	if response == nil || response.Usage == nil {
		return errors.New("empty worker Invoke response or usage")
	}
	if response.RequestId != request.RequestId {
		return errors.New("worker Invoke response request binding mismatch")
	}
	if uint64(len(response.Output)) > request.MaxOutputBytes ||
		response.Usage.OutputBytes != uint64(len(response.Output)) ||
		response.Usage.InputBytes != uint64(len(request.Payload)) {
		return errors.New("worker Invoke response byte accounting mismatch")
	}
	if err := boundedWorkerString(
		"model revision", response.ModelRevision, 1, 512,
	); err != nil {
		return err
	}
	return boundedWorkerString(
		"runtime revision", response.RuntimeRevision, 1, 512,
	)
}

func validateWorkerResourceLimits(values []*edgev1.ResourceLimit) error {
	if len(values) > maxWorkerResourceLimits {
		return errors.New("worker resource limits exceed limit")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == nil {
			return errors.New("nil worker resource limit")
		}
		if err := boundedWorkerString("resource limit ID", value.Id, 1, 128); err != nil {
			return err
		}
		if value.Unit < edgev1.ResourceUnit_RESOURCE_UNIT_COUNT ||
			value.Unit > edgev1.ResourceUnit_RESOURCE_UNIT_BITS_PER_SECOND ||
			value.Quantity == 0 {
			return errors.New("invalid worker resource limit")
		}
		if _, duplicate := seen[value.Id]; duplicate {
			return errors.New("duplicate worker resource limit")
		}
		seen[value.Id] = struct{}{}
	}
	return nil
}

func validateWorkerID(name, value string) error {
	if len(value) < 8 || len(value) > 128 {
		return fmt.Errorf("%s must contain 8..128 safe bytes", name)
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '-' && character != '_' &&
			character != '.' && character != ':' {
			return fmt.Errorf("%s must contain 8..128 safe bytes", name)
		}
	}
	return nil
}

func validateWorkerSelector(serviceID, operation, model string) error {
	if !workerServiceIDPattern.MatchString(serviceID) {
		return errors.New("invalid worker service ID")
	}
	for name, value := range map[string]string{
		"operation": operation,
		"model":     model,
	} {
		if err := boundedWorkerString(name, value, 1, 256); err != nil ||
			strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("invalid worker %s", name)
		}
	}
	return nil
}

func validateWorkerDeadline(
	value int64,
	now time.Time,
	maxDuration time.Duration,
) error {
	deadline := time.UnixMilli(value)
	if !deadline.After(now) || deadline.After(now.Add(maxDuration)) {
		return errors.New("worker deadline is outside local policy")
	}
	return nil
}

func boundedWorkerString(name, value string, minimum, maximum int) error {
	if len(value) < minimum || len(value) > maximum ||
		strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s has invalid length or content", name)
	}
	return nil
}

func cloneQuoteRequest(request *edgev1.QuoteRequest) *edgev1.QuoteRequest {
	if request == nil {
		return nil
	}
	return proto.Clone(request).(*edgev1.QuoteRequest)
}

func cloneInvokeRequest(request *edgev1.InvokeRequest) *edgev1.InvokeRequest {
	if request == nil {
		return nil
	}
	return proto.Clone(request).(*edgev1.InvokeRequest)
}
