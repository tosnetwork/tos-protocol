package atosrpc

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
)

// validateThirdPartyBinding validates an optional ThirdPartyBinding. A nil
// binding is valid -- it means an ordinary tos-native/model request, per
// atos-spec docs/THIRD_PARTY_EXECUTION_PLANE.md.
func validateThirdPartyBinding(b *atostosv1.ThirdPartyBinding) error {
	if b == nil {
		return nil
	}
	if b.Transport == atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_UNSPECIFIED {
		return invalid("INVALID_ARGUMENT", "third_party_binding.transport is required")
	}
	if strings.TrimSpace(b.EndpointRef) == "" {
		return invalid("INVALID_ARGUMENT", "third_party_binding.endpoint_ref is required")
	}
	if err := validateDigest(b.BindingCommitment); err != nil {
		return invalid("INVALID_ARGUMENT", "third_party_binding.binding_commitment: "+err.Error())
	}
	return nil
}

func mapThirdPartyTransport(t atostosv1.EndpointAdapterType) (edgev1.ThirdPartyTransport, error) {
	switch t {
	case atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_HTTP:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_HTTP, nil
	case atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_MCP:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_MCP, nil
	case atostosv1.EndpointAdapterType_ENDPOINT_ADAPTER_TYPE_A2A:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_A2A, nil
	default:
		return edgev1.ThirdPartyTransport_THIRD_PARTY_TRANSPORT_UNSPECIFIED, invalid("INVALID_ARGUMENT", "unsupported third_party_binding.transport")
	}
}

// toEdgeBindingRef maps an atos.tos.v1.ThirdPartyBinding (the ATOS-facing
// wire shape) to a tos.edge.v1.ThirdPartyBindingRef (the private Worker
// boundary wire shape) -- the two are intentionally independent proto
// definitions (see worker.proto's own doc comment on why this boundary
// stays decoupled from ATOS-specific types), so this is where they're
// reconciled.
func toEdgeBindingRef(b *atostosv1.ThirdPartyBinding, capabilityID, capabilityVersion string) (*edgev1.ThirdPartyBindingRef, error) {
	transport, err := mapThirdPartyTransport(b.Transport)
	if err != nil {
		return nil, err
	}
	commitment := ""
	if b.BindingCommitment != nil {
		commitment = b.BindingCommitment.Algorithm + ":" + hex.EncodeToString(b.BindingCommitment.Value)
	}
	return &edgev1.ThirdPartyBindingRef{
		Transport: transport, EndpointRef: b.EndpointRef,
		CapabilityId: capabilityID, CapabilityVersion: capabilityVersion,
		BindingCommitment: commitment,
	}, nil
}

// getThirdPartyProviderStatus is GetProviderStatus's third-party-binding
// branch: it probes tos.edge.v1.ThirdPartyExecutionService.Health instead of
// resolving a Router entry, since a third-party request already names its
// own transport + endpoint_ref -- there is no provider/capability -> service
// selector table to resolve, per atos-spec
// docs/THIRD_PARTY_EXECUTION_PLANE.md.
func (s *Server) getThirdPartyProviderStatus(
	ctx context.Context,
	req *connect.Request[atostosv1.GetProviderStatusRequest],
) (*connect.Response[atostosv1.GetProviderStatusResponse], error) {
	if err := validateThirdPartyBinding(req.Msg.ThirdPartyBinding); err != nil {
		return nil, err
	}
	response := &atostosv1.GetProviderStatusResponse{
		ProviderId: req.Msg.ProviderId, CapabilityId: req.Msg.CapabilityId,
		Readiness:          atostosv1.ProviderReadiness_PROVIDER_READINESS_UNAVAILABLE,
		ObservedUnixMillis: s.now().UnixMilli(),
		ExpiresUnixMillis:  s.now().Add(5 * time.Second).UnixMilli(),
	}
	if s.thirdPartyWorker == nil {
		response.ReasonCode = "THIRD_PARTY_WORKER_NOT_CONFIGURED"
		return connect.NewResponse(response), nil
	}
	binding, err := toEdgeBindingRef(req.Msg.ThirdPartyBinding, req.Msg.CapabilityId, "")
	if err != nil {
		return nil, err
	}
	callContext, cancel, err := s.boundedContext(ctx, req.Msg.Context.DeadlineUnixMillis)
	if err != nil {
		return nil, err
	}
	defer cancel()
	health, err := s.thirdPartyWorker.Health(callContext, &edgev1.ThirdPartyHealthRequest{Binding: binding})
	if err != nil {
		response.ReasonCode = "THIRD_PARTY_WORKER_UNAVAILABLE"
		return connect.NewResponse(response), nil
	}
	if !health.Healthy {
		response.ReasonCode = "CAPABILITY_UNAVAILABLE"
		if health.FailureReason != "" {
			response.ReasonCode = health.FailureReason
		}
		return connect.NewResponse(response), nil
	}
	response.Readiness = atostosv1.ProviderReadiness_PROVIDER_READINESS_READY
	if s.supportsMode(atostosv1.TrustMode_TRUST_MODE_MANAGED) {
		response.AvailableTrustModes = []atostosv1.TrustMode{atostosv1.TrustMode_TRUST_MODE_MANAGED}
	}
	return connect.NewResponse(response), nil
}
