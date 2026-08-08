// Package atosrpc implements the ATOS-facing TOS v0.2 ConnectRPC boundary.
// It keeps AI execution behind the private tos.edge.v1 Worker RPC and keeps
// trust, settlement, and proof state in one durable Edge-owned store.
package atosrpc

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
)

const (
	DefaultMaxMessageBytes = 16 << 20
	DefaultMaxRecordBytes  = 32 << 20
	DefaultCallTimeout     = 30 * time.Second
	DefaultRetention       = 48 * time.Hour
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{1,255}$`)

// Authority is the trust/economic anchoring boundary. The bundled local
// authority supports Managed mode only and emits references on the explicit
// tos-local development network. A production TOS authority must independently
// implement Verified/Native commitment and finality semantics.
type Authority interface {
	Network() string
	Supports(mode TrustMode) bool
	CheckReady(context.Context) error
	Commit(ctx context.Context, kind, id, digest string) (NetworkReference, error)
	Close() error
}

// Worker is the narrow Edge Core -> private Worker dependency used by
// ExecutionGatewayService. localrpc.WorkerClient satisfies this interface.
type Worker interface {
	CheckReady(context.Context) error
	GetCapabilities(context.Context) (*edgev1.GetCapabilitiesResponse, error)
	Quote(context.Context, *edgev1.QuoteRequest) (*edgev1.QuoteResponse, error)
	Invoke(context.Context, *edgev1.InvokeRequest) (localrpc.ValidatedInvocation, error)
	GetTask(context.Context, *edgev1.InvokeRequest) (localrpc.RecoveredTask, error)
	Cancel(context.Context, *edgev1.InvokeRequest) (bool, error)
}

// Route maps one public ATOS capability to an existing private Worker route.
// CapabilityID and CapabilityVersion may be "*" for an explicit fallback.
type Route struct {
	ProviderID        string          `json:"provider_id"`
	CapabilityID      string          `json:"capability_id"`
	CapabilityVersion string          `json:"capability_version"`
	ServiceID         string          `json:"service_id"`
	Operation         string          `json:"operation"`
	Model             string          `json:"model"`
	MaxOutputBytes    uint64          `json:"max_output_bytes"`
	Priority          edgev1.Priority `json:"priority"`
}

func (r Route) validate() error {
	for name, value := range map[string]string{
		"provider_id": r.ProviderID, "capability_id": r.CapabilityID,
		"capability_version": r.CapabilityVersion, "service_id": r.ServiceID,
		"operation": r.Operation, "model": r.Model,
	} {
		if value == "*" && (name == "capability_id" || name == "capability_version") {
			continue
		}
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("invalid route %s", name)
		}
	}
	if r.MaxOutputBytes == 0 || r.MaxOutputBytes > uint64(DefaultMaxMessageBytes) {
		return errors.New("invalid route max_output_bytes")
	}
	if r.Priority == edgev1.Priority_PRIORITY_UNSPECIFIED {
		return errors.New("route priority is required")
	}
	return nil
}

// Router resolves a public capability to a private Worker selector.
type Router interface {
	Resolve(providerID, capabilityID, version string) (Route, bool)
}

// StaticRouter is an immutable validated route table.
type StaticRouter struct {
	routes []Route
}

func NewStaticRouter(routes []Route) (*StaticRouter, error) {
	seen := make(map[string]struct{}, len(routes))
	copyRoutes := make([]Route, len(routes))
	for i, route := range routes {
		if err := route.validate(); err != nil {
			return nil, fmt.Errorf("route %d: %w", i, err)
		}
		key := strings.Join([]string{route.ProviderID, route.CapabilityID, route.CapabilityVersion}, "\x00")
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("duplicate ATOS Worker route")
		}
		seen[key] = struct{}{}
		copyRoutes[i] = route
	}
	return &StaticRouter{routes: copyRoutes}, nil
}

func (r *StaticRouter) Resolve(providerID, capabilityID, version string) (Route, bool) {
	if r == nil {
		return Route{}, false
	}
	var fallback Route
	foundFallback := false
	for _, route := range r.routes {
		if route.ProviderID != providerID {
			continue
		}
		capabilityMatch := route.CapabilityID == capabilityID || route.CapabilityID == "*"
		versionMatch := route.CapabilityVersion == version || route.CapabilityVersion == "*"
		if !capabilityMatch || !versionMatch {
			continue
		}
		if route.CapabilityID == capabilityID && route.CapabilityVersion == version {
			return route, true
		}
		if !foundFallback || (route.CapabilityID == capabilityID && fallback.CapabilityID == "*") {
			fallback, foundFallback = route, true
		}
	}
	return fallback, foundFallback
}

// Config controls one ATOS/TOS RPC server.
type Config struct {
	StatePath       string
	BearerToken     string
	Authority       Authority
	EconomicDriver  economic.Driver
	Worker          Worker
	Router          Router
	MaxMessageBytes int
	MaxRecordBytes  int
	CallTimeout     time.Duration
	Retention       time.Duration
	Now             func() time.Time
}

func (c Config) withDefaults() (Config, error) {
	if c.StatePath == "" {
		return Config{}, errors.New("ATOS RPC state path is required")
	}
	if strings.TrimSpace(c.BearerToken) == "" {
		return Config{}, errors.New("ATOS RPC bearer token is required")
	}
	if c.Authority == nil {
		return Config{}, errors.New("ATOS RPC authority is required")
	}
	if strings.TrimSpace(c.Authority.Network()) == "" {
		return Config{}, errors.New("ATOS RPC authority network is required")
	}
	if c.EconomicDriver != nil {
		if strings.TrimSpace(c.EconomicDriver.Network()) == "" ||
			c.EconomicDriver.Network() != c.Authority.Network() {
			return Config{}, errors.New("ATOS RPC economic driver network must match authority")
		}
		if !c.Authority.Supports(TrustModeVerified) ||
			!c.EconomicDriver.Supports(economic.TrustModeVerified) {
			return Config{}, errors.New("ATOS RPC economic driver requires a Verified-capable authority")
		}
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if c.MaxMessageBytes <= 0 || c.MaxMessageBytes > 64<<20 {
		return Config{}, errors.New("invalid ATOS RPC message limit")
	}
	if c.MaxRecordBytes == 0 {
		c.MaxRecordBytes = DefaultMaxRecordBytes
	}
	if c.MaxRecordBytes < c.MaxMessageBytes || c.MaxRecordBytes > 128<<20 {
		return Config{}, errors.New("invalid ATOS RPC record limit")
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = DefaultCallTimeout
	}
	if c.CallTimeout <= 0 || c.CallTimeout > 15*time.Minute {
		return Config{}, errors.New("invalid ATOS RPC call timeout")
	}
	if c.Retention == 0 {
		c.Retention = DefaultRetention
	}
	if c.Retention < time.Hour || c.Retention > 30*24*time.Hour {
		return Config{}, errors.New("invalid ATOS RPC retention")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}
