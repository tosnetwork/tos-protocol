// Command tos-atos-rpc runs the authenticated ATOS-facing Edge Core RPC
// boundary. It never exposes the private Worker Unix socket to ATOS.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/atosrpc"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
)

func main() {
	var (
		listen          = flag.String("listen", envOr("TOS_ATOS_RPC_LISTEN", "127.0.0.1:8090"), "ATOS RPC listen address")
		statePath       = flag.String("state", envOr("TOS_ATOS_RPC_STATE", "./data/atos-rpc.db"), "durable bbolt state path")
		bearerToken     = flag.String("token", os.Getenv("TOS_ATOS_RPC_TOKEN"), "shared bearer token (or TOS_ATOS_RPC_TOKEN)")
		workerSocket    = flag.String("worker-socket", os.Getenv("TOS_WORKER_SOCKET"), "private tos-ai Worker Unix socket")
		routeFile       = flag.String("routes", os.Getenv("TOS_ATOS_RPC_ROUTES"), "JSON array of public capability to Worker routes")
		tlsCert         = flag.String("tls-cert", os.Getenv("TOS_ATOS_RPC_TLS_CERT"), "TLS server certificate PEM")
		tlsKey          = flag.String("tls-key", os.Getenv("TOS_ATOS_RPC_TLS_KEY"), "TLS server private key PEM")
		clientCA        = flag.String("client-ca", os.Getenv("TOS_ATOS_RPC_CLIENT_CA"), "optional client CA PEM; enables required mTLS")
		authorityMode   = flag.String("authority", envOr("TOS_ATOS_RPC_AUTHORITY", "local"), "Authority backend: local or chain")
		authorityConfig = flag.String("authority-config", os.Getenv("TOS_ATOS_RPC_AUTHORITY_CONFIG"), "strict JSON chain Authority configuration")
		economicMode    = flag.String("economic-driver", envOr("TOS_ATOS_RPC_ECONOMIC_DRIVER", "disabled"), "Economic backend: disabled or task-escrow")
		economicConfig  = flag.String("economic-config", os.Getenv("TOS_ATOS_RPC_ECONOMIC_CONFIG"), "strict JSON Task Escrow economic configuration")
		// identitySeedFile is the ONLY way this process establishes a new
		// AgentIdentity -- Server.SeedIdentity is deliberately not a
		// network RPC (atos-spec proto/atos/tos/v1/identity.proto: "Creating
		// a brand-new AgentIdentity from nothing remains an out-of-band
		// operator/bootstrap action... Full self-service, wallet-proved
		// Agent Identity creation is Phase 5's deliverable, not this
		// phase's"). This flag is that operator/bootstrap mechanism made
		// practically usable: an operator who has already independently
		// verified an Agent's TOS controller key (by whatever out-of-band
		// process this deployment uses) lists it here; re-running with the
		// same file content on every restart is safe (SeedIdentity's
		// Authority.Commit digest is stable across identical re-seeds).
		identitySeedFile = flag.String("identity-seed-file", os.Getenv("TOS_ATOS_RPC_IDENTITY_SEED_FILE"), "JSON array of already-verified AgentIdentity records to seed at startup")
	)
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if strings.TrimSpace(*bearerToken) == "" {
		logger.Error("TOS_ATOS_RPC_TOKEN or -token is required")
		os.Exit(2)
	}
	routes, err := loadRoutes(*routeFile)
	if err != nil {
		logger.Error("load routes", "error", err)
		os.Exit(2)
	}
	router, err := atosrpc.NewStaticRouter(routes)
	if err != nil {
		logger.Error("validate routes", "error", err)
		os.Exit(2)
	}
	var worker atosrpc.Worker
	if strings.TrimSpace(*workerSocket) != "" {
		client, err := localrpc.NewWorkerClient(localrpc.DefaultWorkerClientConfig(*workerSocket))
		if err != nil {
			logger.Error("configure private Worker client", "error", err)
			os.Exit(2)
		}
		worker = client
	}
	authority, err := buildAuthority(*authorityMode, *authorityConfig)
	if err != nil {
		logger.Error("configure ATOS RPC authority", "error", err)
		os.Exit(2)
	}
	economicDriver, err := buildEconomicDriver(*economicMode, *economicConfig)
	if err != nil {
		_ = authority.Close()
		logger.Error("configure ATOS RPC economic driver", "error", err)
		os.Exit(2)
	}
	server, err := atosrpc.Open(atosrpc.Config{
		StatePath: *statePath, BearerToken: *bearerToken,
		Authority: authority, EconomicDriver: economicDriver,
		Worker: worker, Router: router,
	})
	if err != nil {
		logger.Error("open ATOS RPC server", "error", err)
		os.Exit(1)
	}
	defer server.Close()

	seeded, err := seedIdentities(server, *identitySeedFile)
	if err != nil {
		logger.Error("seed identities", "error", err)
		os.Exit(2)
	}
	if seeded > 0 {
		logger.Info("seeded operator-verified identities", "count", seeded)
	}

	tlsConfig, useTLS, err := buildServerTLS(*listen, *tlsCert, *tlsKey, *clientCA)
	if err != nil {
		logger.Error("configure ATOS RPC transport", "error", err)
		os.Exit(2)
	}
	httpServer := &http.Server{
		Addr: *listen, Handler: server.Handler(), TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       35 * time.Second, WriteTimeout: 35 * time.Second,
		IdleTimeout: 2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("ATOS TOS RPC listening", "address", *listen, "network", authority.Network(),
			"authority", strings.ToLower(strings.TrimSpace(*authorityMode)),
			"economic_driver", strings.ToLower(strings.TrimSpace(*economicMode)),
			"worker_configured", worker != nil, "tls", useTLS,
			"mtls", strings.TrimSpace(*clientCA) != "")
		var serveErr error
		if useTLS {
			serveErr = httpServer.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			serveErr = httpServer.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("ATOS RPC server failed", "error", serveErr)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdown); err != nil {
		logger.Error("ATOS RPC shutdown", "error", err)
	}
}

// identitySeed is the JSON operator/bootstrap record shape -- deliberately a
// plain DTO, not atostosv1.AgentIdentity's own JSON encoding, so this file
// format stays stable/reviewable independent of the proto's wire shape.
type identitySeed struct {
	AgentID      string            `json:"agent_id"`
	CanonicalURI string            `json:"canonical_uri"`
	Controllers  []string          `json:"controllers"`
	Assurance    string            `json:"assurance"`
	PublicAttrs  map[string]string `json:"public_attributes"`
}

// seedIdentities loads and applies path's operator/bootstrap identity file
// (empty path is a no-op, not an error). Every record MUST declare a
// non-empty, non-"self_asserted" assurance level -- this file exists
// precisely because the operator running this process has ALREADY verified
// each Agent's TOS controller key through some out-of-band process; a
// self-asserted entry here would defeat the entire point (see
// pkg/atosrpc/economic.go's verifiedTOSController, which rejects
// self-asserted assurance for any Verified-mode-gating decision).
func seedIdentities(server *atosrpc.Server, path string) (int, error) {
	if strings.TrimSpace(path) == "" {
		return 0, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var seeds []identitySeed
	if err := decoder.Decode(&seeds); err != nil {
		return 0, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return 0, errors.New("identity seed file contains trailing JSON")
		}
		return 0, err
	}
	for _, seed := range seeds {
		if strings.TrimSpace(seed.AgentID) == "" || strings.TrimSpace(seed.CanonicalURI) == "" {
			return 0, fmt.Errorf("identity seed missing agent_id or canonical_uri")
		}
		if strings.TrimSpace(seed.Assurance) == "" || strings.EqualFold(strings.TrimSpace(seed.Assurance), "self_asserted") {
			return 0, fmt.Errorf("identity seed %q must declare a non-self-asserted assurance level", seed.AgentID)
		}
		if len(seed.Controllers) == 0 {
			return 0, fmt.Errorf("identity seed %q must list at least one controller", seed.AgentID)
		}
		if err := server.SeedIdentity(&atostosv1.AgentIdentity{
			AgentId: seed.AgentID, CanonicalUri: seed.CanonicalURI,
			Controllers: seed.Controllers, Assurance: seed.Assurance,
			PublicAttributes: seed.PublicAttrs,
		}); err != nil {
			return 0, fmt.Errorf("seed identity %q: %w", seed.AgentID, err)
		}
	}
	return len(seeds), nil
}

func loadRoutes(path string) ([]atosrpc.Route, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var routes []atosrpc.Route
	if err := decoder.Decode(&routes); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("route file contains trailing JSON")
		}
		return nil, err
	}
	return routes, nil
}

func buildAuthority(mode, configPath string) (atosrpc.Authority, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	configPath = strings.TrimSpace(configPath)
	switch mode {
	case "local":
		if configPath != "" {
			return nil, errors.New("authority-config is valid only for chain Authority")
		}
		return atosrpc.NewLocalAuthority("tos-local"), nil
	case "chain":
		if configPath == "" {
			return nil, errors.New("chain Authority requires authority-config")
		}
		info, err := os.Stat(configPath)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 ||
			info.Size() > atosrpc.MaxChainAuthorityConfigBytes {
			return nil, errors.New("chain Authority config file is outside bounds")
		}
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, err
		}
		config, err := atosrpc.DecodeChainAuthorityStartupConfigJSON(data)
		if err != nil {
			return nil, err
		}
		return config.Build()
	default:
		return nil, errors.New("unsupported ATOS RPC authority backend")
	}
}

func buildEconomicDriver(mode, configPath string) (economic.Driver, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	configPath = strings.TrimSpace(configPath)
	switch mode {
	case "disabled":
		if configPath != "" {
			return nil, errors.New("economic-config requires task-escrow economic driver")
		}
		return nil, nil
	case "task-escrow":
		if configPath == "" {
			return nil, errors.New("task-escrow economic driver requires economic-config")
		}
		info, err := os.Stat(configPath)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 ||
			info.Size() > economic.MaxTaskEscrowConfigBytes {
			return nil, errors.New("Task Escrow economic config file is outside bounds")
		}
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, err
		}
		config, err := economic.DecodeTaskEscrowStartupConfigJSON(data)
		if err != nil {
			return nil, err
		}
		return config.Build()
	default:
		return nil, errors.New("unsupported ATOS RPC economic driver")
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func buildServerTLS(listen, certFile, keyFile, clientCAFile string) (*tls.Config, bool, error) {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	clientCAFile = strings.TrimSpace(clientCAFile)
	if (certFile == "") != (keyFile == "") {
		return nil, false, errors.New("TLS certificate and key must be configured together")
	}
	if certFile == "" {
		if clientCAFile != "" {
			return nil, false, errors.New("client CA requires TLS certificate and key")
		}
		if !loopbackListen(listen) {
			return nil, false, errors.New("plain HTTP ATOS RPC may listen only on loopback")
		}
		return nil, false, nil
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, false, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, false, errors.New("client CA file contains no certificates")
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, true, nil
}

func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
