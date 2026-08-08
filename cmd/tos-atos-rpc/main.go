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
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/atosrpc"
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
	server, err := atosrpc.Open(atosrpc.Config{
		StatePath: *statePath, BearerToken: *bearerToken,
		Authority: authority, Worker: worker, Router: router,
	})
	if err != nil {
		logger.Error("open ATOS RPC server", "error", err)
		os.Exit(1)
	}
	defer server.Close()

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
		logger.Info("ATOS TOS RPC listening", "address", *listen, "network", authority.Network(), "authority", strings.ToLower(strings.TrimSpace(*authorityMode)), "worker_configured", worker != nil, "tls", useTLS, "mtls", strings.TrimSpace(*clientCA) != "")
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
