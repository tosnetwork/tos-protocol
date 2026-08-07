// Command tos-atos-rpc runs the authenticated ATOS-facing Edge Core RPC
// boundary. It never exposes the private Worker Unix socket to ATOS.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
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
		listen       = flag.String("listen", envOr("TOS_ATOS_RPC_LISTEN", "127.0.0.1:8090"), "ATOS RPC listen address")
		statePath    = flag.String("state", envOr("TOS_ATOS_RPC_STATE", "./data/atos-rpc.db"), "durable bbolt state path")
		bearerToken  = flag.String("token", os.Getenv("TOS_ATOS_RPC_TOKEN"), "shared bearer token (or TOS_ATOS_RPC_TOKEN)")
		workerSocket = flag.String("worker-socket", os.Getenv("TOS_WORKER_SOCKET"), "private tos-ai Worker Unix socket")
		routeFile    = flag.String("routes", os.Getenv("TOS_ATOS_RPC_ROUTES"), "JSON array of public capability to Worker routes")
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
	server, err := atosrpc.Open(atosrpc.Config{
		StatePath: *statePath, BearerToken: *bearerToken,
		Authority: atosrpc.NewLocalAuthority("tos-local"), Worker: worker, Router: router,
	})
	if err != nil {
		logger.Error("open ATOS RPC server", "error", err)
		os.Exit(1)
	}
	defer server.Close()

	httpServer := &http.Server{
		Addr: *listen, Handler: server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       35 * time.Second, WriteTimeout: 35 * time.Second,
		IdleTimeout: 2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("ATOS TOS RPC listening", "address", *listen, "network", "tos-local", "worker_configured", worker != nil)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("ATOS RPC server failed", "error", err)
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

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
