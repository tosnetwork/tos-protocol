// Command tos-service-rpc runs the private tos_service_v1 chain boundary.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/servicerpc"
)

func main() {
	listen := flag.String("listen", envOr("TOS_SERVICE_RPC_LISTEN", "127.0.0.1:8090"), "listen address")
	bearerToken := flag.String("bearer-token", os.Getenv("TOS_SERVICE_RPC_TOKEN"), "private bearer token")
	nativeConfig := flag.String("native-v1-config", os.Getenv("TOS_SERVICE_V1_CONFIG"), "absolute tos_service_v1 JSON config")
	tlsCert := flag.String("tls-cert", os.Getenv("TOS_SERVICE_RPC_TLS_CERT"), "server TLS certificate")
	tlsKey := flag.String("tls-key", os.Getenv("TOS_SERVICE_RPC_TLS_KEY"), "server TLS key")
	clientCA := flag.String("client-ca", os.Getenv("TOS_SERVICE_RPC_CLIENT_CA"), "optional client CA for mTLS")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	relayer, resolver, dnsResolver, closeSender, err := buildNativeV1(*nativeConfig)
	if err != nil || relayer == nil || resolver == nil {
		logger.Error("configure tos_service_v1", "error", err)
		os.Exit(2)
	}
	defer closeSender()
	server, err := servicerpc.Open(servicerpc.Config{BearerToken: *bearerToken, NativeV1Relayer: relayer,
		NativeV1Resolver: resolver, DNSAliasResolver: dnsResolver})
	if err != nil {
		logger.Error("start Native RPC", "error", err)
		os.Exit(1)
	}

	tlsConfig, useTLS, err := buildServerTLS(*listen, *tlsCert, *tlsKey, *clientCA)
	if err != nil {
		logger.Error("configure server transport", "error", err)
		os.Exit(2)
	}
	httpServer := &http.Server{Addr: *listen, Handler: server.Handler(), TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("tos-service-protocol Native RPC listening", "address", *listen, "tls", useTLS)
		if useTLS {
			errCh <- httpServer.ListenAndServeTLS("", "")
		} else {
			errCh <- httpServer.ListenAndServe()
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		logger.Info("shutdown requested", "signal", sig.String())
	case serveErr := <-errCh:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("Native RPC stopped", "error", serveErr)
			os.Exit(1)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func buildServerTLS(listen, certFile, keyFile, clientCAFile string) (*tls.Config, bool, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, false, errors.New("TLS certificate and key must be configured together")
	}
	if certFile == "" {
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return nil, false, errors.New("invalid listen address")
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, false, errors.New("plaintext RPC is restricted to loopback")
		}
		if clientCAFile != "" {
			return nil, false, errors.New("client CA requires server TLS")
		}
		return nil, false, nil
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, false, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, false, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, false, errors.New("client CA contains no valid certificate")
		}
		config.ClientCAs, config.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return config, true, nil
}
