package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/receiptsigner"
)

func main() {
	var socketPath, seedFile, keyID string
	var maxMessageBytes, maxConcurrent int
	flag.StringVar(&socketPath, "socket", "", "absolute private Unix socket path")
	flag.StringVar(&seedFile, "seed-file", "", "absolute private Ed25519 seed file")
	flag.StringVar(&keyID, "key-id", "", "manifest receipt-role key ID")
	flag.IntVar(&maxMessageBytes, "max-message-bytes", receiptsigner.DefaultMaxMessageBytes, "maximum request and response bytes")
	flag.IntVar(&maxConcurrent, "max-concurrent", receiptsigner.DefaultMaxConcurrent, "maximum concurrent signing requests")
	flag.Parse()
	if socketPath == "" || seedFile == "" || keyID == "" {
		fmt.Fprintln(os.Stderr, "-socket, -seed-file, and -key-id are required")
		os.Exit(2)
	}
	privateKey, err := receiptsigner.LoadPrivateKey(seedFile)
	if err != nil {
		log.Fatal(err)
	}
	handler, err := receiptsigner.NewHandler(receiptsigner.Config{
		KeyID: keyID, PrivateKey: privateKey,
		MaxMessageBytes: maxMessageBytes, MaxConcurrent: maxConcurrent,
	})
	for index := range privateKey {
		privateKey[index] = 0
	}
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := handler.Close(); closeErr != nil {
			log.Printf("close receipt signer key: %v", closeErr)
		}
	}()
	listener, err := receiptsigner.ListenPrivateUnix(socketPath)
	if err != nil {
		log.Fatal(err)
	}
	limitedListener, err := receiptsigner.LimitListener(listener, maxConcurrent)
	if err != nil {
		_ = listener.Close()
		log.Fatal(err)
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	shutdown, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- server.Serve(limitedListener) }()
	select {
	case err := <-errorsChannel:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	case <-shutdown.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Fatal(err)
		}
	}
}
