package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/files"
	"github.com/tosnetwork/tos-protocol/internal/serve"
	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/edge"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func main() {
	var listenAddress string
	var descriptorPath string
	var catalogPath string
	var requestJournalPath string
	var cleanupInterval time.Duration
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:8080", "HTTP listen address")
	flag.StringVar(&descriptorPath, "descriptor", "", "path to tos-service.json")
	flag.StringVar(&catalogPath, "catalog", "", "path to ai-catalog.json")
	flag.StringVar(
		&requestJournalPath, "request-journal", "",
		"absolute path to the durable request journal (optional while discovery-only)",
	)
	flag.DurationVar(
		&cleanupInterval, "journal-cleanup-interval", edge.DefaultCleanupInterval,
		"bounded expired-request cleanup interval",
	)
	flag.Parse()

	if descriptorPath == "" || catalogPath == "" {
		fmt.Fprintln(os.Stderr, "-descriptor and -catalog are required")
		os.Exit(2)
	}
	var descriptor protocol.ServiceDescriptor
	if err := files.DecodeJSON(descriptorPath, 256<<10, &descriptor); err != nil {
		log.Fatal(err)
	}
	catalogFile, err := os.Open(catalogPath)
	if err != nil {
		log.Fatal(err)
	}
	catalog, err := ard.DecodeCatalog(catalogFile, ard.DefaultLimits())
	catalogFile.Close()
	if err != nil {
		log.Fatal(err)
	}
	var core *edge.Core
	if requestJournalPath != "" {
		coreConfig := edge.DefaultCoreConfig(requestJournalPath)
		coreConfig.CleanupInterval = cleanupInterval
		core, err = edge.OpenCore(coreConfig)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if closeErr := core.Close(); closeErr != nil {
				log.Printf("close Edge Core: %v", closeErr)
			}
		}()
	}
	var handler *edge.Server
	if core == nil {
		handler, err = edge.NewServer(descriptor, catalog, time.Now())
	} else {
		handler, err = edge.NewServerWithCore(descriptor, catalog, time.Now(), core)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tos-edge discovery listener: %s", listenAddress)
	if err := serve.HTTP(edge.NewHTTPServer(listenAddress, handler.Routes())); err != nil {
		log.Fatal(err)
	}
}
