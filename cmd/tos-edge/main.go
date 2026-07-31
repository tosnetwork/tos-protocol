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
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:8080", "HTTP listen address")
	flag.StringVar(&descriptorPath, "descriptor", "", "path to tos-service.json")
	flag.StringVar(&catalogPath, "catalog", "", "path to ai-catalog.json")
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
	handler, err := edge.NewServer(descriptor, catalog, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tos-edge discovery listener: %s", listenAddress)
	if err := serve.HTTP(edge.NewHTTPServer(listenAddress, handler.Routes())); err != nil {
		log.Fatal(err)
	}
}
