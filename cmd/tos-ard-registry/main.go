package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/tosnetwork/tos-protocol/internal/serve"
	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/registry"
)

type catalogFlags []string

func (f *catalogFlags) String() string { return fmt.Sprint([]string(*f)) }
func (f *catalogFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	var listenAddress string
	var publicURL string
	var catalogPaths catalogFlags
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:8090", "HTTP listen address")
	flag.StringVar(&publicURL, "public-url", "http://127.0.0.1:8090/search", "public Registry search URL")
	flag.Var(&catalogPaths, "catalog", "operator-approved local ai-catalog.json; may repeat")
	flag.Parse()

	index, err := registry.NewIndex(registry.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}
	for _, path := range catalogPaths {
		file, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		catalog, decodeErr := ard.DecodeCatalog(file, ard.DefaultLimits())
		file.Close()
		if decodeErr != nil {
			log.Fatalf("%s: %v", path, decodeErr)
		}
		if err := index.AddCatalog("file://"+path, catalog); err != nil {
			log.Fatalf("%s: %v", path, err)
		}
	}
	handler, err := registry.NewHandler(index, publicURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tos-ard-registry listener: %s (%d catalogs)", listenAddress, len(catalogPaths))
	if err := serve.HTTP(registry.NewHTTPServer(listenAddress, handler.Routes())); err != nil {
		log.Fatal(err)
	}
}
