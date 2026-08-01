package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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
	if err := reloadCatalogs(index, catalogPaths); err != nil {
		log.Fatal(err)
	}
	handler, err := registry.NewHandler(index, publicURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tos-ard-registry listener: %s (%d catalogs)", listenAddress, len(catalogPaths))
	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	stopReload := make(chan struct{})
	go func() {
		for {
			select {
			case <-reloadSignals:
				if err := reloadCatalogs(index, catalogPaths); err != nil {
					log.Printf("catalog reload rejected; retaining previous generation: %v", err)
					continue
				}
				log.Printf("catalog reload committed (%d catalogs)", len(catalogPaths))
			case <-stopReload:
				return
			}
		}
	}()
	err = serve.HTTP(registry.NewHTTPServer(listenAddress, handler.Routes()))
	signal.Stop(reloadSignals)
	close(stopReload)
	if err != nil {
		log.Fatal(err)
	}
}

func reloadCatalogs(index *registry.Index, paths []string) error {
	inputs := make([]registry.CatalogInput, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve catalog path %q: %w", path, err)
		}
		catalog, err := ard.ReadCatalogFile(absolute, ard.DefaultLimits())
		if err != nil {
			return fmt.Errorf("load catalog %q: %w", path, err)
		}
		inputs = append(inputs, registry.CatalogInput{
			Source:  (&url.URL{Scheme: "file", Path: absolute}).String(),
			Catalog: catalog,
		})
	}
	if err := index.ReplaceCatalogs(inputs); err != nil {
		return fmt.Errorf("replace Registry catalog set: %w", err)
	}
	return nil
}
