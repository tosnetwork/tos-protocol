package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

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
	var federationRoots catalogFlags
	var federationOrigins catalogFlags
	var federationRefresh time.Duration
	var federationAllowPrivate bool
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:8090", "HTTP listen address")
	flag.StringVar(&publicURL, "public-url", "http://127.0.0.1:8090/search", "public Registry search URL")
	flag.Var(&catalogPaths, "catalog", "operator-approved local ai-catalog.json; may repeat")
	flag.Var(&federationRoots, "federation-root", "remote HTTPS ARD catalog root; may repeat")
	flag.Var(&federationOrigins, "federation-origin", "exact allowed HTTPS origin; may repeat")
	flag.DurationVar(&federationRefresh, "federation-refresh", 5*time.Minute, "bounded cached federation refresh interval")
	flag.BoolVar(&federationAllowPrivate, "federation-allow-private", false, "explicitly permit private federation origins")
	flag.Parse()

	index, err := registry.NewIndex(registry.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}
	if len(catalogPaths) != 0 && len(federationRoots) != 0 {
		log.Fatal("local catalogs and federation roots cannot be combined")
	}
	if (len(federationRoots) == 0) != (len(federationOrigins) == 0) {
		log.Fatal("federation roots and origins must be configured together")
	}
	if federationRefresh < time.Minute || federationRefresh > 24*time.Hour {
		log.Fatal("federation refresh must be between one minute and 24 hours")
	}
	var federation *registry.Federation
	if len(federationRoots) != 0 {
		config := registry.DefaultFederationConfig()
		config.Roots = append([]string(nil), federationRoots...)
		config.AllowedOrigins = append([]string(nil), federationOrigins...)
		config.AllowPrivateOrigins = federationAllowPrivate
		federation, err = registry.NewFederation(index, &http.Client{Timeout: 30 * time.Second}, config)
		if err != nil {
			log.Fatal(err)
		}
		refreshContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = federation.Refresh(refreshContext, time.Now().UTC())
		cancel()
		if err != nil {
			log.Fatal(err)
		}
	} else if err := reloadCatalogs(index, catalogPaths); err != nil {
		log.Fatal(err)
	}
	handler, err := registry.NewHandler(index, publicURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tos-ard-registry listener: %s (%d local catalogs, %d federation roots)", listenAddress, len(catalogPaths), len(federationRoots))
	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	stopReload := make(chan struct{})
	var refreshTicker *time.Ticker
	var refreshTick <-chan time.Time
	if federation != nil {
		refreshTicker = time.NewTicker(federationRefresh)
		refreshTick = refreshTicker.C
	}
	go func() {
		for {
			select {
			case <-reloadSignals:
				if err := refreshRegistry(index, catalogPaths, federation); err != nil {
					log.Printf("catalog reload rejected; retaining previous generation: %v", err)
					continue
				}
				log.Printf("catalog reload committed (%d catalogs)", len(catalogPaths))
			case <-refreshTick:
				if err := refreshRegistry(index, catalogPaths, federation); err != nil {
					log.Printf("federation refresh rejected; retaining previous generation: %v", err)
				}
			case <-stopReload:
				return
			}
		}
	}()
	err = serve.HTTP(registry.NewHTTPServer(listenAddress, handler.Routes()))
	signal.Stop(reloadSignals)
	close(stopReload)
	if refreshTicker != nil {
		refreshTicker.Stop()
	}
	if err != nil {
		log.Fatal(err)
	}
}

func refreshRegistry(index *registry.Index, paths []string, federation *registry.Federation) error {
	if federation == nil {
		return reloadCatalogs(index, paths)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	if err := federation.Refresh(ctx, now); err != nil {
		_, _ = federation.Expire(now)
		return err
	}
	return nil
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
