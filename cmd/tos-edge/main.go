package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/files"
	"github.com/tosnetwork/tos-protocol/internal/serve"
	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/edge"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const chainStartupTimeout = 10 * time.Second

type tosServiceReadiness struct {
	runtime   *toschain.Runtime
	reference authorization.Reference
}

func (readiness *tosServiceReadiness) CheckReady(ctx context.Context) error {
	if readiness == nil {
		return errors.New("nil TOS service readiness")
	}
	_, err := readiness.runtime.CheckServiceReady(ctx, readiness.reference, time.Now())
	return err
}

func main() {
	var listenAddress string
	var descriptorPath string
	var catalogPath string
	var requestJournalPath string
	var tosChainConfigPath string
	var cleanupInterval time.Duration
	var paymentReconciliationInterval time.Duration
	var paymentReconciliationMaxInterval time.Duration
	var paymentReconciliationTimeout time.Duration
	var paymentReconciliationBatch int
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:8080", "HTTP listen address")
	flag.StringVar(&descriptorPath, "descriptor", "", "path to tos-service.json")
	flag.StringVar(&catalogPath, "catalog", "", "path to ai-catalog.json")
	flag.StringVar(
		&requestJournalPath, "request-journal", "",
		"absolute path to the durable request journal (optional while discovery-only)",
	)
	flag.StringVar(
		&tosChainConfigPath, "tos-chain-config", "",
		"path to strict TOS authority/client-key/payment startup configuration",
	)
	flag.DurationVar(
		&cleanupInterval, "journal-cleanup-interval", edge.DefaultCleanupInterval,
		"bounded expired-request cleanup interval",
	)
	flag.DurationVar(
		&paymentReconciliationInterval, "payment-reconciliation-interval",
		edge.DefaultPaymentReconciliationInterval,
		"durable applied-payment rescan interval when chain runtime and journal are configured",
	)
	flag.DurationVar(
		&paymentReconciliationMaxInterval, "payment-reconciliation-max-interval",
		edge.DefaultPaymentReconciliationMaxInterval,
		"maximum bounded backoff after consecutive payment reconciliation failures",
	)
	flag.DurationVar(
		&paymentReconciliationTimeout, "payment-reconciliation-timeout",
		edge.DefaultPaymentReconciliationTimeout,
		"timeout for one bounded payment reconciliation batch",
	)
	flag.IntVar(
		&paymentReconciliationBatch, "payment-reconciliation-batch",
		edge.DefaultPaymentReconciliationBatch,
		"maximum durable payment records scanned per reconciliation batch",
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
	var chainRuntime *toschain.Runtime
	if tosChainConfigPath != "" {
		var readiness toschain.ReadinessSnapshot
		chainRuntime, readiness, err = loadTOSChainRuntime(
			tosChainConfigPath, descriptor, time.Now(),
		)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf(
			"TOS chain runtime ready: network=%s master_seqno=%d quorum=%d",
			readiness.Network, readiness.ObservedMasterSeqno, readiness.QuorumEndpoints,
		)
	}
	var core *edge.Core
	if requestJournalPath != "" {
		coreConfig := edge.DefaultCoreConfig(requestJournalPath)
		coreConfig.CleanupInterval = cleanupInterval
		if chainRuntime != nil {
			coreConfig.PaymentObserver = chainRuntime.Payments
			coreConfig.PaymentReconciliationInterval = paymentReconciliationInterval
			coreConfig.PaymentReconciliationMaxInterval = paymentReconciliationMaxInterval
			coreConfig.PaymentReconciliationTimeout = paymentReconciliationTimeout
			coreConfig.PaymentReconciliationBatch = paymentReconciliationBatch
		}
		core, err = edge.OpenCore(coreConfig)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if closeErr := core.Close(); closeErr != nil {
				log.Printf("close Edge Core: %v", closeErr)
			}
		}()
		if chainRuntime != nil {
			log.Printf(
				"payment reconciliation enabled: interval=%s max_interval=%s timeout=%s batch=%d",
				paymentReconciliationInterval, paymentReconciliationMaxInterval,
				paymentReconciliationTimeout,
				paymentReconciliationBatch,
			)
		}
	}
	var handler *edge.Server
	if chainRuntime != nil {
		chainReadiness := &tosServiceReadiness{
			runtime: chainRuntime,
			reference: authorization.Reference{
				Network: descriptor.Network, Address: descriptor.Controller,
				ServiceID: descriptor.ServiceID,
			},
		}
		handler, err = edge.NewServerWithDependencies(
			descriptor, catalog, time.Now(),
			edge.ServerDependencies{Core: core, ChainReadiness: chainReadiness},
		)
	} else if core == nil {
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

func loadTOSChainRuntime(
	configPath string,
	descriptor protocol.ServiceDescriptor,
	now time.Time,
) (*toschain.Runtime, toschain.ReadinessSnapshot, error) {
	if configPath == "" || now.IsZero() {
		return nil, toschain.ReadinessSnapshot{}, errors.New("invalid TOS chain startup request")
	}
	var config toschain.StartupConfig
	if err := files.DecodeJSON(configPath, toschain.MaxStartupConfigBytes, &config); err != nil {
		return nil, toschain.ReadinessSnapshot{}, fmt.Errorf("load TOS chain config: %w", err)
	}
	if config.Network != descriptor.Network {
		return nil, toschain.ReadinessSnapshot{}, errors.New(
			"TOS chain config network does not match service descriptor",
		)
	}
	runtime, err := config.BuildRuntime()
	if err != nil {
		return nil, toschain.ReadinessSnapshot{}, fmt.Errorf("configure TOS chain runtime: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), chainStartupTimeout)
	defer cancel()
	readiness, err := runtime.CheckServiceReady(ctx, authorization.Reference{
		Network: descriptor.Network, Address: descriptor.Controller,
		ServiceID: descriptor.ServiceID,
	}, now)
	if err != nil {
		return nil, toschain.ReadinessSnapshot{}, fmt.Errorf(
			"preflight TOS service readiness: %w", err,
		)
	}
	return runtime, readiness, nil
}
