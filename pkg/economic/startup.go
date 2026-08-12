package economic

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const (
	TaskEscrowStartupConfigVersion = "1"
	MaxTaskEscrowConfigBytes       = int64(128 << 10)
)

// TaskEscrowStartupConfig is operator-owned and contains no wallet seed or
// private key. Key custody remains in the private Unix-socket publisher.
type TaskEscrowStartupConfig struct {
	Version                     string                 `json:"version"`
	Chain                       toschain.StartupConfig `json:"chain"`
	AllowedTaskEscrowCodeHashes []string               `json:"allowedTaskEscrowCodeHashes"`
	VerifierAddress             string                 `json:"verifierAddress"`
	PublisherSocket             string                 `json:"publisherSocket"`
	PublisherJournalIdentity    string                 `json:"publisherJournalIdentity"`
	PublisherJournalBinding     string                 `json:"publisherJournalBinding"`
	PublisherTimeoutMillis      uint64                 `json:"publisherTimeoutMillis,omitempty"`
	PublisherMaxMessageBytes    int                    `json:"publisherMaxMessageBytes,omitempty"`
	PublisherMaxConcurrent      int                    `json:"publisherMaxConcurrent,omitempty"`
	FundingOverheadNanoTOS      uint64                 `json:"fundingOverheadNanoTOS"`
	ReviewPeriodSeconds         uint64                 `json:"reviewPeriodSeconds,omitempty"`
	DriverCallTimeoutMillis     uint64                 `json:"driverCallTimeoutMillis,omitempty"`
	ActionLifetimeSeconds       uint64                 `json:"actionLifetimeSeconds,omitempty"`
}

func DecodeTaskEscrowStartupConfigJSON(data []byte) (TaskEscrowStartupConfig, error) {
	var config TaskEscrowStartupConfig
	if err := jsonstrict.Decode(data, &config); err != nil {
		return TaskEscrowStartupConfig{}, errors.New("invalid Task Escrow economic config JSON")
	}
	return config, nil
}

func (c TaskEscrowStartupConfig) Build() (Driver, error) {
	if c.Version != TaskEscrowStartupConfigVersion {
		return nil, errors.New("unsupported Task Escrow economic config version")
	}
	runtime, err := c.Chain.BuildRuntime()
	if err != nil {
		return nil, err
	}
	publisherConfig := localrpc.DefaultTaskEscrowActionPublisherClientConfig(
		c.PublisherSocket, c.Chain.Network, c.PublisherJournalIdentity, c.PublisherJournalBinding,
	)
	if c.PublisherTimeoutMillis > 0 {
		if c.PublisherTimeoutMillis > uint64((2*time.Minute)/time.Millisecond) {
			return nil, errors.New("Task Escrow publisher timeout is outside bounds")
		}
		publisherConfig.Timeout = time.Duration(c.PublisherTimeoutMillis) * time.Millisecond
	}
	if c.PublisherMaxMessageBytes != 0 {
		publisherConfig.MaxMessageBytes = c.PublisherMaxMessageBytes
	}
	if c.PublisherMaxConcurrent != 0 {
		publisherConfig.MaxConcurrent = c.PublisherMaxConcurrent
	}
	publisher, err := localrpc.NewTaskEscrowActionPublisherClient(publisherConfig)
	if err != nil {
		return nil, err
	}
	reviewPeriod := time.Duration(0)
	if c.ReviewPeriodSeconds > 0 {
		if c.ReviewPeriodSeconds > uint64(maxTaskEscrowReviewPeriod/time.Second) {
			_ = publisher.Close()
			return nil, errors.New("Task Escrow review period is outside bounds")
		}
		reviewPeriod = time.Duration(c.ReviewPeriodSeconds) * time.Second
	}
	callTimeout := time.Duration(0)
	if c.DriverCallTimeoutMillis > 0 {
		if c.DriverCallTimeoutMillis > uint64(maxTaskEscrowCallTimeout/time.Millisecond) {
			_ = publisher.Close()
			return nil, errors.New("Task Escrow driver timeout is outside bounds")
		}
		callTimeout = time.Duration(c.DriverCallTimeoutMillis) * time.Millisecond
	}
	actionLifetime := time.Duration(0)
	if c.ActionLifetimeSeconds > 0 {
		if c.ActionLifetimeSeconds > uint64(maxTaskEscrowActionLifetime/time.Second) {
			_ = publisher.Close()
			return nil, errors.New("Task Escrow action lifetime is outside bounds")
		}
		actionLifetime = time.Duration(c.ActionLifetimeSeconds) * time.Second
	}
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: runtime, Publisher: publisher, Network: c.Chain.Network,
		AllowedCodeHashes: append([]string(nil), c.AllowedTaskEscrowCodeHashes...),
		Verifier:          c.VerifierAddress, FundingOverhead: c.FundingOverheadNanoTOS,
		ReviewPeriod: reviewPeriod, CallTimeout: callTimeout,
		ActionLifetime: actionLifetime,
	})
	if err != nil {
		_ = publisher.Close()
		return nil, err
	}
	return driver, nil
}
