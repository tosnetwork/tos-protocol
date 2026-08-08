package atosrpc

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const (
	ChainAuthorityStartupConfigVersion = "1"
	MaxChainAuthorityConfigBytes       = int64(128 << 10)
)

// ChainAuthorityStartupConfig is a strict, operator-owned configuration for
// the finalized TOS commitment Authority. It contains no wallet seed or
// private key. Transaction signing/submission remains in the configured
// private Unix-socket publisher.
type ChainAuthorityStartupConfig struct {
	Version                    string                 `json:"version"`
	Chain                      toschain.StartupConfig `json:"chain"`
	ServiceAddress             string                 `json:"serviceAddress"`
	ServiceID                  string                 `json:"serviceId"`
	MinimumMasterSeqno         uint64                 `json:"minimumMasterSeqno,omitempty"`
	PublisherSocket            string                 `json:"publisherSocket"`
	PublisherTimeoutMillis     uint64                 `json:"publisherTimeoutMillis,omitempty"`
	PublisherMaxMessageBytes   int                    `json:"publisherMaxMessageBytes,omitempty"`
	PublisherMaxConcurrent     int                    `json:"publisherMaxConcurrent,omitempty"`
	AnchorPayer                string                 `json:"anchorPayer"`
	AnchorPayee                string                 `json:"anchorPayee"`
	AnchorAmountNanoTOS        uint64                 `json:"anchorAmountNanoTOS"`
	AuthorityCallTimeoutMillis uint64                 `json:"authorityCallTimeoutMillis,omitempty"`
	AnchorLifetimeSeconds      uint64                 `json:"anchorLifetimeSeconds,omitempty"`
}

func DecodeChainAuthorityStartupConfigJSON(
	data []byte,
) (ChainAuthorityStartupConfig, error) {
	var config ChainAuthorityStartupConfig
	if err := jsonstrict.Decode(data, &config); err != nil {
		return ChainAuthorityStartupConfig{}, errors.New("invalid chain Authority startup config JSON")
	}
	return config, nil
}

func (c ChainAuthorityStartupConfig) Build() (Authority, error) {
	if c.Version != ChainAuthorityStartupConfigVersion {
		return nil, errors.New("unsupported chain Authority startup config version")
	}
	runtime, err := c.Chain.BuildRuntime()
	if err != nil {
		return nil, err
	}
	publisherConfig := localrpc.DefaultChainActionPublisherClientConfig(
		c.PublisherSocket, c.Chain.Network,
	)
	if c.PublisherTimeoutMillis > 0 {
		if c.PublisherTimeoutMillis > uint64((2*time.Minute)/time.Millisecond) {
			return nil, errors.New("chain Authority publisher timeout is outside bounds")
		}
		publisherConfig.Timeout = time.Duration(c.PublisherTimeoutMillis) * time.Millisecond
	}
	if c.PublisherMaxMessageBytes != 0 {
		publisherConfig.MaxMessageBytes = c.PublisherMaxMessageBytes
	}
	if c.PublisherMaxConcurrent != 0 {
		publisherConfig.MaxConcurrent = c.PublisherMaxConcurrent
	}
	publisher, err := localrpc.NewChainActionPublisherClient(publisherConfig)
	if err != nil {
		return nil, err
	}
	callTimeout := time.Duration(0)
	if c.AuthorityCallTimeoutMillis > 0 {
		if c.AuthorityCallTimeoutMillis > uint64(maxChainAuthorityCallTimeout/time.Millisecond) {
			_ = publisher.Close()
			return nil, errors.New("chain Authority call timeout is outside bounds")
		}
		callTimeout = time.Duration(c.AuthorityCallTimeoutMillis) * time.Millisecond
	}
	anchorLifetime := time.Duration(0)
	if c.AnchorLifetimeSeconds > 0 {
		if c.AnchorLifetimeSeconds > uint64(maxChainAnchorLifetime/time.Second) {
			_ = publisher.Close()
			return nil, errors.New("chain Authority anchor lifetime is outside bounds")
		}
		anchorLifetime = time.Duration(c.AnchorLifetimeSeconds) * time.Second
	}
	authority, err := NewChainAuthority(ChainAuthorityConfig{
		Runtime: runtime,
		ServiceReference: authorization.Reference{
			Network: c.Chain.Network, Address: c.ServiceAddress,
			ServiceID: c.ServiceID, MinimumMasterSeqno: c.MinimumMasterSeqno,
		},
		Publisher:   publisher,
		AnchorPayer: c.AnchorPayer, AnchorPayee: c.AnchorPayee,
		AnchorAmountNano: c.AnchorAmountNanoTOS,
		CallTimeout:      callTimeout, AnchorLifetime: anchorLifetime,
	})
	if err != nil {
		_ = publisher.Close()
		return nil, err
	}
	return authority, nil
}
