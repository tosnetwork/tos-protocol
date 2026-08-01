package toschain

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
)

const (
	StartupConfigVersion  = "1"
	MaxStartupConfigBytes = int64(64 << 10)
)

// StartupConfig is the strict JSON operator surface for tos-edge. Durations
// use explicit integer units so configuration never depends on Go's internal
// time.Duration nanosecond representation.
type StartupConfig struct {
	Version                         string   `json:"version"`
	Network                         string   `json:"network"`
	Endpoints                       []string `json:"endpoints"`
	Quorum                          int      `json:"quorum"`
	QueryTimeoutMillis              uint64   `json:"queryTimeoutMillis,omitempty"`
	MaxResponseBytes                int64    `json:"maxResponseBytes,omitempty"`
	ClientKeyLeaseSeconds           uint64   `json:"clientKeyLeaseSeconds,omitempty"`
	ReadinessMaxAgeSeconds          uint64   `json:"readinessMaxAgeSeconds,omitempty"`
	AllowedServiceCodeHashes        []string `json:"allowedServiceCodeHashes"`
	PaymentQueryTimeoutMillis       uint64   `json:"paymentQueryTimeoutMillis,omitempty"`
	PaymentMaxObservationAgeSeconds uint64   `json:"paymentMaxObservationAgeSeconds,omitempty"`
	AllowOverpayment                bool     `json:"allowOverpayment,omitempty"`
}

// DecodeStartupConfigJSON strictly decodes an operator-owned chain runtime
// document. Duplicate and unknown fields are rejected before any endpoint is
// contacted; BuildRuntime remains the single semantic-policy validator.
func DecodeStartupConfigJSON(data []byte) (StartupConfig, error) {
	var config StartupConfig
	if err := jsonstrict.Decode(data, &config); err != nil {
		return StartupConfig{}, errors.New("invalid TOS chain startup config JSON")
	}
	return config, nil
}

// BuildRuntime validates all startup bounds and creates one shared
// strict-majority adapter for authority, client-key and payment decisions.
func (c StartupConfig) BuildRuntime() (*Runtime, error) {
	if c.Version != StartupConfigVersion {
		return nil, errors.New("unsupported TOS chain startup config version")
	}
	queryTimeout, err := configuredDuration(
		c.QueryTimeoutMillis, time.Millisecond,
		DefaultQueryTimeout, maxQueryTimeout,
	)
	if err != nil {
		return nil, err
	}
	clientKeyLease, err := configuredDuration(
		c.ClientKeyLeaseSeconds, time.Second,
		DefaultClientKeyLease, maxClientKeyLease,
	)
	if err != nil {
		return nil, err
	}
	readinessAge, err := configuredDuration(
		c.ReadinessMaxAgeSeconds, time.Second,
		DefaultReadinessMaxAge, maxReadinessAge,
	)
	if err != nil {
		return nil, err
	}
	paymentQueryTimeout, err := configuredDuration(
		c.PaymentQueryTimeoutMillis, time.Millisecond,
		payment.DefaultQueryTimeout, time.Minute,
	)
	if err != nil {
		return nil, err
	}
	paymentObservationAge, err := configuredDuration(
		c.PaymentMaxObservationAgeSeconds, time.Second,
		payment.DefaultMaxObservationAge, time.Hour,
	)
	if err != nil {
		return nil, err
	}
	paymentPolicy := payment.DefaultPolicy()
	paymentPolicy.QueryTimeout = paymentQueryTimeout
	paymentPolicy.MaxObservationAge = paymentObservationAge
	paymentPolicy.AllowOverpayment = c.AllowOverpayment
	return NewRuntime(
		Config{
			Network: c.Network, Endpoints: append([]string(nil), c.Endpoints...),
			Quorum: c.Quorum, QueryTimeout: queryTimeout,
			MaxResponseBytes: c.MaxResponseBytes,
			ClientKeyLease:   clientKeyLease, ReadinessMaxAge: readinessAge,
		},
		append([]string(nil), c.AllowedServiceCodeHashes...),
		paymentPolicy,
	)
}

func configuredDuration(
	value uint64,
	unit time.Duration,
	fallback time.Duration,
	maximum time.Duration,
) (time.Duration, error) {
	if value == 0 {
		return fallback, nil
	}
	if unit <= 0 || value > uint64(maximum/unit) {
		return 0, errors.New("TOS chain startup duration is outside bounds")
	}
	return time.Duration(value) * unit, nil
}
