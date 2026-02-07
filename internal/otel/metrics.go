package otel

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// LegionMetrics holds state for observable gauges and counters.
// State is updated by the main application; gauges are read by the OTel SDK
// at each export interval (15s) via callbacks.
type LegionMetrics struct {
	mu             sync.RWMutex
	tokenExpiry    float64 // unix timestamp
	baseURL        string
	organizationID string
	entityID       string
	serialNumber   string
	terminalType   string
	configLoaded   bool
	terminalLoaded bool

	refreshes    atomic.Int64
	refreshErrors atomic.Int64
}

// NewLegionMetrics registers observable gauges and counters on the given MeterProvider.
// Returns a LegionMetrics whose Set* methods should be called to update state.
func NewLegionMetrics(mp metric.MeterProvider) (*LegionMetrics, error) {
	m := &LegionMetrics{}
	meter := mp.Meter("legion-auth")

	// Token gauges — observable so TTL is computed fresh at each export
	if _, err := meter.Float64ObservableGauge("legion_oauth_token_expiry_seconds",
		metric.WithDescription("Unix timestamp when the OAuth access token expires"),
		metric.WithUnit("s"),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.tokenExpiry > 0 {
				o.Observe(m.tokenExpiry)
			}
			return nil
		}),
	); err != nil {
		return nil, err
	}

	if _, err := meter.Float64ObservableGauge("legion_oauth_token_ttl_seconds",
		metric.WithDescription("Seconds remaining until the OAuth access token expires"),
		metric.WithUnit("s"),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.tokenExpiry > 0 {
				ttl := m.tokenExpiry - float64(time.Now().Unix())
				if ttl < 0 {
					ttl = 0
				}
				o.Observe(ttl)
			}
			return nil
		}),
	); err != nil {
		return nil, err
	}

	if _, err := meter.Int64ObservableGauge("legion_oauth_token_valid",
		metric.WithDescription("Whether the OAuth access token is currently valid (1=valid, 0=expired)"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.tokenExpiry > 0 {
				if float64(time.Now().Unix()) < m.tokenExpiry {
					o.Observe(1)
				} else {
					o.Observe(0)
				}
			}
			return nil
		}),
	); err != nil {
		return nil, err
	}

	// Config info gauge — value 1 with labels
	if _, err := meter.Int64ObservableGauge("legion_info",
		metric.WithDescription("Legion platform configuration (labels carry metadata)"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.configLoaded {
				o.Observe(1,
					metric.WithAttributes(
						attribute.String("base_url", m.baseURL),
						attribute.String("organization_id", m.organizationID),
					),
				)
			}
			return nil
		}),
	); err != nil {
		return nil, err
	}

	// Terminal info gauge — value 1 with labels
	if _, err := meter.Int64ObservableGauge("legion_terminal_info",
		metric.WithDescription("Legion terminal entity identity (labels carry metadata)"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.terminalLoaded {
				o.Observe(1,
					metric.WithAttributes(
						attribute.String("entity_id", m.entityID),
						attribute.String("serial_number", m.serialNumber),
						attribute.String("terminal_type", m.terminalType),
					),
				)
			}
			return nil
		}),
	); err != nil {
		return nil, err
	}

	// Counters for refresh operations
	if _, err := meter.Int64ObservableCounter("legion_auth_token_refreshes_total",
		metric.WithDescription("Total successful token refreshes"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(m.refreshes.Load())
			return nil
		}),
	); err != nil {
		return nil, err
	}

	if _, err := meter.Int64ObservableCounter("legion_auth_token_refresh_errors_total",
		metric.WithDescription("Total failed token refresh attempts"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(m.refreshErrors.Load())
			return nil
		}),
	); err != nil {
		return nil, err
	}

	return m, nil
}

// SetTokenExpiry updates the cached token expiry unix timestamp.
func (m *LegionMetrics) SetTokenExpiry(expiry float64) {
	m.mu.Lock()
	m.tokenExpiry = expiry
	m.mu.Unlock()
}

// SetConfig updates the cached Legion platform config labels.
func (m *LegionMetrics) SetConfig(baseURL, organizationID string) {
	m.mu.Lock()
	m.baseURL = baseURL
	m.organizationID = organizationID
	m.configLoaded = true
	m.mu.Unlock()
}

// SetTerminal updates the cached terminal entity labels.
func (m *LegionMetrics) SetTerminal(entityID, serialNumber, terminalType string) {
	m.mu.Lock()
	m.entityID = entityID
	m.serialNumber = serialNumber
	m.terminalType = terminalType
	m.terminalLoaded = true
	m.mu.Unlock()
}

// RecordRefreshSuccess increments the successful refresh counter.
func (m *LegionMetrics) RecordRefreshSuccess() {
	m.refreshes.Add(1)
}

// RecordRefreshError increments the failed refresh counter.
func (m *LegionMetrics) RecordRefreshError() {
	m.refreshErrors.Add(1)
}
