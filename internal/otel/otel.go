package otel

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.28.0"
)

// Config holds OTel configuration, typically populated from environment variables.
type Config struct {
	Enabled     bool
	Endpoint    string // host:port (no scheme)
	ServiceName string
	Version     string
	Environment string
}

// ConfigFromEnv reads OTel configuration from standard environment variables.
func ConfigFromEnv(version string) Config {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:4318"
	}

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "legion-auth"
	}

	env := os.Getenv("DEPLOYMENT_ENVIRONMENT")
	if env == "" {
		env = "production"
	}

	return Config{
		Enabled:     strings.ToLower(os.Getenv("PG_OTEL_ENABLED")) == "true",
		Endpoint:    endpoint,
		ServiceName: serviceName,
		Version:     version,
		Environment: env,
	}
}

// Providers holds initialized OTel SDK providers for lifecycle management.
type Providers struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
}

// Shutdown flushes and shuts down all providers.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var errs []error
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("meter provider shutdown: %w", err))
		}
	}
	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("tracer provider shutdown: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Meter returns the MeterProvider, or a no-op provider if uninitialized.
func (p *Providers) Meter() *sdkmetric.MeterProvider {
	if p != nil && p.meterProvider != nil {
		return p.meterProvider
	}
	return sdkmetric.NewMeterProvider() // no-op (no readers)
}

// parseEndpoint extracts host:port from an endpoint that may include a scheme.
func parseEndpoint(raw string) string {
	if !strings.Contains(raw, "://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

// isInsecure returns true if the endpoint uses http (not https).
func isInsecure(raw string) bool {
	return strings.HasPrefix(raw, "http://") || !strings.Contains(raw, "://")
}

// Init initializes OTel tracing and metrics providers.
// If cfg.Enabled is false, returns a no-op Providers (safe to call Shutdown on).
func Init(ctx context.Context, cfg Config) (*Providers, error) {
	if !cfg.Enabled {
		return &Providers{}, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.Version),
			semconv.DeploymentEnvironmentName(cfg.Environment),
		),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating resource: %w", err)
	}

	endpoint := parseEndpoint(cfg.Endpoint)
	insecure := isInsecure(cfg.Endpoint)

	// Tracer provider
	traceOpts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if insecure {
		traceOpts = append(traceOpts, otlptracehttp.WithInsecure())
	}
	traceExporter, err := otlptracehttp.New(ctx, traceOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Meter provider
	metricOpts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(endpoint)}
	if insecure {
		metricOpts = append(metricOpts, otlpmetrichttp.WithInsecure())
	}
	metricExporter, err := otlpmetrichttp.New(ctx, metricOpts...)
	if err != nil {
		_ = tp.Shutdown(ctx)
		return nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter,
			sdkmetric.WithInterval(15*time.Second),
		)),
	)
	otel.SetMeterProvider(mp)

	return &Providers{
		tracerProvider: tp,
		meterProvider:  mp,
	}, nil
}
