package otel

import (
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// NewHTTPClient returns an http.Client with OTel tracing instrumentation.
// When OTel is not initialized (no-op TracerProvider), the transport
// passes through to http.DefaultTransport with negligible overhead.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}
