package otel

import "testing"

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantHost string
		wantPath string
	}{
		{
			name:     "host only",
			raw:      "localhost:4318",
			wantHost: "localhost:4318",
			wantPath: "",
		},
		{
			name:     "host with path no scheme",
			raw:      "collector:4318/otlp",
			wantHost: "collector:4318",
			wantPath: "/otlp",
		},
		{
			name:     "url with scheme and path",
			raw:      "https://collector.internal:4318/custom",
			wantHost: "collector.internal:4318",
			wantPath: "/custom",
		},
		{
			name:     "invalid endpoint falls back to raw",
			raw:      "://bad-endpoint",
			wantHost: "://bad-endpoint",
			wantPath: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotHost, gotPath := parseEndpoint(tc.raw)
			if gotHost != tc.wantHost {
				t.Fatalf("host mismatch: got %q want %q", gotHost, tc.wantHost)
			}
			if gotPath != tc.wantPath {
				t.Fatalf("path mismatch: got %q want %q", gotPath, tc.wantPath)
			}
		})
	}
}

func TestOTLPSignalPath(t *testing.T) {
	tests := []struct {
		name       string
		basePath   string
		suffix     string
		wantResult string
	}{
		{
			name:       "empty path uses default signal path",
			basePath:   "",
			suffix:     "/v1/traces",
			wantResult: "/v1/traces",
		},
		{
			name:       "base path appended to traces",
			basePath:   "/otlp",
			suffix:     "/v1/traces",
			wantResult: "/otlp/v1/traces",
		},
		{
			name:       "base path appended to metrics",
			basePath:   "/otlp/",
			suffix:     "/v1/metrics",
			wantResult: "/otlp/v1/metrics",
		},
		{
			name:       "normalizes explicit traces path",
			basePath:   "/v1/traces",
			suffix:     "/v1/metrics",
			wantResult: "/v1/metrics",
		},
		{
			name:       "adds leading slash for relative path",
			basePath:   "custom",
			suffix:     "/v1/traces",
			wantResult: "/custom/v1/traces",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := otlpSignalPath(tc.basePath, tc.suffix)
			if got != tc.wantResult {
				t.Fatalf("path mismatch: got %q want %q", got, tc.wantResult)
			}
		})
	}
}
