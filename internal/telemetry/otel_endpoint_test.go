package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

func TestHTTPSignalEndpointAppendsSignalPathToBaseEndpoint(t *testing.T) {
	cases := []struct {
		name   string
		signal string
		base   string
		want   string
	}{
		{name: "base without path", base: "http://127.0.0.1:4318", want: "http://127.0.0.1:4318/v1/metrics"},
		{name: "base with trailing slash", base: "http://127.0.0.1:4318/", want: "http://127.0.0.1:4318/v1/metrics"},
		{name: "base with prefix path", base: "https://collector.example/otlp", want: "https://collector.example/otlp/v1/metrics"},
		{name: "signal endpoint is used as-is", signal: "http://127.0.0.1:4318/custom", base: "http://127.0.0.1:4318", want: "http://127.0.0.1:4318/custom"},
		{name: "no endpoint", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpSignalEndpoint(tc.signal, tc.base, "/v1/metrics"); got != tc.want {
				t.Fatalf("httpSignalEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConfigureOpenTelemetryHTTPExportsToSignalPaths(t *testing.T) {
	var (
		mu    sync.Mutex
		paths = map[string]int{}
	)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path != "/v1/metrics" && r.URL.Path != "/v1/traces" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	oldTracer := otel.GetTracerProvider()
	oldMeter := otel.GetMeterProvider()
	t.Cleanup(func() {
		otel.SetTracerProvider(oldTracer)
		otel.SetMeterProvider(oldMeter)
	})

	shutdown, err := ConfigureOpenTelemetry(context.Background(), OpenTelemetryOptions{
		Enabled:         true,
		ServiceName:     "telemetry-test",
		Protocol:        "http/protobuf",
		Endpoint:        collector.URL,
		Insecure:        true,
		TraceSampleRate: 1,
		MetricInterval:  time.Hour,
	})
	if err != nil {
		t.Fatalf("ConfigureOpenTelemetry() error = %v", err)
	}
	counter, err := otel.Meter("telemetry-test").Int64Counter("telemetry.test.count")
	if err != nil {
		t.Fatalf("Int64Counter() error = %v", err)
	}
	counter.Add(context.Background(), 1)
	_, span := otel.Tracer("telemetry-test").Start(context.Background(), "telemetry.test.span")
	span.End()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if paths["/v1/metrics"] == 0 || paths["/v1/traces"] == 0 {
		t.Fatalf("collector requests by path = %v, want /v1/metrics and /v1/traces", paths)
	}
	if paths["/"] != 0 {
		t.Fatalf("collector received %d exports at /, want none", paths["/"])
	}
}
