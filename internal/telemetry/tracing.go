package telemetry

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

type Config struct {
	Enabled       bool
	ServiceName   string
	OTLPEndpoint  string
	OTLPInsecure  bool
	OTLPHeaders   map[string]string
	SampleRatio   float64
	ExportTimeout time.Duration
}

var enabled atomic.Bool

func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if !cfg.Enabled {
		enabled.Store(false)
		return func(context.Context) error { return nil }, nil
	}

	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "cerebro"
	}

	ratio := cfg.SampleRatio
	if ratio <= 0 || ratio > 1 {
		ratio = 1
	}

	options := make([]otlptracehttp.Option, 0, 4)
	if endpoint := strings.TrimSpace(cfg.OTLPEndpoint); endpoint != "" {
		options = append(options, otlptracehttp.WithEndpoint(endpoint))
	}
	if cfg.OTLPInsecure {
		options = append(options, otlptracehttp.WithInsecure())
	}
	if len(cfg.OTLPHeaders) > 0 {
		options = append(options, otlptracehttp.WithHeaders(cfg.OTLPHeaders))
	}
	if cfg.ExportTimeout > 0 {
		options = append(options, otlptracehttp.WithTimeout(cfg.ExportTimeout))
	}

	exporter, err := otlptracehttp.New(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("initialize otlp trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithContainer(),
		resource.WithHost(),
		resource.WithAttributes(semconv.ServiceNameKey.String(serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize otel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	enabled.Store(true)

	return tp.Shutdown, nil
}

func Enabled() bool {
	return enabled.Load()
}

func Tracer(instrumentationName string) trace.Tracer {
	return otel.Tracer(instrumentationName)
}
