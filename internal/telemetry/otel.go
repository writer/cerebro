package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const defaultOTELProtocol = "http/protobuf"

type OpenTelemetryOptions struct {
	Enabled         bool
	ServiceName     string
	ServiceVersion  string
	Protocol        string
	Endpoint        string
	TracesEndpoint  string
	MetricsEndpoint string
	Headers         map[string]string
	Insecure        bool
	TraceSampleRate float64
	MetricInterval  time.Duration
}

type ShutdownFunc func(context.Context) error

func ConfigureOpenTelemetry(ctx context.Context, options OpenTelemetryOptions) (ShutdownFunc, error) {
	if !options.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	if options.Protocol == "" {
		options.Protocol = defaultOTELProtocol
	}
	if options.MetricInterval <= 0 {
		options.MetricInterval = time.Minute
	}
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(resourceAttributes(options)...),
	)
	if err != nil {
		return nil, fmt.Errorf("build OTEL resource: %w", err)
	}
	traceExporter, err := newTraceExporter(ctx, options)
	if err != nil {
		return nil, err
	}
	metricExporter, err := newMetricExporter(ctx, options)
	if err != nil {
		return nil, err
	}
	traceProvider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(options.TraceSampleRate))),
		sdktrace.WithBatcher(traceExporter),
	)
	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(metricExporter, metric.WithInterval(options.MetricInterval))),
	)
	otel.SetTracerProvider(traceProvider)
	otel.SetMeterProvider(meterProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return func(ctx context.Context) error {
		return errors.Join(meterProvider.Shutdown(ctx), traceProvider.Shutdown(ctx))
	}, nil
}

func resourceAttributes(options OpenTelemetryOptions) []attribute.KeyValue {
	var attrs []attribute.KeyValue
	if serviceName := strings.TrimSpace(options.ServiceName); serviceName != "" {
		attrs = append(attrs, attribute.String("service.name", serviceName))
	}
	if version := strings.TrimSpace(options.ServiceVersion); version != "" {
		attrs = append(attrs, attribute.String("service.version", version))
	}
	return attrs
}

func newTraceExporter(ctx context.Context, options OpenTelemetryOptions) (sdktrace.SpanExporter, error) {
	switch options.Protocol {
	case "grpc":
		exporter, err := otlptracegrpc.New(ctx, traceGRPCOptions(options)...)
		if err != nil {
			return nil, fmt.Errorf("create OTEL trace gRPC exporter: %w", err)
		}
		return exporter, nil
	case "http/protobuf":
		exporter, err := otlptracehttp.New(ctx, traceHTTPOptions(options)...)
		if err != nil {
			return nil, fmt.Errorf("create OTEL trace HTTP exporter: %w", err)
		}
		return exporter, nil
	default:
		return nil, fmt.Errorf("unsupported OTEL protocol %q", options.Protocol)
	}
}

func newMetricExporter(ctx context.Context, options OpenTelemetryOptions) (metric.Exporter, error) {
	switch options.Protocol {
	case "grpc":
		exporter, err := otlpmetricgrpc.New(ctx, metricGRPCOptions(options)...)
		if err != nil {
			return nil, fmt.Errorf("create OTEL metric gRPC exporter: %w", err)
		}
		return exporter, nil
	case "http/protobuf":
		exporter, err := otlpmetrichttp.New(ctx, metricHTTPOptions(options)...)
		if err != nil {
			return nil, fmt.Errorf("create OTEL metric HTTP exporter: %w", err)
		}
		return exporter, nil
	default:
		return nil, fmt.Errorf("unsupported OTEL protocol %q", options.Protocol)
	}
}

func traceHTTPOptions(options OpenTelemetryOptions) []otlptracehttp.Option {
	var opts []otlptracehttp.Option
	if endpoint := firstNonEmpty(options.TracesEndpoint, options.Endpoint); endpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpointURL(endpoint))
	}
	if options.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(options.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(options.Headers))
	}
	return opts
}

func traceGRPCOptions(options OpenTelemetryOptions) []otlptracegrpc.Option {
	var opts []otlptracegrpc.Option
	if endpoint := firstNonEmpty(options.TracesEndpoint, options.Endpoint); endpoint != "" {
		opts = append(opts, otlptracegrpc.WithEndpointURL(endpoint))
	}
	if options.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if len(options.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(options.Headers))
	}
	return opts
}

func metricHTTPOptions(options OpenTelemetryOptions) []otlpmetrichttp.Option {
	var opts []otlpmetrichttp.Option
	if endpoint := firstNonEmpty(options.MetricsEndpoint, options.Endpoint); endpoint != "" {
		opts = append(opts, otlpmetrichttp.WithEndpointURL(endpoint))
	}
	if options.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(options.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(options.Headers))
	}
	return opts
}

func metricGRPCOptions(options OpenTelemetryOptions) []otlpmetricgrpc.Option {
	var opts []otlpmetricgrpc.Option
	if endpoint := firstNonEmpty(options.MetricsEndpoint, options.Endpoint); endpoint != "" {
		opts = append(opts, otlpmetricgrpc.WithEndpointURL(endpoint))
	}
	if options.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if len(options.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(options.Headers))
	}
	return opts
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
