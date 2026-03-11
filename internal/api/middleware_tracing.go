package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracingMiddleware emits OpenTelemetry server spans for incoming HTTP requests.
func TracingMiddleware(next http.Handler) http.Handler {
	tracer := telemetry.Tracer("cerebro.api")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := r
		ctx, span := tracer.Start(req.Context(),
			fmt.Sprintf("%s %s", req.Method, normalizePath(req.URL.Path)),
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.method", req.Method),
				attribute.String("url.path", req.URL.Path),
			),
		)
		if traceparent := strings.TrimSpace(req.Header.Get("traceparent")); traceparent != "" {
			ctx = context.WithValue(ctx, contextKeyTraceparent, traceparent)
			span.SetAttributes(attribute.String("traceparent", traceparent))
		}
		defer span.End()

		req = req.WithContext(ctx)
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, req)

		route := metricPath(req)
		span.SetName(fmt.Sprintf("%s %s", req.Method, route))
		span.SetAttributes(
			attribute.String("http.route", route),
			attribute.Int("http.status_code", wrapped.statusCode),
			attribute.String("http.status_text", http.StatusText(wrapped.statusCode)),
		)
		if wrapped.statusCode >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(wrapped.statusCode))
		}
	})
}
