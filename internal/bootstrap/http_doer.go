package bootstrap

import (
	"bytes"
	"context"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/internal/telemetry"
)

const maxHTTPDoerResponseBytes = 4 << 20

type stdHTTPDoer struct {
	client *http.Client
}

func NewHTTPDoer() graphagent.HTTPDoer {
	return &stdHTTPDoer{client: &http.Client{Timeout: 60 * time.Second}}
}

func (d *stdHTTPDoer) Post(ctx context.Context, endpoint string, headers map[string]string, body []byte) (int, []byte, error) {
	ctx, span := telemetry.Start(ctx, "graphagent.http.request", telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "graphagent.http_doer"},
		telemetry.Field{Key: "http.request.method", Value: http.MethodPost},
		telemetry.Field{Key: "server.address", Value: endpointHost(endpoint)},
		telemetry.Field{Key: "url.scheme", Value: endpointScheme(endpoint)},
	))
	finish := func(statusCode int, err error) {
		attrs := telemetry.Attrs(telemetry.Field{Key: "http.response.status_code", Value: statusCode})
		telemetry.IncrementMain(ctx, "outbound.http.request.count", 1)
		telemetry.AnnotateMain(ctx, telemetry.Attrs(
			telemetry.Field{Key: "outbound.http.last_component", Value: "graphagent.http_doer"},
			telemetry.Field{Key: "outbound.http.last_host", Value: endpointHost(endpoint)},
			telemetry.Field{Key: "outbound.http.last_method", Value: http.MethodPost},
			telemetry.Field{Key: "outbound.http.last_scheme", Value: endpointScheme(endpoint)},
			telemetry.Field{Key: "outbound.http.last_status_code", Value: statusCode},
		))
		if err != nil {
			telemetry.IncrementMain(ctx, "outbound.http.error.count", 1)
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
			telemetry.CaptureError(ctx, "graphagent.http.error", err, telemetry.Attrs(
				telemetry.Field{Key: "component", Value: "graphagent.http_doer"},
				telemetry.Field{Key: "operation", Value: "post"},
			))
			telemetry.End(span, "failed", attrs)
			return
		}
		if statusCode >= http.StatusInternalServerError {
			telemetry.IncrementMain(ctx, "outbound.http.server_error.count", 1)
			telemetry.End(span, "failed", attrs.WithField(telemetry.Field{Key: "status_detail", Value: "server_error"}))
			return
		}
		telemetry.IncrementMain(ctx, "outbound.http.success.count", 1)
		telemetry.End(span, "completed", attrs)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		finish(0, err)
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if traceparent := telemetry.TraceParent(ctx); traceparent != "" && req.Header.Get("Traceparent") == "" {
		req.Header.Set("Traceparent", traceparent)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		finish(0, err)
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxHTTPDoerResponseBytes)
	if err != nil {
		finish(resp.StatusCode, err)
		return resp.StatusCode, nil, err
	}
	finish(resp.StatusCode, nil)
	return resp.StatusCode, respBody, nil
}

func endpointHost(raw string) string {
	parsed, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
}

func endpointScheme(raw string) string {
	parsed, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Scheme))
}
