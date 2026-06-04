package bootstrap

import (
	"bytes"
	"context"
	"net/http"
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

func (d *stdHTTPDoer) Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
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
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxHTTPDoerResponseBytes)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}
