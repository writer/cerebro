package bootstrap

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/graphagent"
)

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
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}
