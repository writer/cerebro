package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

func New(cfg config.Config) (*http.Client, error) {
	transport := &http.Transport{}
	if cfg.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: cfg.TLSMinVersion}
	} else {
		transport.TLSClientConfig = &tls.Config{MinVersion: cfg.TLSMinVersion}
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, nil
}

func Send(ctx context.Context, httpClient *http.Client, cfg config.Config, telemetry *types.HostTelemetry) error {
	payload, err := json.Marshal(telemetry)
	if err != nil {
		return fmt.Errorf("marshal telemetry: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/telemetry/host", cfg.APIBaseURL), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
