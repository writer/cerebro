package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

type Service struct {
	client *http.Client
	cfg    config.Config
}

func New(cfg config.Config) (*Service, error) {
	transport := &http.Transport{}
	if cfg.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: cfg.TLSMinVersion}
	} else {
		transport.TLSClientConfig = &tls.Config{MinVersion: cfg.TLSMinVersion}
	}

	return &Service{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		cfg: cfg,
	}, nil
}

func (s *Service) SendSnapshot(ctx context.Context, telemetry *types.HostTelemetry) error {
	if telemetry == nil {
		return nil
	}
	payload, err := json.Marshal(telemetry)
	if err != nil {
		return fmt.Errorf("marshal telemetry: %w", err)
	}

	url := fmt.Sprintf("%s/telemetry/host", s.cfg.APIBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	s.decorate(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("snapshot request failed: status %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) SendEvents(ctx context.Context, batch types.HostEventBatch) error {
	if len(batch.Events) == 0 {
		return nil
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	url := fmt.Sprintf("%s/telemetry/host/events", s.cfg.APIBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build events request: %w", err)
	}

	s.decorate(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("events request failed: status %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) decorate(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.APIToken)
	}
}

func (s *Service) FetchArtifactPacks(ctx context.Context, hostID, hostname string, tags map[string]string) ([]types.ArtifactPackDefinition, error) {
	if hostID == "" {
		return nil, fmt.Errorf("host id required for pack retrieval")
	}
	endpoint := fmt.Sprintf("%s/telemetry/host/packs", s.cfg.APIBaseURL)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse pack endpoint: %w", err)
	}

	query := parsed.Query()
	query.Set("host_id", hostID)
	if hostname != "" {
		query.Set("hostname", hostname)
	}
	if s.cfg.Organization != "" {
		query.Set("organization", s.cfg.Organization)
	}
	if s.cfg.Site != "" {
		query.Set("site", s.cfg.Site)
	}
	for k, v := range tags {
		if k == "" || v == "" {
			continue
		}
		query.Add("tag", fmt.Sprintf("%s=%s", k, v))
	}
	parsed.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build pack request: %w", err)
	}

	s.decorate(req)
	req.Header.Del("Content-Type")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch packs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("pack request failed: status %d", resp.StatusCode)
	}

	var payload []types.ArtifactPackDefinition
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode pack response: %w", err)
	}
	return payload, nil
}
