package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

// Service wraps HTTP interactions with the Cerebro API. It centralises TLS
// configuration, headers, and request construction so collectors can focus on
// payload generation.
type Service struct {
	client    *http.Client
	cfg       config.Config
	backoffFn func(context.Context, int) error
}

const (
	maxRetryAttempts    = 3
	initialRetryBackoff = 200 * time.Millisecond
)

// New constructs a Service with a hardened HTTP client. TLS settings are
// derived from the agent configuration, including optional insecure mode for
// local development.
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
		cfg:       cfg,
		backoffFn: defaultBackoff,
	}, nil
}

// SendSnapshot transports the host snapshot payload to the Cerebro ingest API.
// The method short-circuits when the payload is nil, allowing callers to skip
// allocations when no data was collected.
func (s *Service) SendSnapshot(ctx context.Context, telemetry *types.HostTelemetry) error {
	if telemetry == nil {
		return nil
	}
	payload, err := json.Marshal(telemetry)
	if err != nil {
		return fmt.Errorf("marshal telemetry: %w", err)
	}

	url := fmt.Sprintf("%s/telemetry/host", s.cfg.APIBaseURL)
	resp, err := s.doWithRetry(ctx, http.MethodPost, url, payload, func(req *http.Request) {
		s.decorate(req)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// SendEvents uploads a batch of host events. Empty batches are ignored to save
// unnecessary network round-trips.
func (s *Service) SendEvents(ctx context.Context, batch types.HostEventBatch) error {
	if len(batch.Events) == 0 {
		return nil
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	url := fmt.Sprintf("%s/telemetry/host/events", s.cfg.APIBaseURL)
	resp, err := s.doWithRetry(ctx, http.MethodPost, url, payload, func(req *http.Request) {
		s.decorate(req)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// decorate attaches shared headers (content type, bearer token) to outbound
// requests.
func (s *Service) decorate(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.APIToken)
	}
}

// FetchArtifactPacks queries the control plane for artifact packs that match
// the host identity and tag selectors. It returns nil when no packs are
// available.
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

	resp, err := s.doWithRetry(ctx, http.MethodGet, parsed.String(), nil, func(req *http.Request) {
		s.decorate(req)
		req.Header.Del("Content-Type")
	})
	if err != nil {
		return nil, fmt.Errorf("fetch packs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	var payload []types.ArtifactPackDefinition
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode pack response: %w", err)
	}
	return payload, nil
}

func (s *Service) doWithRetry(ctx context.Context, method, url string, body []byte, mutate func(*http.Request)) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		var reader io.Reader
		if len(body) > 0 {
			reader = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}

		if mutate != nil {
			mutate(req)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("send request: %w", err)
		} else {
			status := resp.StatusCode
			if status >= 400 {
				if shouldRetryStatus(status) && attempt < maxRetryAttempts-1 {
					drainAndClose(resp.Body)
					lastErr = fmt.Errorf("request failed: status %d", status)
					if err := s.backoff(ctx, attempt); err != nil {
						return nil, err
					}
					continue
				}
				bodyErr := readBodyMessage(resp.Body)
				resp.Body.Close()
				if bodyErr != "" {
					return nil, fmt.Errorf("request failed: status %d: %s", status, bodyErr)
				}
				return nil, fmt.Errorf("request failed: status %d", status)
			}
			return resp, nil
		}

		if attempt == maxRetryAttempts-1 {
			break
		}
		if err := s.backoff(ctx, attempt); err != nil {
			return nil, err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("request failed after %d attempts", maxRetryAttempts)
}

func (s *Service) backoff(ctx context.Context, attempt int) error {
	if s.backoffFn != nil {
		return s.backoffFn(ctx, attempt)
	}
	return defaultBackoff(ctx, attempt)
}

func defaultBackoff(ctx context.Context, attempt int) error {
	delay := initialRetryBackoff * (1 << attempt)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func shouldRetryStatus(status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= http.StatusInternalServerError
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	io.Copy(io.Discard, body)
	body.Close()
}

func readBodyMessage(body io.ReadCloser) string {
	if body == nil {
		return ""
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, 4<<10))
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}
