// Package vulnfetch performs the outbound GET requests that vulnerability
// pull profiles make, using the shared Source CDK HTTP safety controls
// (public-address dialing, bounded bodies, and retry).
package vulnfetch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/writer/cerebro/internal/sourcehttp"
)

// Options configures one fetcher.
type Options struct {
	SourceID      string
	Timeout       time.Duration
	MaxBodyBytes  int
	AllowLoopback bool
}

// Fetcher issues bounded GET requests through one pooled client.
type Fetcher struct {
	client       *http.Client
	maxBodyBytes int
}

// New builds a fetcher.
func New(options Options) *Fetcher {
	return &Fetcher{
		client: sourcehttp.NewClient(sourcehttp.ClientOptions{
			SourceID:      options.SourceID,
			Timeout:       options.Timeout,
			AllowLoopback: options.AllowLoopback,
		}),
		maxBodyBytes: options.MaxBodyBytes,
	}
}

// Get fetches endpoint, sending header: value when value is set, and returns
// the body and content type of a 2xx response.
func (f *Fetcher) Get(ctx context.Context, endpoint string, header string, value string) ([]byte, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Accept", "application/json")
	if value != "" {
		request.Header.Set(header, value)
	}
	response, err := sourcehttp.DoWithRetry(ctx, f.client, request, sourcehttp.RetryOptions{MaxBodyBytes: f.maxBodyBytes})
	if err != nil {
		return nil, "", fmt.Errorf("fetch %s: %w", redactedEndpoint(endpoint), err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, "", fmt.Errorf("fetch %s: unexpected status %d", redactedEndpoint(endpoint), response.StatusCode)
	}
	return response.Body, response.Header.Get("Content-Type"), nil
}

// redactedEndpoint drops the query and user info, which can carry tokens.
func redactedEndpoint(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "endpoint"
	}
	parsed.RawQuery, parsed.User = "", nil
	return parsed.String()
}
