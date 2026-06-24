// HTTP spec fetching routed through internal/sourcehttp, the repo's sanctioned
// SSRF-hardened client, so this build-time tool stays within the
// "Source CDK owns external HTTP clients" architecture boundary (no direct
// net/http usage outside the allowed packages).
package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/writer/cerebro/internal/sourcehttp"
)

const fetchSourceID = "connectorimport"

// fetcher retrieves OpenAPI specs over HTTPS using the shared safe client.
type fetcher struct {
	timeout time.Duration
}

func newFetcher(timeout time.Duration) *fetcher {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &fetcher{timeout: timeout}
}

// get fetches rawURL, following HTTPS redirects manually because the safe
// client does not auto-follow. Each hop is re-validated against the SSRF guard
// and required to stay on https.
func (f *fetcher) get(rawURL string) ([]byte, error) {
	const maxHops = 8
	current := rawURL
	for hop := 0; hop <= maxHops; hop++ {
		parsed, err := url.Parse(current)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", current, err)
		}
		if parsed.Scheme != "https" {
			return nil, fmt.Errorf("refusing non-https spec url %q", current)
		}
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
		client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: fetchSourceID, Timeout: f.timeout})
		req, err := sourcehttp.NewRequest(ctx, fetchSourceID, parsed.Scheme+"://"+parsed.Host, false, "GET", path, parsed.Query(), nil)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("build request %s: %w", current, err)
		}
		resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{MaxAttempts: 3, MaxBodyBytes: maxSpecBytes})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", current, err)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				return nil, fmt.Errorf("fetch %s: redirect without location", current)
			}
			next, err := parsed.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("resolve redirect %q: %w", location, err)
			}
			current = next.String()
			continue
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fetch %s: HTTP %d", current, resp.StatusCode)
		}
		return resp.Body, nil
	}
	return nil, fmt.Errorf("fetch %s: too many redirects", rawURL)
}
