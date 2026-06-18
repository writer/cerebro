package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/internal/vulndb"
)

type vulndbFeedOptions struct {
	allowLoopback bool
}

// OpenVulnDBFeed fetches a remote vulnerability feed with Cerebro's feed transport policy.
func OpenVulnDBFeed(ctx context.Context, rawURL string, allowInsecureHTTP bool) (io.ReadCloser, error) {
	return openVulnDBFeed(ctx, rawURL, allowInsecureHTTP, vulndbFeedOptions{})
}

func openVulnDBFeed(ctx context.Context, rawURL string, allowInsecureHTTP bool, options vulndbFeedOptions) (io.ReadCloser, error) {
	if err := vulndb.ValidateFeedURL(rawURL, allowInsecureHTTP); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	initialScheme := strings.ToLower(request.URL.Scheme)
	client := &http.Client{
		Transport: vulndbFeedTransport(options),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if initialScheme == "https" && strings.EqualFold(req.URL.Scheme, "http") {
				return fmt.Errorf("refusing vulnerability feed redirect from https to http")
			}
			return vulndb.ValidateFeedURL(req.URL.String(), allowInsecureHTTP)
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		return nil, fmt.Errorf("fetch vulnerability feed: %s", response.Status)
	}
	return response.Body, nil
}

func vulndbFeedTransport(options vulndbFeedOptions) http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return sourcehttp.SafeRoundTripper{
			Base:          http.DefaultTransport,
			SourceID:      "vulndb",
			AllowLoopback: options.allowLoopback,
		}
	}
	clone := transport.Clone()
	clone.ResponseHeaderTimeout = 30 * time.Second
	return sourcehttp.SafeRoundTripper{
		Base:          clone,
		SourceID:      "vulndb",
		AllowLoopback: options.allowLoopback,
	}
}
