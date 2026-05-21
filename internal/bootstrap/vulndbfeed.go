package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/vulndb"
)

// OpenVulnDBFeed fetches a remote vulnerability feed with Cerebro's feed transport policy.
func OpenVulnDBFeed(ctx context.Context, rawURL string, allowInsecureHTTP bool) (io.ReadCloser, error) {
	if err := vulndb.ValidateFeedURL(rawURL, allowInsecureHTTP); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
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
