package functionscan

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/webhooks"
)

var artifactURLValidator = webhooks.ValidateWebhookURL
var artifactDialTargetValidator = validateArtifactDialTarget

const maxArtifactRedirects = 10

func openHTTPArtifact(ctx context.Context, client *http.Client, rawURL string) (io.ReadCloser, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("artifact download url is empty")
	}
	if err := artifactURLValidator(rawURL); err != nil {
		return nil, fmt.Errorf("validate artifact download url: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	cloned := *client
	transport := cloneArtifactTransport(cloned.Transport)
	baseDialContext := transport.DialContext
	if baseDialContext == nil {
		dialer := &net.Dialer{}
		baseDialContext = dialer.DialContext
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if err := artifactDialTargetValidator(host); err != nil {
			return nil, err
		}
		return baseDialContext(ctx, network, addr)
	}
	cloned.Transport = transport
	existingRedirectPolicy := cloned.CheckRedirect
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxArtifactRedirects {
			return fmt.Errorf("stopped after %d redirects", maxArtifactRedirects)
		}
		if err := artifactURLValidator(req.URL.String()); err != nil {
			return err
		}
		if existingRedirectPolicy != nil {
			return existingRedirectPolicy(req, via)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cloned.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s", operatorSafeErrorMessage(err))
	}
	if resp.StatusCode >= 400 {
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		return nil, fmt.Errorf("artifact download failed %d: %s", resp.StatusCode, sanitizeEmbeddedURL(strings.TrimSpace(string(body))))
	}
	return resp.Body, nil
}

func cloneArtifactTransport(base http.RoundTripper) *http.Transport {
	switch transport := base.(type) {
	case nil:
		return http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		return transport.Clone()
	default:
		return http.DefaultTransport.(*http.Transport).Clone()
	}
}

func validateArtifactDialTarget(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("artifact download hostname is empty")
	}
	dialURL := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, "443"),
	}).String()
	if err := artifactURLValidator(dialURL); err != nil {
		return fmt.Errorf("validate artifact dial target: %w", err)
	}
	return nil
}
