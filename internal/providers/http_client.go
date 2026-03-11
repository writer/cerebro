package providers

import (
	"net"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/telemetry"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var sharedProviderTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          200,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var tracedProviderTransport = otelhttp.NewTransport(sharedProviderTransport)

func newProviderHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	transport := http.RoundTripper(sharedProviderTransport)
	if telemetry.Enabled() {
		transport = tracedProviderTransport
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
