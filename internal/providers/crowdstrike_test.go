package providers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrowdStrikeAuthenticateRetriesReplayableBody(t *testing.T) {
	var attempts atomic.Int32
	requestBodies := make([]string, 0, 2)
	provider := &CrowdStrikeProvider{
		BaseProvider: NewBaseProvider("crowdstrike", ProviderTypeEndpoint),
		clientID:     "client-id",
		clientSecret: "client-secret",
		baseURL:      "https://api.crowdstrike.example",
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &providerResilientTransport{
				base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					body, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					requestBodies = append(requestBodies, string(body))
					switch attempts.Add(1) {
					case 1:
						return &http.Response{
							StatusCode: http.StatusServiceUnavailable,
							Body:       io.NopCloser(strings.NewReader("retry me")),
						}, nil
					case 2:
						return &http.Response{
							StatusCode: http.StatusCreated,
							Body:       io.NopCloser(strings.NewReader(`{"access_token":"token","expires_in":300}`)),
						}, nil
					default:
						return nil, context.Canceled
					}
				}),
				options: ProviderHTTPClientOptions{
					Provider:                "crowdstrike",
					RetryAttempts:           2,
					RetryBackoff:            time.Millisecond,
					RetryMaxBackoff:         time.Millisecond,
					CircuitFailureThreshold: 5,
					CircuitOpenTimeout:      time.Minute,
				},
				circuit: newProviderCircuitBreaker("crowdstrike", 5, time.Minute),
				sleep:   func(context.Context, time.Duration) error { return nil },
			},
		},
	}

	token, err := provider.authenticate(context.Background())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if token != "token" {
		t.Fatalf("token = %q, want token", token)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	if len(requestBodies) != 2 {
		t.Fatalf("request body count = %d, want 2", len(requestBodies))
	}
	for i, body := range requestBodies {
		if body != "client_id=client-id&client_secret=client-secret" {
			t.Fatalf("request body %d = %q", i+1, body)
		}
	}
}
