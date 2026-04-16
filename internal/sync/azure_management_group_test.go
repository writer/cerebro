package sync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type staticTokenCredential struct{}

func (staticTokenCredential) GetToken(context.Context, azpolicy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func rewriteAzureManagementHost(target *url.URL, base http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.URL.Scheme = target.Scheme
		clone.URL.Host = target.Host
		clone.Host = target.Host
		return base.RoundTrip(clone)
	})
}

func TestNewAzureHTTPClientConfiguresTimeout(t *testing.T) {
	client := newAzureHTTPClient()
	if client == nil {
		t.Fatal("expected Azure HTTP client")
	}
	if client.Timeout != 30*time.Second {
		t.Fatalf("timeout = %s, want %s", client.Timeout, 30*time.Second)
	}
}

func TestListManagementGroupSubscriptionsFiltersCaseInsensitively(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("expected bearer token, got %q", got)
		}
		_, _ = w.Write([]byte(`{
			"properties": {
				"children": [
					{"childType":"Subscription","id":"/subscriptions/SUB-123","name":"SUB-123"},
					{"childType":"Subscription","id":"/subscriptions/sub-456","name":"sub-456"}
				]
			}
		}`))
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	engine := &AzureSyncEngine{
		httpClient: &http.Client{
			Transport: rewriteAzureManagementHost(target, server.Client().Transport),
		},
		tokenCredential: staticTokenCredential{},
		listEnabledFunc: func(context.Context) ([]string, error) {
			return []string{"sub-123"}, nil
		},
	}

	got, err := engine.listManagementGroupSubscriptions(context.Background(), "mg-root")
	if err != nil {
		t.Fatalf("list management group subscriptions: %v", err)
	}
	if len(got) != 1 || got[0] != "SUB-123" {
		t.Fatalf("expected preserved management-group subscription match, got %#v", got)
	}
}

func TestListManagementGroupSubscriptionsChecksHTTPStatusBeforeDecode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	engine := &AzureSyncEngine{
		httpClient: &http.Client{
			Transport: rewriteAzureManagementHost(target, server.Client().Transport),
		},
		tokenCredential: staticTokenCredential{},
		listEnabledFunc: func(context.Context) ([]string, error) {
			return []string{"sub-123"}, nil
		},
	}

	_, err = engine.listManagementGroupSubscriptions(context.Background(), "mg-root")
	if err == nil {
		t.Fatal("expected status error")
	}
	if !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("expected status error, got %v", err)
	}
	if strings.Contains(err.Error(), "decode Azure management group response") {
		t.Fatalf("expected status check before decode, got %v", err)
	}
}
