package providers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEntraSyncOAuth2PermissionGrants_UsesV1SupportedSelectFields(t *testing.T) {
	t.Parallel()

	provider := NewEntraIDProvider()
	provider.accessToken = "token"
	provider.tokenExpiry = time.Now().Add(time.Hour)

	var requestedPath string
	provider.client = &http.Client{Transport: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requestedPath = req.URL.RequestURI()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"value": [
					{
						"id": "grant-1",
						"clientId": "sp-client-1",
						"consentType": "AllPrincipals",
						"principalId": null,
						"resourceId": "sp-resource-1",
						"scope": "User.Read"
					}
				]
			}`)),
		}, nil
	})}

	result, err := provider.syncOAuth2PermissionGrants(context.Background())
	if err != nil {
		t.Fatalf("syncOAuth2PermissionGrants returned error: %v", err)
	}
	if result.Rows != 1 {
		t.Fatalf("expected one delegated grant row, got %d", result.Rows)
	}
	if strings.Contains(requestedPath, "startTime") || strings.Contains(requestedPath, "expiryTime") {
		t.Fatalf("expected v1.0 grant sync query to avoid beta-only fields, got %q", requestedPath)
	}
}
