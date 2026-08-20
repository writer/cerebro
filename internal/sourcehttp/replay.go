package sourcehttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ValidateReplayRequest binds a replay server handler to the exact method,
// path, and canonical query issued by the production source transport.
func ValidateReplayRequest(request *http.Request, method, requestPath, rawQuery string) error {
	if request == nil || request.URL == nil {
		return errors.New("replay HTTP request is required")
	}
	if got, want := strings.ToUpper(strings.TrimSpace(request.Method)), strings.ToUpper(strings.TrimSpace(method)); got == "" || got != want {
		return fmt.Errorf("replay HTTP method = %q, want %q", got, want)
	}
	if got, want := request.URL.EscapedPath(), strings.TrimSpace(requestPath); got != want {
		return fmt.Errorf("replay HTTP path = %q, want %q", got, want)
	}
	actualQuery, err := canonicalReplayQuery(request.URL.RawQuery)
	if err != nil {
		return fmt.Errorf("replay HTTP query is invalid: %w", err)
	}
	expectedQuery, err := canonicalReplayQuery(strings.TrimSpace(rawQuery))
	if err != nil {
		return fmt.Errorf("expected replay HTTP query is invalid: %w", err)
	}
	if actualQuery != expectedQuery {
		return fmt.Errorf("replay HTTP query = %q, want %q", actualQuery, expectedQuery)
	}
	return nil
}

func canonicalReplayQuery(rawQuery string) (string, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	return values.Encode(), nil
}
