package cli

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	apiclient "github.com/evalops/cerebro/internal/client"
)

func TestLoadCLIExecutionMode(t *testing.T) {
	t.Setenv(envCLIExecutionMode, "")
	mode, err := loadCLIExecutionMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != cliExecutionModeAuto {
		t.Fatalf("expected default mode auto, got %s", mode)
	}

	t.Setenv(envCLIExecutionMode, "api")
	mode, err = loadCLIExecutionMode()
	if err != nil {
		t.Fatalf("unexpected error for api mode: %v", err)
	}
	if mode != cliExecutionModeAPI {
		t.Fatalf("expected api mode, got %s", mode)
	}

	t.Setenv(envCLIExecutionMode, "invalid")
	if _, err := loadCLIExecutionMode(); err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestResolveCLIAPIClientConfig_DefaultsAndAPIKeyFallback(t *testing.T) {
	t.Setenv(envCLIAPIURL, "")
	t.Setenv(envAPIPort, "9191")
	t.Setenv(envCLIAPIKey, "")
	t.Setenv(envLegacyAPIKey, "")
	t.Setenv(envAPIKeys, "key-one:svc-one,key-two:svc-two")
	t.Setenv(envCLIAPITimeout, "")

	cfg, err := resolveCLIAPIClientConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseURL != "http://127.0.0.1:9191" {
		t.Fatalf("unexpected default base URL: %s", cfg.BaseURL)
	}
	if cfg.APIKey != "key-one" {
		t.Fatalf("expected first API key fallback, got %q", cfg.APIKey)
	}
	if cfg.Timeout != 15*time.Second {
		t.Fatalf("unexpected default timeout: %s", cfg.Timeout)
	}
}

func TestResolveCLIAPIClientConfig_TimeoutValidation(t *testing.T) {
	t.Setenv(envCLIAPITimeout, "not-a-duration")
	if _, err := resolveCLIAPIClientConfig(); err == nil {
		t.Fatal("expected timeout parse error")
	}

	t.Setenv(envCLIAPITimeout, "0s")
	if _, err := resolveCLIAPIClientConfig(); err == nil {
		t.Fatal("expected timeout validation error for zero duration")
	}
}

func TestFirstAPIKeyFromEntries(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "colon entry", input: "alpha:user", want: "alpha"},
		{name: "equals entry", input: "beta=user", want: "beta"},
		{name: "raw entry", input: "gamma", want: "gamma"},
		{name: "skip blanks", input: ", ,delta:user", want: "delta"},
		{name: "empty", input: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstAPIKeyFromEntries(tc.input); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestShouldFallbackToDirect(t *testing.T) {
	transportErr := &url.Error{Op: "Get", URL: "http://127.0.0.1:1", Err: http.ErrServerClosed}
	apiErr := &apiclient.APIError{StatusCode: http.StatusUnauthorized, Message: "unauthorized"}

	if shouldFallbackToDirect(cliExecutionModeAPI, transportErr) {
		t.Fatal("api mode should not fallback")
	}
	if !shouldFallbackToDirect(cliExecutionModeAuto, transportErr) {
		t.Fatal("auto mode should fallback on transport errors")
	}
	if shouldFallbackToDirect(cliExecutionModeAuto, apiErr) {
		t.Fatal("auto mode should not fallback on API status errors")
	}
}
