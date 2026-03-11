package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	apiclient "github.com/writer/cerebro/internal/client"
)

type cliExecutionMode string

const (
	cliExecutionModeAuto   cliExecutionMode = "auto"
	cliExecutionModeAPI    cliExecutionMode = "api"
	cliExecutionModeDirect cliExecutionMode = "direct"
)

const (
	envCLIExecutionMode = "CEREBRO_CLI_MODE"
	envCLIAPIURL        = "CEREBRO_API_URL"
	envCLIAPIKey        = "CEREBRO_API_KEY"
	envCLIAPITimeout    = "CEREBRO_API_TIMEOUT"
	envLegacyAPIKey     = "API_KEY"
	envAPIKeys          = "API_KEYS"
	envAPIPort          = "API_PORT"
)

func loadCLIExecutionMode() (cliExecutionMode, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(envCLIExecutionMode)))
	if raw == "" {
		return cliExecutionModeAuto, nil
	}

	switch cliExecutionMode(raw) {
	case cliExecutionModeAuto, cliExecutionModeAPI, cliExecutionModeDirect:
		return cliExecutionMode(raw), nil
	default:
		return "", fmt.Errorf("%s must be one of: auto, api, direct", envCLIExecutionMode)
	}
}

func newCLIAPIClient() (*apiclient.Client, error) {
	cfg, err := resolveCLIAPIClientConfig()
	if err != nil {
		return nil, err
	}
	return apiclient.New(cfg)
}

func resolveCLIAPIClientConfig() (apiclient.Config, error) {
	baseURL := strings.TrimSpace(os.Getenv(envCLIAPIURL))
	if baseURL == "" {
		baseURL = defaultCLIAPIBaseURL()
	}

	timeout := 15 * time.Second
	if raw := strings.TrimSpace(os.Getenv(envCLIAPITimeout)); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return apiclient.Config{}, fmt.Errorf("%s must be a positive duration", envCLIAPITimeout)
		}
		timeout = parsed
	}

	return apiclient.Config{
		BaseURL:   baseURL,
		APIKey:    resolveCLIAPIKey(),
		Timeout:   timeout,
		UserAgent: "cerebro-cli",
	}, nil
}

func defaultCLIAPIBaseURL() string {
	port := strings.TrimSpace(os.Getenv(envAPIPort))
	if port == "" {
		port = "8080"
	}
	return "http://127.0.0.1:" + port
}

func resolveCLIAPIKey() string {
	for _, candidate := range []string{
		strings.TrimSpace(os.Getenv(envCLIAPIKey)),
		strings.TrimSpace(os.Getenv(envLegacyAPIKey)),
		firstAPIKeyFromEntries(strings.TrimSpace(os.Getenv(envAPIKeys))),
	} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func firstAPIKeyFromEntries(raw string) string {
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if parts := strings.SplitN(entry, ":", 2); len(parts) == 2 {
			if key := strings.TrimSpace(parts[0]); key != "" {
				return key
			}
			continue
		}
		if parts := strings.SplitN(entry, "=", 2); len(parts) == 2 {
			if key := strings.TrimSpace(parts[0]); key != "" {
				return key
			}
			continue
		}
		return entry
	}
	return ""
}

func shouldFallbackToDirect(mode cliExecutionMode, err error) bool {
	return mode == cliExecutionModeAuto && apiclient.IsTransportError(err)
}
