package cerebroapi

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const DefaultHTTPTimeout = 15 * time.Second

type Config struct {
	BaseURL       string
	MCPURL        string
	APIKey        string
	TenantID      string
	RuntimeID     string
	SourceID      string
	RuntimeConfig map[string]string
	Timeout       time.Duration
	UserAgent     string
}

func ConfigFromEnv() Config {
	return Config{
		BaseURL:  trimEnv("CEREBRO_BASE_URL"),
		MCPURL:   trimEnv("CEREBRO_MCP_URL"),
		APIKey:   firstEnv("CEREBRO_API_KEY", "CEREBRO_TOKEN"),
		TenantID: trimEnv("CEREBRO_TENANT_ID"),
		RuntimeID: firstEnv(
			"CEREBRO_SOURCE_RUNTIME_ID",
			"CEREBRO_RUNTIME_ID",
		),
		SourceID: firstEnv(
			"CEREBRO_SOURCE_ID",
			"CEREBRO_CONNECTOR_SOURCE_ID",
		),
		Timeout: durationEnv("CEREBRO_HTTP_TIMEOUT_SECONDS", DefaultHTTPTimeout),
	}
}

func (c Config) Enabled() bool {
	return strings.TrimSpace(c.BaseURL) != "" &&
		strings.TrimSpace(c.APIKey) != "" &&
		strings.TrimSpace(c.TenantID) != ""
}

func (c Config) DefaultRuntime() SourceRuntime {
	return SourceRuntime{
		ID:       strings.TrimSpace(c.RuntimeID),
		SourceID: strings.TrimSpace(c.SourceID),
		TenantID: strings.TrimSpace(c.TenantID),
		Config:   copyStringMap(c.RuntimeConfig),
	}
}

func trimEnv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := trimEnv(key); value != "" {
			return value
		}
	}
	return ""
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := trimEnv(key)
	if value == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
