package app

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/apiauth"
	"github.com/writer/cerebro/internal/envutil"
	"github.com/writer/cerebro/internal/secretsource"
)

var configValueSourceState struct {
	mu     sync.RWMutex
	source secretsource.Source
}

// Only explicit credential/auth material is overrideable via file/Vault-backed
// credential sources. This intentionally excludes runtime policy and platform
// integrity controls such as graph or attestation signing keys.
var credentialSourceAllowedKeys = map[string]struct{}{
	"ANTHROPIC_API_KEY":                  {},
	"API_CREDENTIALS_JSON":               {},
	"API_KEYS":                           {},
	"AUTH0_CLIENT_SECRET":                {},
	"AZURE_CLIENT_SECRET":                {},
	"BAMBOOHR_API_TOKEN":                 {},
	"CEREBRO_OTEL_EXPORTER_OTLP_HEADERS": {},
	"CLOUDFLARE_API_TOKEN":               {},
	"CROWDSTRIKE_CLIENT_SECRET":          {},
	"CYBERARK_API_TOKEN":                 {},
	"DATADOG_API_KEY":                    {},
	"DATADOG_APP_KEY":                    {},
	"DUO_SECRET_KEY":                     {},
	"DUO_SKEY":                           {},
	"ENTRA_CLIENT_SECRET":                {},
	"FIGMA_API_TOKEN":                    {},
	"FORGEROCK_API_TOKEN":                {},
	"GITHUB_TOKEN":                       {},
	"GITLAB_TOKEN":                       {},
	"GONG_ACCESS_KEY":                    {},
	"GONG_ACCESS_SECRET":                 {},
	"GOOGLE_WORKSPACE_CREDENTIALS_JSON":  {},
	"INTUNE_CLIENT_SECRET":               {},
	"JAMF_CLIENT_SECRET":                 {},
	"JIRA_API_TOKEN":                     {},
	"JUMPCLOUD_API_TOKEN":                {},
	"KANDJI_API_TOKEN":                   {},
	"KOLIDE_API_TOKEN":                   {},
	"LINEAR_API_KEY":                     {},
	"NATS_JETSTREAM_NKEY_SEED":           {},
	"NATS_JETSTREAM_PASSWORD":            {},
	"NATS_JETSTREAM_USERNAME":            {},
	"NATS_JETSTREAM_USER_JWT":            {},
	"OKTA_API_TOKEN":                     {},
	"ONELOGIN_CLIENT_SECRET":             {},
	"OPENAI_API_KEY":                     {},
	"ORACLE_IDCS_API_TOKEN":              {},
	"OTEL_EXPORTER_OTLP_HEADERS":         {},
	"PAGERDUTY_ROUTING_KEY":              {},
	"PANTHER_API_TOKEN":                  {},
	"PINGIDENTITY_CLIENT_SECRET":         {},
	"PINGONE_CLIENT_SECRET":              {},
	"QUALYS_PASSWORD":                    {},
	"RAMP_CLIENT_SECRET":                 {},
	"RIPPLING_API_TOKEN":                 {},
	"SAILPOINT_API_TOKEN":                {},
	"SALESFORCE_CLIENT_SECRET":           {},
	"SALESFORCE_PASSWORD":                {},
	"SALESFORCE_SECURITY_TOKEN":          {},
	"SAVIYNT_API_TOKEN":                  {},
	"SEMGREP_API_TOKEN":                  {},
	"SENTINELONE_API_TOKEN":              {},
	"SERVICENOW_API_TOKEN":               {},
	"SERVICENOW_PASSWORD":                {},
	"SLACK_API_TOKEN":                    {},
	"SLACK_SIGNING_SECRET":               {},
	"SLACK_WEBHOOK_URL":                  {},
	"SNOWFLAKE_PRIVATE_KEY":              {},
	"SNYK_API_TOKEN":                     {},
	"SOCKET_API_TOKEN":                   {},
	"SPLUNK_TOKEN":                       {},
	"TAILSCALE_API_KEY":                  {},
	"TENABLE_ACCESS_KEY":                 {},
	"TENABLE_SECRET_KEY":                 {},
	"TFC_TOKEN":                          {},
	"VAULT_TOKEN":                        {},
	"VANTA_API_TOKEN":                    {},
	"WIZ_CLIENT_SECRET":                  {},
	"WORKDAY_API_TOKEN":                  {},
	"ZOOM_CLIENT_SECRET":                 {},
}

func getEnv(key, fallback string) string {
	if credentialSourceEligibleKey(key) {
		if value, ok := lookupActiveConfigSourceValue(key); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	if value, ok := lookupRawConfigValue(key); ok {
		return value
	}
	return fallback
}

func credentialSourceEligibleKey(key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	_, ok := credentialSourceAllowedKeys[key]
	return ok
}

func withConfigValueSource(source secretsource.Source, fn func()) {
	configValueSourceState.mu.Lock()
	previous := configValueSourceState.source
	configValueSourceState.source = source
	configValueSourceState.mu.Unlock()
	defer func() {
		configValueSourceState.mu.Lock()
		configValueSourceState.source = previous
		configValueSourceState.mu.Unlock()
	}()
	fn()
}

func lookupActiveConfigSourceValue(key string) (string, bool) {
	configValueSourceState.mu.RLock()
	source := configValueSourceState.source
	configValueSourceState.mu.RUnlock()
	if source == nil {
		return "", false
	}
	return source.Lookup(key)
}

func lookupRawConfigValue(key string) (string, bool) {
	if value := strings.TrimSpace(envutil.Get(key, "")); value != "" {
		return value, true
	}
	if value, ok := lookupConfigFileValue(key); ok {
		return value, true
	}
	return "", false
}

func bootstrapConfigValue(key, fallback string) string {
	if value, ok := lookupRawConfigValue(key); ok {
		return value
	}
	return fallback
}

func bootstrapConfigInt(key string, fallback int) int {
	value := strings.TrimSpace(bootstrapConfigValue(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		recordConfigProblem("%s must be a valid integer", key)
		return fallback
	}
	return parsed
}

var configParseRecorder struct {
	mu       sync.Mutex
	problems *[]string
}

func withConfigParseRecorder(fn func()) []string {
	configParseRecorder.mu.Lock()
	defer configParseRecorder.mu.Unlock()

	problems := make([]string, 0)
	configParseRecorder.problems = &problems
	defer func() {
		configParseRecorder.problems = nil
	}()

	fn()
	return normalizeConfigProblems(problems)
}

func recordConfigProblem(format string, args ...any) {
	if configParseRecorder.problems == nil {
		return
	}
	*configParseRecorder.problems = append(*configParseRecorder.problems, fmt.Sprintf(format, args...))
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(getEnv(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		recordConfigProblem("%s must be a valid integer", key)
		return fallback
	}
	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(getEnv(key, "")))
	if value == "" {
		return fallback
	}
	switch value {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		recordConfigProblem("%s must be a valid boolean", key)
		return fallback
	}
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(getEnv(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		recordConfigProblem("%s must be a valid duration", key)
		return fallback
	}
	return parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	value := strings.TrimSpace(getEnv(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		recordConfigProblem("%s must be a valid number", key)
		return fallback
	}
	return parsed
}

func parseKeyValueCSV(value string) map[string]string {
	parsed := make(map[string]string)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" || val == "" {
			continue
		}
		parsed[key] = val
	}
	return parsed
}

func parseAPIKeys(value string) map[string]string {
	keys := make(map[string]string)
	if value == "" {
		return keys
	}

	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) == 1 {
			parts = strings.SplitN(entry, "=", 2)
		}

		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}

		userID := ""
		if len(parts) == 2 {
			userID = strings.TrimSpace(parts[1])
		}
		if userID == "" {
			userID = defaultAPIUserID(key)
		}
		keys[key] = userID
	}

	return keys
}

func defaultAPIUserID(key string) string {
	return apiauth.DefaultUserIDForKey(key)
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func splitCSV(s string) []string {
	var result []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			result = append(result, t)
		}
	}
	return result
}

func parseDurationEnvMap(prefix string) map[string]time.Duration {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil
	}
	out := make(map[string]time.Duration)
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(key, prefix) || len(key) <= len(prefix) {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			recordConfigProblem("%s must be a valid duration", key)
			continue
		}
		suffix := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(key, prefix)))
		if suffix == "" {
			continue
		}
		out[suffix] = duration
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// defaultScanTables returns the comprehensive list of tables to scan

func normalizePrivateKey(value string) string {
	return envutil.NormalizePrivateKey(value)
}
