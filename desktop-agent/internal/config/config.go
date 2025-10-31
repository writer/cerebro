package config

import (
	"crypto/tls"
	"flag"
	"os"
	"strconv"
	"time"
)

// Config captures runtime settings for the desktop agent. Most values can be
// supplied via environment variables or CLI flags so operators can tune
// collection behaviour without rebuilding.
type Config struct {
	APIBaseURL           string
	APIToken             string
	Organization         string
	Site                 string
	Interval             time.Duration
	Once                 bool
	MaxProcesses         int
	AgentVersion         string
	InsecureTLS          bool
	TLSMinVersion        uint16
	HostnameOverride     string
	Tags                 map[string]string
	EventFlushInterval   time.Duration
	EventBatchSize       int
	PackDirectory        string
	ArtifactPollInterval time.Duration
	SecuritySignatures   string
}

const defaultInterval = 5 * time.Minute

// Load constructs a Config by merging environment variables with flag values
// and sensible defaults. Flags override environment settings so operators can
// tweak behaviour ad-hoc.
func Load() Config {
	cfg := Config{
		APIBaseURL:           envOr("CEREBRO_API_BASE_URL", "http://localhost:8000/api/v1"),
		APIToken:             os.Getenv("CEREBRO_API_TOKEN"),
		Organization:         os.Getenv("CEREBRO_AGENT_ORG"),
		Site:                 os.Getenv("CEREBRO_AGENT_SITE"),
		Interval:             parseDurationEnv("CEREBRO_COLLECTION_INTERVAL", defaultInterval),
		Once:                 parseBoolEnv("CEREBRO_AGENT_ONCE", false),
		MaxProcesses:         parseIntEnv("CEREBRO_AGENT_MAX_PROCESSES", 40),
		AgentVersion:         envOr("CEREBRO_AGENT_VERSION", "0.1.0"),
		InsecureTLS:          parseBoolEnv("CEREBRO_AGENT_INSECURE_TLS", false),
		TLSMinVersion:        tls.VersionTLS12,
		HostnameOverride:     os.Getenv("CEREBRO_AGENT_HOSTNAME"),
		Tags:                 map[string]string{"agent": "desktop-go"},
		EventFlushInterval:   parseDurationEnv("CEREBRO_EVENT_FLUSH_INTERVAL", time.Minute),
		EventBatchSize:       parseIntEnv("CEREBRO_EVENT_BATCH_SIZE", 256),
		PackDirectory:        envOr("CEREBRO_PACK_DIRECTORY", ""),
		ArtifactPollInterval: parseDurationEnv("CEREBRO_ARTIFACT_POLL_INTERVAL", 5*time.Minute),
		SecuritySignatures:   envOr("CEREBRO_SECURITY_SIGNATURES", ""),
	}

	minTLS := os.Getenv("CEREBRO_AGENT_TLS_MIN_VERSION")
	switch minTLS {
	case "1.3":
		cfg.TLSMinVersion = tls.VersionTLS13
	case "1.2":
		cfg.TLSMinVersion = tls.VersionTLS12
	case "1.1":
		cfg.TLSMinVersion = tls.VersionTLS11
	}

	apiURL := flag.String("api", cfg.APIBaseURL, "Cerebro API base URL")
	token := flag.String("token", cfg.APIToken, "API token with ingest:telemetry scope")
	interval := flag.Duration("interval", cfg.Interval, "Collection interval")
	once := flag.Bool("once", cfg.Once, "Collect and send once, then exit")
	maxProcs := flag.Int("max-processes", cfg.MaxProcesses, "Maximum processes to include")
	insecure := flag.Bool("insecure-tls", cfg.InsecureTLS, "Disable TLS verification (dev only)")
	org := flag.String("org", cfg.Organization, "Organization name override")
	site := flag.String("site", cfg.Site, "Site or location tag")
	hostOverride := flag.String("hostname", cfg.HostnameOverride, "Hostname override")
	eventFlush := flag.Duration("event-flush", cfg.EventFlushInterval, "Interval to flush queued host events")
	eventBatch := flag.Int("event-batch", cfg.EventBatchSize, "Maximum queued events per batch")
	packDir := flag.String("pack-dir", cfg.PackDirectory, "Directory containing artifact packs")
	artifactPoll := flag.Duration("artifact-poll", cfg.ArtifactPollInterval, "Interval to poll for artifact jobs")
	securitySignatures := flag.String("security-signatures", cfg.SecuritySignatures, "Path to custom security agent signature definitions")

	flag.Parse()

	cfg.APIBaseURL = *apiURL
	cfg.APIToken = *token
	cfg.Interval = *interval
	cfg.Once = *once
	cfg.MaxProcesses = *maxProcs
	cfg.InsecureTLS = *insecure
	cfg.Organization = *org
	cfg.Site = *site
	cfg.HostnameOverride = *hostOverride
	cfg.EventFlushInterval = *eventFlush
	cfg.EventBatchSize = *eventBatch
	cfg.PackDirectory = *packDir
	cfg.ArtifactPollInterval = *artifactPoll
	cfg.SecuritySignatures = *securitySignatures

	return cfg
}

// envOr returns the environment variable if set, otherwise the fallback.
func envOr(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// parseDurationEnv parses a duration from the environment, falling back when
// parsing fails.
func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			return parsed
		}
	}
	return fallback
}

// parseBoolEnv parses a boolean value from the environment with a default.
func parseBoolEnv(key string, fallback bool) bool {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
			return parsed
		}
	}
	return fallback
}

// parseIntEnv parses an integer from the environment or returns fallback.
func parseIntEnv(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return fallback
}
