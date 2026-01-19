package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                int
	LogLevel            string
	SnowflakeConnection string
	SnowflakeAccount    string
	SnowflakeUser       string
	SnowflakePrivateKey string
	SnowflakeWarehouse  string
	SnowflakeDatabase   string
	SnowflakeSchema     string
	SnowflakeRole       string
	CedarPoliciesPath   string

	// Rate limiting
	RateLimitEnabled  bool
	RateLimitRequests int
	RateLimitWindow   time.Duration

	// Slack integration
	SlackSigningSecret string
	SlackWebhookURL    string
}

func Load() *Config {
	return &Config{
		Port:                getEnvInt("API_PORT", 8080),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
		SnowflakeConnection: getEnv("SNOWFLAKE_CONNECTION_STRING", ""),
		SnowflakeAccount:    getEnv("SNOWFLAKE_ACCOUNT", ""),
		SnowflakeUser:       getEnv("SNOWFLAKE_USER", ""),
		SnowflakePrivateKey: getEnv("SNOWFLAKE_PRIVATE_KEY", ""),
		SnowflakeWarehouse:  getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		SnowflakeDatabase:   getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:     getEnv("SNOWFLAKE_SCHEMA", "RAW"),
		SnowflakeRole:       getEnv("SNOWFLAKE_ROLE", ""),
		CedarPoliciesPath:   getEnv("CEDAR_POLICIES_PATH", "policies"),

		RateLimitEnabled:  getEnvBool("RATE_LIMIT_ENABLED", false),
		RateLimitRequests: getEnvInt("RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:   getEnvDuration("RATE_LIMIT_WINDOW", time.Hour),

		SlackSigningSecret: getEnv("SLACK_SIGNING_SECRET", ""),
		SlackWebhookURL:    getEnv("SLACK_WEBHOOK_URL", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
