package config

import (
	"time"

	"github.com/writerinternal/cerebro/internal/envutil"
)

type Config struct {
	Port                int
	LogLevel            string
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
		Port:                envutil.GetInt("API_PORT", 8080),
		LogLevel:            envutil.Get("LOG_LEVEL", "info"),
		SnowflakeAccount:    envutil.Get("SNOWFLAKE_ACCOUNT", ""),
		SnowflakeUser:       envutil.Get("SNOWFLAKE_USER", ""),
		SnowflakePrivateKey: envutil.NormalizePrivateKey(envutil.Get("SNOWFLAKE_PRIVATE_KEY", "")),
		SnowflakeWarehouse:  envutil.Get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		SnowflakeDatabase:   envutil.Get("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:     envutil.Get("SNOWFLAKE_SCHEMA", "CEREBRO"),
		SnowflakeRole:       envutil.Get("SNOWFLAKE_ROLE", ""),
		CedarPoliciesPath:   envutil.Get("CEDAR_POLICIES_PATH", "policies"),

		RateLimitEnabled:  envutil.GetBool("RATE_LIMIT_ENABLED", false),
		RateLimitRequests: envutil.GetInt("RATE_LIMIT_REQUESTS", 1000),
		RateLimitWindow:   envutil.GetDuration("RATE_LIMIT_WINDOW", time.Hour),

		SlackSigningSecret: envutil.Get("SLACK_SIGNING_SECRET", ""),
		SlackWebhookURL:    envutil.Get("SLACK_WEBHOOK_URL", ""),
	}
}
