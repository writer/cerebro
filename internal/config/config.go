package config

import (
	"time"

	"github.com/writer/cerebro/internal/app"
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
	appCfg := app.LoadConfig()

	return &Config{
		Port:                appCfg.Port,
		LogLevel:            appCfg.LogLevel,
		SnowflakeAccount:    appCfg.SnowflakeAccount,
		SnowflakeUser:       appCfg.SnowflakeUser,
		SnowflakePrivateKey: appCfg.SnowflakePrivateKey,
		SnowflakeWarehouse:  appCfg.SnowflakeWarehouse,
		SnowflakeDatabase:   appCfg.SnowflakeDatabase,
		SnowflakeSchema:     appCfg.SnowflakeSchema,
		SnowflakeRole:       appCfg.SnowflakeRole,
		CedarPoliciesPath:   appCfg.PoliciesPath,

		RateLimitEnabled:  appCfg.RateLimitEnabled,
		RateLimitRequests: appCfg.RateLimitRequests,
		RateLimitWindow:   appCfg.RateLimitWindow,

		SlackSigningSecret: appCfg.SlackSigningSecret,
		SlackWebhookURL:    appCfg.SlackWebhookURL,
	}
}
