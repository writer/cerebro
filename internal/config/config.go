package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port                 int
	LogLevel             string
	SnowflakeConnection  string
	SnowflakeWarehouse   string
	SnowflakeDatabase    string
	SnowflakeSchema      string
	CedarPoliciesPath    string
}

func Load() *Config {
	return &Config{
		Port:                 getEnvInt("API_PORT", 8080),
		LogLevel:             getEnv("LOG_LEVEL", "info"),
		SnowflakeConnection:  getEnv("SNOWFLAKE_CONNECTION_STRING", ""),
		SnowflakeWarehouse:   getEnv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
		SnowflakeDatabase:    getEnv("SNOWFLAKE_DATABASE", "CEREBRO"),
		SnowflakeSchema:      getEnv("SNOWFLAKE_SCHEMA", "RAW"),
		CedarPoliciesPath:    getEnv("CEDAR_POLICIES_PATH", "policies"),
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
