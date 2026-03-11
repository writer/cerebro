package snowflake

import (
	"fmt"
	"os"
	"strings"

	sf "github.com/snowflakedb/gosnowflake"
)

// DSNConfig holds configuration for building a Snowflake DSN.
type DSNConfig struct {
	Account    string
	User       string
	PrivateKey string
	Database   string
	Schema     string
	Warehouse  string
	Role       string
}

// DSNConfigFromEnv loads DSN configuration from environment variables.
func DSNConfigFromEnv() DSNConfig {
	return DSNConfig{
		Account:    os.Getenv("SNOWFLAKE_ACCOUNT"),
		User:       os.Getenv("SNOWFLAKE_USER"),
		PrivateKey: NormalizePrivateKey(os.Getenv("SNOWFLAKE_PRIVATE_KEY")),
		Database:   getEnvOrDefault("SNOWFLAKE_DATABASE", "CEREBRO"),
		Schema:     getEnvOrDefault("SNOWFLAKE_SCHEMA", "CEREBRO"),
		Warehouse:  os.Getenv("SNOWFLAKE_WAREHOUSE"),
		Role:       os.Getenv("SNOWFLAKE_ROLE"),
	}
}

// MissingFields returns the names of required fields that are empty.
func (c DSNConfig) MissingFields() []string {
	var missing []string
	if c.Account == "" {
		missing = append(missing, "SNOWFLAKE_ACCOUNT")
	}
	if c.User == "" {
		missing = append(missing, "SNOWFLAKE_USER")
	}
	if c.PrivateKey == "" {
		missing = append(missing, "SNOWFLAKE_PRIVATE_KEY")
	}
	return missing
}

// IsComplete returns true if all required fields are set.
func (c DSNConfig) IsComplete() bool {
	return len(c.MissingFields()) == 0
}

// BuildDSN constructs a Snowflake DSN using key-pair authentication.
// Returns the DSN string, a boolean indicating if config was complete, and any error.
func BuildDSN(cfg DSNConfig) (string, bool, error) {
	if !cfg.IsComplete() {
		return "", false, nil
	}

	privateKey, err := parsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse private key: %w", err)
	}

	sfCfg := &sf.Config{
		Account:       cfg.Account,
		User:          cfg.User,
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    privateKey,
		Database:      cfg.Database,
		Schema:        cfg.Schema,
		Warehouse:     cfg.Warehouse,
		Role:          cfg.Role,
	}

	dsn, err := sf.DSN(sfCfg)
	if err != nil {
		return "", false, fmt.Errorf("failed to build DSN: %w", err)
	}

	return dsn, true, nil
}

// BuildDSNFromEnv is a convenience function that loads config from env and builds DSN.
func BuildDSNFromEnv() (string, bool, error) {
	return BuildDSN(DSNConfigFromEnv())
}

// NormalizePrivateKey cleans up PEM-encoded private key strings that may have
// escaped newlines or extra whitespace from environment variable storage.
func NormalizePrivateKey(value string) string {
	if value == "" {
		return value
	}
	if strings.Contains(value, "\\n") {
		value = strings.ReplaceAll(value, "\\n", "\n")
	}
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
