package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()

	cfg := Load()

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log level 'info', got '%s'", cfg.LogLevel)
	}
	if cfg.SnowflakeDatabase != "CEREBRO" {
		t.Errorf("expected default database 'CEREBRO', got '%s'", cfg.SnowflakeDatabase)
	}
	if cfg.SnowflakeSchema != "CEREBRO" {
		t.Errorf("expected default schema 'CEREBRO', got '%s'", cfg.SnowflakeSchema)
	}
	if cfg.CedarPoliciesPath != "policies" {
		t.Errorf("expected default policies path 'policies', got '%s'", cfg.CedarPoliciesPath)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("API_PORT", "9000")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("SNOWFLAKE_ACCOUNT", "testaccount")
	t.Setenv("SNOWFLAKE_USER", "testuser")
	t.Setenv("SNOWFLAKE_DATABASE", "TESTDB")
	t.Setenv("SNOWFLAKE_SCHEMA", "TESTSCHEMA")

	cfg := Load()

	if cfg.Port != 9000 {
		t.Errorf("expected port 9000, got %d", cfg.Port)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log level 'debug', got '%s'", cfg.LogLevel)
	}
	if cfg.SnowflakeAccount != "testaccount" {
		t.Errorf("expected snowflake account 'testaccount', got '%s'", cfg.SnowflakeAccount)
	}
	if cfg.SnowflakeUser != "testuser" {
		t.Errorf("expected snowflake user 'testuser', got '%s'", cfg.SnowflakeUser)
	}
	if cfg.SnowflakeDatabase != "TESTDB" {
		t.Errorf("expected database 'TESTDB', got '%s'", cfg.SnowflakeDatabase)
	}
	if cfg.SnowflakeSchema != "TESTSCHEMA" {
		t.Errorf("expected schema 'TESTSCHEMA', got '%s'", cfg.SnowflakeSchema)
	}
}
