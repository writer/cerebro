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
	if cfg.SnowflakeSchema != "RAW" {
		t.Errorf("expected default schema 'RAW', got '%s'", cfg.SnowflakeSchema)
	}
	if cfg.CedarPoliciesPath != "policies" {
		t.Errorf("expected default policies path 'policies', got '%s'", cfg.CedarPoliciesPath)
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("API_PORT", "9000")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("SNOWFLAKE_CONNECTION_STRING", "user:pass@account/db")
	os.Setenv("SNOWFLAKE_DATABASE", "TESTDB")
	os.Setenv("SNOWFLAKE_SCHEMA", "TESTSCHEMA")
	defer os.Clearenv()

	cfg := Load()

	if cfg.Port != 9000 {
		t.Errorf("expected port 9000, got %d", cfg.Port)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log level 'debug', got '%s'", cfg.LogLevel)
	}
	if cfg.SnowflakeConnection != "user:pass@account/db" {
		t.Errorf("expected snowflake connection string, got '%s'", cfg.SnowflakeConnection)
	}
	if cfg.SnowflakeDatabase != "TESTDB" {
		t.Errorf("expected database 'TESTDB', got '%s'", cfg.SnowflakeDatabase)
	}
	if cfg.SnowflakeSchema != "TESTSCHEMA" {
		t.Errorf("expected schema 'TESTSCHEMA', got '%s'", cfg.SnowflakeSchema)
	}
}
