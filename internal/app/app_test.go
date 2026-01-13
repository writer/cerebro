package app

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Set some env vars
	os.Setenv("API_PORT", "9999")
	os.Setenv("LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("API_PORT")
		os.Unsetenv("LOG_LEVEL")
	}()

	cfg := LoadConfig()

	if cfg.Port != 9999 {
		t.Errorf("expected port 9999, got %d", cfg.Port)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("expected log level debug, got %s", cfg.LogLevel)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear any env vars that might affect defaults
	os.Unsetenv("API_PORT")
	os.Unsetenv("LOG_LEVEL")

	cfg := LoadConfig()

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("expected default log level info, got %s", cfg.LogLevel)
	}

	if cfg.SnowflakeDatabase != "CEREBRO" {
		t.Errorf("expected default database CEREBRO, got %s", cfg.SnowflakeDatabase)
	}

	if cfg.SnowflakeSchema != "CEREBRO" {
		t.Errorf("expected default schema CEREBRO, got %s", cfg.SnowflakeSchema)
	}
}

func TestNew_WithoutSnowflake(t *testing.T) {
	// Clear snowflake config to test initialization without it
	os.Unsetenv("SNOWFLAKE_CONNECTION_STRING")

	ctx := context.Background()
	app, err := New(ctx)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer app.Close()

	// Core services should be initialized
	if app.Policy == nil {
		t.Error("Policy engine should be initialized")
	}

	if app.Findings == nil {
		t.Error("Findings store should be initialized")
	}

	if app.Scanner == nil {
		t.Error("Scanner should be initialized")
	}

	if app.Cache == nil {
		t.Error("Cache should be initialized")
	}

	// Feature services should be initialized
	if app.Agents == nil {
		t.Error("Agents should be initialized")
	}

	if app.Ticketing == nil {
		t.Error("Ticketing should be initialized")
	}

	if app.Identity == nil {
		t.Error("Identity should be initialized")
	}

	if app.AttackPath == nil {
		t.Error("AttackPath should be initialized")
	}

	if app.Providers == nil {
		t.Error("Providers should be initialized")
	}

	if app.Webhooks == nil {
		t.Error("Webhooks should be initialized")
	}

	if app.Notifications == nil {
		t.Error("Notifications should be initialized")
	}

	if app.Scheduler == nil {
		t.Error("Scheduler should be initialized")
	}

	// New services should be initialized
	if app.RBAC == nil {
		t.Error("RBAC should be initialized")
	}

	if app.ThreatIntel == nil {
		t.Error("ThreatIntel should be initialized")
	}

	if app.Health == nil {
		t.Error("Health should be initialized")
	}

	if app.Lineage == nil {
		t.Error("Lineage should be initialized")
	}

	if app.Remediation == nil {
		t.Error("Remediation should be initialized")
	}

	if app.RuntimeDetect == nil {
		t.Error("RuntimeDetect should be initialized")
	}

	if app.RuntimeRespond == nil {
		t.Error("RuntimeRespond should be initialized")
	}
}

func TestNew_ServicesWired(t *testing.T) {
	os.Unsetenv("SNOWFLAKE_CONNECTION_STRING")

	ctx := context.Background()
	app, err := New(ctx)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer app.Close()

	// Verify policy engine loaded policies
	policies := app.Policy.ListPolicies()
	if len(policies) == 0 {
		t.Log("No policies loaded - may need policies directory")
	}

	// Verify RBAC has default roles
	roles := app.RBAC.ListRoles()
	if len(roles) == 0 {
		t.Error("RBAC should have default roles")
	}

	// Verify remediation has default rules
	rules := app.Remediation.ListRules()
	if len(rules) == 0 {
		t.Error("Remediation should have default rules")
	}

	// Verify runtime detection has rules
	detectionRules := app.RuntimeDetect.ListRules()
	if len(detectionRules) == 0 {
		t.Error("RuntimeDetect should have detection rules")
	}

	// Verify health checks registered
	healthResults := app.Health.RunAll(ctx)
	if len(healthResults) == 0 {
		t.Error("Health should have registered checks")
	}
}

func TestApp_Close(t *testing.T) {
	os.Unsetenv("SNOWFLAKE_CONNECTION_STRING")

	ctx := context.Background()
	app, _ := New(ctx)

	err := app.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestGetEnv(t *testing.T) {
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	val := getEnv("TEST_VAR", "default")
	if val != "test_value" {
		t.Errorf("expected test_value, got %s", val)
	}

	val = getEnv("NONEXISTENT_VAR", "default")
	if val != "default" {
		t.Errorf("expected default, got %s", val)
	}
}

func TestGetEnvInt(t *testing.T) {
	os.Setenv("TEST_INT", "42")
	defer os.Unsetenv("TEST_INT")

	val := getEnvInt("TEST_INT", 0)
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}

	val = getEnvInt("NONEXISTENT_INT", 100)
	if val != 100 {
		t.Errorf("expected 100, got %d", val)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
	}

	for _, tt := range tests {
		os.Setenv("TEST_BOOL", tt.value)
		got := getEnvBool("TEST_BOOL", false)
		if got != tt.want {
			t.Errorf("getEnvBool(%q) = %v, want %v", tt.value, got, tt.want)
		}
		os.Unsetenv("TEST_BOOL")
	}
}

func TestGetEnvDuration(t *testing.T) {
	os.Setenv("TEST_DUR", "5m")
	defer os.Unsetenv("TEST_DUR")

	val := getEnvDuration("TEST_DUR", time.Hour)
	if val != 5*time.Minute {
		t.Errorf("expected 5m, got %v", val)
	}

	val = getEnvDuration("NONEXISTENT_DUR", time.Hour)
	if val != time.Hour {
		t.Errorf("expected 1h, got %v", val)
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"debug", "DEBUG"},
		{"info", "INFO"},
		{"warn", "WARN"},
		{"error", "ERROR"},
		{"unknown", "INFO"}, // default
	}

	for _, tt := range tests {
		got := parseLogLevel(tt.input)
		if got.String() != tt.want {
			t.Errorf("parseLogLevel(%q) = %s, want %s", tt.input, got.String(), tt.want)
		}
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"5s", 5 * time.Second, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := parseDuration(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSplitTables(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"a,b,c", 3},
		{"  a , b , c  ", 3},
		{"single", 1},
		{"", 0},
		{",,,", 0},
	}

	for _, tt := range tests {
		got := splitTables(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitTables(%q) len = %d, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{
		Port:                      8080,
		LogLevel:                  "info",
		SnowflakeDatabase:         "CEREBRO",
		SnowflakeSchema:           "CEREBRO",
		PoliciesPath:              "policies",
		ScanInterval:              "1h",
		RateLimitEnabled:          true,
		RateLimitRequests:         1000,
		RateLimitWindow:           time.Hour,
	}

	if cfg.Port != 8080 {
		t.Error("Port field incorrect")
	}

	if cfg.RateLimitEnabled != true {
		t.Error("RateLimitEnabled field incorrect")
	}

	if cfg.RateLimitWindow != time.Hour {
		t.Error("RateLimitWindow field incorrect")
	}
}
