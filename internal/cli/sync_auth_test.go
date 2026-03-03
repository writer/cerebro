package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestApplyGCPAuthOverrides(t *testing.T) {
	originalFile := syncGCPCredentialsFile
	originalImpersonateSA := syncGCPImpersonateSA
	originalImpersonateDel := syncGCPImpersonateDel
	originalImpersonateTTL := syncGCPImpersonateTTL
	t.Cleanup(func() {
		syncGCPCredentialsFile = originalFile
		syncGCPImpersonateSA = originalImpersonateSA
		syncGCPImpersonateDel = originalImpersonateDel
		syncGCPImpersonateTTL = originalImpersonateTTL
	})

	t.Run("no credentials file", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "existing-path")
		syncGCPCredentialsFile = ""
		syncGCPImpersonateSA = ""
		syncGCPImpersonateDel = ""
		syncGCPImpersonateTTL = ""

		cleanup, err := applyGCPAuthOverrides()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		cleanup()
		if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "existing-path" {
			t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS to remain unchanged, got %q", got)
		}
	})

	t.Run("missing credentials file", func(t *testing.T) {
		syncGCPCredentialsFile = filepath.Join(t.TempDir(), "missing-creds.json")
		syncGCPImpersonateSA = ""
		syncGCPImpersonateDel = ""
		syncGCPImpersonateTTL = ""

		_, err := applyGCPAuthOverrides()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "gcp credentials file") {
			t.Fatalf("expected file read error, got %v", err)
		}
	})

	t.Run("sets GOOGLE_APPLICATION_CREDENTIALS", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "previous-path")
		credsPath := filepath.Join(t.TempDir(), "creds.json")
		if err := os.WriteFile(credsPath, []byte(`{"type":"service_account"}`), 0o600); err != nil {
			t.Fatalf("failed to write creds file: %v", err)
		}

		syncGCPCredentialsFile = credsPath
		syncGCPImpersonateSA = ""
		syncGCPImpersonateDel = ""
		syncGCPImpersonateTTL = ""

		cleanup, err := applyGCPAuthOverrides()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != credsPath {
			t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS=%q, got %q", credsPath, got)
		}

		cleanup()
		if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "previous-path" {
			t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS to be restored, got %q", got)
		}
	})

	t.Run("impersonation creates temporary credentials and cleans up", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "existing-path")

		sourceCredsPath := filepath.Join(t.TempDir(), "source-creds.json")
		sourceCreds := `{"type":"authorized_user","client_id":"cid","client_secret":"secret","refresh_token":"refresh"}`
		if err := os.WriteFile(sourceCredsPath, []byte(sourceCreds), 0o600); err != nil {
			t.Fatalf("failed to write source creds file: %v", err)
		}

		syncGCPCredentialsFile = sourceCredsPath
		syncGCPImpersonateSA = "svc-impersonated@example-project.iam.gserviceaccount.com"
		syncGCPImpersonateDel = "delegate-1@project.iam.gserviceaccount.com, delegate-2@project.iam.gserviceaccount.com"
		syncGCPImpersonateTTL = "2400"

		cleanup, err := applyGCPAuthOverrides()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		tempPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		if tempPath == "" || tempPath == sourceCredsPath {
			t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS to point to temporary impersonation file, got %q", tempPath)
		}

		contents, err := os.ReadFile(tempPath)
		if err != nil {
			t.Fatalf("failed to read temp impersonation file: %v", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(contents, &payload); err != nil {
			t.Fatalf("failed to parse temp impersonation file: %v", err)
		}
		if got := payload["type"]; got != "impersonated_service_account" {
			t.Fatalf("expected impersonated_service_account type, got %v", got)
		}
		if _, ok := payload["source_credentials"]; !ok {
			t.Fatalf("expected source_credentials in temp impersonation file")
		}
		if got := payload["token_lifetime_seconds"]; got != float64(2400) {
			t.Fatalf("expected token_lifetime_seconds=2400, got %v", got)
		}

		cleanup()
		if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "existing-path" {
			t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS to be restored, got %q", got)
		}
		if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
			t.Fatalf("expected temp impersonation file to be deleted, stat err=%v", err)
		}
	})

	t.Run("impersonation requires source credentials", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("APPDATA", t.TempDir())
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		syncGCPCredentialsFile = ""
		syncGCPImpersonateSA = "svc-impersonated@example-project.iam.gserviceaccount.com"
		syncGCPImpersonateDel = ""
		syncGCPImpersonateTTL = ""

		_, err := applyGCPAuthOverrides()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "gcp impersonation requires source credentials") {
			t.Fatalf("expected missing source credentials error, got %v", err)
		}
	})

	t.Run("token lifetime requires impersonation", func(t *testing.T) {
		syncGCPCredentialsFile = ""
		syncGCPImpersonateSA = ""
		syncGCPImpersonateDel = ""
		syncGCPImpersonateTTL = "2400"

		_, err := applyGCPAuthOverrides()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires --gcp-impersonate-service-account") {
			t.Fatalf("expected impersonation requirement error, got %v", err)
		}
	})

	t.Run("delegates require impersonation", func(t *testing.T) {
		syncGCPCredentialsFile = ""
		syncGCPImpersonateSA = ""
		syncGCPImpersonateDel = "delegate-1@project.iam.gserviceaccount.com"
		syncGCPImpersonateTTL = ""

		_, err := applyGCPAuthOverrides()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires --gcp-impersonate-service-account") {
			t.Fatalf("expected impersonation requirement error, got %v", err)
		}
	})
}

func TestApplyAWSAssumeRoleOverride(t *testing.T) {
	originalRoleARN := syncAWSRoleARN
	originalSession := syncAWSRoleSession
	originalExternalID := syncAWSRoleExternalID
	originalMFASerial := syncAWSRoleMFASerial
	originalMFAToken := syncAWSRoleMFAToken
	originalSourceID := syncAWSRoleSourceID
	originalDuration := syncAWSRoleDuration
	originalTags := syncAWSRoleTags
	originalTransitive := syncAWSRoleTransitive
	t.Cleanup(func() {
		syncAWSRoleARN = originalRoleARN
		syncAWSRoleSession = originalSession
		syncAWSRoleExternalID = originalExternalID
		syncAWSRoleMFASerial = originalMFASerial
		syncAWSRoleMFAToken = originalMFAToken
		syncAWSRoleSourceID = originalSourceID
		syncAWSRoleDuration = originalDuration
		syncAWSRoleTags = originalTags
		syncAWSRoleTransitive = originalTransitive
	})

	t.Run("no role configured", func(t *testing.T) {
		syncAWSRoleARN = ""
		syncAWSRoleSession = ""
		syncAWSRoleExternalID = ""
		syncAWSRoleMFASerial = ""
		syncAWSRoleMFAToken = ""
		syncAWSRoleSourceID = ""
		syncAWSRoleDuration = ""
		syncAWSRoleTags = ""
		syncAWSRoleTransitive = ""

		cfg := aws.Config{Region: "us-east-1"}
		out, err := applyAWSAssumeRoleOverride(context.Background(), cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if out.Region != cfg.Region {
			t.Fatalf("expected region %q, got %q", cfg.Region, out.Region)
		}
		if out.Credentials != cfg.Credentials {
			t.Fatalf("expected credentials to be unchanged")
		}
	})

	t.Run("role configured", func(t *testing.T) {
		syncAWSRoleARN = "arn:aws:iam::123456789012:role/CerebroReadOnly"
		syncAWSRoleSession = "sync-session"
		syncAWSRoleExternalID = "external-id"
		syncAWSRoleMFASerial = ""
		syncAWSRoleMFAToken = ""
		syncAWSRoleSourceID = "source-user@example.com"
		syncAWSRoleDuration = "1800"
		syncAWSRoleTags = "env=prod,owner=platform"
		syncAWSRoleTransitive = "env"

		cfg := aws.Config{Region: "us-east-1"}
		out, err := applyAWSAssumeRoleOverride(context.Background(), cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if out.Credentials == nil {
			t.Fatal("expected assumed credentials provider to be configured")
		}
		if out.Region != cfg.Region {
			t.Fatalf("expected region %q, got %q", cfg.Region, out.Region)
		}
	})

	t.Run("mfa token requires serial", func(t *testing.T) {
		syncAWSRoleARN = "arn:aws:iam::123456789012:role/CerebroReadOnly"
		syncAWSRoleSession = "sync-session"
		syncAWSRoleExternalID = ""
		syncAWSRoleMFASerial = ""
		syncAWSRoleMFAToken = "123456"
		syncAWSRoleSourceID = ""
		syncAWSRoleDuration = ""
		syncAWSRoleTags = ""
		syncAWSRoleTransitive = ""

		cfg := aws.Config{Region: "us-east-1"}
		_, err := applyAWSAssumeRoleOverride(context.Background(), cfg)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires --aws-role-mfa-serial") {
			t.Fatalf("expected MFA serial validation error, got %v", err)
		}
	})

	t.Run("duration requires role", func(t *testing.T) {
		syncAWSRoleARN = ""
		syncAWSRoleSession = ""
		syncAWSRoleExternalID = ""
		syncAWSRoleMFASerial = ""
		syncAWSRoleMFAToken = ""
		syncAWSRoleSourceID = ""
		syncAWSRoleDuration = "1800"
		syncAWSRoleTags = ""
		syncAWSRoleTransitive = ""

		cfg := aws.Config{Region: "us-east-1"}
		_, err := applyAWSAssumeRoleOverride(context.Background(), cfg)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "require --aws-role-arn") {
			t.Fatalf("expected role requirement validation error, got %v", err)
		}
	})
}

func TestApplyAWSAuthOverrides(t *testing.T) {
	originalWebIDToken := syncAWSWebIDTokenFile
	originalWebIDRole := syncAWSWebIDRoleARN
	originalSession := syncAWSRoleSession
	t.Cleanup(func() {
		syncAWSWebIDTokenFile = originalWebIDToken
		syncAWSWebIDRoleARN = originalWebIDRole
		syncAWSRoleSession = originalSession
	})

	t.Run("no web identity flags", func(t *testing.T) {
		t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "existing-token")
		t.Setenv("AWS_ROLE_ARN", "existing-role")

		syncAWSWebIDTokenFile = ""
		syncAWSWebIDRoleARN = ""
		syncAWSRoleSession = ""

		cleanup, err := applyAWSAuthOverrides()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		cleanup()

		if got := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); got != "existing-token" {
			t.Fatalf("expected token file env unchanged, got %q", got)
		}
	})

	t.Run("requires token and role together", func(t *testing.T) {
		syncAWSWebIDTokenFile = "/tmp/token"
		syncAWSWebIDRoleARN = ""

		_, err := applyAWSAuthOverrides()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "must be set together") {
			t.Fatalf("expected paired-flag validation error, got %v", err)
		}
	})

	t.Run("sets web identity env and restores", func(t *testing.T) {
		t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "old-token")
		t.Setenv("AWS_ROLE_ARN", "old-role")
		t.Setenv("AWS_ROLE_SESSION_NAME", "old-session")

		tokenPath := filepath.Join(t.TempDir(), "token.jwt")
		if err := os.WriteFile(tokenPath, []byte("token"), 0o600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		syncAWSWebIDTokenFile = tokenPath
		syncAWSWebIDRoleARN = "arn:aws:iam::123456789012:role/CerebroIRSA"
		syncAWSRoleSession = "web-identity-session"

		cleanup, err := applyAWSAuthOverrides()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if got := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); got != tokenPath {
			t.Fatalf("expected token env to be set, got %q", got)
		}
		if got := os.Getenv("AWS_ROLE_ARN"); got != syncAWSWebIDRoleARN {
			t.Fatalf("expected role env to be set, got %q", got)
		}
		if got := os.Getenv("AWS_ROLE_SESSION_NAME"); got != syncAWSRoleSession {
			t.Fatalf("expected role session env to be set, got %q", got)
		}

		cleanup()

		if got := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); got != "old-token" {
			t.Fatalf("expected token env to be restored, got %q", got)
		}
		if got := os.Getenv("AWS_ROLE_ARN"); got != "old-role" {
			t.Fatalf("expected role env to be restored, got %q", got)
		}
		if got := os.Getenv("AWS_ROLE_SESSION_NAME"); got != "old-session" {
			t.Fatalf("expected session env to be restored, got %q", got)
		}
	})
}

func TestLoadAWSConfigValidatesFiles(t *testing.T) {
	originalConfigFile := syncAWSConfigFile
	originalCredsFile := syncAWSSharedCredsFile
	originalCredentialProc := syncAWSCredentialProc
	t.Cleanup(func() {
		syncAWSConfigFile = originalConfigFile
		syncAWSSharedCredsFile = originalCredsFile
		syncAWSCredentialProc = originalCredentialProc
	})

	t.Run("missing config file", func(t *testing.T) {
		syncAWSConfigFile = filepath.Join(t.TempDir(), "missing-config")
		syncAWSSharedCredsFile = ""
		syncAWSCredentialProc = ""

		_, err := loadAWSConfig(context.Background(), "")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "--aws-config-file") {
			t.Fatalf("expected config file validation error, got %v", err)
		}
	})

	t.Run("missing shared credentials file", func(t *testing.T) {
		syncAWSConfigFile = ""
		syncAWSSharedCredsFile = filepath.Join(t.TempDir(), "missing-creds")
		syncAWSCredentialProc = ""

		_, err := loadAWSConfig(context.Background(), "")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "--aws-shared-credentials-file") {
			t.Fatalf("expected shared credentials file validation error, got %v", err)
		}
	})

	t.Run("validates credential process even when profile is set", func(t *testing.T) {
		syncAWSConfigFile = ""
		syncAWSSharedCredsFile = ""
		syncAWSCredentialProc = "credential-helper --profile prod"

		_, err := loadAWSConfig(context.Background(), "prod")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "absolute executable path") {
			t.Fatalf("expected credential process validation error, got %v", err)
		}
	})
}

func TestValidateAWSCredentialProcess(t *testing.T) {
	helperPath := filepath.Join(t.TempDir(), "credential-helper")
	if err := os.WriteFile(helperPath, []byte("#!/bin/sh\necho credentials\n"), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	t.Run("requires absolute executable path", func(t *testing.T) {
		err := validateAWSCredentialProcess("helper --profile prod", "--aws-credential-process")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "absolute executable path") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects shell operators", func(t *testing.T) {
		err := validateAWSCredentialProcess(helperPath+";echo hacked", "--aws-credential-process")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "disallowed shell operators") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("allows absolute path without allowlist", func(t *testing.T) {
		t.Setenv("CEREBRO_AWS_CREDENTIAL_PROCESS_ALLOWLIST", "")
		err := validateAWSCredentialProcess(helperPath+" --profile prod", "--aws-credential-process")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("enforces allowlist", func(t *testing.T) {
		t.Setenv("CEREBRO_AWS_CREDENTIAL_PROCESS_ALLOWLIST", "/usr/local/bin")
		err := validateAWSCredentialProcess(helperPath+" --profile prod", "--aws-credential-process")
		if err == nil {
			t.Fatal("expected allowlist error")
		}
		if !strings.Contains(err.Error(), "not permitted") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("allowlist accepts quoted path", func(t *testing.T) {
		t.Setenv("CEREBRO_AWS_CREDENTIAL_PROCESS_ALLOWLIST", filepath.Dir(helperPath))
		err := validateAWSCredentialProcess("\""+helperPath+"\" --profile prod", "--aws-credential-process")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestLooksLikePlaceholderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "placeholder prefix", value: "PLACEHOLDER_AWS_PROFILE", want: true},
		{name: "replace me", value: "replace_me", want: true},
		{name: "change me", value: "change_me", want: true},
		{name: "regular value", value: "cerebro-prod", want: false},
		{name: "empty value", value: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikePlaceholderValue(tt.value); got != tt.want {
				t.Fatalf("looksLikePlaceholderValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestSanitizeAWSAuthEnv(t *testing.T) {
	validDir := t.TempDir()
	validConfig := filepath.Join(validDir, "config")
	validToken := filepath.Join(validDir, "token.jwt")
	missingCreds := filepath.Join(validDir, "missing-credentials")

	if err := os.WriteFile(validConfig, []byte("[default]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatalf("write valid config: %v", err)
	}
	if err := os.WriteFile(validToken, []byte("token"), 0o600); err != nil {
		t.Fatalf("write valid token: %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "PLACEHOLDER_AWS_ACCESS_KEY_ID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "PLACEHOLDER_AWS_SECRET_ACCESS_KEY")
	t.Setenv("AWS_SESSION_TOKEN", "PLACEHOLDER_AWS_SESSION_TOKEN")
	t.Setenv("AWS_PROFILE", "PLACEHOLDER_AWS_PROFILE")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missingCreds)
	t.Setenv("AWS_CONFIG_FILE", validConfig)
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", validToken)

	cleanup := sanitizeAWSAuthEnv()

	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		if got := os.Getenv(key); got != "" {
			t.Fatalf("expected %s to be unset, got %q", key, got)
		}
	}

	if got := os.Getenv("AWS_CONFIG_FILE"); got != validConfig {
		t.Fatalf("expected AWS_CONFIG_FILE to remain set, got %q", got)
	}
	if got := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); got != validToken {
		t.Fatalf("expected AWS_WEB_IDENTITY_TOKEN_FILE to remain set, got %q", got)
	}

	cleanup()

	if got := os.Getenv("AWS_PROFILE"); got != "PLACEHOLDER_AWS_PROFILE" {
		t.Fatalf("expected AWS_PROFILE to be restored, got %q", got)
	}
	if got := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); got != missingCreds {
		t.Fatalf("expected AWS_SHARED_CREDENTIALS_FILE to be restored, got %q", got)
	}
}
