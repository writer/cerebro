package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyGCPAuth_Noop(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "existing-path")

	cleanup, err := ApplyGCPAuth(context.Background(), GCPAuthConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cleanup()

	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "existing-path" {
		t.Fatalf("expected env unchanged, got %q", got)
	}
}

func TestApplyGCPAuth_CredentialsFileOnly(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "previous-path")

	credsPath := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(credsPath, []byte(`{"type":"service_account"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanup, err := ApplyGCPAuth(context.Background(), GCPAuthConfig{CredentialsFile: credsPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != credsPath {
		t.Fatalf("expected %q, got %q", credsPath, got)
	}

	cleanup()
	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "previous-path" {
		t.Fatalf("expected restored, got %q", got)
	}
}

func TestApplyGCPAuth_CredentialsFileImpersonation(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	sourceCredsPath := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(sourceCredsPath, []byte(`{"type":"authorized_user","client_id":"cid"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanup, err := ApplyGCPAuth(context.Background(), GCPAuthConfig{
		CredentialsFile: sourceCredsPath,
		ImpersonateSA:   "scanner@proj.iam.gserviceaccount.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tmpPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if tmpPath == "" || tmpPath == sourceCredsPath {
		t.Fatalf("expected temp file path, got %q", tmpPath)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["type"] != "impersonated_service_account" {
		t.Fatalf("expected impersonated_service_account, got %v", payload["type"])
	}
	if _, ok := payload["source_credentials"]; !ok {
		t.Fatal("expected source_credentials key")
	}

	cleanup()
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file deleted, stat err=%v", err)
	}
}

func TestApplyGCPAuth_WIFMode(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")

	cleanup, err := ApplyGCPAuth(context.Background(), GCPAuthConfig{
		WIFAudience:   "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
		ImpersonateSA: "scanner@proj.iam.gserviceaccount.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tmpPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if tmpPath == "" {
		t.Fatal("expected GOOGLE_APPLICATION_CREDENTIALS to be set")
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}

	if payload["type"] != "external_account" {
		t.Fatalf("expected external_account type, got %v", payload["type"])
	}
	if payload["subject_token_type"] != "urn:ietf:params:aws:token-type:aws4_request" {
		t.Fatalf("unexpected subject_token_type: %v", payload["subject_token_type"])
	}
	if payload["token_url"] != "https://sts.googleapis.com/v1/token" {
		t.Fatalf("unexpected token_url: %v", payload["token_url"])
	}

	impURL, _ := payload["service_account_impersonation_url"].(string)
	if !strings.Contains(impURL, "scanner%40proj.iam.gserviceaccount.com") && !strings.Contains(impURL, "scanner@proj.iam.gserviceaccount.com") {
		t.Fatalf("expected impersonation URL to contain scanner SA, got %q", impURL)
	}

	credSource, ok := payload["credential_source"].(map[string]interface{})
	if !ok {
		t.Fatal("expected credential_source map")
	}
	if credSource["environment_id"] != "aws1" {
		t.Fatalf("expected aws1 environment_id, got %v", credSource["environment_id"])
	}

	cleanup()
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file deleted after cleanup")
	}
	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "" {
		t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS restored to empty, got %q", got)
	}
}

func TestApplyGCPAuth_WIFModeNoSA(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	cleanup, err := ApplyGCPAuth(context.Background(), GCPAuthConfig{
		WIFAudience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tmpPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	data, _ := os.ReadFile(tmpPath)
	var payload map[string]interface{}
	_ = json.Unmarshal(data, &payload)

	if payload["type"] != "external_account" {
		t.Fatalf("expected external_account, got %v", payload["type"])
	}
	if _, ok := payload["service_account_impersonation_url"]; ok {
		t.Fatal("expected no impersonation URL when SA is empty")
	}

	cleanup()
}

func TestApplyGCPAuth_WIFEnvRestore(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "original-gac")
	t.Setenv("AWS_ACCESS_KEY_ID", "ORIGINAL_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ORIGINAL_SECRET")
	t.Setenv("AWS_SESSION_TOKEN", "ORIGINAL_TOKEN")

	cleanup, err := ApplyGCPAuth(context.Background(), GCPAuthConfig{
		WIFAudience:   "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
		ImpersonateSA: "sa@proj.iam.gserviceaccount.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cleanup()

	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != "original-gac" {
		t.Fatalf("GOOGLE_APPLICATION_CREDENTIALS not restored, got %q", got)
	}
	if got := os.Getenv("AWS_ACCESS_KEY_ID"); got != "ORIGINAL_KEY" {
		t.Fatalf("AWS_ACCESS_KEY_ID not restored, got %q", got)
	}
	if got := os.Getenv("AWS_SECRET_ACCESS_KEY"); got != "ORIGINAL_SECRET" {
		t.Fatalf("AWS_SECRET_ACCESS_KEY not restored, got %q", got)
	}
	if got := os.Getenv("AWS_SESSION_TOKEN"); got != "ORIGINAL_TOKEN" {
		t.Fatalf("AWS_SESSION_TOKEN not restored, got %q", got)
	}
}

func TestApplyGCPAuth_MissingCredentialsFile(t *testing.T) {
	_, err := ApplyGCPAuth(context.Background(), GCPAuthConfig{
		CredentialsFile: "/nonexistent/path/creds.json",
	})
	if err == nil {
		t.Fatal("expected error for missing credentials file")
		return
	}
	if !strings.Contains(err.Error(), "gcp credentials file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGCPAuthConfigFromEnv(t *testing.T) {
	t.Setenv("CEREBRO_GCP_CREDENTIALS_FILE", "/tmp/creds.json")
	t.Setenv("CEREBRO_GCP_IMPERSONATE_SERVICE_ACCOUNT", "sa@proj.iam.gserviceaccount.com")
	t.Setenv("CEREBRO_GCP_IMPERSONATE_DELEGATES", "d1@proj.iam.gserviceaccount.com")
	t.Setenv("CEREBRO_GCP_WIF_AUDIENCE", "//iam.googleapis.com/test")

	cfg := GCPAuthConfigFromEnv()
	if cfg.CredentialsFile != "/tmp/creds.json" {
		t.Fatalf("unexpected CredentialsFile: %q", cfg.CredentialsFile)
	}
	if cfg.ImpersonateSA != "sa@proj.iam.gserviceaccount.com" {
		t.Fatalf("unexpected ImpersonateSA: %q", cfg.ImpersonateSA)
	}
	if cfg.ImpersonateDelegates != "d1@proj.iam.gserviceaccount.com" {
		t.Fatalf("unexpected ImpersonateDelegates: %q", cfg.ImpersonateDelegates)
	}
	if cfg.WIFAudience != "//iam.googleapis.com/test" {
		t.Fatalf("unexpected WIFAudience: %q", cfg.WIFAudience)
	}
}
