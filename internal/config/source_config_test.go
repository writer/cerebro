package config

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/sourceconfig"
)

func TestResolveSourceConfigSecretReferencesResolvesEnvValues(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_TOKEN", "secret-token")
	config := map[string]string{ // #nosec G101 -- env-reference test fixture, not credential material.
		"owner": "writer",
		"token": "env:CEREBRO_SOURCE_GITHUB_TOKEN",
	}

	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", config)
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["token"]; got != "secret-token" {
		t.Fatalf("resolved token = %q, want secret-token", got)
	}
	if got := config["token"]; got != "env:CEREBRO_SOURCE_GITHUB_TOKEN" {
		t.Fatalf("input token mutated to %q", got)
	}
}

func TestResolveSourceConfigSecretReferencesRejectsUnsetEnv(t *testing.T) {
	_, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{ // #nosec G101 -- env-reference test fixture, not credential material.
		"token": "env:CEREBRO_SOURCE_GITHUB_TOKEN",
	})
	if err == nil {
		t.Fatal("ResolveSourceConfigSecretReferences() error = nil, want error")
	}
}

func TestResolveSourceConfigSecretReferencesRejectsDisallowedEnv(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "deployment-secret")
	_, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{ // #nosec G101 -- disallowed env-reference fixture, not credential material.
		"token": "env:AWS_SECRET_ACCESS_KEY",
	})
	if err == nil {
		t.Fatal("ResolveSourceConfigSecretReferences() error = nil, want error")
	}
}

func TestResolveSourceConfigSecretReferencesAllowsExplicitEnvAllowlist(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST", "SHARED_GITHUB_TOKEN")
	t.Setenv("SHARED_GITHUB_TOKEN", "secret-token")
	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{ // #nosec G101 -- allowlisted env-reference test fixture, not credential material.
		"token": "env:SHARED_GITHUB_TOKEN",
	})
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["token"]; got != "secret-token" {
		t.Fatalf("resolved token = %q, want secret-token", got)
	}
}

func TestResolveSourceConfigSecretReferencesPreservesLiteralEnvQueryValues(t *testing.T) {
	t.Setenv("prod", "from-env")
	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"phrase": "env:prod",
	})
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["phrase"]; got != "env:prod" {
		t.Fatalf("resolved phrase = %q, want literal env:prod", got)
	}
}

func TestResolveSourceConfigSecretReferencesResolvesAllowedQueryEnvValues(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_PHRASE", "archived:false")
	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "github", map[string]string{
		"phrase": "env:CEREBRO_SOURCE_GITHUB_PHRASE",
	})
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if got := resolved["phrase"]; got != "archived:false" {
		t.Fatalf("resolved phrase = %q, want archived:false", got)
	}
}

func TestResolveSourceRuntimeConfigSecretReferencesResolvesQuerySelectors(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_PHRASE", "archived:false")
	resolved, err := ResolveSourceRuntimeConfigSecretReferences(context.Background(), "github", map[string]string{
		"phrase": "env:CEREBRO_SOURCE_GITHUB_PHRASE",
	})
	if err != nil {
		t.Fatalf("ResolveSourceRuntimeConfigSecretReferences() error = %v", err)
	}
	if got := resolved["phrase"]; got != "archived:false" {
		t.Fatalf("resolved phrase = %q, want archived:false", got)
	}
}

func TestResolveSourceRuntimeConfigSecretReferencesPreservesLiteralEnvQueryValues(t *testing.T) {
	t.Setenv("prod", "from-env")
	resolved, err := ResolveSourceRuntimeConfigSecretReferences(context.Background(), "github", map[string]string{
		"phrase": "env:prod",
	})
	if err != nil {
		t.Fatalf("ResolveSourceRuntimeConfigSecretReferences() error = %v", err)
	}
	if got := resolved["phrase"]; got != "env:prod" {
		t.Fatalf("resolved phrase = %q, want literal env:prod", got)
	}
}

func TestResolveSourceRuntimeConfigInjectsAWSAssumeRoleAllowlist(t *testing.T) {
	t.Setenv(awsAssumeRoleARNsEnv, "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role")
	resolved, err := ResolveSourceRuntimeConfigSecretReferences(context.Background(), "aws", map[string]string{
		sourceconfig.AWSAssumeRoleAllowlistKey: "caller-controlled",
		sourceconfig.RuntimeTenantIDKey:        "writer",
	})
	if err != nil {
		t.Fatalf("ResolveSourceRuntimeConfigSecretReferences() error = %v", err)
	}
	if got := resolved[sourceconfig.AWSAssumeRoleAllowlistKey]; got != "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role" {
		t.Fatalf("resolved assume-role allowlist = %q, want deployment env value", got)
	}
	if got := resolved[sourceconfig.RuntimeTenantIDKey]; got != "writer" {
		t.Fatalf("resolved runtime tenant = %q, want writer", got)
	}
}

func TestResolveSourceRuntimeConfigInjectsAssumeRoleAllowlistForRoleARN(t *testing.T) {
	t.Setenv(awsAssumeRoleARNsEnv, "writer=arn:aws:iam::502497380968:role/cerebro-aurelius-source-dev")
	resolved, err := ResolveSourceRuntimeConfigSecretReferences(context.Background(), "aurelius", map[string]string{
		"bucket":   "writer-aurelius-scan-results-dev",
		"prefix":   "aurelius/verdicts/",
		"role_arn": "arn:aws:iam::502497380968:role/cerebro-aurelius-source-dev",
	})
	if err != nil {
		t.Fatalf("ResolveSourceRuntimeConfigSecretReferences() error = %v", err)
	}
	if got := resolved[sourceconfig.AWSAssumeRoleAllowlistKey]; got != "writer=arn:aws:iam::502497380968:role/cerebro-aurelius-source-dev" {
		t.Fatalf("resolved assume-role allowlist = %q", got)
	}
}

func TestResolveSourceRuntimeConfigInjectsGCPWIFAllowlist(t *testing.T) {
	binding := "writer=//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws|scanner@writer-iam.iam.gserviceaccount.com"
	t.Setenv(gcpWIFBindingsEnv, binding)
	resolved, err := ResolveSourceRuntimeConfigSecretReferences(context.Background(), "gcp", map[string]string{
		"wif_audience":                  "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws",
		"wif_service_account_email":     "scanner@writer-iam.iam.gserviceaccount.com",
		sourceconfig.GCPWIFAllowlistKey: "caller-controlled",
		sourceconfig.RuntimeTenantIDKey: "writer",
	})
	if err != nil {
		t.Fatalf("ResolveSourceRuntimeConfigSecretReferences() error = %v", err)
	}
	if got := resolved[sourceconfig.GCPWIFAllowlistKey]; got != binding {
		t.Fatalf("resolved gcp wif allowlist = %q, want deployment env value", got)
	}
	if got := resolved[sourceconfig.RuntimeTenantIDKey]; got != "writer" {
		t.Fatalf("resolved runtime tenant = %q, want writer", got)
	}
}

func TestResolveSourceRuntimeConfigInjectsGCPWIFAllowlistForWIFConfig(t *testing.T) {
	binding := "writer=//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws|scanner@writer-iam.iam.gserviceaccount.com"
	t.Setenv(gcpWIFBindingsEnv, binding)
	resolved, err := ResolveSourceRuntimeConfigSecretReferences(context.Background(), "custom-gcp-wrapper", map[string]string{
		"wif_audience":              "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws",
		"wif_service_account_email": "scanner@writer-iam.iam.gserviceaccount.com",
	})
	if err != nil {
		t.Fatalf("ResolveSourceRuntimeConfigSecretReferences() error = %v", err)
	}
	if got := resolved[sourceconfig.GCPWIFAllowlistKey]; got != binding {
		t.Fatalf("resolved gcp wif allowlist = %q", got)
	}
}

func TestResolveSourceConfigDoesNotInjectRuntimeAWSAllowlist(t *testing.T) {
	t.Setenv(awsAssumeRoleARNsEnv, "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role")
	t.Setenv(gcpWIFBindingsEnv, "writer=//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws|scanner@writer-iam.iam.gserviceaccount.com")
	resolved, err := ResolveSourceConfigSecretReferences(context.Background(), "aws", map[string]string{
		"account_id": "123456789012",
	})
	if err != nil {
		t.Fatalf("ResolveSourceConfigSecretReferences() error = %v", err)
	}
	if _, ok := resolved[sourceconfig.AWSAssumeRoleAllowlistKey]; ok {
		t.Fatal("direct source config injected runtime AWS assume-role allowlist")
	}
	if _, ok := resolved[sourceconfig.GCPWIFAllowlistKey]; ok {
		t.Fatal("direct source config injected runtime GCP WIF allowlist")
	}
}
