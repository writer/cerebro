package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRunRejectsUnsupportedCommand(t *testing.T) {
	err := run([]string{"unsupported"})
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("run(unsupported) error = %v, want usageError", err)
	}
}

func TestParseSourceRuntimePutArgsSeparatesTenantID(t *testing.T) {
	t.Setenv("CEREBRO_TEST_TOKEN", "test")
	runtime, err := parseSourceRuntimePutArgs([]string{
		"writer-okta-users",
		"okta",
		"tenant_id=writer",
		"domain=writer.okta.com",
		"family=user",
		"token=env:CEREBRO_TEST_TOKEN",
	})
	if err != nil {
		t.Fatalf("parseSourceRuntimePutArgs() error = %v", err)
	}
	if got := runtime.GetTenantId(); got != "writer" {
		t.Fatalf("runtime.TenantId = %q, want %q", got, "writer")
	}
	if got := runtime.GetConfig()["domain"]; got != "writer.okta.com" {
		t.Fatalf("runtime.Config[domain] = %q, want %q", got, "writer.okta.com")
	}
	if _, ok := runtime.GetConfig()["tenant_id"]; ok {
		t.Fatal("runtime.Config[tenant_id] present, want omitted")
	}
}

func TestParseSourceCommandArgsRejectsLiteralSensitiveValues(t *testing.T) {
	for _, arg := range []string{
		"token=test-token",
		"clientSecret=test-secret",
		"apiKey=test-key",
		"privateKey=test-key",
	} {
		t.Run(arg, func(t *testing.T) {
			_, _, _, err := parseSourceCommandArgs([]string{"github", arg})
			if err == nil {
				t.Fatal("parseSourceCommandArgs() error = nil, want non-nil")
			}
			if strings.Contains(fmt.Sprint(err), "test-") {
				t.Fatalf("parseSourceCommandArgs() error leaked literal value: %v", err)
			}
		})
	}
}

func TestParseSourceArgsAllowNonSecretAccessKeyID(t *testing.T) {
	_, config, _, err := parseSourceCommandArgs([]string{"aws", "access_key_id=access-key-id"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if got := config["access_key_id"]; got != "access-key-id" {
		t.Fatalf("config[access_key_id] = %q, want access-key-id", got)
	}
	runtime, err := parseSourceRuntimePutArgs([]string{"writer-aws", "aws", "access_key_id=access-key-id"})
	if err != nil {
		t.Fatalf("parseSourceRuntimePutArgs() error = %v", err)
	}
	if got := runtime.GetConfig()["access_key_id"]; got != "access-key-id" {
		t.Fatalf("runtime config[access_key_id] = %q, want access-key-id", got)
	}
}

func TestParseSourceCommandArgsResolvesEnvReferences(t *testing.T) {
	t.Setenv("CEREBRO_TEST_TOKEN", "test-token")
	sourceID, config, cursor, err := parseSourceCommandArgs([]string{
		"github",
		"token=env:CEREBRO_TEST_TOKEN",
		"lookup_key=email",
		"cursor=opaque",
	})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if sourceID != "github" {
		t.Fatalf("sourceID = %q, want github", sourceID)
	}
	if got := config["token"]; got != "test-token" {
		t.Fatalf("config[token] = %q, want env value", got)
	}
	if got := config["lookup_key"]; got != "email" {
		t.Fatalf("config[lookup_key] = %q, want email", got)
	}
	if cursor.GetOpaque() != "opaque" {
		t.Fatalf("cursor = %q, want opaque", cursor.GetOpaque())
	}
}

func TestParseSourceCommandArgsPreservesEnvPrefixForNonSensitiveValues(t *testing.T) {
	t.Setenv("prod", "from-env")
	_, config, _, err := parseSourceCommandArgs([]string{"github", "phrase=env:prod"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if got := config["phrase"]; got != "env:prod" {
		t.Fatalf("config[phrase] = %q, want literal env:prod", got)
	}
}

func TestParseSourceCommandArgsResolvesEnvReferencesForNonSensitiveValues(t *testing.T) {
	t.Setenv("CEREBRO_TEST_OKTA_DOMAIN", "writer.okta.com")
	_, config, _, err := parseSourceCommandArgs([]string{"okta", "domain=env:CEREBRO_TEST_OKTA_DOMAIN"})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if got := config["domain"]; got != "writer.okta.com" {
		t.Fatalf("config[domain] = %q, want %q", got, "writer.okta.com")
	}
}

func TestParseSourceCommandArgsRejectsUnsetSensitiveEnvReference(t *testing.T) {
	_, _, _, err := parseSourceCommandArgs([]string{"github", "token=env:CEREBRO_MISSING_TOKEN"})
	if err == nil {
		t.Fatal("parseSourceCommandArgs() error = nil, want non-nil")
	}
	if strings.Contains(fmt.Sprint(err), "token=env:") {
		t.Fatalf("parseSourceCommandArgs() error leaked argument: %v", err)
	}
}
