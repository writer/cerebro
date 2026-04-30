package main

import "testing"

func TestParseSourceCommandArgsRejectsSensitiveLiteral(t *testing.T) {
	_, _, _, err := parseSourceCommandArgs([]string{"github", "token=secret"})
	if err == nil {
		t.Fatal("parseSourceCommandArgs() error = nil, want non-nil")
	}
}

func TestParseSourceCommandArgsReadsSensitiveEnv(t *testing.T) {
	t.Setenv("CEREBRO_TEST_SOURCE_TOKEN", "secret")
	sourceID, config, cursor, err := parseSourceCommandArgs([]string{
		"github",
		"token=env:CEREBRO_TEST_SOURCE_TOKEN",
		"owner=writer",
		"cursor=2",
	})
	if err != nil {
		t.Fatalf("parseSourceCommandArgs() error = %v", err)
	}
	if sourceID != "github" {
		t.Fatalf("sourceID = %q, want github", sourceID)
	}
	if config["token"] != "secret" {
		t.Fatalf("config[token] = %q, want secret", config["token"])
	}
	if config["owner"] != "writer" {
		t.Fatalf("config[owner] = %q, want writer", config["owner"])
	}
	if cursor == nil || cursor.GetOpaque() != "2" {
		t.Fatalf("cursor = %#v, want opaque 2", cursor)
	}
}

func TestParseSourceRuntimePutArgsSeparatesTenantID(t *testing.T) {
	runtime, err := parseSourceRuntimePutArgs([]string{
		"writer-okta-users",
		"okta",
		"tenant_id=writer",
		"domain=writer.okta.com",
		"family=user",
		"token=test",
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
