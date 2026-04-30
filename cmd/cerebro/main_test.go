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
