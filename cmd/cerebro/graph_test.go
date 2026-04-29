package main

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestParseGraphIngestArgs(t *testing.T) {
	options, err := parseGraphIngestArgs([]string{
		"github",
		"tenant_id=writer",
		"page_limit=5",
		"cursor=next-page",
		"checkpoint=true",
		"checkpoint_id=github-writer",
		"family=audit",
		"owner=WriterInternal",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestArgs() error = %v", err)
	}
	if options.SourceID != "github" {
		t.Fatalf("SourceID = %q, want github", options.SourceID)
	}
	if options.TenantID != "writer" {
		t.Fatalf("TenantID = %q, want writer", options.TenantID)
	}
	if options.PageLimit != 5 {
		t.Fatalf("PageLimit = %d, want 5", options.PageLimit)
	}
	if options.Cursor == nil || options.Cursor.GetOpaque() != "next-page" {
		t.Fatalf("Cursor = %#v, want next-page", options.Cursor)
	}
	if !options.CheckpointEnabled || options.CheckpointID != "github-writer" {
		t.Fatalf("checkpoint options = enabled:%t id:%q, want enabled github-writer", options.CheckpointEnabled, options.CheckpointID)
	}
	if options.SourceConfig["family"] != "audit" || options.SourceConfig["owner"] != "WriterInternal" {
		t.Fatalf("SourceConfig = %#v, want source config preserved", options.SourceConfig)
	}
}

func TestParseGraphIngestArgsDefaultsPageLimit(t *testing.T) {
	options, err := parseGraphIngestArgs([]string{"aws", "family=cloudtrail"})
	if err != nil {
		t.Fatalf("parseGraphIngestArgs() error = %v", err)
	}
	if options.PageLimit != defaultGraphIngestPageLimit {
		t.Fatalf("PageLimit = %d, want %d", options.PageLimit, defaultGraphIngestPageLimit)
	}
}

func TestParseGraphIngestArgsRejectsInvalidPageLimit(t *testing.T) {
	_, err := parseGraphIngestArgs([]string{"aws", "page_limit=0"})
	if err == nil {
		t.Fatal("parseGraphIngestArgs() error = nil, want non-nil")
	}
}

func TestGraphIngestCheckpointIDScrubsSensitiveConfig(t *testing.T) {
	options := graphIngestOptions{
		SourceID: "github",
		TenantID: "writer",
		SourceConfig: map[string]string{
			"owner": "WriterInternal",
			"token": "secret-token-a",
		},
	}
	first := graphIngestCheckpointID(options)
	options.SourceConfig["token"] = "secret-token-b"
	second := graphIngestCheckpointID(options)
	if first != second {
		t.Fatalf("checkpoint id changed after token mutation: %q != %q", first, second)
	}
}

func TestParseGraphNeighborhoodArgs(t *testing.T) {
	rootURN, limit, err := parseGraphNeighborhoodArgs([]string{"root_urn=urn:cerebro:writer:github_user:alice", "limit=7"})
	if err != nil {
		t.Fatalf("parseGraphNeighborhoodArgs() error = %v", err)
	}
	if rootURN != "urn:cerebro:writer:github_user:alice" {
		t.Fatalf("rootURN = %q, want alice urn", rootURN)
	}
	if limit != 7 {
		t.Fatalf("limit = %d, want 7", limit)
	}
}

func TestGraphIngestEventOverridesTenant(t *testing.T) {
	original := &cerebrov1.EventEnvelope{
		Id:       "evt-1",
		TenantId: "aws-account",
		SourceId: "aws",
		Kind:     "aws.cloudtrail",
	}
	cloned := graphIngestEvent(original, "writer")
	if cloned.GetTenantId() != "writer" {
		t.Fatalf("cloned.TenantId = %q, want writer", cloned.GetTenantId())
	}
	if original.GetTenantId() != "aws-account" {
		t.Fatalf("original.TenantId = %q, want unchanged aws-account", original.GetTenantId())
	}
}

func TestParseGraphRebuildArgs(t *testing.T) {
	runtimeID, mode, pageLimit, eventLimit, previewLimit, dryRun, err := parseGraphRebuildArgs([]string{
		"writer-github",
		"mode=replay",
		"page_limit=3",
		"event_limit=11",
		"preview_limit=7",
		"dry_run=true",
	})
	if err != nil {
		t.Fatalf("parseGraphRebuildArgs() error = %v", err)
	}
	if runtimeID != "writer-github" {
		t.Fatalf("runtimeID = %q, want %q", runtimeID, "writer-github")
	}
	if mode != "replay" {
		t.Fatalf("mode = %q, want %q", mode, "replay")
	}
	if pageLimit != 3 {
		t.Fatalf("pageLimit = %d, want 3", pageLimit)
	}
	if eventLimit != 11 {
		t.Fatalf("eventLimit = %d, want 11", eventLimit)
	}
	if previewLimit != 7 {
		t.Fatalf("previewLimit = %d, want 7", previewLimit)
	}
	if !dryRun {
		t.Fatalf("dryRun = %t, want true", dryRun)
	}
}

func TestParseGraphRebuildArgsRejectsUnknownKey(t *testing.T) {
	_, _, _, _, _, _, err := parseGraphRebuildArgs([]string{"writer-github", "bogus=1"})
	if err == nil {
		t.Fatal("parseGraphRebuildArgs() error = nil, want usage error")
	}
}
