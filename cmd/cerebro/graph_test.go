package main

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestParseGraphIngestArgs(t *testing.T) {
	sourceID, config, tenantID, pageLimit, cursor, err := parseGraphIngestArgs([]string{
		"github",
		"tenant_id=writer",
		"page_limit=5",
		"cursor=next-page",
		"family=audit",
		"owner=WriterInternal",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestArgs() error = %v", err)
	}
	if sourceID != "github" {
		t.Fatalf("sourceID = %q, want github", sourceID)
	}
	if tenantID != "writer" {
		t.Fatalf("tenantID = %q, want writer", tenantID)
	}
	if pageLimit != 5 {
		t.Fatalf("pageLimit = %d, want 5", pageLimit)
	}
	if cursor == nil || cursor.GetOpaque() != "next-page" {
		t.Fatalf("cursor = %#v, want next-page", cursor)
	}
	if config["family"] != "audit" || config["owner"] != "WriterInternal" {
		t.Fatalf("config = %#v, want source config preserved", config)
	}
}

func TestParseGraphIngestArgsDefaultsPageLimit(t *testing.T) {
	_, _, _, pageLimit, _, err := parseGraphIngestArgs([]string{"aws", "family=cloudtrail"})
	if err != nil {
		t.Fatalf("parseGraphIngestArgs() error = %v", err)
	}
	if pageLimit != defaultGraphIngestPageLimit {
		t.Fatalf("pageLimit = %d, want %d", pageLimit, defaultGraphIngestPageLimit)
	}
}

func TestParseGraphIngestArgsRejectsInvalidPageLimit(t *testing.T) {
	_, _, _, _, _, err := parseGraphIngestArgs([]string{"aws", "page_limit=0"})
	if err == nil {
		t.Fatal("parseGraphIngestArgs() error = nil, want non-nil")
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
