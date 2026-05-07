package main

import (
	"context"
	"testing"
	"time"

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

func TestParseGraphIngestRuntimeArgs(t *testing.T) {
	options, err := parseGraphIngestRuntimeArgs([]string{
		"writer-github",
		"page_limit=3",
		"checkpoint_id=runtime-writer-github",
		"reset_checkpoint=true",
		"interval=30s",
		"iterations=2",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestRuntimeArgs() error = %v", err)
	}
	if options.RuntimeID != "writer-github" {
		t.Fatalf("RuntimeID = %q, want writer-github", options.RuntimeID)
	}
	if options.PageLimit != 3 {
		t.Fatalf("PageLimit = %d, want 3", options.PageLimit)
	}
	if options.CheckpointID != "runtime-writer-github" || !options.ResetCheckpoint {
		t.Fatalf("checkpoint options = id:%q reset:%t", options.CheckpointID, options.ResetCheckpoint)
	}
	if options.Interval != 30*time.Second || options.Iterations != 2 || options.RunForever {
		t.Fatalf("schedule options = interval:%s iterations:%d forever:%t", options.Interval, options.Iterations, options.RunForever)
	}
}

func TestParseGraphIngestRuntimeArgsRequiresIntervalForSchedule(t *testing.T) {
	_, err := parseGraphIngestRuntimeArgs([]string{"writer-github", "iterations=2"})
	if err == nil {
		t.Fatal("parseGraphIngestRuntimeArgs() error = nil, want non-nil")
	}
}

func TestPrepareGraphRuntimeSourceConfigResolvesEnvReferences(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_OKTA_TOKEN", "resolved-token")
	config, err := prepareGraphRuntimeSourceConfig(context.Background(), "okta", map[string]string{
		"token": "env:CEREBRO_SOURCE_OKTA_TOKEN",
	})
	if err != nil {
		t.Fatalf("prepareGraphRuntimeSourceConfig() error = %v", err)
	}
	if got := config["token"]; got != "resolved-token" {
		t.Fatalf("config[token] = %q, want resolved-token", got)
	}
}

func TestPrepareGraphRuntimeSourceConfigDoesNotHydrateGitHubFromLocalCLI(t *testing.T) {
	config, err := prepareGraphRuntimeSourceConfig(context.Background(), githubSourceID, map[string]string{
		"family": "pull_request",
		"owner":  "writer",
	})
	if err != nil {
		t.Fatalf("prepareGraphRuntimeSourceConfig() error = %v", err)
	}
	if got := config["owner"]; got != "writer" {
		t.Fatalf("config[owner] = %q, want writer", got)
	}
	if _, ok := config["repo"]; ok {
		t.Fatalf("config[repo] was hydrated from local gh state: %#v", config)
	}
	if _, ok := config["token"]; ok {
		t.Fatalf("config[token] was hydrated from local gh auth: %#v", config)
	}
}

func TestParseGraphIngestRunsArgs(t *testing.T) {
	options, err := parseGraphIngestRunsArgs([]string{
		"runtime_id=writer-github",
		"status=failed",
		"limit=7",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestRunsArgs() error = %v", err)
	}
	if options.RuntimeID != "writer-github" || options.Status != "failed" || options.Limit != 7 {
		t.Fatalf("options = %#v, want runtime/status/limit", options)
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

func TestParseGraphImpactArgs(t *testing.T) {
	request, err := parseGraphImpactArgs([]string{"cve-impact", "CVE-2026-4242", "tenant_id=writer", "limit=25", "depth=3"})
	if err != nil {
		t.Fatalf("parseGraphImpactArgs() error = %v", err)
	}
	if request.Kind != "vulnerability" || request.Identifier != "CVE-2026-4242" || request.TenantID != "writer" {
		t.Fatalf("request = %#v, want vulnerability request", request)
	}
	if request.Limit != 25 || request.Depth != 3 {
		t.Fatalf("limit/depth = %d/%d, want 25/3", request.Limit, request.Depth)
	}
}

func TestParseGraphImpactArgsRejectsExplicitZeroBounds(t *testing.T) {
	for _, args := range [][]string{
		{"cve-impact", "CVE-2026-4242", "tenant_id=writer", "limit=0"},
		{"cve-impact", "CVE-2026-4242", "tenant_id=writer", "depth=0"},
	} {
		if _, err := parseGraphImpactArgs(args); err == nil {
			t.Fatalf("parseGraphImpactArgs(%v) error = nil, want non-nil", args)
		}
	}
}

func TestParseGraphImpactArgsRequiresTenantForPackage(t *testing.T) {
	if _, err := parseGraphImpactArgs([]string{"package-exposure", "pkg:npm/foo@1.2.3"}); err == nil {
		t.Fatal("parseGraphImpactArgs() error = nil, want tenant requirement")
	}
}

func TestParseGraphImpactArgsAllowsAssetURNWithoutTenant(t *testing.T) {
	request, err := parseGraphImpactArgs([]string{"asset-vulns", "urn:cerebro:writer:sentinelone_agent:agent-1"})
	if err != nil {
		t.Fatalf("parseGraphImpactArgs() error = %v", err)
	}
	if request.Kind != "asset" || request.RootURN != "urn:cerebro:writer:sentinelone_agent:agent-1" {
		t.Fatalf("request = %#v, want asset root request", request)
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
