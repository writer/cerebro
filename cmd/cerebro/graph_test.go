package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/ports"
)

type cleanupStateStore struct {
	request ports.ProjectionLinkCleanupRequest
	result  ports.ProjectionLinkCleanupResult
}

func (s *cleanupStateStore) Ping(context.Context) error { return nil }

func (s *cleanupStateStore) CleanupEndpointOwnerIDLinks(_ context.Context, request ports.ProjectionLinkCleanupRequest) (ports.ProjectionLinkCleanupResult, error) {
	s.request = request
	return s.result, nil
}

func TestParseGraphIngestArgs(t *testing.T) {
	options, err := parseGraphIngestArgs([]string{
		"github",
		"tenant_id=example",
		"page_limit=5",
		"cursor=next-page",
		"checkpoint=true",
		"checkpoint_id=github-writer",
		"family=audit",
		"owner=ExampleInternal",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestArgs() error = %v", err)
	}
	if options.SourceID != "github" {
		t.Fatalf("SourceID = %q, want github", options.SourceID)
	}
	if options.TenantID != "example" {
		t.Fatalf("TenantID = %q, want example", options.TenantID)
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
	if options.SourceConfig["family"] != "audit" || options.SourceConfig["owner"] != "ExampleInternal" {
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
		"example-github",
		"page_limit=3",
		"checkpoint_id=runtime-example-github",
		"reset_checkpoint=true",
		"interval=30s",
		"iterations=2",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestRuntimeArgs() error = %v", err)
	}
	if options.RuntimeID != "example-github" {
		t.Fatalf("RuntimeID = %q, want example-github", options.RuntimeID)
	}
	if options.PageLimit != 3 {
		t.Fatalf("PageLimit = %d, want 3", options.PageLimit)
	}
	if options.CheckpointID != "runtime-example-github" || !options.ResetCheckpoint {
		t.Fatalf("checkpoint options = id:%q reset:%t", options.CheckpointID, options.ResetCheckpoint)
	}
	if options.Interval != 30*time.Second || options.Iterations != 2 || options.RunForever {
		t.Fatalf("schedule options = interval:%s iterations:%d forever:%t", options.Interval, options.Iterations, options.RunForever)
	}
}

func TestParseGraphIngestRuntimeArgsRequiresIntervalForSchedule(t *testing.T) {
	_, err := parseGraphIngestRuntimeArgs([]string{"example-github", "iterations=2"})
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
		"runtime_id=example-github",
		"status=failed",
		"limit=7",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestRunsArgs() error = %v", err)
	}
	if options.RuntimeID != "example-github" || options.Status != "failed" || options.Limit != 7 {
		t.Fatalf("options = %#v, want runtime/status/limit", options)
	}
}

func TestParseGraphEndpointOwnerIDCleanupArgsDefaultsDryRun(t *testing.T) {
	options, err := parseGraphEndpointOwnerIDCleanupArgs([]string{
		"tenant_id=example",
		"source_id=kolide",
		"runtime_id=example-kolide",
		"limit=25",
	})
	if err != nil {
		t.Fatalf("parseGraphEndpointOwnerIDCleanupArgs() error = %v", err)
	}
	if !options.DryRun || options.TenantID != "example" || options.SourceID != "kolide" || options.RuntimeID != "example-kolide" || options.Limit != 25 {
		t.Fatalf("options = %#v, want dry-run scoped cleanup", options)
	}
}

func TestParseGraphEndpointOwnerIDCleanupArgsRequiresApplyForDeletes(t *testing.T) {
	if _, err := parseGraphEndpointOwnerIDCleanupArgs([]string{"tenant_id=example", "dry_run=false"}); err == nil {
		t.Fatal("parseGraphEndpointOwnerIDCleanupArgs() error = nil, want apply requirement")
	}
	options, err := parseGraphEndpointOwnerIDCleanupArgs([]string{"tenant_id=example", "apply=true"})
	if err != nil {
		t.Fatalf("parseGraphEndpointOwnerIDCleanupArgs(apply) error = %v", err)
	}
	if options.DryRun {
		t.Fatalf("DryRun = true, want apply mode")
	}
}

func TestCleanupEndpointOwnerIDLinksAllowsStateStoreOnly(t *testing.T) {
	state := &cleanupStateStore{result: ports.ProjectionLinkCleanupResult{LinksMatched: 3, LinksDeleted: 0}}
	result, err := cleanupEndpointOwnerIDLinks(context.Background(), bootstrap.Dependencies{StateStore: state}, graphEndpointOwnerIDCleanupOptions{
		TenantID: "example",
		SourceID: "kolide",
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("cleanupEndpointOwnerIDLinks() error = %v", err)
	}
	if state.request.TenantID != "example" || state.request.SourceID != "kolide" || !state.request.DryRun {
		t.Fatalf("cleanup request = %#v, want scoped dry-run", state.request)
	}
	if result.StateStore.LinksMatched != 3 || result.GraphStore.LinksMatched != 0 {
		t.Fatalf("cleanup result = %#v, want state-only result", result)
	}
}

func TestGraphIngestCheckpointIDScrubsSensitiveConfig(t *testing.T) {
	options := graphIngestOptions{
		SourceID: "github",
		TenantID: "example",
		SourceConfig: map[string]string{
			"owner": "ExampleInternal",
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
	rootURN, limit, err := parseGraphNeighborhoodArgs([]string{"root_urn=urn:cerebro:example:github_user:alice", "limit=7"})
	if err != nil {
		t.Fatalf("parseGraphNeighborhoodArgs() error = %v", err)
	}
	if rootURN != "urn:cerebro:example:github_user:alice" {
		t.Fatalf("rootURN = %q, want alice urn", rootURN)
	}
	if limit != 7 {
		t.Fatalf("limit = %d, want 7", limit)
	}
}

func TestParseGraphRelationCountsArgs(t *testing.T) {
	relations, err := parseGraphRelationCountsArgs([]string{"relations=belongs_to, represents,belongs_to,can_reach"})
	if err != nil {
		t.Fatalf("parseGraphRelationCountsArgs() error = %v", err)
	}
	want := []string{"belongs_to", "represents", "can_reach"}
	if !reflect.DeepEqual(relations, want) {
		t.Fatalf("relations = %#v, want %#v", relations, want)
	}
}

func TestParseGraphRelationCountsArgsRequiresRelations(t *testing.T) {
	if _, err := parseGraphRelationCountsArgs(nil); err == nil {
		t.Fatal("parseGraphRelationCountsArgs() error = nil, want non-nil")
	}
}

func TestParseGraphImpactArgs(t *testing.T) {
	request, err := parseGraphImpactArgs([]string{"cve-impact", "CVE-2026-4242", "tenant_id=example", "limit=25", "depth=3"})
	if err != nil {
		t.Fatalf("parseGraphImpactArgs() error = %v", err)
	}
	if request.Kind != "vulnerability" || request.Identifier != "CVE-2026-4242" || request.TenantID != "example" {
		t.Fatalf("request = %#v, want vulnerability request", request)
	}
	if request.Limit != 25 || request.Depth != 3 {
		t.Fatalf("limit/depth = %d/%d, want 25/3", request.Limit, request.Depth)
	}
}

func TestParseGraphImpactArgsRejectsExplicitZeroBounds(t *testing.T) {
	for _, args := range [][]string{
		{"cve-impact", "CVE-2026-4242", "tenant_id=example", "limit=0"},
		{"cve-impact", "CVE-2026-4242", "tenant_id=example", "depth=0"},
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
	request, err := parseGraphImpactArgs([]string{"asset-vulns", "urn:cerebro:example:sentinelone_agent:agent-1"})
	if err != nil {
		t.Fatalf("parseGraphImpactArgs() error = %v", err)
	}
	if request.Kind != "asset" || request.RootURN != "urn:cerebro:example:sentinelone_agent:agent-1" {
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
		"example-github",
		"mode=replay",
		"page_limit=3",
		"event_limit=11",
		"preview_limit=7",
		"dry_run=true",
	})
	if err != nil {
		t.Fatalf("parseGraphRebuildArgs() error = %v", err)
	}
	if runtimeID != "example-github" {
		t.Fatalf("runtimeID = %q, want %q", runtimeID, "example-github")
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
	_, _, _, _, _, _, err := parseGraphRebuildArgs([]string{"example-github", "bogus=1"})
	if err == nil {
		t.Fatal("parseGraphRebuildArgs() error = nil, want usage error")
	}
}
