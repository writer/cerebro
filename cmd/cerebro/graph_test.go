package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/ports"
)

type cleanupStateStore struct {
	request           ports.ProjectionLinkCleanupRequest
	result            ports.ProjectionLinkCleanupResult
	err               error
	projectionRequest ports.ProjectionCleanupRequest
	projectionResult  ports.ProjectionCleanupResult
}

func (s *cleanupStateStore) Ping(context.Context) error { return nil }

func (s *cleanupStateStore) CleanupEndpointOwnerIDLinks(_ context.Context, request ports.ProjectionLinkCleanupRequest) (ports.ProjectionLinkCleanupResult, error) {
	s.request = request
	return s.result, s.err
}

//nolint:unparam // Test fake keeps the store interface signature, including the error result.
func (s *cleanupStateStore) CleanupProjectedEntities(_ context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	s.projectionRequest = request
	return s.projectionResult, nil
}

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
	config, err := prepareGraphRuntimeSourceConfig(context.Background(), "okta", map[string]string{ // #nosec G101 -- env-reference test fixture, not credential material.
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
		"runtime_ids=writer-github,writer-kolide",
		"status=failed",
		"limit=7",
	})
	if err != nil {
		t.Fatalf("parseGraphIngestRunsArgs() error = %v", err)
	}
	if options.RuntimeID != "writer-github" || options.Status != "failed" || options.Limit != 7 {
		t.Fatalf("options = %#v, want runtime/status/limit", options)
	}
	if got, want := strings.Join(options.RuntimeIDs, ","), "writer-github,writer-kolide"; got != want {
		t.Fatalf("RuntimeIDs = %q, want %q", got, want)
	}
}

func TestParseGraphEndpointOwnerIDCleanupArgsDefaultsDryRun(t *testing.T) {
	options, err := parseGraphEndpointOwnerIDCleanupArgs([]string{
		"tenant_id=writer",
		"source_id=kolide",
		"runtime_id=writer-kolide",
		"limit=25",
	})
	if err != nil {
		t.Fatalf("parseGraphEndpointOwnerIDCleanupArgs() error = %v", err)
	}
	if !options.DryRun || options.TenantID != "writer" || options.SourceID != "kolide" || options.RuntimeID != "writer-kolide" || options.Limit != 25 {
		t.Fatalf("options = %#v, want dry-run scoped cleanup", options)
	}
}

func TestParseGraphEndpointOwnerIDCleanupArgsRequiresApplyForDeletes(t *testing.T) {
	if _, err := parseGraphEndpointOwnerIDCleanupArgs([]string{"tenant_id=writer", "dry_run=false"}); err == nil {
		t.Fatal("parseGraphEndpointOwnerIDCleanupArgs() error = nil, want apply requirement")
	}
	options, err := parseGraphEndpointOwnerIDCleanupArgs([]string{"tenant_id=writer", "apply=true"})
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
		TenantID: "writer",
		SourceID: "kolide",
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("cleanupEndpointOwnerIDLinks() error = %v", err)
	}
	if state.request.TenantID != "writer" || state.request.SourceID != "kolide" || !state.request.DryRun {
		t.Fatalf("cleanup request = %#v, want scoped dry-run", state.request)
	}
	if result.StateStore.LinksMatched != 3 || result.GraphStore.LinksMatched != 0 {
		t.Fatalf("cleanup result = %#v, want state-only result", result)
	}
}

func TestCleanupEndpointOwnerIDLinksTelemetryClassifiesErrors(t *testing.T) {
	state := &cleanupStateStore{err: errors.New("cleanup backend failed credential=fake-sensitive-value")}
	stderr := captureCommandStderr(t, func() {
		_, err := cleanupEndpointOwnerIDLinks(context.Background(), bootstrap.Dependencies{StateStore: state}, graphEndpointOwnerIDCleanupOptions{
			TenantID: "writer",
			DryRun:   true,
		})
		if !errors.Is(err, errEndpointOwnerIDStateCleanupFailed) {
			t.Fatalf("cleanupEndpointOwnerIDLinks() error = %v, want state cleanup failure", err)
		}
	})

	payload := lastCommandTelemetryPayload(t, stderr)
	if got := payload["name"]; got != "projection_cleanup.endpoint_owner_id_links" {
		t.Fatalf("telemetry name = %#v, want projection cleanup; payload=%#v", got, payload)
	}
	if got := payload["status"]; got != "error" {
		t.Fatalf("telemetry status = %#v, want error; payload=%#v", got, payload)
	}
	if got := payload["error_kind"]; got != "state_cleanup_failed" {
		t.Fatalf("telemetry error_kind = %#v, want state_cleanup_failed; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "fake-sensitive-value") || strings.Contains(stderr, "credential=") {
		t.Fatalf("cleanup telemetry leaked raw error: %s", stderr)
	}
}

func TestParseGraphProjectedEntityCleanupArgsDefaultsSafeDryRun(t *testing.T) {
	options, err := parseGraphProjectedEntityCleanupArgs([]string{
		"tenant_id=writer",
		"source_id=example-okta-audit",
		"entity_type=finding,evidence",
		"urn_prefix=urn:cerebro:example:finding:",
		"limit=25",
	})
	if err != nil {
		t.Fatalf("parseGraphProjectedEntityCleanupArgs() error = %v", err)
	}
	if !options.DryRun || !options.OnlyIsolated || options.TenantID != "writer" || options.SourceID != "example-okta-audit" || options.Limit != 25 {
		t.Fatalf("options = %#v, want safe dry-run scoped cleanup", options)
	}
	if !reflect.DeepEqual(options.EntityTypes, []string{"finding", "evidence"}) {
		t.Fatalf("EntityTypes = %#v, want finding/evidence", options.EntityTypes)
	}
	if !reflect.DeepEqual(options.URNPrefixes, []string{"urn:cerebro:example:finding:"}) {
		t.Fatalf("URNPrefixes = %#v, want finding prefix", options.URNPrefixes)
	}
}

func TestParseGraphProjectedEntityCleanupArgsRequiresApplyForDeletes(t *testing.T) {
	args := []string{"tenant_id=writer", "source_id=example-okta-audit", "entity_type=finding", "dry_run=false"}
	if _, err := parseGraphProjectedEntityCleanupArgs(args); err == nil {
		t.Fatal("parseGraphProjectedEntityCleanupArgs() error = nil, want apply requirement")
	}
	options, err := parseGraphProjectedEntityCleanupArgs([]string{"tenant_id=writer", "source_id=example-okta-audit", "entity_type=finding", "apply=true"})
	if err != nil {
		t.Fatalf("parseGraphProjectedEntityCleanupArgs(apply) error = %v", err)
	}
	if options.DryRun {
		t.Fatalf("DryRun = true, want apply mode")
	}
}

func TestParseGraphProjectedEntityCleanupArgsRequiresAllowDetachForBroadDetach(t *testing.T) {
	_, err := parseGraphProjectedEntityCleanupArgs([]string{
		"tenant_id=writer",
		"source_id=example-okta-audit",
		"entity_type=finding",
		"only_isolated=false",
	})
	if err == nil {
		t.Fatal("parseGraphProjectedEntityCleanupArgs() error = nil, want allow_detach requirement")
	}
}

func TestParseGraphProjectedEntityCleanupArgsRequiresAllowDetachForFindingDeletes(t *testing.T) {
	_, err := parseGraphProjectedEntityCleanupArgs([]string{
		"tenant_id=writer",
		"finding_id=finding-1",
		"apply=true",
	})
	if err == nil {
		t.Fatal("parseGraphProjectedEntityCleanupArgs() error = nil, want finding detach opt-in requirement")
	}
	options, err := parseGraphProjectedEntityCleanupArgs([]string{
		"tenant_id=writer",
		"finding_id=finding-1",
		"apply=true",
		"allow_detach=true",
	})
	if err != nil {
		t.Fatalf("parseGraphProjectedEntityCleanupArgs(allow_detach) error = %v", err)
	}
	if options.DryRun || !options.AllowDetach {
		t.Fatalf("options = %#v, want apply mode with detach opt-in", options)
	}
}

func TestCleanupProjectedEntitiesAllowsStateStoreOnly(t *testing.T) {
	state := &cleanupStateStore{projectionResult: ports.ProjectionCleanupResult{EntitiesMatched: 3}}
	result, err := cleanupProjectedEntities(context.Background(), bootstrap.Dependencies{StateStore: state}, graphProjectedEntityCleanupOptions{
		TenantID:     "writer",
		SourceID:     "example-okta-audit",
		EntityTypes:  []string{"finding"},
		OnlyIsolated: true,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("cleanupProjectedEntities() error = %v", err)
	}
	if state.projectionRequest.TenantID != "writer" || state.projectionRequest.SourceID != "example-okta-audit" || !state.projectionRequest.DryRun || !state.projectionRequest.OnlyIsolated {
		t.Fatalf("cleanup request = %#v, want scoped dry-run", state.projectionRequest)
	}
	if result.StateStore.EntitiesMatched != 3 || result.GraphStore.EntitiesMatched != 0 {
		t.Fatalf("cleanup result = %#v, want state-only result", result)
	}
}

func TestParseGraphOpenFindingPrimaryLinkRepairArgsDefaultsDryRun(t *testing.T) {
	options, err := parseGraphOpenFindingPrimaryLinkRepairArgs([]string{"limit=7"})
	if err != nil {
		t.Fatalf("parseGraphOpenFindingPrimaryLinkRepairArgs() error = %v", err)
	}
	if !options.DryRun || options.Limit != 7 {
		t.Fatalf("options = %#v, want dry-run limit 7", options)
	}
}

func TestParseGraphOpenFindingPrimaryLinkRepairArgsRequiresApply(t *testing.T) {
	if _, err := parseGraphOpenFindingPrimaryLinkRepairArgs([]string{"dry_run=false"}); err == nil {
		t.Fatal("parseGraphOpenFindingPrimaryLinkRepairArgs() error = nil, want apply requirement")
	}
	options, err := parseGraphOpenFindingPrimaryLinkRepairArgs([]string{"apply=true"})
	if err != nil {
		t.Fatalf("parseGraphOpenFindingPrimaryLinkRepairArgs(apply) error = %v", err)
	}
	if options.DryRun {
		t.Fatalf("DryRun = true, want apply mode")
	}
}

func TestRepairOpenFindingPrimaryLinksCreatesMissingEdge(t *testing.T) {
	store := newGraphTestStore()
	resourceURN := "urn:cerebro:writer:resource:primary"
	findingURN := "urn:cerebro:writer:finding:finding-1"
	if err := store.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   "writer",
		SourceID:   "example",
		EntityType: "resource",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(resource) error = %v", err)
	}
	if err := store.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        findingURN,
		TenantID:   "writer",
		SourceID:   "example",
		RuntimeID:  "example-runtime",
		EntityType: "finding",
		Attributes: map[string]string{
			"status":               "open",
			"primary_resource_urn": resourceURN,
		},
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(finding) error = %v", err)
	}

	dryRun, err := repairOpenFindingPrimaryLinks(context.Background(), bootstrap.Dependencies{GraphStore: store}, graphOpenFindingPrimaryLinkRepairOptions{DryRun: true})
	if err != nil {
		t.Fatalf("repairOpenFindingPrimaryLinks(dry-run) error = %v", err)
	}
	if dryRun.LinksMatched != 1 || dryRun.LinksCreated != 0 || !dryRun.DryRun {
		t.Fatalf("dryRun result = %#v, want one matched and no creates", dryRun)
	}
	applied, err := repairOpenFindingPrimaryLinks(context.Background(), bootstrap.Dependencies{GraphStore: store}, graphOpenFindingPrimaryLinkRepairOptions{DryRun: false})
	if err != nil {
		t.Fatalf("repairOpenFindingPrimaryLinks(apply) error = %v", err)
	}
	if applied.LinksMatched != 1 || applied.LinksCreated != 1 || applied.DryRun {
		t.Fatalf("applied result = %#v, want one created", applied)
	}
	if _, ok := store.links[resourceURN+"|has_finding|"+findingURN]; !ok {
		t.Fatal("missing repaired has_finding edge")
	}
}

func TestParseGraphBackfillEntityTypedPropertiesArgsDefaultsDryRun(t *testing.T) {
	options, err := parseGraphBackfillEntityTypedPropertiesArgs([]string{"batch_size=100"})
	if err != nil {
		t.Fatalf("parseGraphBackfillEntityTypedPropertiesArgs() error = %v", err)
	}
	if !options.DryRun || options.BatchSize != 100 {
		t.Fatalf("options = %#v, want dry-run batch_size 100", options)
	}
}

func TestParseGraphBackfillEntityTypedPropertiesArgsRequiresApply(t *testing.T) {
	if _, err := parseGraphBackfillEntityTypedPropertiesArgs([]string{"dry_run=false"}); err == nil {
		t.Fatal("parseGraphBackfillEntityTypedPropertiesArgs() error = nil, want apply requirement")
	}
	if _, err := parseGraphBackfillEntityTypedPropertiesArgs([]string{"apply=true", "dry_run=true"}); err == nil {
		t.Fatal("parseGraphBackfillEntityTypedPropertiesArgs(apply+dry_run) error = nil, want conflict")
	}
	options, err := parseGraphBackfillEntityTypedPropertiesArgs([]string{"apply=true"})
	if err != nil {
		t.Fatalf("parseGraphBackfillEntityTypedPropertiesArgs(apply) error = %v", err)
	}
	if options.DryRun {
		t.Fatalf("DryRun = true, want apply mode")
	}
}

func TestBackfillEntityTypedPropertiesForwardsOptions(t *testing.T) {
	store := newGraphTestStore()
	if err := store.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:aws_user:admin",
		TenantID:   "writer",
		SourceID:   "aws",
		EntityType: "aws.user",
		Attributes: map[string]string{"is_admin": "true"},
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity() error = %v", err)
	}

	dryRun, err := backfillEntityTypedProperties(context.Background(), bootstrap.Dependencies{GraphStore: store}, graphBackfillEntityTypedPropertiesOptions{DryRun: true})
	if err != nil {
		t.Fatalf("backfillEntityTypedProperties(dry-run) error = %v", err)
	}
	if dryRun.EntitiesMatched != 1 || dryRun.EntitiesUpdated != 0 || !dryRun.DryRun {
		t.Fatalf("dryRun result = %#v, want one matched and no updates", dryRun)
	}
	applied, err := backfillEntityTypedProperties(context.Background(), bootstrap.Dependencies{GraphStore: store}, graphBackfillEntityTypedPropertiesOptions{DryRun: false})
	if err != nil {
		t.Fatalf("backfillEntityTypedProperties(apply) error = %v", err)
	}
	if applied.EntitiesUpdated != 1 || applied.Batches != 1 || applied.DryRun {
		t.Fatalf("applied result = %#v, want one updated in one batch", applied)
	}
}

func TestBackfillEntityTypedPropertiesUnsupportedStore(t *testing.T) {
	if _, err := backfillEntityTypedProperties(context.Background(), bootstrap.Dependencies{}, graphBackfillEntityTypedPropertiesOptions{DryRun: true}); err == nil {
		t.Fatal("backfillEntityTypedProperties() error = nil, want unsupported store error")
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
