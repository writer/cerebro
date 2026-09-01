package graphquery

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type recordingInventoryCatalog struct {
	entities []struct {
		workspaceID string
		entity      ports.CatalogEntity
	}
	entityRequests []ports.EntityCatalogPageRequest
}

func (s *recordingInventoryCatalog) ListEntities(_ context.Context, request ports.EntityCatalogPageRequest) (*ports.EntityCatalogPage, error) {
	s.entityRequests = append(s.entityRequests, request)
	page := &ports.EntityCatalogPage{TenantID: request.Filter.TenantID}
	for _, candidate := range s.entities {
		if request.Filter.ApplicationWorkspaceID != "" && candidate.workspaceID != request.Filter.ApplicationWorkspaceID {
			continue
		}
		if request.Filter.ExactAgentKey != "" && candidate.entity.URN != request.Filter.ExactAgentKey {
			continue
		}
		page.Entities = append(page.Entities, candidate.entity)
	}
	return page, nil
}

func (s *recordingInventoryCatalog) CountEntityKinds(_ context.Context, request ports.EntityKindCountRequest) (*ports.EntityKindCountPage, error) {
	counts := map[string]uint64{}
	for _, candidate := range s.entities {
		if request.Filter.ApplicationWorkspaceID == "" || candidate.workspaceID == request.Filter.ApplicationWorkspaceID {
			counts[candidate.entity.EntityType]++
		}
	}
	page := &ports.EntityKindCountPage{TenantID: request.Filter.TenantID}
	for kind, count := range counts {
		page.Counts = append(page.Counts, ports.EntityKindCount{EntityKind: kind, Count: count})
	}
	return page, nil
}

func (s *recordingInventoryCatalog) ListEntityRelations(context.Context, ports.EntityRelationPageRequest) (*ports.EntityRelationPage, error) {
	return &ports.EntityRelationPage{TenantID: "tenant-a"}, nil
}

func TestInventoryReadsIsolateApplicationWorkspacesAndPreserveTenantWideDefault(t *testing.T) {
	store := &recordingInventoryCatalog{entities: []struct {
		workspaceID string
		entity      ports.CatalogEntity
	}{
		{workspaceID: "workspace-a", entity: ports.CatalogEntity{URN: "urn:cerebro:tenant-a:asset:a", TenantID: "tenant-a", EntityType: "asset", Label: "Asset A"}},
		{workspaceID: "workspace-b", entity: ports.CatalogEntity{URN: "urn:cerebro:tenant-a:asset:b", TenantID: "tenant-a", EntityType: "asset", Label: "Asset B"}},
	}}
	service := NewWithCapabilities(nil, store, nil)

	assetsA, err := service.ListInventoryAssets(context.Background(), InventoryAssetRequest{TenantID: "tenant-a", ApplicationWorkspaceID: " workspace-a ", Limit: 10})
	if err != nil {
		t.Fatalf("ListInventoryAssets(workspace-a) error = %v", err)
	}
	assetsB, err := service.ListInventoryAssets(context.Background(), InventoryAssetRequest{TenantID: "tenant-a", ApplicationWorkspaceID: "workspace-b", Limit: 10})
	if err != nil {
		t.Fatalf("ListInventoryAssets(workspace-b) error = %v", err)
	}
	allAssets, err := service.ListInventoryAssets(context.Background(), InventoryAssetRequest{TenantID: "tenant-a", Limit: 10})
	if err != nil {
		t.Fatalf("ListInventoryAssets(tenant-wide) error = %v", err)
	}
	if len(assetsA) != 1 || !strings.HasSuffix(assetsA[0].URN, ":a") || len(assetsB) != 1 || !strings.HasSuffix(assetsB[0].URN, ":b") || len(allAssets) != 2 {
		t.Fatalf("workspace assets = A:%#v B:%#v all:%#v", assetsA, assetsB, allAssets)
	}
	if _, err := service.GetInventoryAsset(context.Background(), InventoryAssetDetailRequest{URN: "urn:cerebro:tenant-a:asset:b", ApplicationWorkspaceID: "workspace-a", Limit: 10}); !errors.Is(err, ports.ErrGraphEntityNotFound) {
		t.Fatalf("GetInventoryAsset(workspace-a, asset-b) error = %v, want graph entity not found", err)
	}
	if got := store.entityRequests[0].Filter.ApplicationWorkspaceID; got != "workspace-a" {
		t.Fatalf("first recorded filter workspace = %q, want workspace-a", got)
	}
}

func TestInventoryEntityTypesForFilterUsesSynthesizedCategoryID(t *testing.T) {
	got := inventoryEntityTypesForFilter("aws-lambda-function", "")
	want := []string{"aws.lambda.function"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventoryEntityTypesForFilter() = %v, want %v", got, want)
	}
}

func TestInventoryEntityTypesForFilterKeepsKnownGroupedCategory(t *testing.T) {
	got := inventoryEntityTypesForFilter("compute-instances", "")
	want := []string{"aws.ec2.instance", "gcp.compute.instance"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventoryEntityTypesForFilter() = %v, want %v", got, want)
	}
}

func TestInventoryEntityTypesForFilterEntityTypePrecedence(t *testing.T) {
	got := inventoryEntityTypesForFilter("compute-instances", "aws.lambda.function")
	want := []string{"aws.lambda.function"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventoryEntityTypesForFilter() = %v, want %v", got, want)
	}
}

func TestInventorySurfaceForEntityType(t *testing.T) {
	tests := []struct {
		name       string
		entityType string
		want       string
	}{
		{name: "reviewable asset", entityType: "sentinelone.agent", want: InventorySurfaceAsset},
		{name: "component", entityType: "sentinelone.installed_application", want: InventorySurfaceComponent},
		{name: "policy rule component", entityType: "policy.rule", want: InventorySurfaceComponent},
		{name: "evidence requirement component", entityType: "evidence.requirement", want: InventorySurfaceComponent},
		{name: "alias", entityType: "identifier.login", want: InventorySurfaceAlias},
		{name: "signal", entityType: "panopticon.alert", want: InventorySurfaceSignal},
		{name: "coverage gap signal", entityType: "coverage.gap", want: InventorySurfaceSignal},
		{name: "raw record", entityType: "okta.resource", want: InventorySurfaceRawRecord},
		{name: "known finding signal", entityType: "aws.securityhub.finding", want: InventorySurfaceSignal},
		{name: "unknown alert suffix", entityType: "custom_vendor.alert", want: InventorySurfaceAsset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InventorySurfaceForEntityType(tt.entityType); got != tt.want {
				t.Fatalf("InventorySurfaceForEntityType(%q) = %q, want %q", tt.entityType, got, tt.want)
			}
		})
	}
}

func TestNormalizeInventorySurfaceDefaultsToAll(t *testing.T) {
	if got := NormalizeInventorySurface(""); got != InventorySurfaceAll {
		t.Fatalf("NormalizeInventorySurface(\"\") = %q, want %q", got, InventorySurfaceAll)
	}
	if got := NormalizeInventorySurface("unknown"); got != InventorySurfaceAsset {
		t.Fatalf("NormalizeInventorySurface(\"unknown\") = %q, want %q", got, InventorySurfaceAsset)
	}
}

func TestInventorySurfaceParamsDefaultKeepsAllRecords(t *testing.T) {
	clause, params := inventorySurfaceParams("")
	if clause != "" {
		t.Fatalf("inventorySurfaceParams(\"\") clause = %q, want empty clause", clause)
	}
	if len(params) != 0 {
		t.Fatalf("inventorySurfaceParams(\"\") params = %v, want none", params)
	}
}

func TestInventorySurfaceParamsExcludeSupportingRecordsFromAssetSurface(t *testing.T) {
	_, params := inventorySurfaceParams(InventorySurfaceAsset)
	exact, _ := params["surface_excluded_entity_types"].([]string)
	prefixes, _ := params["surface_excluded_prefixes"].([]string)
	suffixes, _ := params["surface_excluded_suffixes"].([]string)
	if !inventoryTestContains(exact, "sentinelone.installed_application") {
		t.Fatalf("asset surface exclusions missing sentinelone.installed_application: %v", exact)
	}
	if !inventoryTestContains(prefixes, "identifier.") {
		t.Fatalf("asset surface prefix exclusions missing identifier.: %v", prefixes)
	}
	if !inventoryTestContains(exact, "aws.securityhub.finding") {
		t.Fatalf("asset surface exact exclusions missing aws.securityhub.finding: %v", exact)
	}
	if len(suffixes) != 0 {
		t.Fatalf("asset surface suffix exclusions = %v, want none", suffixes)
	}
}

func inventoryTestContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
