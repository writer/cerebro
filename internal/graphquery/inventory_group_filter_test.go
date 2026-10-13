package graphquery

import (
	"context"
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func inventoryGroupCatalog(entityTypes ...string) *recordingInventoryCatalog {
	entities := make([]struct {
		workspaceID string
		entity      ports.CatalogEntity
	}, 0, len(entityTypes))
	for _, entityType := range entityTypes {
		entities = append(entities, struct {
			workspaceID string
			entity      ports.CatalogEntity
		}{entity: ports.CatalogEntity{
			URN:        "urn:cerebro:tenant-a:asset:" + entityType,
			TenantID:   "tenant-a",
			EntityType: entityType,
			Label:      entityType,
		}})
	}
	return &recordingInventoryCatalog{entities: entities}
}

// The entity types inside a group are assembled at projection time, so the
// group has to resolve against the kinds the catalog actually reports.
func TestInventoryGroupFilterResolvesLiveEntityKinds(t *testing.T) {
	store := inventoryGroupCatalog("okta.user", "aws.role", "aws.ec2.instance", "github.code.repository")
	service := NewWithCapabilities(nil, store, nil)

	if _, err := service.ListInventoryAssets(context.Background(), InventoryAssetRequest{TenantID: "tenant-a", CategoryID: "iam", Limit: 10}); err != nil {
		t.Fatalf("ListInventoryAssets(iam) error = %v", err)
	}
	if len(store.entityRequests) != 1 {
		t.Fatalf("expected one entity listing, got %d", len(store.entityRequests))
	}
	if got, want := store.entityRequests[0].Filter.IncludeKinds, []string{"aws.role", "okta.user"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("iam resolved to %v, want %v", got, want)
	}
}

// Without the empty-group guard the filter stays unset and the catalog returns
// every kind, which would show cloud resources under an empty Secrets page.
func TestInventoryEmptyGroupReturnsNothingRatherThanEverything(t *testing.T) {
	store := inventoryGroupCatalog("aws.ec2.instance", "okta.user")
	service := NewWithCapabilities(nil, store, nil)

	assets, err := service.ListInventoryAssets(context.Background(), InventoryAssetRequest{TenantID: "tenant-a", CategoryID: "secrets", Limit: 10})
	if err != nil {
		t.Fatalf("ListInventoryAssets(secrets) error = %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets for an unpopulated group, got %d", len(assets))
	}
	if len(store.entityRequests) != 0 {
		t.Fatalf("expected no entity listing for an unpopulated group, got %d", len(store.entityRequests))
	}
}

func TestInventoryPerClassCategoryStillResolvesThroughTheClassMap(t *testing.T) {
	store := inventoryGroupCatalog("aws.ec2.instance", "okta.user")
	service := NewWithCapabilities(nil, store, nil)

	if _, err := service.ListInventoryAssets(context.Background(), InventoryAssetRequest{TenantID: "tenant-a", CategoryID: "compute-instances", Limit: 10}); err != nil {
		t.Fatalf("ListInventoryAssets(compute-instances) error = %v", err)
	}
	if got, want := store.entityRequests[0].Filter.IncludeKinds, []string{"aws.ec2.instance", "gcp.compute.instance"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("compute-instances resolved to %v, want %v", got, want)
	}
}

func TestInventoryEntityTypeTakesPrecedenceOverGroup(t *testing.T) {
	store := inventoryGroupCatalog("okta.user", "aws.role")
	service := NewWithCapabilities(nil, store, nil)

	if _, err := service.ListInventoryAssets(context.Background(), InventoryAssetRequest{TenantID: "tenant-a", CategoryID: "iam", EntityType: "aws.role", Limit: 10}); err != nil {
		t.Fatalf("ListInventoryAssets error = %v", err)
	}
	if got, want := store.entityRequests[0].Filter.IncludeKinds, []string{"aws.role"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entity_type resolved to %v, want %v", got, want)
	}
}

func TestInventoryCategoriesReportTheirGroup(t *testing.T) {
	store := inventoryGroupCatalog("okta.user", "aws.ec2.instance", "policy")
	service := NewWithCapabilities(nil, store, nil)

	categories, err := service.ListInventoryCategories(context.Background(), InventoryCategoryRequest{TenantID: "tenant-a", Limit: 10})
	if err != nil {
		t.Fatalf("ListInventoryCategories error = %v", err)
	}
	groups := map[string]string{}
	for _, category := range categories {
		groups[category.ID] = category.Group
	}
	if groups["people"] != InventoryGroupIAM {
		t.Fatalf("expected the people class to report iam, got %q", groups["people"])
	}
	if groups["compute-instances"] != InventoryGroupCloud {
		t.Fatalf("expected the compute class to report cloud, got %q", groups["compute-instances"])
	}
	if groups["policy"] != "" {
		t.Fatalf("expected an ungrouped class to report no group, got %q", groups["policy"])
	}
}
