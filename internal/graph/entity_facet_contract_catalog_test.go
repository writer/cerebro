package graph

import (
	"testing"
	"time"
)

func TestCompareEntityFacetContractCatalogsMarksVersionBumpedBreakingChangesIncompatible(t *testing.T) {
	baseline := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "1.0.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v1",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "array[string]"},
				},
			},
		},
	}
	current := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "2.0.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v1",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "string"},
				},
			},
		},
	}

	report := CompareEntityFacetContractCatalogs(baseline, current, time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC))
	if report.Compatible {
		t.Fatalf("expected breaking change to be incompatible, got %#v", report)
	}
	if len(report.BreakingChanges) != 1 {
		t.Fatalf("expected exactly one breaking change, got %#v", report.BreakingChanges)
	}
	if len(report.VersioningViolations) != 0 {
		t.Fatalf("expected no versioning violations for version bump, got %#v", report.VersioningViolations)
	}
}

func TestCompareEntityFacetContractCatalogsTreatsAdditiveVersionBumpedChangesAsCompatible(t *testing.T) {
	baseline := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "1.0.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v1",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "array[string]"},
				},
			},
		},
	}
	current := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "1.1.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v1",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "array[string]"},
					{Key: "manager_ids", ValueType: "array[string]"},
				},
			},
		},
	}

	report := CompareEntityFacetContractCatalogs(baseline, current, time.Date(2026, 3, 10, 12, 15, 0, 0, time.UTC))
	if !report.Compatible {
		t.Fatalf("expected additive version-bumped changes to stay compatible, got %#v", report)
	}
	if len(report.BreakingChanges) != 0 {
		t.Fatalf("expected no breaking changes for additive evolution, got %#v", report.BreakingChanges)
	}
	if len(report.VersioningViolations) != 0 {
		t.Fatalf("expected no versioning violations for additive evolution with version bump, got %#v", report.VersioningViolations)
	}
	if len(report.DiffSummaries) != 1 || len(report.DiffSummaries[0].AddedPaths) == 0 {
		t.Fatalf("expected additive diff summary, got %#v", report.DiffSummaries)
	}
	if report.DiffSummaries[0].FacetID != "ownership" {
		t.Fatalf("expected diff summary facet id to be populated, got %#v", report.DiffSummaries[0])
	}
}

func TestCompareEntityFacetContractCatalogsTreatsRemovalAsBreakingNotVersioning(t *testing.T) {
	baseline := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:         "ownership",
				Version:    "1.0.0",
				Title:      "Ownership",
				SchemaName: "PlatformEntityOwnershipFacet",
				SchemaURL:  "urn:cerebro:entity-facet:ownership:v1",
			},
		},
	}
	current := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
	}

	report := CompareEntityFacetContractCatalogs(baseline, current, time.Date(2026, 3, 10, 12, 30, 0, 0, time.UTC))
	if len(report.BreakingChanges) != 1 {
		t.Fatalf("expected a removal to register as one breaking change, got %#v", report.BreakingChanges)
	}
	if len(report.VersioningViolations) != 0 {
		t.Fatalf("expected removals to stay out of versioning violations, got %#v", report.VersioningViolations)
	}
}

func TestCompareEntityFacetContractCatalogsIgnoresDocumentationOnlyChanges(t *testing.T) {
	baseline := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:          "ownership",
				Version:     "1.0.0",
				Title:       "Ownership",
				Description: "Original description",
				SchemaName:  "PlatformEntityOwnershipFacet",
				SchemaURL:   "urn:cerebro:entity-facet:ownership:v1",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "array[string]", Description: "Original field description"},
				},
			},
		},
	}
	current := EntityFacetContractCatalog{
		APIVersion: defaultEntityFacetContractCatalogAPIVersion,
		Kind:       defaultEntityFacetContractCatalogKind,
		Facets: []EntityFacetDefinition{
			{
				ID:          "ownership",
				Version:     "1.0.0",
				Title:       "Owner Context",
				Description: "Updated docs only",
				SchemaName:  "PlatformEntityOwnershipFacet",
				SchemaURL:   "urn:cerebro:entity-facet:ownership:v1",
				Fields: []EntityFacetFieldDefinition{
					{Key: "owner_ids", ValueType: "array[string]", Description: "Updated field documentation"},
				},
			},
		},
	}

	report := CompareEntityFacetContractCatalogs(baseline, current, time.Date(2026, 3, 10, 12, 45, 0, 0, time.UTC))
	if !report.Compatible {
		t.Fatalf("expected documentation-only changes to stay compatible, got %#v", report)
	}
	if len(report.BreakingChanges) != 0 || len(report.VersioningViolations) != 0 || len(report.DiffSummaries) != 0 {
		t.Fatalf("expected no compatibility findings for documentation-only changes, got %#v", report)
	}
}
