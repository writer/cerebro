package sourceprojection

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

func TestBuiltinRegistryRegistersGenerateableCatalogProjectors(t *testing.T) {
	catalog, err := connectorcatalog.Builtin()
	if err != nil {
		t.Fatalf("connectorcatalog.Builtin() error = %v", err)
	}
	registry := BuiltinRegistry()
	for _, entry := range catalog.Entries {
		if entry.Status != connectorcatalog.StatusGenerateable {
			continue
		}
		for _, resource := range entry.Definition.ResourceFamilies {
			kind := catalogRuntimeEventKind(entry.Definition.SourceID, resource)
			if kind == "" {
				t.Fatalf("%s resource %s generated empty event kind", entry.Definition.SourceID, resource.ID)
			}
			if _, ok := registry.projectors[kind]; !ok {
				t.Fatalf("BuiltinRegistry() missing catalog-runtime projector for %s", kind)
			}
		}
	}
}

func TestGeneratedCatalogAssetProjectorMaterializesGraphAsset(t *testing.T) {
	projector := BuiltinRegistry().projectors["akeneo.asset"]
	if projector == nil {
		t.Fatal("BuiltinRegistry() missing akeneo.asset projector")
	}
	entities, links, err := projector(&cerebrov1.EventEnvelope{
		Id:       "event-akeneo-asset-1",
		TenantId: "tenant",
		SourceId: "akeneo",
		Kind:     "akeneo.asset",
		Attributes: map[string]string{
			"resource_id":                       "asset-123",
			"resource_name":                     "Laptop fleet",
			"resource_type":                     "asset",
			ports.EventAttributeSourceRuntimeID: "akeneo-runtime",
		},
	})
	if err != nil {
		t.Fatalf("akeneo asset projector error = %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("akeneo asset projector links = %#v, want none without evidence", links)
	}
	wantURN := "urn:cerebro:tenant:runtime_asset:asset-123"
	var got *ports.ProjectedEntity
	for _, entity := range entities {
		if entity != nil && entity.URN == wantURN {
			got = entity
			break
		}
	}
	if got == nil {
		t.Fatalf("projected entities missing %s: %#v", wantURN, entities)
	}
	if got.EntityType != "runtime.asset" {
		t.Fatalf("entity type = %q, want runtime.asset", got.EntityType)
	}
	if got.Attributes[ports.EventAttributeSourceRuntimeID] != "akeneo-runtime" {
		t.Fatalf("source runtime attr = %q, want akeneo-runtime", got.Attributes[ports.EventAttributeSourceRuntimeID])
	}
}

func TestGeneratedCatalogFamiliesProjectIntoGraph(t *testing.T) {
	catalog, err := connectorcatalog.Builtin()
	if err != nil {
		t.Fatalf("connectorcatalog.Builtin() error = %v", err)
	}
	projectors := map[string]ProjectFunc{}
	registerCatalogRuntimeProjectorsForEntries(projectors, catalog.Entries)
	registry, err := catalogRuntimeRegistry(projectors)
	if err != nil {
		t.Fatalf("catalog runtime registry error = %v", err)
	}

	sourceCount := 0
	familyCount := 0
	for _, entry := range catalog.Entries {
		if entry.Status != connectorcatalog.StatusGenerateable {
			continue
		}
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		if sourceID == "" {
			continue
		}
		sourceCount++
		for _, resource := range entry.Definition.ResourceFamilies {
			kind := catalogRuntimeEventKind(sourceID, resource)
			if projectors[kind] == nil {
				t.Fatalf("%s resource %s missing catalog runtime projector", sourceID, resource.ID)
			}
			graph := &projectionRecorder{}
			service := NewWithRegistry(nil, graph, registry)
			result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:         "event-" + catalogRuntimeSyntheticToken(sourceID, resource.ID),
				TenantId:   "tenant",
				SourceId:   sourceID,
				Kind:       kind,
				Attributes: catalogRuntimeSyntheticAttributes(sourceID, resource),
			})
			if err != nil {
				t.Fatalf("%s resource %s graph projection error = %v", sourceID, resource.ID, err)
			}
			if result.EntitiesProjected == 0 || len(graph.entities) == 0 {
				t.Fatalf("%s resource %s projected no graph entities: result=%#v", sourceID, resource.ID, result)
			}
			familyCount++
		}
	}
	if sourceCount < 750 {
		t.Fatalf("generateable catalog sources = %d, want at least 750 projected sources", sourceCount)
	}
	if familyCount < 3500 {
		t.Fatalf("generateable catalog resource families = %d, want at least 3500 projected graph items", familyCount)
	}
}

func TestCatalogRuntimeProjectorsCoverGeneratedTemplates(t *testing.T) {
	projectors := map[string]ProjectFunc{}
	registerCatalogRuntimeProjectorsForEntries(projectors, []connectorcatalog.Entry{{
		Status: connectorcatalog.StatusGenerateable,
		Definition: connectordefinitions.Definition{
			SourceID: "example_catalog",
			ResourceFamilies: []connectordefinitions.ResourceFamily{
				{
					ID:         "users",
					Event:      connectordefinitions.EventMappingSpec{Kind: "example_catalog.user"},
					Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
				},
				{
					ID:         "findings",
					Event:      connectordefinitions.EventMappingSpec{Kind: "example_catalog.finding"},
					Projection: &connectordefinitions.ProjectionSpec{Template: "finding"},
				},
				{
					ID:         "assets",
					Event:      connectordefinitions.EventMappingSpec{Kind: "example_catalog.asset"},
					Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
				},
				{
					ID:         "evidence",
					Event:      connectordefinitions.EventMappingSpec{Kind: "example_catalog.evidence"},
					Projection: &connectordefinitions.ProjectionSpec{Template: "evidence_cas_reference"},
				},
			},
		},
	}})

	tests := []struct {
		name           string
		kind           string
		attributes     map[string]string
		wantEntityType string
	}{
		{
			name:           "identity user",
			kind:           "example_catalog.user",
			attributes:     map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"},
			wantEntityType: "example_catalog.user",
		},
		{
			name:           "finding",
			kind:           "example_catalog.finding",
			attributes:     map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"},
			wantEntityType: "finding",
		},
		{
			name:           "asset",
			kind:           "example_catalog.asset",
			attributes:     map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1"},
			wantEntityType: "runtime.host",
		},
		{
			name:           "evidence",
			kind:           "example_catalog.evidence",
			attributes:     map[string]string{"evidence_id": "evidence-1", "evidence_type": "artifact", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"},
			wantEntityType: "runtime.evidence",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projector := projectors[test.kind]
			if projector == nil {
				t.Fatalf("projector %s missing", test.kind)
			}
			entities, _, err := projector(&cerebrov1.EventEnvelope{
				Id:         "event-1",
				TenantId:   "tenant",
				SourceId:   "example_catalog",
				Kind:       test.kind,
				Attributes: test.attributes,
			})
			if err != nil {
				t.Fatalf("projector(%s) error = %v", test.kind, err)
			}
			if !hasProjectedEntityType(entities, test.wantEntityType) {
				t.Fatalf("projected entities missing type %q: %#v", test.wantEntityType, entities)
			}
		})
	}
}

func TestCatalogRuntimeProjectorRegistrationAcceptsCatalogReadyEntries(t *testing.T) {
	projectors := map[string]ProjectFunc{}
	registerCatalogRuntimeProjectorsForEntries(projectors, []connectorcatalog.Entry{{
		Status: connectorcatalog.StatusCatalogReady,
		Definition: connectordefinitions.Definition{
			SourceID: "example_catalog",
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:    "assets",
				Event: connectordefinitions.EventMappingSpec{Kind: "example_catalog.asset"},
			}},
		},
	}})
	if projectors["example_catalog.asset"] == nil {
		t.Fatal("catalog-ready entry did not register catalog runtime projector")
	}
}

func TestCatalogRuntimeProjectorRegistrationDoesNotOverrideStaticProjector(t *testing.T) {
	called := false
	projectors := map[string]ProjectFunc{
		"example_catalog.asset": func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			called = true
			return nil, nil, nil
		},
	}
	registerCatalogRuntimeProjectorsForEntries(projectors, []connectorcatalog.Entry{{
		Status: connectorcatalog.StatusGenerateable,
		Definition: connectordefinitions.Definition{
			SourceID: "example_catalog",
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:         "assets",
				Event:      connectordefinitions.EventMappingSpec{Kind: "example_catalog.asset"},
				Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			}},
		},
	}})
	if _, _, err := projectors["example_catalog.asset"](&cerebrov1.EventEnvelope{}); err != nil {
		t.Fatalf("static projector error = %v", err)
	}
	if !called {
		t.Fatal("catalog runtime registration replaced the existing static projector")
	}
}

func TestRegistryRegistersConnectorDefinitionProjectors(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	definition, err := connectordefinitions.Normalize(connectordefinitions.Definition{
		TenantID: "tenant-a",
		SourceID: "example_dynamic",
		Auth:     connectordefinitions.AuthSpec{Model: "none"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "assets",
			Path:      "/v1/assets",
			IDField:   "id",
			NameField: "name",
			Event:     connectordefinitions.EventMappingSpec{Kind: "example_dynamic.asset"},
			Projection: &connectordefinitions.ProjectionSpec{
				Entity: &connectordefinitions.ProjectionEntitySpec{
					EntityType:     "example.dynamic.asset",
					URNKind:        "example_dynamic_asset",
					IDAttributes:   []string{"id"},
					LabelAttribute: "name",
				},
			},
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.Validation.Status == connectordefinitions.ValidationBlocked {
		t.Fatalf("definition blocked unexpectedly: %#v", definition.Validation.Checks)
	}
	registry.RegisterConnectorDefinitions(definition)
	registry.RegisterConnectorDefinitions(definition)
	if got := len(registry.connectorDefinitionFingerprints); got != 1 {
		t.Fatalf("registered connector fingerprints = %d, want 1", got)
	}
	entities, _, err := registry.Project(&cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant-a",
		SourceId: "example_dynamic",
		Kind:     "example_dynamic.asset",
		Attributes: map[string]string{
			"id":   "asset-1",
			"name": "Asset One",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if !hasProjectedEntityType(entities, "example.dynamic.asset") {
		t.Fatalf("projected entities missing dynamic asset type: %#v", entities)
	}
}

func TestRegistrySkipsUnnormalizedConnectorDefinitionWithUnsupportedRelationship(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	registry.RegisterConnectorDefinitions(connectordefinitions.Definition{
		TenantID: "tenant-a",
		SourceID: "example_dynamic",
		Auth:     connectordefinitions.AuthSpec{Model: "none"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "assets",
			Path:      "/v1/assets",
			IDField:   "id",
			NameField: "name",
			Event:     connectordefinitions.EventMappingSpec{Kind: "example_dynamic.asset"},
			Projection: &connectordefinitions.ProjectionSpec{
				Fields: map[string]string{
					"owner_id":   "owner.id",
					"owner_name": "owner.name",
				},
				Entity: &connectordefinitions.ProjectionEntitySpec{
					EntityType:     "example.dynamic.asset",
					URNKind:        "example_dynamic_asset",
					IDAttributes:   []string{"id"},
					LabelAttribute: "name",
				},
				Relationships: []connectordefinitions.ProjectionRelationshipSpec{{
					Relation: "custom relation",
					To: connectordefinitions.ProjectionEntitySpec{
						EntityType:     "example.dynamic.owner",
						URNKind:        "example_dynamic_owner",
						IDAttributes:   []string{"owner_id"},
						LabelAttribute: "owner_name",
					},
					MatchType: "owner",
				}},
			},
		}},
	})
	if len(registry.connectorDefinitionFingerprints) != 0 {
		t.Fatalf("registered blocked connector definition fingerprints = %#v", registry.connectorDefinitionFingerprints)
	}
	entities, links, err := registry.Project(&cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant-a",
		SourceId: "example_dynamic",
		Kind:     "example_dynamic.asset",
		Attributes: map[string]string{
			"id":         "asset-1",
			"name":       "Asset One",
			"owner_id":   "owner-1",
			"owner_name": "Owner One",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if len(entities) != 0 || len(links) != 0 {
		t.Fatalf("blocked connector definition projected entities=%#v links=%#v", entities, links)
	}
}

func TestRegistryUpdatesConnectorDefinitionProjectors(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	base := connectordefinitions.Definition{
		TenantID: "tenant-a",
		SourceID: "example_dynamic",
		Auth:     connectordefinitions.AuthSpec{Model: "none"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "assets",
			Path:      "/v1/assets",
			IDField:   "id",
			NameField: "name",
			Event:     connectordefinitions.EventMappingSpec{Kind: "example_dynamic.asset"},
			Projection: &connectordefinitions.ProjectionSpec{
				Entity: &connectordefinitions.ProjectionEntitySpec{
					EntityType:     "example.dynamic.asset",
					URNKind:        "example_dynamic_asset",
					IDAttributes:   []string{"id"},
					LabelAttribute: "name",
				},
			},
		}},
	}
	initial, err := connectordefinitions.Normalize(base)
	if err != nil {
		t.Fatalf("Normalize(initial) error = %v", err)
	}
	registry.RegisterConnectorDefinitions(initial)
	updated := base
	updated.ResourceFamilies = append(updated.ResourceFamilies, connectordefinitions.ResourceFamily{
		ID:        "findings",
		Path:      "/v1/findings",
		IDField:   "id",
		NameField: "name",
		Event:     connectordefinitions.EventMappingSpec{Kind: "example_dynamic.finding"},
		Projection: &connectordefinitions.ProjectionSpec{
			Entity: &connectordefinitions.ProjectionEntitySpec{
				EntityType:     "example.dynamic.finding",
				URNKind:        "example_dynamic_finding",
				IDAttributes:   []string{"id"},
				LabelAttribute: "name",
			},
		},
	})
	normalized, err := connectordefinitions.Normalize(updated)
	if err != nil {
		t.Fatalf("Normalize(updated) error = %v", err)
	}
	registry.RegisterConnectorDefinitions(normalized)
	entities, _, err := registry.Project(&cerebrov1.EventEnvelope{
		Id:       "event-2",
		TenantId: "tenant-a",
		SourceId: "example_dynamic",
		Kind:     "example_dynamic.finding",
		Attributes: map[string]string{
			"id":   "finding-1",
			"name": "Finding One",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if !hasProjectedEntityType(entities, "example.dynamic.finding") {
		t.Fatalf("projected entities missing updated finding type: %#v", entities)
	}
}

func TestRegistryKeepsSharedKindProjectorsAcrossUpdates(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	sourceA, err := connectordefinitions.Normalize(sharedKindDefinition("source_a", "shared.source_a.asset"))
	if err != nil {
		t.Fatalf("Normalize(sourceA) error = %v", err)
	}
	sourceB, err := connectordefinitions.Normalize(sharedKindDefinition("source_b", "shared.source_b.asset"))
	if err != nil {
		t.Fatalf("Normalize(sourceB) error = %v", err)
	}
	registry.RegisterConnectorDefinitions(sourceA, sourceB)

	updatedA, err := connectordefinitions.Normalize(sharedKindDefinition("source_a", "shared.source_a.updated"))
	if err != nil {
		t.Fatalf("Normalize(updatedA) error = %v", err)
	}
	registry.RegisterConnectorDefinitions(updatedA)

	entities, _, err := registry.Project(&cerebrov1.EventEnvelope{
		Id:       "event-a",
		TenantId: "tenant-a",
		SourceId: "source_a",
		Kind:     "shared.asset",
		Attributes: map[string]string{
			"id":   "asset-a",
			"name": "Asset A",
		},
	})
	if err != nil {
		t.Fatalf("Project(source_a) error = %v", err)
	}
	if !hasProjectedEntityType(entities, "shared.source_a.updated") {
		t.Fatalf("source_a projected entities = %#v, want updated type", entities)
	}

	entities, _, err = registry.Project(&cerebrov1.EventEnvelope{
		Id:       "event-b",
		TenantId: "tenant-a",
		SourceId: "source_b",
		Kind:     "shared.asset",
		Attributes: map[string]string{
			"id":   "asset-b",
			"name": "Asset B",
		},
	})
	if err != nil {
		t.Fatalf("Project(source_b) error = %v", err)
	}
	if !hasProjectedEntityType(entities, "shared.source_b.asset") {
		t.Fatalf("source_b projected entities = %#v, want original type", entities)
	}
}

func sharedKindDefinition(sourceID string, entityType string) connectordefinitions.Definition {
	return connectordefinitions.Definition{
		TenantID: "tenant-a",
		SourceID: sourceID,
		Auth:     connectordefinitions.AuthSpec{Model: "none"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:        "assets",
			Path:      "/v1/assets",
			IDField:   "id",
			NameField: "name",
			Event:     connectordefinitions.EventMappingSpec{Kind: "shared.asset"},
			Projection: &connectordefinitions.ProjectionSpec{
				Entity: &connectordefinitions.ProjectionEntitySpec{
					EntityType:     entityType,
					URNKind:        sourceID + "_asset",
					IDAttributes:   []string{"id"},
					LabelAttribute: "name",
				},
			},
		}},
	}
}

func TestCatalogRuntimeAssetProjectionRequiresStableResourceIdentity(t *testing.T) {
	entities, links, err := catalogRuntimeAssetProjections(&cerebrov1.EventEnvelope{
		Id:       "event-ephemeral",
		TenantId: "tenant",
		SourceId: "example_catalog",
		Kind:     "example_catalog.asset",
		Attributes: map[string]string{
			"resource_type": "host",
		},
	})
	if err != nil {
		t.Fatalf("catalogRuntimeAssetProjections() error = %v", err)
	}
	if len(entities) != 0 || len(links) != 0 {
		t.Fatalf("projected ephemeral asset identity from event id: entities=%#v links=%#v", entities, links)
	}
}

func TestCatalogRuntimeProjectionRelationships(t *testing.T) {
	resource := connectordefinitions.ResourceFamily{
		ID: "secrets",
		Projection: &connectordefinitions.ProjectionSpec{
			Template: "secret",
			Fields: map[string]string{
				"owner_user_id": "created_by.id",
				"vault_id":      "mount_accessor",
			},
			Entity: &connectordefinitions.ProjectionEntitySpec{
				EntityType:     "secret",
				URNKind:        "secret",
				IDAttributes:   []string{"secret_id"},
				LabelAttribute: "secret_name",
			},
			Relationships: []connectordefinitions.ProjectionRelationshipSpec{
				{
					Relation: "belongs_to",
					To: connectordefinitions.ProjectionEntitySpec{
						EntityType:   "hashicorp_vault.vault",
						URNKind:      "hashicorp_vault_vault",
						IDAttributes: []string{"vault_id"},
					},
					MatchType: "secret_vault",
				},
				{
					Relation:           "owned_by",
					RequiredAttributes: []string{"owner_user_id"},
					To: connectordefinitions.ProjectionEntitySpec{
						EntityType:   "hashicorp_vault.user",
						URNKind:      "hashicorp_vault_user",
						IDAttributes: []string{"owner_user_id"},
					},
					MatchType: "secret_owner",
				},
			},
		},
	}
	projector := catalogRuntimeProjectorFor("hashicorp_vault", resource)
	entities, links, err := projector(&cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant",
		SourceId: "hashicorp_vault",
		Kind:     "hashicorp_vault.secrets",
		Attributes: map[string]string{
			"resource_id":    "secret-1",
			"resource_type":  "secret",
			"secret_id":      "secret-1",
			"secret_name":    "database/password",
			"vault_id":       "kv",
			"owner_user_id":  "user-1",
			"source_runtime": "runtime-1",
		},
	})
	if err != nil {
		t.Fatalf("projector error = %v", err)
	}
	if !hasProjectedEntityType(entities, "secret") || !hasProjectedEntityType(entities, "hashicorp_vault.vault") || !hasProjectedEntityType(entities, "hashicorp_vault.user") {
		t.Fatalf("entities missing deep relationship endpoints: %#v", entities)
	}
	if hasProjectedEntityType(entities, "runtime.secret") {
		t.Fatalf("projection.entity should replace flat runtime secret entity: %#v", entities)
	}
	if !projectedLinksContain(links, "urn:cerebro:tenant:secret:secret-1", relationBelongsTo, "urn:cerebro:tenant:hashicorp_vault_vault:kv") {
		t.Fatalf("secret-vault link missing: %#v", links)
	}
	if !projectedLinksContain(links, "urn:cerebro:tenant:secret:secret-1", relationOwnedBy, "urn:cerebro:tenant:hashicorp_vault_user:user-1") {
		t.Fatalf("secret-owner link missing: %#v", links)
	}

	entities, links, err = projector(&cerebrov1.EventEnvelope{
		Id:       "event-2",
		TenantId: "tenant",
		SourceId: "hashicorp_vault",
		Kind:     "hashicorp_vault.secrets",
		Attributes: map[string]string{
			"resource_id":   "secret-2",
			"resource_type": "secret",
			"secret_id":     "secret-2",
			"secret_name":   "database/username",
			"vault_id":      "kv",
		},
	})
	if err != nil {
		t.Fatalf("projector without owner error = %v", err)
	}
	if !hasProjectedEntityType(entities, "secret") || !projectedLinksContain(links, "urn:cerebro:tenant:secret:secret-2", relationBelongsTo, "urn:cerebro:tenant:hashicorp_vault_vault:kv") {
		t.Fatalf("missing required owner should not suppress base entity or vault link: entities=%#v links=%#v", entities, links)
	}
	if projectedLinksContainRelationFrom(links, "urn:cerebro:tenant:secret:secret-2", relationOwnedBy) {
		t.Fatalf("owner link emitted despite missing owner_user_id: %#v", links)
	}
}

func TestCatalogRuntimeFindingProjectionRequiresStableFindingIdentity(t *testing.T) {
	entities, links, err := catalogRuntimeFindingProjections(&cerebrov1.EventEnvelope{
		Id:       "event-ephemeral",
		TenantId: "tenant",
		SourceId: "example_catalog",
		Kind:     "example_catalog.finding",
		Attributes: map[string]string{
			"title":    "Finding without provider id",
			"severity": "high",
		},
	})
	if err != nil {
		t.Fatalf("catalogRuntimeFindingProjections() error = %v", err)
	}
	if len(entities) != 0 || len(links) != 0 {
		t.Fatalf("projected ephemeral finding identity from event id: entities=%#v links=%#v", entities, links)
	}
}

func hasProjectedEntityType(entities []*ports.ProjectedEntity, entityType string) bool {
	for _, entity := range entities {
		if entity.EntityType == entityType {
			return true
		}
	}
	return false
}

func projectedLinksContain(links []*ports.ProjectedLink, fromURN string, relation string, toURN string) bool {
	for _, link := range links {
		if link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
			return true
		}
	}
	return false
}

func projectedLinksContainRelationFrom(links []*ports.ProjectedLink, fromURN string, relation string) bool {
	for _, link := range links {
		if link.FromURN == fromURN && link.Relation == relation {
			return true
		}
	}
	return false
}

func catalogRuntimeRegistry(projectors map[string]ProjectFunc) (*Registry, error) {
	entries := make([]EventProjector, 0, len(projectors))
	for kind, projector := range projectors {
		entries = append(entries, EventProjector{Kind: kind, Project: projector})
	}
	return NewRegistry(entries...)
}

func catalogRuntimeSyntheticAttributes(sourceID string, resource connectordefinitions.ResourceFamily) map[string]string {
	familyID := firstNonEmpty(strings.TrimSpace(resource.ID), "resource")
	token := catalogRuntimeSyntheticToken(sourceID, familyID)
	recordID := token + "-1"
	email := catalogRuntimeSyntheticEmail(token)
	label := familyID + " one"
	resourceURN := projectionURN("tenant", "runtime_"+familyID, recordID)
	attrs := map[string]string{
		"id":                                recordID,
		"uuid":                              recordID,
		"uid":                               recordID,
		"sid":                               recordID,
		"key":                               recordID,
		"slug":                              recordID,
		"external_id":                       recordID,
		"object_id":                         recordID,
		"resource_id":                       recordID,
		"asset_id":                          recordID,
		"record_id":                         recordID,
		"item_id":                           recordID,
		"entity_id":                         recordID,
		"guid":                              recordID,
		"_id":                               recordID,
		"name":                              label,
		"display_name":                      label,
		"displayName":                       label,
		"title":                             label,
		"friendly_name":                     label,
		"label":                             label,
		"summary":                           label,
		"description":                       label,
		"subject":                           label,
		"hostname":                          token + ".example.test",
		"url":                               "https://example.test/" + token,
		"self":                              "https://example.test/" + token,
		"resource_name":                     label,
		"resource_type":                     familyID,
		"resource_urn":                      resourceURN,
		"resource_entity_type":              "runtime." + strings.ReplaceAll(familyID, "_", "."),
		"provider_id":                       recordID,
		"domain":                            "example.test",
		"user_id":                           recordID,
		"primary_email":                     email,
		"email":                             email,
		"login":                             email,
		"status":                            "active",
		"group_id":                          "group-" + recordID,
		"group_name":                        familyID + " group",
		"group_email":                       "group-" + email,
		"member_id":                         "member-" + recordID,
		"member_user_id":                    "member-" + recordID,
		"member_email":                      "member-" + email,
		"member_name":                       familyID + " member",
		"member_type":                       "user",
		"role":                              "member",
		"actor_id":                          "actor-" + recordID,
		"actor_email":                       "actor-" + email,
		"actor_name":                        familyID + " actor",
		"actor_type":                        "user",
		"target_id":                         recordID,
		"target_type":                       familyID,
		"target_name":                       label,
		"event_type":                        "updated",
		"finding_id":                        "finding-" + recordID,
		"severity":                          "medium",
		"priority":                          "medium",
		"risk":                              "medium",
		"state":                             "open",
		"resolution":                        "open",
		"evidence_id":                       "evidence-" + recordID,
		"evidence_type":                     familyID,
		"evidence_cas_uri":                  "cas://tenant/" + token,
		"evidence_cas_digest":               "sha256:" + token,
		"source_event_id":                   "source-event-" + recordID,
		"observed_at":                       "2026-06-28T00:00:00Z",
		"occurred_at":                       "2026-06-28T00:00:00Z",
		ports.EventAttributeSourceRuntimeID: sourceID + "-runtime",
		"policy_id":                         "policy-" + recordID,
		"policy_name":                       familyID + " policy",
		"policy_type":                       familyID,
		"deployment_id":                     "deployment-" + recordID,
		"deployment_name":                   familyID + " deployment",
		"deployment_environment":            "prod",
		"deployment_status":                 "ready",
		"alert_id":                          "alert-" + recordID,
		"alert_name":                        familyID + " alert",
		"alert_severity":                    "medium",
		"alert_status":                      "open",
		"secret_id":                         "secret-" + recordID,
		"secret_name":                       familyID + " secret",
		"secret_type":                       familyID,
		"tenant_id":                         "tenant",
		"resource_link_status":              "linked",
		"case_id":                           "case-" + recordID,
		"case_link_status":                  "linked",
		"confidence":                        "0.9",
		"unresolved_case_context":           "false",
		"unresolved_resource_context":       "false",
		"evidence_cas_manifest_version":     "1",
		"evidence_cas_blocks_count":         "1",
		"evidence_cas_content_type":         "application/json",
		"evidence_cas_ref_type":             "object",
		"evidence_cas_size_bytes":           "128",
		"evidence_cas_commit_id":            "commit-" + token,
		"evidence_cas_merkle_root":          "root-" + token,
		"detector_id":                       sourceID,
		"trace_id":                          "trace-" + token,
		"request_id":                        "request-" + token,
		"verdict":                           "observed",
	}
	catalogRuntimeSetSyntheticField(attrs, resource.IDField, recordID)
	catalogRuntimeSetSyntheticField(attrs, resource.NameField, label)
	for _, attr := range resource.Event.RequiredAttributes {
		catalogRuntimeSetSyntheticField(attrs, attr, catalogRuntimeSyntheticFieldValue(attr, recordID, label, familyID, resourceURN, email))
	}
	for _, attr := range resource.Event.RequiredPayloadFields {
		catalogRuntimeSetSyntheticField(attrs, attr, catalogRuntimeSyntheticFieldValue(attr, recordID, label, familyID, resourceURN, email))
	}
	if resource.Projection != nil {
		for target, source := range resource.Projection.Fields {
			value := catalogRuntimeSyntheticFieldValue(target, recordID, label, familyID, resourceURN, email)
			catalogRuntimeSetSyntheticField(attrs, target, value)
			if strings.TrimSpace(source) != "" {
				catalogRuntimeSetSyntheticField(attrs, source, value)
			}
		}
		if resource.Projection.Entity != nil {
			catalogRuntimeFillEntitySpec(attrs, *resource.Projection.Entity, recordID, label, familyID, resourceURN, email)
		}
		for _, relationship := range resource.Projection.Relationships {
			for _, attr := range relationship.RequiredAttributes {
				catalogRuntimeSetSyntheticField(attrs, attr, catalogRuntimeSyntheticFieldValue(attr, recordID, label, familyID, resourceURN, email))
			}
			for _, attr := range relationship.LinkAttributes {
				catalogRuntimeSetSyntheticField(attrs, attr, catalogRuntimeSyntheticFieldValue(attr, recordID, label, familyID, resourceURN, email))
			}
			if relationship.From != nil {
				catalogRuntimeFillEntitySpec(attrs, *relationship.From, recordID, label, familyID, resourceURN, email)
			}
			catalogRuntimeFillEntitySpec(attrs, relationship.To, recordID, label, familyID, resourceURN, email)
		}
	}
	return attrs
}

func catalogRuntimeFillEntitySpec(attrs map[string]string, spec connectordefinitions.ProjectionEntitySpec, recordID string, label string, familyID string, resourceURN string, email string) {
	for _, attr := range spec.IDAttributes {
		catalogRuntimeSetSyntheticField(attrs, attr, catalogRuntimeSyntheticFieldValue(attr, recordID, label, familyID, resourceURN, email))
	}
	catalogRuntimeSetSyntheticField(attrs, spec.LabelAttribute, label)
}

func catalogRuntimeSetSyntheticField(attrs map[string]string, key string, value string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	if strings.TrimSpace(value) == "" {
		value = "value"
	}
	attrs[key] = value
}

func catalogRuntimeSyntheticFieldValue(field string, recordID string, label string, familyID string, resourceURN string, email string) string {
	key := strings.ToLower(strings.TrimSpace(field))
	switch {
	case key == "":
		return recordID
	case strings.Contains(key, "urn"):
		return resourceURN
	case strings.Contains(key, "email") || strings.Contains(key, "login"):
		return email
	case strings.Contains(key, "name") || strings.Contains(key, "title") || strings.Contains(key, "summary") || strings.Contains(key, "description") || strings.Contains(key, "label"):
		return label
	case strings.Contains(key, "type"):
		return familyID
	case strings.Contains(key, "severity") || strings.Contains(key, "priority") || strings.Contains(key, "risk"):
		return "medium"
	case strings.Contains(key, "status") || strings.Contains(key, "state") || strings.Contains(key, "resolution"):
		return "active"
	case strings.Contains(key, "time") || strings.Contains(key, "date") || strings.HasSuffix(key, "_at"):
		return "2026-06-28T00:00:00Z"
	case strings.Contains(key, "url") || key == "self":
		return "https://example.test/" + recordID
	default:
		return recordID
	}
}

func catalogRuntimeSyntheticToken(parts ...string) string {
	tokens := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var builder strings.Builder
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z':
				builder.WriteRune(r)
			case r >= 'A' && r <= 'Z':
				builder.WriteRune(r + ('a' - 'A'))
			case r >= '0' && r <= '9':
				builder.WriteRune(r)
			default:
				builder.WriteByte('-')
			}
		}
		token := strings.Trim(builder.String(), "-")
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return "resource"
	}
	return strings.Join(tokens, "-")
}

func catalogRuntimeSyntheticEmail(token string) string {
	token = catalogRuntimeSyntheticToken(token)
	token = strings.ReplaceAll(token, "-", ".")
	return token + "@example.test"
}

func TestBuiltinRegistryAppliesDeclaredCatalogRelationships(t *testing.T) {
	registry := BuiltinRegistry()

	t.Run("doppler secrets belongs_to project", func(t *testing.T) {
		projector := registry.projectors["doppler.secrets"]
		if projector == nil {
			t.Fatal("missing registered projector for doppler.secrets")
		}
		entities, links, err := projector(&cerebrov1.EventEnvelope{
			Id:       "event-1",
			TenantId: "tenant",
			SourceId: "doppler",
			Kind:     "doppler.secrets",
			Attributes: map[string]string{
				"secret_id":   "secret-1",
				"secret_name": "DATABASE_URL",
				"project_id":  "proj-1",
				"evidence_id": "evidence-1",
			},
		})
		if err != nil {
			t.Fatalf("doppler.secrets projector error = %v", err)
		}
		if !projectedLinksContain(links, "urn:cerebro:tenant:secret:secret-1", relationBelongsTo, "urn:cerebro:tenant:doppler_project:proj-1") {
			t.Fatalf("declared belongs_to edge not emitted by registered projector: %#v", links)
		}
		if !hasProjectedEntityType(entities, "runtime_evidence") {
			t.Fatalf("evidence node dropped by relationship augmentation: %#v", entities)
		}
		if !projectedLinksContain(links, "urn:cerebro:tenant:secret:secret-1", relationHasEvidence, "urn:cerebro:tenant:runtime_evidence:evidence-1") {
			t.Fatalf("has_evidence edge corrupted or dropped by relationship augmentation: %#v", links)
		}
	})

	t.Run("hashicorp_vault secrets owned_by user", func(t *testing.T) {
		projector := registry.projectors["hashicorp_vault.secrets"]
		if projector == nil {
			t.Fatal("missing registered projector for hashicorp_vault.secrets")
		}
		_, links, err := projector(&cerebrov1.EventEnvelope{
			Id:       "event-1",
			TenantId: "tenant",
			SourceId: "hashicorp_vault",
			Kind:     "hashicorp_vault.secrets",
			Attributes: map[string]string{
				"secret_id":     "secret-1",
				"secret_name":   "kv/db",
				"owner_user_id": "user-1",
			},
		})
		if err != nil {
			t.Fatalf("hashicorp_vault.secrets projector error = %v", err)
		}
		if !projectedLinksContain(links, "urn:cerebro:tenant:secret:secret-1", relationOwnedBy, "urn:cerebro:tenant:hashicorp_vault_user:user-1") {
			t.Fatalf("declared owned_by edge not emitted by registered projector: %#v", links)
		}
	})
}

func TestCatalogProjectionPrimaryURNSkipsEvidenceAndIsDeterministic(t *testing.T) {
	evidenceDotted := &ports.ProjectedEntity{URN: "urn:cerebro:tenant:runtime_evidence:e1", EntityType: "runtime.evidence"}
	evidenceUnderscore := &ports.ProjectedEntity{URN: "urn:cerebro:tenant:runtime_evidence:e2", EntityType: "runtime_evidence"}
	secret := &ports.ProjectedEntity{URN: "urn:cerebro:tenant:secret:s1", EntityType: "secret"}
	runtimeNode := &ports.ProjectedEntity{URN: "urn:cerebro:tenant:runtime_host:h1", EntityType: "runtime.host"}

	orders := [][]*ports.ProjectedEntity{
		{evidenceUnderscore, runtimeNode, secret},
		{secret, runtimeNode, evidenceDotted},
		{runtimeNode, evidenceUnderscore, secret, evidenceDotted},
	}
	for _, order := range orders {
		if got := catalogProjectionPrimaryURN(order); got != secret.URN {
			t.Fatalf("primary URN = %q, want %q (typed entity preferred, evidence skipped) for order %#v", got, secret.URN, order)
		}
	}

	if got := catalogProjectionPrimaryURN([]*ports.ProjectedEntity{evidenceDotted, evidenceUnderscore}); got != "" {
		t.Fatalf("primary URN = %q, want empty when only evidence entities present", got)
	}
}
