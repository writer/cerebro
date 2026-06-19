package sourceprojection

import (
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
