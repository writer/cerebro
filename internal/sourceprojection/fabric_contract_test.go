package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestProjectRecordsRejectsUnknownFabricRelation(t *testing.T) {
	registry, err := NewRegistry(EventProjector{
		Kind: "test.event",
		Project: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return nil, []*ports.ProjectedLink{{
				TenantID: "writer",
				SourceID: "test",
				FromURN:  "urn:cerebro:writer:test:from",
				ToURN:    "urn:cerebro:writer:test:to",
				Relation: "made_up_relation",
			}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(nil, nil, registry)
	_, _, err = service.ProjectRecords(&cerebrov1.EventEnvelope{Kind: "test.event", TenantId: "writer", SourceId: "test"})
	if err == nil {
		t.Fatalf("ProjectRecords() error = %v, want fabric contract rejection", err)
	}
}

func TestProjectAllowsKnownFabricRelation(t *testing.T) {
	store := &projectionRecorder{}
	registry, err := NewRegistry(EventProjector{
		Kind: "test.event",
		Project: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{
					URN:        "urn:cerebro:writer:test:from",
					TenantID:   "writer",
					SourceID:   "test",
					EntityType: "test",
					Label:      "from",
				}}, []*ports.ProjectedLink{{
					TenantID: "writer",
					SourceID: "test",
					FromURN:  "urn:cerebro:writer:test:from",
					ToURN:    "urn:cerebro:writer:test:to",
					Relation: relationBelongsTo,
				}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	service := NewWithRegistry(store, nil, registry)
	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{Kind: "test.event", TenantId: "writer", SourceId: "test"})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.LinksProjected != 1 {
		t.Fatalf("LinksProjected = %d, want 1", result.LinksProjected)
	}
}
