package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectGRCEventLogLinksActorAndTargets(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-event-log-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.event_log",
		Attributes: map[string]string{
			"provider":     "grc",
			"event_log_id": "event-log-1",
			"action":       "vendor.review.created",
			"actor_type":   "user",
			"actor_id":     "user-1",
			"targets":      "vendor:vendor-1;control:control-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	eventURN := "urn:cerebro:writer:grc_audit_event:grc:event-log-1"
	actorURN := "urn:cerebro:writer:user:grc:user-1"
	vendorTargetURN := "urn:cerebro:writer:grc_audit_target:grc:vendor:vendor-1"
	controlTargetURN := "urn:cerebro:writer:grc_audit_target:grc:control:control-1"
	if entity := state.entities[eventURN]; entity == nil || entity.EntityType != "audit.event" {
		t.Fatalf("event log entity missing: %#v", entity)
	}
	if got := state.entities[actorURN].Attributes["user_id"]; got != "user-1" {
		t.Fatalf("user actor user_id = %q, want user-1", got)
	}
	assertProjectedLink(t, state, actorURN, relationActedOn, eventURN)
	assertProjectedLink(t, state, eventURN, relationObservedOn, vendorTargetURN)
	assertProjectedLink(t, state, eventURN, relationObservedOn, controlTargetURN)
}

func TestProjectGRCEventLogDoesNotSetUserIDForNonUserActor(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-event-log-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.event_log",
		Attributes: map[string]string{
			"provider":     "grc",
			"event_log_id": "event-log-2",
			"action":       "integration.sync.completed",
			"actor_type":   "system",
			"actor_id":     "automation",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	actorURN := "urn:cerebro:writer:grc_audit_actor:grc:system:automation"
	entity := state.entities[actorURN]
	if entity == nil || entity.EntityType != "audit.actor" {
		t.Fatalf("non-user actor entity missing: %#v", entity)
	}
	if got := entity.Attributes["user_id"]; got != "" {
		t.Fatalf("non-user actor user_id = %q, want unset", got)
	}
}

func TestProjectGRCEventLogDefaultsMissingActorTypeToResource(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-event-log-3",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.event_log",
		Attributes: map[string]string{
			"provider":     "grc",
			"event_log_id": "event-log-3",
			"action":       "resource.updated",
			"actor_id":     "automation",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	eventURN := "urn:cerebro:writer:grc_audit_event:grc:event-log-3"
	actorURN := "urn:cerebro:writer:grc_audit_actor:grc:resource:automation"
	entity := state.entities[actorURN]
	if entity == nil || entity.EntityType != "audit.actor" {
		t.Fatalf("default actor entity missing: %#v", entity)
	}
	if got := entity.Attributes["actor_type"]; got != "resource" {
		t.Fatalf("default actor_type = %q, want resource", got)
	}
	assertProjectedLink(t, state, actorURN, relationActedOn, eventURN)
	link := state.links[actorURN+"|"+relationActedOn+"|"+eventURN]
	if got := link.Attributes["actor_type"]; got != "resource" {
		t.Fatalf("default actor link actor_type = %q, want resource", got)
	}
}
