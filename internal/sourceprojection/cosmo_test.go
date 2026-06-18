package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestProjectCosmoSession(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-session-ticket-1",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.session",
		Attributes: map[string]string{
			"record_id":  "ticket-1",
			"ticket_id":  "ticket-1",
			"thread_key": "thread-1",
			"user":       "alice@example.com",
			"status":     "open",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_session:ticket-1", "cosmo.session")
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:identity:email:alice@example.com", "identity.email")
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_session:ticket-1", relationRepresentsIdentity, "urn:cerebro:writer:identity:email:alice@example.com")
}

func TestProjectCosmoFact(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-fact-risk",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.fact",
		Attributes: map[string]string{
			"record_id":  "risk:key",
			"key":        "risk:key",
			"category":   "risk",
			"confidence": "0.9",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_fact:risk:key", "cosmo.fact")
	if len(links) != 0 {
		t.Fatalf("len(links) = %d, want 0", len(links))
	}
}

func TestProjectCosmoFactLinksSourceSession(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-fact-risk",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.fact",
		Attributes: map[string]string{
			"record_id": "risk:key",
			"key":       "risk:key",
			"source":    "session:slack-C123-1779126269.376359",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_fact:risk:key", "cosmo.fact")
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_session:slack-C123-1779126269.376359", "cosmo.session")
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_fact:risk:key", relationBelongsTo, "urn:cerebro:writer:cosmo_session:slack-C123-1779126269.376359")
}

func TestProjectCosmoFactCarriesCoordinationRiskState(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-fact-coordination-risk",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.fact",
		Attributes: map[string]string{
			"record_id": "coordination:risk:thread-1",
			"key":       "coordination:risk:thread-1",
			"category":  "coordination_risk",
			"source":    "session:thread-1",
		},
		Payload: mustJSON(t, map[string]any{
			"key":         "coordination:risk:thread-1",
			"category":    "coordination_risk",
			"status":      "active",
			"risk_reason": "agent coordinated a privileged change across sessions",
			"severity":    "high",
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	fact := cosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_fact:coordination:risk:thread-1", "cosmo.fact")
	if got := fact.Attributes["risk_state"]; got != "active" {
		t.Fatalf("fact risk_state = %q, want active", got)
	}
	if got := fact.Attributes["risk_reason"]; got == "" {
		t.Fatal("fact risk_reason = empty, want reason carried into projection")
	}
	if got := fact.Attributes["risk_severity"]; got != "high" {
		t.Fatalf("fact risk_severity = %q, want high", got)
	}
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_session:thread-1", "cosmo.session")
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_fact:coordination:risk:thread-1", relationBelongsTo, "urn:cerebro:writer:cosmo_session:thread-1")
}

func TestProjectCosmoFactResolvedBooleanMatchesFindingState(t *testing.T) {
	entities, _, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-fact-coordination-risk-resolved",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.fact",
		Payload: mustJSON(t, map[string]any{
			"key":      "coordination:risk:thread-1",
			"category": "coordination_risk",
			"resolved": true,
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	fact := cosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_fact:coordination:risk:thread-1", "cosmo.fact")
	if got := fact.Attributes["risk_state"]; got != "resolved" {
		t.Fatalf("fact risk_state = %q, want resolved for native JSON boolean resolved=true", got)
	}
}

func TestProjectCosmoMessageLinksSession(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-message-msg-1",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.message",
		Attributes: map[string]string{
			"record_id":  "msg-1",
			"ticket_id":  "ticket-1",
			"event_type": "message",
			"role":       "assistant",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_message:msg-1", "cosmo.message")
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_session:ticket-1", "cosmo.session")
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_message:msg-1", relationBelongsTo, "urn:cerebro:writer:cosmo_session:ticket-1")
}

func TestProjectCosmoUserMessageLinksIdentity(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-message-msg-2",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.message",
		Attributes: map[string]string{
			"record_id": "msg-2",
			"ticket_id": "ticket-1",
			"role":      "user",
			"user":      "alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_message:msg-2", "cosmo.message")
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:identity:email:alice@example.com", "identity.email")
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_message:msg-2", relationRepresentsIdentity, "urn:cerebro:writer:identity:email:alice@example.com")
}

func TestProjectCosmoMessageLinksPayloadUserIdentity(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-message-msg-3",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.message",
		Payload:  mustJSON(t, map[string]any{"id": "msg-3", "ticket_id": "ticket-1", "userEmail": "alice@example.com"}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	message := cosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_message:msg-3", "cosmo.message")
	if got := message.Attributes["email"]; got != "alice@example.com" {
		t.Fatalf("message email = %q, want alice@example.com", got)
	}
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_message:msg-3", relationRepresentsIdentity, "urn:cerebro:writer:identity:email:alice@example.com")
}

func TestProjectCosmoSurveyFeedbackLinksSessionAndUser(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Id:       "cosmo-writer-survey-feedback-feedback-1",
		TenantId: "writer",
		SourceId: "cosmo",
		Kind:     "cosmo.survey_feedback",
		Attributes: map[string]string{
			"record_id": "feedback-1",
			"ticket_id": "ticket-1",
			"user_id":   "alice@example.com",
			"sentiment": "positive",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_survey_feedback:feedback-1", "cosmo.survey_feedback")
	assertCosmoProjectedEntity(t, entities, "urn:cerebro:writer:cosmo_session:ticket-1", "cosmo.session")
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_survey_feedback:feedback-1", relationBelongsTo, "urn:cerebro:writer:cosmo_session:ticket-1")
	assertCosmoProjectedLink(t, links, "urn:cerebro:writer:cosmo_survey_feedback:feedback-1", relationRepresentsIdentity, "urn:cerebro:writer:identity:email:alice@example.com")
}

func TestProjectCosmoSkipsUnidentifiedEvents(t *testing.T) {
	for _, kind := range []string{"cosmo.session", "cosmo.fact", "cosmo.message", "cosmo.survey_feedback"} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
				Id:       "event-without-record-id",
				TenantId: "writer",
				SourceId: "cosmo",
				Kind:     kind,
			})
			if err != nil {
				t.Fatalf("Project() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Project() = %d entities, %d links; want none", len(entities), len(links))
			}
		})
	}
}

func assertCosmoProjectedEntity(t *testing.T, entities []*ports.ProjectedEntity, urn string, entityType string) {
	t.Helper()
	_ = cosmoProjectedEntity(t, entities, urn, entityType)
}

func cosmoProjectedEntity(t *testing.T, entities []*ports.ProjectedEntity, urn string, entityType string) *ports.ProjectedEntity {
	t.Helper()
	for _, entity := range entities {
		if entity.URN == urn && entity.EntityType == entityType {
			return entity
		}
	}
	t.Fatalf("projected entity %q type %q missing from %#v", urn, entityType, entities)
	return nil
}

func assertCosmoProjectedLink(t *testing.T, links []*ports.ProjectedLink, from string, relation string, to string) {
	t.Helper()
	for _, link := range links {
		if link.FromURN == from && link.Relation == relation && link.ToURN == to {
			return
		}
	}
	t.Fatalf("projected link %q %q %q missing from %#v", from, relation, to, links)
}
