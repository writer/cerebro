package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectLangChainWorkspaceMemberAccess(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "langchain-workspace-member",
		TenantId:   "writer",
		SourceId:   "langchain",
		Kind:       "langchain.workspace_member",
		OccurredAt: timestamppb.New(time.Date(2026, time.June, 24, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"email":        "ada@example.com",
			"name":         "Ada Lovelace",
			"role":         "Admin",
			"user_id":      "user_123",
			"workspace_id": "workspace_123",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:langchain_user:user_123"
	workspaceURN := "urn:cerebro:writer:langchain_workspace:workspace_123"
	if entity := state.entities[userURN]; entity == nil || entity.EntityType != "langchain.user" || entity.Attributes["email"] != "ada@example.com" {
		t.Fatalf("langchain user entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[workspaceURN]; entity == nil || entity.EntityType != "langchain.workspace" {
		t.Fatalf("langchain workspace entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, userURN, relationCanAdmin, workspaceURN)
}

func TestProjectLangfuseProjectAccessAndCredential(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 24, 12, 0, 0, 0, time.UTC)
	events := []*cerebrov1.EventEnvelope{{
		Id:         "langfuse-project-member",
		TenantId:   "writer",
		SourceId:   "langfuse",
		Kind:       "langfuse.project_member",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"email":      "owner@example.com",
			"name":       "Project Owner",
			"project_id": "project_123",
			"role":       "OWNER",
			"user_id":    "user_123",
		},
	}, {
		Id:         "langfuse-api-key",
		TenantId:   "writer",
		SourceId:   "langfuse",
		Kind:       "langfuse.api_key",
		OccurredAt: timestamppb.New(occurred.Add(time.Minute)),
		Attributes: map[string]string{
			"api_key_id": "key_123",
			"name":       "prod-observability",
			"project_id": "project_123",
			"status":     "active",
		},
	}}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetId(), err)
		}
	}

	userURN := "urn:cerebro:writer:langfuse_user:user_123"
	projectURN := "urn:cerebro:writer:langfuse_project:project_123"
	credentialURN := "urn:cerebro:writer:langfuse_credential:key_123" // #nosec G101 -- test credential URN fixture, not credential material.
	if entity := state.entities[projectURN]; entity == nil || entity.EntityType != "langfuse.project" {
		t.Fatalf("langfuse project entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[credentialURN]; entity == nil || entity.EntityType != "langfuse.credential" || entity.Attributes["project_id"] != "project_123" {
		t.Fatalf("langfuse credential entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, userURN, relationCanAdmin, projectURN)
	assertProjectedLink(t, state, credentialURN, relationCanPerform, projectURN)
}

func TestRegistryRoutesLangChainAndLangfuseDeclaredKinds(t *testing.T) {
	declared := []string{
		"langchain.organization",
		"langchain.workspace",
		"langchain.organization_member",
		"langchain.workspace_member",
		"langchain.role",
		"langchain.api_key",
		"langchain.service_account",
		"langchain.project",
		"langchain.run",
		"langchain.feedback",
		"langchain.dataset",
		"langchain.usage_limit",
		"langchain.audit_log",
		"langfuse.project",
		"langfuse.project_member",
		"langfuse.api_key",
		"langfuse.trace",
		"langfuse.observation",
		"langfuse.score",
		"langfuse.prompt",
		"langfuse.session",
		"langfuse.metric",
		"langfuse.annotation_queue",
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, kind := range declared {
		if _, ok := registered[kind]; !ok {
			t.Fatalf("declared kind %q is not routed in the projection registry", kind)
		}
	}
}
