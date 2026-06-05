package graphquery

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestGetPersonAccessPathsRequiresSelector(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetPersonAccessPaths(context.Background(), PersonAccessPathRequest{TenantID: "writer"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetPersonAccessPaths() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetPersonAccessPathsRejectsCrossTenantURN(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetPersonAccessPaths(context.Background(), PersonAccessPathRequest{
		TenantID:  "writer",
		PersonURN: "urn:cerebro:other:person:vanta:person-1",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetPersonAccessPaths() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetPersonAccessPathsQueriesAndParsesRows(t *testing.T) {
	store := &awsExposureStubStore{responses: [][]ports.CypherRow{
		{{Values: map[string]any{
			"person_urn":            "urn:cerebro:writer:person:vanta:person-1",
			"person_entity_type":    "person",
			"person_label":          "designer@example.com",
			"identity_urn":          "urn:cerebro:writer:identity:email:designer@example.com",
			"identity_entity_type":  "identity.email",
			"identity_label":        "designer@example.com",
			"principal_urn":         "urn:cerebro:writer:okta_user:00u1",
			"principal_entity_type": "okta.user",
			"principal_label":       "designer@example.com",
			"target_urn":            "urn:cerebro:writer:aws_role:DesignerAnalytics",
			"target_entity_type":    "aws.role",
			"target_label":          "DesignerAnalytics",
			"relation_chain":        []any{"assigned_to"},
		}}},
	}}

	result, err := New(store).GetPersonAccessPaths(context.Background(), PersonAccessPathRequest{
		TenantID:    "writer",
		PersonQuery: "Product Designer",
		Limit:       500,
		Depth:       99,
	})
	if err != nil {
		t.Fatalf("GetPersonAccessPaths() error = %v", err)
	}
	if len(store.requests) != 1 {
		t.Fatalf("query count = %d, want 1", len(store.requests))
	}
	request := store.requests[0]
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("tenant_id param = %v, want writer", got)
	}
	if got := request.Params["person_query"]; got != "product designer" {
		t.Fatalf("person_query param = %v, want product designer", got)
	}
	if request.RowLimit != maxPersonAccessPathLimit {
		t.Fatalf("row limit = %d, want %d", request.RowLimit, maxPersonAccessPathLimit)
	}
	if !strings.Contains(request.Query, "*1..4") {
		t.Fatalf("query = %q, want normalized max depth 4", request.Query)
	}
	for _, want := range []string{
		"person_identity.tenant_id = $tenant_id",
		"principal_identity.tenant_id = $tenant_id",
		"all(node IN nodes(path) WHERE node.tenant_id = $tenant_id)",
		"all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id",
	} {
		if !strings.Contains(request.Query, want) {
			t.Fatalf("query missing tenant-scoping clause %q: %s", want, request.Query)
		}
	}
	if result.Filters.Limit != maxPersonAccessPathLimit || result.Filters.Depth != maxPersonAccessPathDepth {
		t.Fatalf("filters = %#v", result.Filters)
	}
	if result.Counts.Paths != 1 || len(result.Paths) != 1 {
		t.Fatalf("result = %#v", result)
	}
	path := result.Paths[0]
	if path.Person.EntityType != "person" || path.Principal.EntityType != "okta.user" || path.AccessTarget.URN != "urn:cerebro:writer:aws_role:DesignerAnalytics" {
		t.Fatalf("path = %#v", path)
	}
	if len(path.RelationChain) != 1 || path.RelationChain[0] != "assigned_to" {
		t.Fatalf("relation chain = %#v", path.RelationChain)
	}
}
