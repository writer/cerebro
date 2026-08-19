package graphquery

import (
	"context"
	"errors"
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
	entity := func(kind, urn, label string) ports.CatalogEntity {
		return ports.CatalogEntity{URN: urn, TenantID: "writer", EntityType: kind, Label: label}
	}
	store := &awsExposureStubStore{personResult: &ports.PersonAccessPathResult{
		TenantID: "writer",
		Paths: []ports.PersonAccessPath{{
			Person:        entity("person", "urn:cerebro:writer:person:vanta:person-1", "designer@example.com"),
			Identity:      entity("identity.email", "urn:cerebro:writer:identity:email:designer@example.com", "designer@example.com"),
			Principal:     entity("okta.user", "urn:cerebro:writer:okta_user:00u1", "designer@example.com"),
			AccessTarget:  entity("aws.role", "urn:cerebro:writer:aws_role:DesignerAnalytics", "DesignerAnalytics"),
			RelationChain: []string{"assigned_to"},
		}},
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
	if len(store.personRequests) != 1 {
		t.Fatalf("typed request count = %d, want 1", len(store.personRequests))
	}
	request := store.personRequests[0]
	if request.TenantID != "writer" {
		t.Fatalf("tenant_id = %v, want writer", request.TenantID)
	}
	if request.PersonQuery != "product designer" {
		t.Fatalf("person_query = %v, want product designer", request.PersonQuery)
	}
	if request.Limit != maxPersonAccessPathLimit || request.Depth != maxPersonAccessPathDepth {
		t.Fatalf("request bounds = %#v", request)
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
