package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestPermissionEvaluationContextFromRequest_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/graph/principals/user:alice/effective-permissions", nil)
	if ctx := permissionEvaluationContextFromRequest(req); ctx != nil {
		t.Fatalf("expected nil context for request without evaluation params, got %#v", ctx)
	}
}

func TestPermissionEvaluationContextFromRequest_ParsesFields(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"/api/v1/graph/principals/user:alice/effective-permissions?source_ip=10.1.2.3&source_vpce=vpce-123&current_time=2026-03-15T00:00:00Z&context.aws:SourceIp=10.1.2.3&request.time=2026-03-15T00:00:00Z&principal.arn=arn:aws:iam::111111111111:user/alice&resource.name=projects/_/buckets/data&principal_tag.env=prod&resource_tag.classification=restricted",
		nil,
	)

	ctx := permissionEvaluationContextFromRequest(req)
	if ctx == nil {
		t.Fatal("expected parsed evaluation context")
	}
	if ctx.SourceIP != "10.1.2.3" {
		t.Fatalf("expected source IP to be parsed, got %#v", ctx.SourceIP)
	}
	if ctx.SourceVPCe != "vpce-123" {
		t.Fatalf("expected source VPC endpoint to be parsed, got %#v", ctx.SourceVPCe)
	}
	if ctx.CurrentTime.IsZero() || !ctx.CurrentTime.Equal(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("expected current time to be parsed, got %#v", ctx.CurrentTime)
	}
	if ctx.Keys["aws:SourceIp"] != "10.1.2.3" {
		t.Fatalf("expected generic context key to be parsed, got %#v", ctx.Keys)
	}
	if ctx.Request["time"] != "2026-03-15T00:00:00Z" {
		t.Fatalf("expected request.* attribute to be parsed, got %#v", ctx.Request)
	}
	if ctx.Principal["arn"] != "arn:aws:iam::111111111111:user/alice" {
		t.Fatalf("expected principal.* attribute to be parsed, got %#v", ctx.Principal)
	}
	if ctx.Resource["name"] != "projects/_/buckets/data" {
		t.Fatalf("expected resource.* attribute to be parsed, got %#v", ctx.Resource)
	}
	if ctx.PrincipalTags["env"] != "prod" {
		t.Fatalf("expected principal tag to be parsed, got %#v", ctx.PrincipalTags)
	}
	if ctx.ResourceTags["classification"] != "restricted" {
		t.Fatalf("expected resource tag to be parsed, got %#v", ctx.ResourceTags)
	}
}
