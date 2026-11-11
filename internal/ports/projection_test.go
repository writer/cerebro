package ports

import (
	"errors"
	"strings"
	"testing"
)

func requireProjectedTenantScopeError(t *testing.T, err error, field, urn string) {
	t.Helper()
	if !errors.Is(err, ErrProjectedTenantScope) {
		t.Fatalf("error = %v, want %v", err, ErrProjectedTenantScope)
	}
	var scopeErr *ProjectedTenantScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("error = %T, want *ProjectedTenantScopeError", err)
	}
	if scopeErr.Field != field || scopeErr.URN != urn || scopeErr.URNTenantID != "victim" || scopeErr.ProjectionTenantID != "writer" {
		t.Fatalf("scope error = %#v", scopeErr)
	}
}

func TestValidateProjectedTenantScopesRejectsCrossTenantCerebroURNs(t *testing.T) {
	err := ValidateProjectedTenantScopes(
		[]*ProjectedEntity{
			{URN: "urn:cerebro:writer:asset:ok", TenantID: "writer"},
			{URN: "arn:aws:s3:::shared-bucket", TenantID: "writer"},
			{URN: "urn:cerebro:victim:asset:stolen", TenantID: "writer"},
		},
		nil,
	)
	if err == nil {
		t.Fatal("ValidateProjectedTenantScopes() error = nil, want cross-tenant Cerebro URN error")
	}
	requireProjectedTenantScopeError(t, err, "projected entity urn", "urn:cerebro:victim:asset:stolen")
}

func TestValidateProjectedTenantScopesAllowsSameTenantAndExternalURNs(t *testing.T) {
	err := ValidateProjectedTenantScopes(
		[]*ProjectedEntity{
			{URN: "urn:cerebro:writer:asset:ok", TenantID: "writer"},
			{URN: "arn:aws:s3:::shared-bucket", TenantID: "writer"},
		},
		[]*ProjectedLink{
			{
				TenantID: "writer",
				FromURN:  "urn:cerebro:writer:asset:ok",
				ToURN:    "https://example.test/resource",
			},
		},
	)
	if err != nil {
		t.Fatalf("ValidateProjectedTenantScopes() error = %v", err)
	}
}

func TestValidateProjectedTenantScopesRejectsCrossTenantLinkEndpoint(t *testing.T) {
	err := ValidateProjectedTenantScopes(nil, []*ProjectedLink{
		{
			TenantID: "writer",
			FromURN:  "urn:cerebro:writer:asset:ok",
			ToURN:    "urn:cerebro:victim:asset:target",
		},
	})
	if err == nil {
		t.Fatal("ValidateProjectedTenantScopes() error = nil, want cross-tenant link endpoint error")
	}
	requireProjectedTenantScopeError(t, err, "projected link to urn", "urn:cerebro:victim:asset:target")
}

func TestValidateApplicationWorkspaceScopeIsTenantQualifiedAndBounded(t *testing.T) {
	if got, err := ValidateApplicationWorkspaceScope("tenant-a", " workspace-a "); err != nil || got != "workspace-a" {
		t.Fatalf("ValidateApplicationWorkspaceScope() = %q, %v", got, err)
	}
	for _, test := range []struct {
		tenantID    string
		workspaceID string
	}{
		{workspaceID: "workspace-a"},
		{tenantID: "tenant-a", workspaceID: "*"},
		{tenantID: "tenant-a", workspaceID: "workspace-a,workspace-b"},
		{tenantID: "tenant-a", workspaceID: "workspace\nother"},
	} {
		if _, err := ValidateApplicationWorkspaceScope(test.tenantID, test.workspaceID); err == nil {
			t.Fatalf("ValidateApplicationWorkspaceScope(%q, %q) error = nil", test.tenantID, test.workspaceID)
		}
	}
	if got, err := ValidateApplicationWorkspaceScope("", ""); err != nil || got != "" {
		t.Fatalf("blank tenant-wide legacy scope = %q, %v", got, err)
	}
	if got, err := ValidateApplicationWorkspaceScope("tenant-a", strings.Repeat("w", 128)); err != nil || len(got) != 128 {
		t.Fatalf("128-byte workspace scope = %q, %v", got, err)
	}
	if _, err := ValidateApplicationWorkspaceScope("tenant-a", strings.Repeat("w", 129)); err == nil {
		t.Fatal("129-byte workspace scope error = nil")
	}
}

// Contract G1 rule 4: Incomplete must never carry links.
func TestValidateProjectedLinkSetIncompleteRejectsLinks(t *testing.T) {
	set := &ProjectedLinkSet{
		OwnerURN: "urn:cerebro:writer:aws_role:principal", Relation: "associated_with", Incomplete: true,
		Links: []*ProjectedLink{{FromURN: "urn:cerebro:writer:aws_role:principal", ToURN: "urn:cerebro:writer:kubernetes_service_account:ns/a", Relation: "associated_with"}},
	}
	if err := ValidateProjectedLinkSetIncomplete(set); err == nil {
		t.Fatal("ValidateProjectedLinkSetIncomplete(incomplete with links) error = nil, want rejection")
	}
	set.Links = nil
	if err := ValidateProjectedLinkSetIncomplete(set); err != nil {
		t.Fatalf("ValidateProjectedLinkSetIncomplete(incomplete without links) error = %v, want nil", err)
	}
	set.Incomplete = false
	set.Links = []*ProjectedLink{{FromURN: "a", ToURN: "b", Relation: "r"}}
	if err := ValidateProjectedLinkSetIncomplete(set); err != nil {
		t.Fatalf("ValidateProjectedLinkSetIncomplete(complete with links) error = %v, want nil", err)
	}
}

// Contract G1 rule 1: a key present in incoming must never be removed, even
// if it is also named in retracted; keys absent from incoming are deleted.
func TestApplyRetractedAttributesRemovesAbsentKeysOnly(t *testing.T) {
	attributes := map[string]string{"triage_state": "none", "triage_reason": "reviewed", "status": "open"}
	incoming := map[string]string{"triage_state": "none", "status": "open"}
	got := ApplyRetractedAttributes(attributes, incoming, []string{"triage_reason", "status"})
	if _, present := got["triage_reason"]; present {
		t.Fatalf("ApplyRetractedAttributes() = %#v, want triage_reason removed", got)
	}
	if got["status"] != "open" {
		t.Fatalf("ApplyRetractedAttributes() = %#v, want status kept (present in incoming)", got)
	}
}

// Contract G1 rule 3: the coalesced RetractedAttributes field is the union
// of both lists minus whichever keys the final coalesced attributes still
// carry.
func TestCoalesceRetractedAttributesUnionsMinusPresentKeys(t *testing.T) {
	attributes := map[string]string{"triage_reason": "reinstated"}
	got := CoalesceRetractedAttributes(attributes, []string{"triage_reason", "triage_by"}, []string{"triage_by", "status"})
	want := []string{"status", "triage_by"}
	if len(got) != len(want) {
		t.Fatalf("CoalesceRetractedAttributes() = %#v, want %#v", got, want)
	}
	for i, key := range want {
		if got[i] != key {
			t.Fatalf("CoalesceRetractedAttributes() = %#v, want %#v", got, want)
		}
	}
	if got := CoalesceRetractedAttributes(nil, nil, nil); got != nil {
		t.Fatalf("CoalesceRetractedAttributes(empty) = %#v, want nil", got)
	}
}
