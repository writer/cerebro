package graphquery

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestGetEffectiveAccessPathsRequiresIdentitySelector(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{TenantID: "writer"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetEffectiveAccessPaths() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetEffectiveAccessPathsRejectsCrossTenantSelectors(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:    "writer",
		IdentityURN: "urn:cerebro:other:identity:email:alice@example.com",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetEffectiveAccessPaths(identity) error = %v, want %v", err, ErrInvalidRequest)
	}

	_, err = New(&awsExposureStubStore{}).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:       "writer",
		IdentityURN:    "urn:cerebro:writer:identity:email:alice@example.com",
		ApplicationURN: "urn:cerebro:other:okta_application:app-1",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetEffectiveAccessPaths(application) error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestEffectiveAccessPathRequestFromQueryRejectsZeroLimit(t *testing.T) {
	_, err := EffectiveAccessPathRequestFromQuery(url.Values{"limit": []string{"0"}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("EffectiveAccessPathRequestFromQuery() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetEffectiveAccessPathsQueriesAndParsesRows(t *testing.T) {
	store := &awsExposureStubStore{responses: [][]ports.CypherRow{
		{{Values: map[string]any{
			"identity_urn":            "urn:cerebro:writer:identity:email:alice@example.com",
			"identity_entity_type":    "identity.email",
			"identity_label":          "alice@example.com",
			"principal_urn":           "urn:cerebro:writer:okta_user:00u1",
			"principal_entity_type":   "okta.user",
			"principal_label":         "alice@example.com",
			"mediator_urn":            "urn:cerebro:writer:okta_group:grp-security",
			"mediator_entity_type":    "okta.group",
			"mediator_label":          "Security Engineering",
			"target_urn":              "urn:cerebro:writer:okta_application:app-aws-admin",
			"target_entity_type":      "okta.application",
			"target_label":            "AWS Admin Console",
			"entitlement_urn":         "urn:cerebro:writer:okta_entitlement:administratoraccess",
			"entitlement_entity_type": "okta.entitlement",
			"entitlement_label":       "AdministratorAccess",
			"capability_urn":          "urn:cerebro:writer:privileged_capability:cloud_admin",
			"capability_entity_type":  "privileged.capability",
			"capability_label":        "Cloud administrator",
			"assignment_kind":         "group_app_assignment",
			"relation_chain":          []any{"member_of", "assigned_to", "grants_entitlement", "confers_capability"},
			"edges":                   effectiveAccessPathTestEdges(),
		}}},
	}}

	result, err := New(store).GetEffectiveAccessPaths(context.Background(), EffectiveAccessPathRequest{
		TenantID:       "writer",
		IdentityQuery:  "Alice",
		ApplicationURN: "urn:cerebro:writer:okta_application:app-aws-admin",
		Capability:     "Cloud Admin",
		Limit:          500,
	})
	if err != nil {
		t.Fatalf("GetEffectiveAccessPaths() error = %v", err)
	}
	if len(store.requests) != 1 {
		t.Fatalf("query count = %d, want 1", len(store.requests))
	}
	request := store.requests[0]
	if request.RowLimit != maxEffectiveAccessPathLimit {
		t.Fatalf("row limit = %d, want %d", request.RowLimit, maxEffectiveAccessPathLimit)
	}
	if got := request.Params["identity_query"]; got != "alice" {
		t.Fatalf("identity_query param = %v, want alice", got)
	}
	if got := request.Params["capability_id"]; got != "cloud_admin" {
		t.Fatalf("capability_id param = %v, want cloud_admin", got)
	}
	for _, want := range []string{
		"subject:Entity {tenant_id: $tenant_id}",
		"ORDER BY subject.label, subject.urn",
		"principal_link.tenant_id = $tenant_id",
		"MATCH (principal)-[assignment:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})",
		"MATCH (principal)-[membership:RELATION {relation: 'member_of'}]->(mediator:Entity {tenant_id: $tenant_id})-[assignment:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})",
		"membership.tenant_id = $tenant_id",
		"grant.tenant_id = $tenant_id",
		"confers.tenant_id = $tenant_id",
		"LIMIT $sample_limit",
	} {
		if !strings.Contains(request.Query, want) {
			t.Fatalf("query missing %q:\n%s", want, request.Query)
		}
	}
	if result.Filters.Limit != maxEffectiveAccessPathLimit || result.Filters.IdentityQuery != "alice" {
		t.Fatalf("filters = %#v", result.Filters)
	}
	if result.Counts.Paths != 1 || result.Counts.GroupMediatedPaths != 1 || result.Counts.CapabilitiesReturned != 1 {
		t.Fatalf("counts = %#v", result.Counts)
	}
	if len(result.Paths) != 1 {
		t.Fatalf("paths = %#v", result.Paths)
	}
	path := result.Paths[0]
	if path.Mediator == nil || path.Mediator.Label != "Security Engineering" {
		t.Fatalf("mediator = %#v", path.Mediator)
	}
	if path.Capability.URN != "urn:cerebro:writer:privileged_capability:cloud_admin" {
		t.Fatalf("capability = %#v", path.Capability)
	}
	if got := path.Edges[1]; got.SourceID != "okta" || got.RuntimeID != "writer-okta" || got.EventID != "evt-assign" || got.At != "2026-06-10T18:00:00Z" {
		t.Fatalf("assignment edge = %#v", got)
	}
	if got := path.Edges[1].Attributes["assignment_id"]; got != "asg-1" {
		t.Fatalf("assignment attribute = %q, want asg-1", got)
	}
}

func TestEffectiveAccessPathsFromRowsDropsIncompleteProofs(t *testing.T) {
	rows := []ports.CypherRow{{Values: map[string]any{
		"identity_urn":            "urn:cerebro:writer:identity:email:alice@example.com",
		"identity_entity_type":    "identity.email",
		"identity_label":          "alice@example.com",
		"principal_urn":           "urn:cerebro:writer:okta_user:00u1",
		"principal_entity_type":   "okta.user",
		"principal_label":         "alice@example.com",
		"target_urn":              "urn:cerebro:writer:okta_application:app-aws-admin",
		"target_entity_type":      "okta.application",
		"target_label":            "AWS Admin Console",
		"entitlement_urn":         "urn:cerebro:writer:okta_entitlement:administratoraccess",
		"entitlement_entity_type": "okta.entitlement",
		"entitlement_label":       "AdministratorAccess",
		"capability_urn":          "urn:cerebro:writer:privileged_capability:cloud_admin",
		"capability_entity_type":  "privileged.capability",
		"capability_label":        "Cloud administrator",
		"assignment_kind":         "direct_app_assignment",
		"relation_chain":          []any{"assigned_to", "grants_entitlement"},
		"edges":                   effectiveAccessPathTestEdges()[1:],
	}}}
	if got := effectiveAccessPathsFromRows(rows); len(got) != 0 {
		t.Fatalf("effectiveAccessPathsFromRows() = %#v, want empty", got)
	}
}

func TestEffectiveAccessPathCountsSplitRoleAssignments(t *testing.T) {
	counts := effectiveAccessPathCounts([]EffectiveAccessPath{
		{AssignmentKind: "direct_app_assignment", Capability: GraphEntityRef{URN: "capability:app"}},
		{AssignmentKind: "group_app_assignment", Capability: GraphEntityRef{URN: "capability:app"}},
		{AssignmentKind: "role_assignment", Capability: GraphEntityRef{URN: "capability:role"}},
		{AssignmentKind: "admin_role_assignment", Capability: GraphEntityRef{URN: "capability:admin"}},
	})
	if counts.DirectAssignments != 1 || counts.GroupMediatedPaths != 1 || counts.RolePaths != 1 || counts.AdminRolePaths != 1 || counts.CapabilitiesReturned != 3 {
		t.Fatalf("counts = %#v", counts)
	}
}

func TestEffectiveAccessPathAccessClassification(t *testing.T) {
	mediator := GraphEntityRef{URN: "urn:cerebro:writer:okta_group:grp-finance", EntityType: "okta.group", Label: "Finance Admins"}
	path := EffectiveAccessPath{
		Mediator:       &mediator,
		AccessTarget:   GraphEntityRef{URN: "urn:cerebro:writer:okta_application:payroll", EntityType: "okta.application", Label: "Payroll"},
		Entitlement:    GraphEntityRef{URN: "urn:cerebro:writer:okta_entitlement:admin", EntityType: "okta.entitlement", Label: "Admin"},
		Capability:     GraphEntityRef{URN: "urn:cerebro:writer:privileged_capability:payroll_admin", EntityType: "privileged.capability", Label: "Payroll administrator"},
		AssignmentKind: "admin_role_assignment",
		RelationChain:  []string{"member_of", "assigned_to", "can_admin"},
		Edges: []EffectiveAccessPathEdge{{
			Relation: "can_admin",
			Attributes: map[string]string{
				"data_classification": "sensitive",
			},
		}},
	}
	if !path.IsPrivileged() {
		t.Fatalf("IsPrivileged() = false, want true")
	}
	if !path.IsSensitive() {
		t.Fatalf("IsSensitive() = false, want true")
	}
	want := []string{"group_mediated", "privileged", "role_based", "sensitive"}
	if got := path.AccessClassification(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("AccessClassification() = %#v, want %#v", got, want)
	}
}

func TestEffectiveAccessPathSupportsOperationProofRequiresChangedPrivilegedOrSensitiveAccess(t *testing.T) {
	standard := EffectiveAccessPath{
		AssignmentKind: "direct_app_assignment",
		AccessTarget:   GraphEntityRef{URN: "urn:cerebro:writer:okta_application:app-1", EntityType: "okta.application", Label: "App"},
		Entitlement:    GraphEntityRef{URN: "urn:cerebro:writer:okta_entitlement:user", EntityType: "okta.entitlement", Label: "User"},
		Capability:     GraphEntityRef{URN: "urn:cerebro:writer:capability:standard_access", EntityType: "capability", Label: "Standard access"},
	}
	if standard.SupportsOperationProof(true) {
		t.Fatalf("standard SupportsOperationProof(true) = true, want false")
	}

	privileged := standard
	privileged.Capability = GraphEntityRef{URN: "urn:cerebro:writer:privileged_capability:admin", EntityType: "privileged.capability", Label: "Administrator"}
	if privileged.SupportsOperationProof(false) {
		t.Fatalf("privileged SupportsOperationProof(false) = true, want false")
	}
	if !privileged.SupportsOperationProof(true) {
		t.Fatalf("privileged SupportsOperationProof(true) = false, want true")
	}

	sensitive := standard
	sensitive.AccessTarget = GraphEntityRef{URN: "urn:cerebro:writer:okta_application:finance", EntityType: "okta.application", Label: "Finance Reports"}
	if !sensitive.SupportsOperationProof(true) {
		t.Fatalf("sensitive SupportsOperationProof(true) = false, want true")
	}
}

func effectiveAccessPathTestEdges() []any {
	return []any{
		map[string]any{
			"from_urn":         "urn:cerebro:writer:okta_user:00u1",
			"from_entity_type": "okta.user",
			"from_label":       "alice@example.com",
			"relation":         "member_of",
			"to_urn":           "urn:cerebro:writer:okta_group:grp-security",
			"to_entity_type":   "okta.group",
			"to_label":         "Security Engineering",
			"source_id":        "okta",
			"runtime_id":       "writer-okta",
			"attributes_json":  `{"event_id":"evt-member","at":"2026-06-10T17:00:00Z"}`,
		},
		map[string]any{
			"from_urn":         "urn:cerebro:writer:okta_group:grp-security",
			"from_entity_type": "okta.group",
			"from_label":       "Security Engineering",
			"relation":         "assigned_to",
			"to_urn":           "urn:cerebro:writer:okta_application:app-aws-admin",
			"to_entity_type":   "okta.application",
			"to_label":         "AWS Admin Console",
			"source_id":        "okta",
			"runtime_id":       "writer-okta",
			"attributes_json":  `{"assignment_id":"asg-1","event_id":"evt-assign","at":"2026-06-10T18:00:00Z"}`,
		},
		map[string]any{
			"from_urn":         "urn:cerebro:writer:okta_application:app-aws-admin",
			"from_entity_type": "okta.application",
			"from_label":       "AWS Admin Console",
			"relation":         "grants_entitlement",
			"to_urn":           "urn:cerebro:writer:okta_entitlement:administratoraccess",
			"to_entity_type":   "okta.entitlement",
			"to_label":         "AdministratorAccess",
			"source_id":        "okta",
			"runtime_id":       "writer-okta",
			"attributes_json":  `{"event_id":"evt-entitlement","at":"2026-06-10T18:00:00Z"}`,
		},
		map[string]any{
			"from_urn":         "urn:cerebro:writer:okta_entitlement:administratoraccess",
			"from_entity_type": "okta.entitlement",
			"from_label":       "AdministratorAccess",
			"relation":         "confers_capability",
			"to_urn":           "urn:cerebro:writer:privileged_capability:cloud_admin",
			"to_entity_type":   "privileged.capability",
			"to_label":         "Cloud administrator",
			"source_id":        "okta",
			"runtime_id":       "writer-okta",
			"attributes_json":  `{"event_id":"evt-capability","at":"2026-06-10T18:00:00Z"}`,
		},
	}
}
