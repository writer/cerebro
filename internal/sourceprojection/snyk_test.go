package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestSnykAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.assets", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := snykAssetsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestSnykFindingProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.findings", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := snykFindingsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected finding")
	}
	if len(links) == 0 {
		t.Fatal("expected projected finding links")
	}
	if !hasProjectedEntityType(entities, "runtime_evidence") {
		t.Fatal("expected projected runtime evidence entity")
	}
}

func TestSnykVulnerabilitiesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.vulnerabilities", Attributes: map[string]string{"finding_id": "finding-1", "title": "Finding One", "severity": "high", "status": "open", "resource_urn": "urn:cerebro:tenant:runtime_asset:asset-1", "evidence_id": "evidence-1"}}
	entities, links, err := snykVulnerabilitiesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected finding")
	}
	if len(links) == 0 {
		t.Fatal("expected projected finding links")
	}
	if !hasProjectedEntityType(entities, "runtime_evidence") {
		t.Fatal("expected projected runtime evidence entity")
	}
}

func TestSnykGroupMembershipProjectionLinksMemberToGroup(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.group_memberships", Attributes: map[string]string{"group_id": "group-1", "member_user_id": "user-1", "member_type": "user", "role": "collaborator"}}
	entities, links, err := snykGroupMembershipsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if !hasProjectedEntityType(entities, "snyk.user") || !hasProjectedEntityType(entities, "snyk.groups") {
		t.Fatalf("expected projected Snyk user and group entities; entities=%#v", entities)
	}
	if !hasSnykProjectedLink(links, identityUserURN("tenant", "snyk", "user-1", ""), relationMemberOf, projectionURN("tenant", "snyk_groups", "group-1")) {
		t.Fatalf("expected member_of link; links=%#v", links)
	}
}

func TestSnykOrgMembershipProjectionLinksMemberToOrg(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.org_memberships", Attributes: map[string]string{"group_id": "org-1", "member_user_id": "user-1", "member_type": "user", "role": "admin"}}
	entities, links, err := snykOrgMembershipsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if !hasProjectedEntityType(entities, "snyk.user") || !hasProjectedEntityType(entities, "snyk.orgs") {
		t.Fatalf("expected projected Snyk user and org entities; entities=%#v", entities)
	}
	if !hasSnykProjectedLink(links, identityUserURN("tenant", "snyk", "user-1", ""), relationMemberOf, projectionURN("tenant", "snyk_orgs", "org-1")) {
		t.Fatalf("expected member_of link; links=%#v", links)
	}
}

func TestSnykServiceAccountProjectionLinksRole(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.service_accounts", Attributes: map[string]string{"service_account_id": "service-account-1", "name": "CI scanner", "role_id": "admin", "level": "org"}}
	entities, links, err := snykServiceAccountsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if !hasProjectedEntityType(entities, "snyk.service_account") || !hasProjectedEntityType(entities, "snyk.admin.role") {
		t.Fatalf("expected service account and admin role entities; entities=%#v", entities)
	}
	if !hasSnykProjectedLink(links, identityPrincipalURN("tenant", "snyk", "service_account", "service-account-1", ""), relationCanAdmin, projectionURN("tenant", "snyk_admin_role", "admin")) {
		t.Fatalf("expected service account admin role link; links=%#v", links)
	}
}

func TestSnykAuditProjectionLinksActorToResource(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.audit_logs", Attributes: map[string]string{"actor_id": "user-1", "actor_email": "alice@example.test", "resource_id": "project-1", "resource_type": "project", "event_type": "org.project.create"}}
	entities, links, err := snykAuditLogsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if !hasProjectedEntityType(entities, "snyk.user") || !hasProjectedEntityType(entities, "snyk.projects") {
		t.Fatalf("expected audit actor and resource entities; entities=%#v", entities)
	}
	if !hasSnykProjectedLink(links, identityUserURN("tenant", "snyk", "user-1", "alice@example.test"), relationActedOn, projectionURN("tenant", "snyk_projects", "project-1")) {
		t.Fatalf("expected acted_on link; links=%#v", links)
	}
}

func TestSnykAssetRelationshipProjectionLinksAssetToProjectAndTarget(t *testing.T) {
	for _, tt := range []struct {
		name       string
		kind       string
		projector  func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)
		attributes map[string]string
		wantType   string
		wantURN    string
	}{
		{
			name:       "project",
			kind:       "snyk.asset_project_relationships",
			projector:  snykAssetProjectRelationshipProjections,
			attributes: map[string]string{"asset_id": "asset-1", "project_id": "project-1", "resource_name": "Checkout API"},
			wantType:   "snyk.projects",
			wantURN:    projectionURN("tenant", "snyk_projects", "project-1"),
		},
		{
			name:       "target",
			kind:       "snyk.asset_target_relationships",
			projector:  snykAssetTargetRelationshipProjections,
			attributes: map[string]string{"asset_id": "asset-1", "target_id": "target-1", "resource_name": "writer/cerebro"},
			wantType:   "snyk.targets",
			wantURN:    projectionURN("tenant", "snyk_targets", "target-1"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "snyk", Kind: tt.kind, Attributes: tt.attributes}
			entities, links, err := tt.projector(event)
			if err != nil {
				t.Fatalf("projection error = %v", err)
			}
			if hasProjectedEntityURN(entities, projectionURN("tenant", "snyk_assets", "asset-1")) {
				t.Fatalf("asset relationship projection upserted asset entity with conflicting type; entities=%#v", entities)
			}
			if !hasProjectedEntityType(entities, tt.wantType) {
				t.Fatalf("expected related entity; entities=%#v", entities)
			}
			if !hasSnykProjectedLink(links, projectionURN("tenant", "snyk_assets", "asset-1"), relationAssociatedWith, tt.wantURN) {
				t.Fatalf("expected asset relationship link; links=%#v", links)
			}
		})
	}
}

func TestSnykRuntimeKindsAreExplicitDepthEvidence(t *testing.T) {
	cases := []struct {
		event      *cerebrov1.EventEnvelope
		entityType string
		entityURN  string
	}{
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-org-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.orgs", Attributes: map[string]string{"org_id": "org-1", "name": "Security"}},
			entityType: "snyk.orgs",
			entityURN:  "urn:cerebro:tenant:snyk_orgs:org-1",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-group-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.groups", Attributes: map[string]string{"group_id": "group-1", "name": "Engineering"}},
			entityType: "snyk.groups",
			entityURN:  "urn:cerebro:tenant:snyk_groups:group-1",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-project-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.projects", Attributes: map[string]string{"project_id": "project-1", "name": "Checkout API", "resource_type": "snyk_project"}},
			entityType: "snyk.projects",
			entityURN:  "urn:cerebro:tenant:snyk_projects:project-1",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-target-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.targets", Attributes: map[string]string{"target_id": "target-1", "display_name": "writer/cerebro", "resource_type": "snyk_target"}},
			entityType: "snyk.targets",
			entityURN:  "urn:cerebro:tenant:snyk_targets:target-1",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-asset-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.assets", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "repository", "resource_name": "writer/cerebro"}},
			entityType: "runtime.repository",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-finding-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.findings", Attributes: map[string]string{"finding_id": "issue-1", "title": "Critical package issue", "severity": "critical", "status": "open"}},
			entityType: "finding",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-vulnerability-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.vulnerabilities", Attributes: map[string]string{"finding_id": "vuln-1", "title": "CVE-2026-0001", "severity": "high", "status": "open"}},
			entityType: "finding",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-org-membership-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.org_memberships", Attributes: map[string]string{"group_id": "org-1", "member_user_id": "user-1", "member_type": "user"}},
			entityType: "snyk.user",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-service-account-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.service_accounts", Attributes: map[string]string{"service_account_id": "service-account-1", "role_id": "admin"}},
			entityType: "snyk.service_account",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-audit-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.audit_logs", Attributes: map[string]string{"actor_id": "user-1", "resource_id": "project-1", "resource_type": "project"}},
			entityType: "snyk.user",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-collection-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.collections", Attributes: map[string]string{"collection_id": "collection-1", "name": "Tier 0 services"}},
			entityType: "snyk.collections",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-cloud-environment-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.cloud_environments", Attributes: map[string]string{"environment_id": "environment-1", "resource_name": "aws-prod"}},
			entityType: "snyk.cloud_environments",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-cloud-resource-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.cloud_resources", Attributes: map[string]string{"resource_id": "arn:aws:s3:::prod-bucket", "resource_type": "aws_s3_bucket", "resource_name": "prod-bucket"}},
			entityType: "runtime.aws.s3.bucket",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-cloud-scan-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.cloud_scans", Attributes: map[string]string{"scan_id": "scan-1", "status": "finished"}},
			entityType: "snyk.cloud_scans",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-group-membership-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.group_memberships", Attributes: map[string]string{"group_id": "group-1", "member_user_id": "user-1", "member_type": "user"}},
			entityType: "snyk.user",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-group-service-account-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.group_service_accounts", Attributes: map[string]string{"service_account_id": "group-service-account-1", "role_id": "admin"}},
			entityType: "snyk.service_account",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-group-audit-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.group_audit_logs", Attributes: map[string]string{"actor_id": "user-1", "resource_id": "group-1", "resource_type": "membership"}},
			entityType: "snyk.user",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-asset-project-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.asset_project_relationships", Attributes: map[string]string{"asset_id": "asset-1", "project_id": "project-1"}},
			entityType: "snyk.projects",
		},
		{
			event:      &cerebrov1.EventEnvelope{Id: "snyk-asset-target-event", TenantId: "tenant", SourceId: "snyk", Kind: "snyk.asset_target_relationships", Attributes: map[string]string{"asset_id": "asset-1", "target_id": "target-1"}},
			entityType: "snyk.targets",
		},
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, tc := range cases {
		t.Run(tc.event.Kind, func(t *testing.T) {
			if _, ok := registered[tc.event.Kind]; !ok {
				t.Fatalf("declared Snyk kind %q is not routed in the projection registry", tc.event.Kind)
			}
			entities, _, err := BuiltinRegistry().Project(tc.event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.event.Kind, err)
			}
			if !hasProjectedEntityType(entities, tc.entityType) {
				t.Fatalf("kind %q did not project %q; entities=%#v", tc.event.Kind, tc.entityType, entities)
			}
			if tc.entityURN != "" && !hasProjectedEntityURN(entities, tc.entityURN) {
				t.Fatalf("kind %q did not project URN %q; entities=%#v", tc.event.Kind, tc.entityURN, entities)
			}
		})
	}
}

func TestSnykOrgProjectionUsesOrgIDWhenGroupIDPresent(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id:       "snyk-org-event",
		TenantId: "tenant",
		SourceId: "snyk",
		Kind:     "snyk.orgs",
		Attributes: map[string]string{
			"org_id":   "org-1",
			"group_id": "group-1",
			"name":     "Security",
		},
	}
	entities, _, err := BuiltinRegistry().Project(event)
	if err != nil {
		t.Fatalf("Project(snyk.orgs) error = %v", err)
	}
	for _, entity := range entities {
		if entity.EntityType == "snyk.orgs" {
			if entity.URN != "urn:cerebro:tenant:snyk_orgs:org-1" {
				t.Fatalf("snyk org URN = %q, want org-scoped URN", entity.URN)
			}
			return
		}
	}
	t.Fatalf("missing snyk.orgs entity in %#v", entities)
}

func hasProjectedEntityURN(entities []*ports.ProjectedEntity, urn string) bool {
	for _, entity := range entities {
		if entity != nil && entity.URN == urn {
			return true
		}
	}
	return false
}

func hasSnykProjectedLink(links []*ports.ProjectedLink, from string, relation string, to string) bool {
	for _, link := range links {
		if link != nil && link.FromURN == from && link.Relation == relation && link.ToURN == to {
			return true
		}
	}
	return false
}
