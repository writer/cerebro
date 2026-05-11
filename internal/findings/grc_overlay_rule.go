package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var (
	_ GraphRule = (*grcInactiveIdentityActiveAccessRule)(nil)
	_ GraphRule = (*grcPrivilegedAccountMissingPersonRule)(nil)
	_ GraphRule = (*grcOverdueVulnerabilityLiveOnAssetsRule)(nil)
	_ GraphRule = (*grcFailingControlOpenOperationalFindingsRule)(nil)
)

const (
	grcInactiveIdentityActiveAccessRuleID        = "grc-inactive-identity-active-access"
	grcInactiveIdentityActiveAccessKind          = "finding.grc_inactive_identity_active_access"
	grcPrivilegedAccountMissingPersonRuleID      = "grc-privileged-account-missing-person"
	grcPrivilegedAccountMissingPersonKind        = "finding.grc_privileged_account_missing_person"
	grcOverdueVulnerabilityLiveOnAssetsRuleID    = "grc-overdue-vulnerability-live-on-assets"
	grcOverdueVulnerabilityLiveOnAssetsKind      = "finding.grc_overdue_vulnerability_live_on_assets"
	grcFailingControlOpenOperationalFindingsID   = "grc-failing-control-open-operational-findings"
	grcFailingControlOpenOperationalFindingsKind = "finding.grc_failing_control_open_operational_findings"
	grcOverlayQueryRowLimit                      = 500
	grcOverlayIdentityRecencyWindow              = 45 * 24 * time.Hour
	grcOverlayActivityRecencyWindow              = 30 * 24 * time.Hour
	grcOverlayAccessEdgeRelationActedOn          = "acted_on"
	grcOverlayAccessEdgeRelationCanAdmin         = "can_admin"
	grcOverlayAccessEdgeRelationCanAssume        = "can_assume"
	grcOverlayAccessEdgeRelationCanImpersonate   = "can_impersonate"
	grcOverlayAccessEdgeRelationCanPerform       = "can_perform"
	grcOverlaySourceID                           = "grc"
	grcOverlayEntityTypePerson                   = "person"
	grcOverlayEntityTypeUser                     = "user"
	grcOverlayEntityTypeVulnerability            = "vulnerability"
	grcOverlayEntityTypeGitHubUser               = "github.user"
	grcOverlayEntityTypeOktaUser                 = "okta.user"
	grcOverlayEntityTypeGoogleWorkspaceUser      = "google_workspace.user"
	grcOverlayEntityTypeAWSUser                  = "aws.user"
	grcOverlayEntityTypeGCPUser                  = "gcp.user"
	grcOverlayEntityTypeAzureUser                = "azure.user"
	grcOverlayRuntimeFamilyPerson                = "person"
	grcOverlayRuntimeFamilyUser                  = "user"
	grcOverlayRuntimeFamilyVulnerability         = "vulnerability"
	grcOverlayRuntimeFamilyAudit                 = "audit"
	grcOverlayRuntimeFamilyCloudTrail            = "cloudtrail"
	grcOverlayRuntimeFamilyAdminRole             = "admin_role"
	grcOverlayRuntimeFamilyRoleAssignment        = "role_assignment"
	grcOverlayRuntimeFamilyIAMRoleAssignment     = "iam_role_assignment"
	grcOverlayRuntimeFamilyIAMRoleTrust          = "iam_role_trust"
	grcOverlayRuntimeFamilyEffectivePermission   = "effective_permission"
	grcOverlayRuntimeFamilyDirectoryRoleAssign   = "directory_role_assignment"
	grcOverlayRuntimeFamilyAppRoleAssignment     = "app_role_assignment"
	grcOverlayRuntimeFamilyActivityLog           = "activity_log"
	grcOverlayRuntimeFamilyDirectoryAudit        = "directory_audit"
	grcOverlayRuntimeFamilyDependabotAlert       = "dependabot_alert"
	grcOverlayRuntimeFamilyApplication           = "application"
	grcOverlayRuntimeFamilyThreat                = "threat"
	grcOverlayRuntimeFamilyServiceImpersonation  = "service_account_impersonation"
)

var (
	grcOverlayHumanPrincipalTypes = []string{
		grcOverlayEntityTypeOktaUser,
		grcOverlayEntityTypeGitHubUser,
		grcOverlayEntityTypeGoogleWorkspaceUser,
		grcOverlayEntityTypeAWSUser,
		grcOverlayEntityTypeGCPUser,
		grcOverlayEntityTypeAzureUser,
	}
	grcOverlayActiveAccessRelations = []string{
		grcOverlayAccessEdgeRelationActedOn,
		grcOverlayAccessEdgeRelationCanAdmin,
		grcOverlayAccessEdgeRelationCanAssume,
		grcOverlayAccessEdgeRelationCanImpersonate,
		grcOverlayAccessEdgeRelationCanPerform,
	}
	grcOverlayPrivilegedRelations = []string{
		grcOverlayAccessEdgeRelationCanAdmin,
		grcOverlayAccessEdgeRelationCanAssume,
		grcOverlayAccessEdgeRelationCanImpersonate,
		grcOverlayAccessEdgeRelationCanPerform,
	}
)

type grcInactiveIdentityActiveAccessRule struct {
	definition RuleDefinition
}

func newGRCInactiveIdentityActiveAccessRule() Rule {
	return &grcInactiveIdentityActiveAccessRule{
		definition: RuleDefinition{
			ID:          grcInactiveIdentityActiveAccessRuleID,
			Name:        "Inactive GRC Identity Still Has Active Access",
			Description: "Detect provider-neutral GRC people or users marked inactive whose email identity still bridges to active access or privileged accounts in connected systems.",
			SourceID:    grcOverlaySourceID,
			EventKinds: []string{
				"grc.person",
				"grc.user",
				"github.audit",
				"okta.user",
				"google_workspace.user",
				"google_workspace.audit",
				"aws.cloudtrail",
				"aws.iam_role_assignment",
				"azure.activity_log",
				"azure.directory_role_assignment",
				"gcp.audit",
				"gcp.iam_role_assignment",
			},
			OutputKind: grcInactiveIdentityActiveAccessKind,
			Severity:   "CRITICAL",
			Status:     findingStatusOpen,
			Maturity:   "test",
			Tags: []string{
				"grc",
				"identity",
				"offboarding",
				"graph-rule",
				"attack.t1078",
			},
			FalsePositives: []string{
				"Break-glass or service account intentionally retained after offboarding with a documented exception.",
				"GRC roster or identity provider sync lag immediately after a lifecycle change.",
			},
			Runbook: "Confirm the person is inactive in the authoritative GRC roster, revoke or suspend the bridged account in the connected system, rotate credentials created by the account, and record any approved exception.",
			FingerprintFields: []string{
				"grc_subject_urn",
				"principal_urn",
			},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
				{FrameworkName: "SOC 2", ControlID: "CC6.6"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
			},
		},
	}
}

func (r *grcInactiveIdentityActiveAccessRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *grcInactiveIdentityActiveAccessRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return grcOverlayIdentityRuntime(runtime)
}

func (r *grcInactiveIdentityActiveAccessRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *grcInactiveIdentityActiveAccessRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	tenantID := grcOverlayTenantID(runtime)
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (grc:Entity {tenant_id: $tenant_id, source_id: 'grc'})
      -[grc_identity:RELATION {relation: 'represents_identity'}]->(identity:Entity)
      <-[principal_identity:RELATION {relation: 'represents_identity'}]-(principal:Entity {tenant_id: $tenant_id})
WHERE grc.entity_type IN ['person', 'user']
  AND principal.entity_type IN $principal_types
WITH grc, grc_identity, identity, principal, principal_identity
OPTIONAL MATCH (principal)-[access:RELATION]->(resource:Entity)
WHERE access.relation IN $access_relations
WITH grc, grc_identity, identity, principal, principal_identity,
     collect(DISTINCT {
       relation: coalesce(access.relation, ''),
       resource_urn: coalesce(resource.urn, ''),
       resource_type: coalesce(resource.entity_type, ''),
       resource_label: coalesce(resource.label, ''),
       attributes_json: coalesce(access.attributes_json, '')
     }) AS access_edges
RETURN grc.urn AS grc_subject_urn,
       grc.label AS grc_subject_label,
       grc.entity_type AS grc_subject_type,
       coalesce(grc.attributes_json, '') AS grc_attributes_json,
       identity.urn AS identity_urn,
       identity.label AS identity_label,
       principal.urn AS principal_urn,
       principal.label AS principal_label,
       principal.entity_type AS principal_entity_type,
       coalesce(principal.attributes_json, '') AS principal_attributes_json,
       coalesce(grc_identity.attributes_json, '') AS grc_identity_attributes_json,
       coalesce(principal_identity.attributes_json, '') AS principal_identity_attributes_json,
       access_edges
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id":        tenantID,
			"principal_types":  grcOverlayHumanPrincipalTypes,
			"access_relations": grcOverlayActiveAccessRelations,
			"row_limit":        int64(grcOverlayQueryRowLimit),
		},
		RowLimit: grcOverlayQueryRowLimit,
	}
}

func (r *grcInactiveIdentityActiveAccessRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*grcInactiveIdentityActiveAccessGroup{}
	keys := []string{}
	for _, row := range rows {
		grcURN := cypherRowString(row, "grc_subject_urn")
		principalURN := cypherRowString(row, "principal_urn")
		if grcURN == "" || principalURN == "" {
			continue
		}
		grcAttributes := grcOverlayAttributes(cypherRowString(row, "grc_attributes_json"))
		if !grcOverlayAttributesAreGRC(grcAttributes) || !grcOverlayIdentityInactive(grcAttributes) {
			continue
		}
		grcIdentityJSON := cypherRowString(row, "grc_identity_attributes_json")
		principalIdentityJSON := cypherRowString(row, "principal_identity_attributes_json")
		if !grcOverlayFreshEmailBridge(grcIdentityJSON, principalIdentityJSON, now) {
			continue
		}
		principalLabel := cypherRowString(row, "principal_label")
		principalEntityType := cypherRowString(row, "principal_entity_type")
		if principalEntityType == grcOverlayEntityTypeGitHubUser && githubActorIsAutomation(cypherRowString(row, "principal_attributes_json")) {
			continue
		}
		accesses := grcOverlayAccessesFromRow(row, now, false)
		if len(accesses) == 0 {
			continue
		}
		key := grcURN + "\x00" + principalURN
		group, ok := groups[key]
		if !ok {
			group = &grcInactiveIdentityActiveAccessGroup{
				grcSubjectURN:       grcURN,
				grcSubjectLabel:     cypherRowString(row, "grc_subject_label"),
				grcSubjectType:      cypherRowString(row, "grc_subject_type"),
				grcStatus:           grcOverlayIdentityStatus(grcAttributes),
				identityURNs:        map[string]struct{}{},
				identityLabels:      map[string]struct{}{},
				principalURN:        principalURN,
				principalLabel:      principalLabel,
				principalEntityType: principalEntityType,
				accesses:            map[string]grcOverlayAccess{},
			}
			groups[key] = group
			keys = append(keys, key)
		}
		if identityURN := cypherRowString(row, "identity_urn"); identityURN != "" {
			group.identityURNs[identityURN] = struct{}{}
		}
		if identityLabel := cypherRowString(row, "identity_label"); identityLabel != "" {
			group.identityLabels[identityLabel] = struct{}{}
		}
		for _, access := range accesses {
			group.accesses[access.resourceURN+"|"+access.relation] = access
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.accesses) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

func (r *grcInactiveIdentityActiveAccessRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *grcInactiveIdentityActiveAccessGroup, now time.Time) *ports.FindingRecord {
	accessURNs, accessLabels, accessTypes, accessRelations := grcOverlayAccessTelemetry(group.accesses)
	identityURNs := sortedKeys(group.identityURNs)
	identityLabels := sortedKeys(group.identityLabels)
	resourceURNs := deduplicateStrings(append(append([]string{group.grcSubjectURN, group.principalURN}, identityURNs...), accessURNs...))
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, group.grcSubjectURN, group.principalURN)
	summary := fmt.Sprintf(
		"Inactive GRC identity %s is still linked to %s account %s with %d active access path(s)",
		firstNonEmpty(group.grcSubjectLabel, group.grcSubjectURN),
		firstNonEmpty(group.principalEntityType, "external"),
		firstNonEmpty(group.principalLabel, group.principalURN),
		len(group.accesses),
	)
	attributes := map[string]string{
		"primary_resource_urn":   group.grcSubjectURN,
		"grc_subject_urn":        group.grcSubjectURN,
		"grc_subject_label":      group.grcSubjectLabel,
		"grc_subject_type":       group.grcSubjectType,
		"grc_status":             group.grcStatus,
		"identity_urns":          strings.Join(identityURNs, ","),
		"identity_labels":        strings.Join(identityLabels, ","),
		"principal_urn":          group.principalURN,
		"principal_label":        group.principalLabel,
		"principal_entity_type":  group.principalEntityType,
		"access_count":           fmt.Sprintf("%d", len(group.accesses)),
		"access_resource_urns":   strings.Join(accessURNs, ","),
		"access_resource_labels": strings.Join(accessLabels, ","),
		"access_resource_types":  strings.Join(accessTypes, ","),
		"access_relations":       strings.Join(accessRelations, ","),
		"source_runtime_id":      strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant":  tenantID,
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		RuleID:          r.definition.ID,
		Title:           r.definition.Name,
		Severity:        r.definition.Severity,
		Status:          findingStatusOpen,
		Summary:         summary,
		ResourceURNs:    resourceURNs,
		ControlRefs:     cloneFindingControlRefs(r.definition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: now,
		LastObservedAt:  now,
		CheckID:         r.definition.ID,
		CheckName:       r.definition.Name,
	}
}

type grcPrivilegedAccountMissingPersonRule struct {
	definition RuleDefinition
}

func newGRCPrivilegedAccountMissingPersonRule() Rule {
	return &grcPrivilegedAccountMissingPersonRule{
		definition: RuleDefinition{
			ID:          grcPrivilegedAccountMissingPersonRuleID,
			Name:        "Privileged Account Missing GRC Person",
			Description: "Detect privileged human accounts in connected systems that do not have a fresh email-backed bridge to any provider-neutral GRC person or user record.",
			SourceID:    grcOverlaySourceID,
			EventKinds: []string{
				"grc.person",
				"grc.user",
				"okta.admin_role",
				"google_workspace.role_assignment",
				"aws.iam_role_assignment",
				"aws.iam_role_trust",
				"azure.directory_role_assignment",
				"azure.iam_role_assignment",
				"gcp.iam_role_assignment",
				"gcp.service_account_impersonation",
			},
			OutputKind: grcPrivilegedAccountMissingPersonKind,
			Severity:   "HIGH",
			Status:     findingStatusOpen,
			Maturity:   "test",
			Tags: []string{
				"grc",
				"identity",
				"privilege",
				"inventory-gap",
				"graph-rule",
				"attack.t1078",
			},
			FalsePositives: []string{
				"Privileged break-glass account intentionally excluded from the GRC people roster with a documented compensating control.",
				"Recently onboarded employee whose GRC people sync has not completed yet.",
			},
			Runbook: "Validate the privileged account owner, add or correct the GRC people record so it carries the account owner's email, or revoke the privilege if no accountable owner exists.",
			FingerprintFields: []string{
				"principal_urn",
			},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.1"},
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
			},
		},
	}
}

func (r *grcPrivilegedAccountMissingPersonRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *grcPrivilegedAccountMissingPersonRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return grcOverlayIdentityRuntime(runtime)
}

func (r *grcPrivilegedAccountMissingPersonRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *grcPrivilegedAccountMissingPersonRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	tenantID := grcOverlayTenantID(runtime)
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (principal:Entity {tenant_id: $tenant_id})-[privilege:RELATION]->(resource:Entity)
WHERE principal.entity_type IN $principal_types
  AND privilege.relation IN $privilege_relations
WITH principal,
     collect(DISTINCT {
       relation: coalesce(privilege.relation, ''),
       resource_urn: coalesce(resource.urn, ''),
       resource_type: coalesce(resource.entity_type, ''),
       resource_label: coalesce(resource.label, ''),
       attributes_json: coalesce(privilege.attributes_json, '')
     }) AS privilege_edges
OPTIONAL MATCH (principal)-[principal_identity:RELATION {relation: 'represents_identity'}]->(identity:Entity)
      <-[grc_identity:RELATION {relation: 'represents_identity'}]-(grc:Entity {tenant_id: $tenant_id, source_id: 'grc'})
WHERE grc.entity_type IN ['person', 'user']
WITH principal, privilege_edges,
     collect(DISTINCT {
       grc_subject_urn: coalesce(grc.urn, ''),
       grc_subject_label: coalesce(grc.label, ''),
       identity_urn: coalesce(identity.urn, ''),
       identity_label: coalesce(identity.label, ''),
       grc_identity_attributes_json: coalesce(grc_identity.attributes_json, ''),
       principal_identity_attributes_json: coalesce(principal_identity.attributes_json, '')
     }) AS grc_bridges
RETURN principal.urn AS principal_urn,
       principal.label AS principal_label,
       principal.entity_type AS principal_entity_type,
       coalesce(principal.attributes_json, '') AS principal_attributes_json,
       privilege_edges,
       grc_bridges
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id":           tenantID,
			"principal_types":     grcOverlayHumanPrincipalTypes,
			"privilege_relations": grcOverlayPrivilegedRelations,
			"row_limit":           int64(grcOverlayQueryRowLimit),
		},
		RowLimit: grcOverlayQueryRowLimit,
	}
}

func (r *grcPrivilegedAccountMissingPersonRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*grcPrivilegedAccountMissingPersonGroup{}
	keys := []string{}
	for _, row := range rows {
		principalURN := cypherRowString(row, "principal_urn")
		if principalURN == "" {
			continue
		}
		principalLabel := cypherRowString(row, "principal_label")
		principalEntityType := cypherRowString(row, "principal_entity_type")
		if principalEntityType == grcOverlayEntityTypeGitHubUser && githubActorIsAutomation(cypherRowString(row, "principal_attributes_json")) {
			continue
		}
		if grcOverlayHasFreshGRCBridge(row, now) {
			continue
		}
		privileges := grcOverlayAccessesFromRowKey(row, "privilege_edges", now, true)
		if len(privileges) == 0 {
			continue
		}
		group, ok := groups[principalURN]
		if !ok {
			group = &grcPrivilegedAccountMissingPersonGroup{
				principalURN:        principalURN,
				principalLabel:      principalLabel,
				principalEntityType: principalEntityType,
				privileges:          map[string]grcOverlayAccess{},
			}
			groups[principalURN] = group
			keys = append(keys, principalURN)
		}
		for _, privilege := range privileges {
			group.privileges[privilege.resourceURN+"|"+privilege.relation] = privilege
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.privileges) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

func (r *grcPrivilegedAccountMissingPersonRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *grcPrivilegedAccountMissingPersonGroup, now time.Time) *ports.FindingRecord {
	privilegeURNs, privilegeLabels, privilegeTypes, privilegeRelations := grcOverlayAccessTelemetry(group.privileges)
	resourceURNs := deduplicateStrings(append([]string{group.principalURN}, privilegeURNs...))
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, group.principalURN)
	summary := fmt.Sprintf(
		"Privileged %s account %s has %d privileged path(s) but no fresh GRC person bridge",
		firstNonEmpty(group.principalEntityType, "external"),
		firstNonEmpty(group.principalLabel, group.principalURN),
		len(group.privileges),
	)
	attributes := map[string]string{
		"primary_resource_urn":      group.principalURN,
		"principal_urn":             group.principalURN,
		"principal_label":           group.principalLabel,
		"principal_entity_type":     group.principalEntityType,
		"privilege_count":           fmt.Sprintf("%d", len(group.privileges)),
		"privilege_resource_urns":   strings.Join(privilegeURNs, ","),
		"privilege_resource_labels": strings.Join(privilegeLabels, ","),
		"privilege_resource_types":  strings.Join(privilegeTypes, ","),
		"privilege_relations":       strings.Join(privilegeRelations, ","),
		"source_runtime_id":         strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant":     tenantID,
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		RuleID:          r.definition.ID,
		Title:           r.definition.Name,
		Severity:        r.definition.Severity,
		Status:          findingStatusOpen,
		Summary:         summary,
		ResourceURNs:    resourceURNs,
		ControlRefs:     cloneFindingControlRefs(r.definition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: now,
		LastObservedAt:  now,
		CheckID:         r.definition.ID,
		CheckName:       r.definition.Name,
	}
}

type grcOverdueVulnerabilityLiveOnAssetsRule struct {
	definition RuleDefinition
}

func newGRCOverdueVulnerabilityLiveOnAssetsRule() Rule {
	return &grcOverdueVulnerabilityLiveOnAssetsRule{
		definition: RuleDefinition{
			ID:          grcOverdueVulnerabilityLiveOnAssetsRuleID,
			Name:        "Overdue GRC Vulnerability Still Present On Assets",
			Description: "Detect provider-neutral GRC vulnerability SLAs that are overdue while non-GRC scanners still show the canonical vulnerability or package present on assets.",
			SourceID:    grcOverlaySourceID,
			EventKinds: []string{
				"grc.vulnerability",
				"github.dependabot_alert",
				"gcp.container_vulnerability",
				"gcp.container_analysis_vulnerability",
				"kandji.vulnerability",
				"sentinelone.vulnerability",
			},
			OutputKind: grcOverdueVulnerabilityLiveOnAssetsKind,
			Severity:   "HIGH",
			Status:     findingStatusOpen,
			Maturity:   "test",
			Tags: []string{
				"grc",
				"vulnerability",
				"sla",
				"asset-overlay",
				"graph-rule",
			},
			FalsePositives: []string{
				"Scanner finding is stale and the asset has already been patched, but the non-GRC source has not synced the fixed state yet.",
				"GRC remediation deadline was extended but the updated deadline has not synced yet.",
			},
			Runbook: "Confirm the scanner evidence is current, prioritize remediation of the affected assets or packages, and update the GRC vulnerability record once the live scanner evidence is gone.",
			FingerprintFields: []string{
				"vulnerability_urn",
			},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC7.1"},
				{FrameworkName: "SOC 2", ControlID: "CC7.2"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
			},
		},
	}
}

func (r *grcOverdueVulnerabilityLiveOnAssetsRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *grcOverdueVulnerabilityLiveOnAssetsRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	switch sourceID {
	case grcOverlaySourceID:
		return family == grcOverlayRuntimeFamilyVulnerability
	case "github":
		return family == grcOverlayRuntimeFamilyDependabotAlert
	case "sentinelone":
		return family == grcOverlayRuntimeFamilyApplication || family == grcOverlayRuntimeFamilyThreat || family == grcOverlayRuntimeFamilyVulnerability
	case "gcp":
		return family == "container_vulnerability" || family == "container_analysis_vulnerability"
	case "kandji":
		return true
	default:
		return false
	}
}

func (r *grcOverdueVulnerabilityLiveOnAssetsRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *grcOverdueVulnerabilityLiveOnAssetsRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	tenantID := grcOverlayTenantID(runtime)
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (vulnerability:Entity {tenant_id: $tenant_id, entity_type: 'vulnerability'})
OPTIONAL MATCH (asset:Entity {tenant_id: $tenant_id})-[affected:RELATION {relation: 'affected_by'}]->(vulnerability)
WHERE coalesce(affected.source_id, '') <> 'grc'
WITH vulnerability,
     collect(DISTINCT {
       asset_urn: coalesce(asset.urn, ''),
       asset_type: coalesce(asset.entity_type, ''),
       asset_label: coalesce(asset.label, ''),
       source_id: coalesce(affected.source_id, ''),
       attributes_json: coalesce(affected.attributes_json, '')
     }) AS assets
RETURN vulnerability.urn AS vulnerability_urn,
       vulnerability.label AS vulnerability_label,
       coalesce(vulnerability.attributes_json, '') AS vulnerability_attributes_json,
       assets
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id": tenantID,
			"row_limit": int64(grcOverlayQueryRowLimit),
		},
		RowLimit: grcOverlayQueryRowLimit,
	}
}

func (r *grcOverdueVulnerabilityLiveOnAssetsRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*grcOverdueVulnerabilityLiveOnAssetsGroup{}
	keys := []string{}
	for _, row := range rows {
		vulnerabilityURN := cypherRowString(row, "vulnerability_urn")
		if vulnerabilityURN == "" {
			continue
		}
		attrs := grcOverlayAttributes(cypherRowString(row, "vulnerability_attributes_json"))
		deadline, ok := parseGRCTime(firstNonEmpty(attrs["remediate_by_date"], attrs["due_date"], attrs["sla_due_date"]))
		if !ok || !deadline.Before(now) || grcOverlayVulnerabilityResolved(attrs) {
			continue
		}
		assets := grcOverlayAssetsFromRow(row)
		if len(assets) == 0 {
			continue
		}
		group, ok := groups[vulnerabilityURN]
		if !ok {
			group = &grcOverdueVulnerabilityLiveOnAssetsGroup{
				vulnerabilityURN:   vulnerabilityURN,
				vulnerabilityLabel: firstNonEmpty(cypherRowString(row, "vulnerability_label"), attrs["name"], attrs["vulnerability_id"], attrs["identifier"]),
				severity:           normalizeFindingSeverity(firstNonEmpty(attrs["severity"], attrs["cvss_severity"], attrs["vulnerability_severity"])),
				deadline:           deadline,
				assets:             map[string]grcOverlayAsset{},
			}
			groups[vulnerabilityURN] = group
			keys = append(keys, vulnerabilityURN)
		}
		for _, asset := range assets {
			group.assets[asset.urn] = asset
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.assets) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

func (r *grcOverdueVulnerabilityLiveOnAssetsRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *grcOverdueVulnerabilityLiveOnAssetsGroup, now time.Time) *ports.FindingRecord {
	assetURNs, assetLabels, assetTypes, sourceIDs := grcOverlayAssetTelemetry(group.assets)
	resourceURNs := deduplicateStrings(append([]string{group.vulnerabilityURN}, assetURNs...))
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, group.vulnerabilityURN)
	summary := fmt.Sprintf(
		"GRC vulnerability %s is overdue since %s and still present on %d non-GRC asset(s)",
		firstNonEmpty(group.vulnerabilityLabel, group.vulnerabilityURN),
		group.deadline.Format("2006-01-02"),
		len(group.assets),
	)
	attributes := map[string]string{
		"primary_resource_urn":  group.vulnerabilityURN,
		"vulnerability_urn":     group.vulnerabilityURN,
		"vulnerability_label":   group.vulnerabilityLabel,
		"remediate_by_date":     group.deadline.Format(time.RFC3339),
		"asset_count":           fmt.Sprintf("%d", len(group.assets)),
		"asset_urns":            strings.Join(assetURNs, ","),
		"asset_labels":          strings.Join(assetLabels, ","),
		"asset_entity_types":    strings.Join(assetTypes, ","),
		"asset_source_ids":      strings.Join(sourceIDs, ","),
		"source_runtime_id":     strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant": tenantID,
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		RuleID:          r.definition.ID,
		Title:           r.definition.Name,
		Severity:        group.severity,
		Status:          findingStatusOpen,
		Summary:         summary,
		ResourceURNs:    resourceURNs,
		PolicyID:        group.vulnerabilityURN,
		PolicyName:      group.vulnerabilityLabel,
		ControlRefs:     cloneFindingControlRefs(r.definition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: now,
		LastObservedAt:  now,
		CheckID:         r.definition.ID,
		CheckName:       r.definition.Name,
	}
}

type grcFailingControlOpenOperationalFindingsRule struct {
	definition RuleDefinition
}

func newGRCFailingControlOpenOperationalFindingsRule() Rule {
	return &grcFailingControlOpenOperationalFindingsRule{
		definition: RuleDefinition{
			ID:          grcFailingControlOpenOperationalFindingsID,
			Name:        "Failing GRC Control Has Open Operational Findings",
			Description: "Detect failing provider-neutral GRC control tests that map to open non-GRC operational findings through shared control references.",
			SourceID:    grcOverlaySourceID,
			EventKinds: []string{
				"grc.control_test",
				"github.audit",
				"github.dependabot_alert",
				"okta.audit",
				"aws.cloudtrail",
				"azure.activity_log",
				"gcp.audit",
				"sentinelone.threat",
				"runtime.evidence",
			},
			OutputKind: grcFailingControlOpenOperationalFindingsKind,
			Severity:   "HIGH",
			Status:     findingStatusOpen,
			Maturity:   "test",
			Tags: []string{
				"grc",
				"compliance",
				"control-overlay",
				"operational-evidence",
				"graph-rule",
			},
			FalsePositives: []string{
				"Operational finding control references are too broad and do not represent the failing test's exact control objective.",
				"GRC control test has already been remediated but the latest passing test result has not synced yet.",
			},
			Runbook: "Review the failing GRC control test, inspect the linked open operational findings, remediate the underlying technical issues, then rerun or resync the GRC control test.",
			FingerprintFields: []string{
				"control_test_urn",
				"control_urn",
			},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC7.1"},
				{FrameworkName: "SOC 2", ControlID: "CC7.2"},
			},
		},
	}
}

func (r *grcFailingControlOpenOperationalFindingsRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *grcFailingControlOpenOperationalFindingsRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	switch sourceID {
	case grcOverlaySourceID:
		return family == "control_test"
	case "github":
		return family == grcOverlayRuntimeFamilyAudit || family == grcOverlayRuntimeFamilyDependabotAlert
	case "okta":
		return family == grcOverlayRuntimeFamilyAudit
	case "aws":
		return family == grcOverlayRuntimeFamilyCloudTrail
	case "azure":
		return family == grcOverlayRuntimeFamilyActivityLog || family == grcOverlayRuntimeFamilyDirectoryAudit
	case "gcp":
		return family == grcOverlayRuntimeFamilyAudit
	case "sentinelone":
		return family == grcOverlayRuntimeFamilyThreat
	case "runtime":
		return true
	default:
		return false
	}
}

func (r *grcFailingControlOpenOperationalFindingsRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *grcFailingControlOpenOperationalFindingsRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	tenantID := grcOverlayTenantID(runtime)
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (test:Entity {tenant_id: $tenant_id, source_id: 'grc', entity_type: 'evidence'})
      -[:RELATION {relation: 'supports'}]->(control:Entity {tenant_id: $tenant_id, entity_type: 'policy'})
WITH test, control,
     coalesce(test.attributes_json, '') AS test_attributes_json,
     coalesce(control.attributes_json, '') AS control_attributes_json,
     coalesce(control.label, '') AS control_label
WHERE (toLower(test_attributes_json) CONTAINS 'fail'
    OR toLower(test_attributes_json) CONTAINS 'needs_attention'
    OR toLower(test_attributes_json) CONTAINS 'error')
  AND control_label <> ''
MATCH (resource:Entity {tenant_id: $tenant_id})-[has_finding:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WITH test, control, test_attributes_json, control_attributes_json, control_label,
     resource, has_finding, finding,
     toUpper(control_label) AS control_label_upper,
     toUpper(coalesce(finding.attributes_json, '')) AS finding_attributes_upper
WHERE coalesce(finding.source_id, '') <> 'grc'
  AND (finding_attributes_upper CONTAINS '"' + control_label_upper + '"'
    OR finding_attributes_upper CONTAINS '"' + control_label_upper + ','
    OR finding_attributes_upper CONTAINS ',' + control_label_upper + ','
    OR finding_attributes_upper CONTAINS ',' + control_label_upper + '"'
    OR finding_attributes_upper CONTAINS ':' + control_label_upper + ','
    OR finding_attributes_upper CONTAINS ':' + control_label_upper + '"')
WITH test, control, test_attributes_json, control_attributes_json,
     collect(DISTINCT {
       finding_urn: coalesce(finding.urn, ''),
       finding_label: coalesce(finding.label, ''),
       finding_attributes_json: coalesce(finding.attributes_json, ''),
       resource_urn: coalesce(resource.urn, ''),
       resource_type: coalesce(resource.entity_type, ''),
       resource_label: coalesce(resource.label, ''),
       link_attributes_json: coalesce(has_finding.attributes_json, '')
     }) AS operational_findings
RETURN test.urn AS control_test_urn,
       test.label AS control_test_label,
       test_attributes_json,
       control.urn AS control_urn,
       control.label AS control_label,
       control_attributes_json,
       operational_findings
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id": tenantID,
			"row_limit": int64(grcOverlayQueryRowLimit),
		},
		RowLimit: grcOverlayQueryRowLimit,
	}
}

func (r *grcFailingControlOpenOperationalFindingsRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*grcFailingControlOpenOperationalFindingsGroup{}
	keys := []string{}
	for _, row := range rows {
		testURN := cypherRowString(row, "control_test_urn")
		controlURN := cypherRowString(row, "control_urn")
		if testURN == "" || controlURN == "" {
			continue
		}
		testAttrs := grcOverlayAttributes(cypherRowString(row, "test_attributes_json"))
		if !grcOverlayControlTestFailing(testAttrs) {
			continue
		}
		findings := grcOverlayOperationalFindingsFromRow(row)
		if len(findings) == 0 {
			continue
		}
		key := testURN + "\x00" + controlURN
		group, ok := groups[key]
		if !ok {
			controlAttrs := grcOverlayAttributes(cypherRowString(row, "control_attributes_json"))
			group = &grcFailingControlOpenOperationalFindingsGroup{
				controlTestURN:   testURN,
				controlTestLabel: cypherRowString(row, "control_test_label"),
				controlStatus:    firstNonEmpty(testAttrs["status"], testAttrs["result"], testAttrs["state"]),
				controlURN:       controlURN,
				controlLabel:     firstNonEmpty(cypherRowString(row, "control_label"), controlAttrs["control_external_id"], controlAttrs["control_id"]),
				controlAttrs:     controlAttrs,
				findings:         map[string]grcOverlayOperationalFinding{},
			}
			groups[key] = group
			keys = append(keys, key)
		}
		for _, finding := range findings {
			if !grcOverlayOperationalFindingMatchesControl(finding, group.controlLabel, group.controlAttrs) {
				continue
			}
			group.findings[finding.findingURN] = finding
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.findings) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

func (r *grcFailingControlOpenOperationalFindingsRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *grcFailingControlOpenOperationalFindingsGroup, now time.Time) *ports.FindingRecord {
	findingURNs, findingLabels, operationalResourceURNs, resourceLabels, severities := grcOverlayOperationalFindingTelemetry(group.findings)
	resourceURNs := deduplicateStrings(append([]string{group.controlTestURN, group.controlURN}, append(findingURNs, operationalResourceURNs...)...))
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, group.controlTestURN, group.controlURN)
	severity := grcOverlayHighestSeverity(severities, r.definition.Severity)
	summary := fmt.Sprintf(
		"Failing GRC control test %s maps to %d open non-GRC operational finding(s)",
		firstNonEmpty(group.controlTestLabel, group.controlLabel, group.controlTestURN),
		len(group.findings),
	)
	attributes := map[string]string{
		"primary_resource_urn":        group.controlTestURN,
		"control_test_urn":            group.controlTestURN,
		"control_test_label":          group.controlTestLabel,
		"control_status":              group.controlStatus,
		"control_urn":                 group.controlURN,
		"control_label":               group.controlLabel,
		"operational_count":           fmt.Sprintf("%d", len(group.findings)),
		"operational_finding_urns":    strings.Join(findingURNs, ","),
		"operational_finding_labels":  strings.Join(findingLabels, ","),
		"operational_resource_urns":   strings.Join(operationalResourceURNs, ","),
		"operational_resource_labels": strings.Join(resourceLabels, ","),
		"operational_severities":      strings.Join(severities, ","),
		"source_runtime_id":           strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant":       tenantID,
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		RuleID:          r.definition.ID,
		Title:           r.definition.Name,
		Severity:        severity,
		Status:          findingStatusOpen,
		Summary:         summary,
		ResourceURNs:    resourceURNs,
		PolicyID:        firstNonEmpty(group.controlLabel, group.controlURN),
		PolicyName:      firstNonEmpty(group.controlLabel, group.controlTestLabel),
		ControlRefs:     grcOverlayControlRefs(group.controlAttrs, group.controlLabel, group.findings, r.definition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: now,
		LastObservedAt:  now,
		CheckID:         r.definition.ID,
		CheckName:       r.definition.Name,
	}
}

type grcInactiveIdentityActiveAccessGroup struct {
	grcSubjectURN       string
	grcSubjectLabel     string
	grcSubjectType      string
	grcStatus           string
	identityURNs        map[string]struct{}
	identityLabels      map[string]struct{}
	principalURN        string
	principalLabel      string
	principalEntityType string
	accesses            map[string]grcOverlayAccess
}

type grcPrivilegedAccountMissingPersonGroup struct {
	principalURN        string
	principalLabel      string
	principalEntityType string
	privileges          map[string]grcOverlayAccess
}

type grcOverdueVulnerabilityLiveOnAssetsGroup struct {
	vulnerabilityURN   string
	vulnerabilityLabel string
	severity           string
	deadline           time.Time
	assets             map[string]grcOverlayAsset
}

type grcFailingControlOpenOperationalFindingsGroup struct {
	controlTestURN   string
	controlTestLabel string
	controlStatus    string
	controlURN       string
	controlLabel     string
	controlAttrs     map[string]string
	findings         map[string]grcOverlayOperationalFinding
}

type grcOverlayAccess struct {
	relation      string
	resourceURN   string
	resourceType  string
	resourceLabel string
}

type grcOverlayAsset struct {
	urn      string
	label    string
	typeName string
	sourceID string
}

type grcOverlayOperationalFinding struct {
	findingURN    string
	findingLabel  string
	resourceURN   string
	resourceType  string
	resourceLabel string
	severity      string
	ruleID        string
	controlRefs   []ports.FindingControlRef
}

func grcOverlayIdentityRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	switch sourceID {
	case grcOverlaySourceID:
		return family == grcOverlayRuntimeFamilyPerson || family == grcOverlayRuntimeFamilyUser
	case "github":
		return family == grcOverlayRuntimeFamilyAudit
	case "okta":
		return family == grcOverlayRuntimeFamilyUser || family == grcOverlayRuntimeFamilyAdminRole
	case "google_workspace":
		return family == grcOverlayRuntimeFamilyUser || family == grcOverlayRuntimeFamilyRoleAssignment || family == grcOverlayRuntimeFamilyAudit
	case "aws":
		return family == "iam_user" || family == grcOverlayRuntimeFamilyIAMRoleAssignment || family == grcOverlayRuntimeFamilyIAMRoleTrust || family == grcOverlayRuntimeFamilyCloudTrail || family == grcOverlayRuntimeFamilyEffectivePermission
	case "gcp":
		return family == grcOverlayRuntimeFamilyIAMRoleAssignment || family == grcOverlayRuntimeFamilyAudit || family == grcOverlayRuntimeFamilyServiceImpersonation || family == grcOverlayRuntimeFamilyEffectivePermission
	case "azure":
		return family == grcOverlayRuntimeFamilyUser || family == grcOverlayRuntimeFamilyDirectoryRoleAssign || family == grcOverlayRuntimeFamilyAppRoleAssignment || family == grcOverlayRuntimeFamilyActivityLog || family == grcOverlayRuntimeFamilyDirectoryAudit || family == grcOverlayRuntimeFamilyIAMRoleAssignment || family == grcOverlayRuntimeFamilyEffectivePermission
	default:
		return false
	}
}

func grcOverlayTenantID(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return ""
	}
	return strings.TrimSpace(runtime.GetTenantId())
}

func grcOverlayAttributes(attributesJSON string) map[string]string {
	trimmed := strings.TrimSpace(attributesJSON)
	if trimmed == "" {
		return nil
	}
	attrs := map[string]string{}
	if err := json.Unmarshal([]byte(trimmed), &attrs); err != nil {
		return nil
	}
	return attrs
}

func grcOverlayAttributesAreGRC(attrs map[string]string) bool {
	return strings.TrimSpace(attrs["source_system"]) != "" || strings.TrimSpace(attrs["provider"]) != ""
}

func grcOverlayIdentityInactive(attrs map[string]string) bool {
	if value := strings.ToLower(strings.TrimSpace(attrs["is_active"])); value == "false" || value == "0" || value == "no" {
		return true
	}
	for _, key := range []string{"employment_status", "status", "lifecycle_status", "lifecycle_state", "state"} {
		value := strings.ToLower(strings.TrimSpace(attrs[key]))
		if value == "" {
			continue
		}
		switch {
		case value == "inactive",
			value == "terminated",
			value == "deprovisioned",
			value == "suspended",
			value == "disabled",
			value == "former",
			value == "offboarded",
			strings.Contains(value, "not_current"),
			strings.Contains(value, "not current"),
			strings.Contains(value, "terminate"),
			strings.Contains(value, "deprovision"),
			strings.Contains(value, "offboard"):
			return true
		}
	}
	return false
}

func grcOverlayIdentityStatus(attrs map[string]string) string {
	return firstNonEmpty(attrs["employment_status"], attrs["status"], attrs["lifecycle_status"], attrs["lifecycle_state"], attrs["state"])
}

func grcOverlayFreshEmailBridge(leftAttributesJSON string, rightAttributesJSON string, now time.Time) bool {
	return edgeIsRecent(leftAttributesJSON, now, grcOverlayIdentityRecencyWindow) &&
		edgeIsRecent(rightAttributesJSON, now, grcOverlayIdentityRecencyWindow) &&
		identifierMatchIsEmail(leftAttributesJSON) &&
		identifierMatchIsEmail(rightAttributesJSON)
}

func grcOverlayAccessesFromRow(row ports.CypherRow, now time.Time, requirePrivilege bool) []grcOverlayAccess {
	return grcOverlayAccessesFromRowKey(row, "access_edges", now, requirePrivilege)
}

func grcOverlayAccessesFromRowKey(row ports.CypherRow, key string, now time.Time, requirePrivilege bool) []grcOverlayAccess {
	accesses := []grcOverlayAccess{}
	for _, item := range cypherRowList(row, key) {
		relation := cypherListMapString(item, "relation")
		resourceURN := cypherListMapString(item, "resource_urn")
		if relation == "" || resourceURN == "" {
			continue
		}
		attributesJSON := cypherListMapString(item, "attributes_json")
		if requirePrivilege {
			if !grcOverlayPrivilegeEdgeIsActionable(relation, attributesJSON) {
				continue
			}
		} else if !grcOverlayAccessEdgeIsActionable(relation, attributesJSON, now) {
			continue
		}
		accesses = append(accesses, grcOverlayAccess{
			relation:      relation,
			resourceURN:   resourceURN,
			resourceType:  cypherListMapString(item, "resource_type"),
			resourceLabel: cypherListMapString(item, "resource_label"),
		})
	}
	return accesses
}

func grcOverlayAccessEdgeIsActionable(relation string, attributesJSON string, now time.Time) bool {
	switch strings.TrimSpace(relation) {
	case grcOverlayAccessEdgeRelationActedOn:
		return edgeIsRecent(attributesJSON, now, grcOverlayActivityRecencyWindow)
	case grcOverlayAccessEdgeRelationCanAdmin,
		grcOverlayAccessEdgeRelationCanAssume,
		grcOverlayAccessEdgeRelationCanImpersonate:
		return true
	case grcOverlayAccessEdgeRelationCanPerform:
		return grcOverlayCanPerformLooksPrivileged(attributesJSON)
	default:
		return false
	}
}

func grcOverlayPrivilegeEdgeIsActionable(relation string, attributesJSON string) bool {
	switch strings.TrimSpace(relation) {
	case grcOverlayAccessEdgeRelationCanAdmin,
		grcOverlayAccessEdgeRelationCanAssume,
		grcOverlayAccessEdgeRelationCanImpersonate:
		return true
	case grcOverlayAccessEdgeRelationCanPerform:
		return grcOverlayCanPerformLooksPrivileged(attributesJSON)
	default:
		return false
	}
}

func grcOverlayCanPerformLooksPrivileged(attributesJSON string) bool {
	attrs := grcOverlayAttributes(attributesJSON)
	value := strings.ToLower(firstNonEmpty(attrs["privilege_level"], attrs["permission"], attrs["actions"], attrs["role_name"], attrs["role_id"]))
	if value == "" {
		return false
	}
	return strings.Contains(value, "admin") ||
		strings.Contains(value, "owner") ||
		strings.Contains(value, "*") ||
		strings.Contains(value, "all")
}

func grcOverlayAccessTelemetry(accesses map[string]grcOverlayAccess) ([]string, []string, []string, []string) {
	urns := map[string]struct{}{}
	labels := map[string]struct{}{}
	types := map[string]struct{}{}
	relations := map[string]struct{}{}
	for _, access := range accesses {
		if access.resourceURN != "" {
			urns[access.resourceURN] = struct{}{}
		}
		if access.resourceLabel != "" {
			labels[access.resourceLabel] = struct{}{}
		}
		if access.resourceType != "" {
			types[access.resourceType] = struct{}{}
		}
		if access.relation != "" {
			relations[access.relation] = struct{}{}
		}
	}
	return sortedKeys(urns), sortedKeys(labels), sortedKeys(types), sortedKeys(relations)
}

func grcOverlayHasFreshGRCBridge(row ports.CypherRow, now time.Time) bool {
	for _, bridge := range cypherRowList(row, "grc_bridges") {
		grcURN := cypherListMapString(bridge, "grc_subject_urn")
		if grcURN == "" {
			continue
		}
		if grcOverlayFreshEmailBridge(
			cypherListMapString(bridge, "grc_identity_attributes_json"),
			cypherListMapString(bridge, "principal_identity_attributes_json"),
			now,
		) {
			return true
		}
	}
	return false
}

func grcOverlayVulnerabilityResolved(attrs map[string]string) bool {
	value := strings.ToLower(firstNonEmpty(attrs["status"], attrs["state"], attrs["resolution_status"], attrs["remediation_status"]))
	if strings.Contains(value, "unresolved") || strings.Contains(value, "not_resolved") || strings.Contains(value, "not resolved") {
		return false
	}
	switch value {
	case "fixed", "resolved", "closed", "remediated", "not_affected":
		return true
	default:
		return strings.Contains(value, "fixed") || strings.Contains(value, "resolved") || strings.Contains(value, "remediated")
	}
}

func grcOverlayAssetsFromRow(row ports.CypherRow) []grcOverlayAsset {
	assets := []grcOverlayAsset{}
	for _, item := range cypherRowList(row, "assets") {
		urn := cypherListMapString(item, "asset_urn")
		sourceID := cypherListMapString(item, "source_id")
		if urn == "" || strings.EqualFold(sourceID, grcOverlaySourceID) {
			continue
		}
		assets = append(assets, grcOverlayAsset{
			urn:      urn,
			label:    cypherListMapString(item, "asset_label"),
			typeName: cypherListMapString(item, "asset_type"),
			sourceID: sourceID,
		})
	}
	return assets
}

func grcOverlayAssetTelemetry(assets map[string]grcOverlayAsset) ([]string, []string, []string, []string) {
	urns := map[string]struct{}{}
	labels := map[string]struct{}{}
	types := map[string]struct{}{}
	sources := map[string]struct{}{}
	for _, asset := range assets {
		if asset.urn != "" {
			urns[asset.urn] = struct{}{}
		}
		if asset.label != "" {
			labels[asset.label] = struct{}{}
		}
		if asset.typeName != "" {
			types[asset.typeName] = struct{}{}
		}
		if asset.sourceID != "" {
			sources[asset.sourceID] = struct{}{}
		}
	}
	return sortedKeys(urns), sortedKeys(labels), sortedKeys(types), sortedKeys(sources)
}

func grcOverlayControlTestFailing(attrs map[string]string) bool {
	status := strings.ToLower(firstNonEmpty(attrs["status"], attrs["result"], attrs["state"]))
	return strings.Contains(status, "fail") ||
		strings.Contains(status, "needs_attention") ||
		strings.Contains(status, "needs attention") ||
		strings.Contains(status, "error")
}

func grcOverlayOperationalFindingsFromRow(row ports.CypherRow) []grcOverlayOperationalFinding {
	findings := []grcOverlayOperationalFinding{}
	for _, item := range cypherRowList(row, "operational_findings") {
		findingURN := cypherListMapString(item, "finding_urn")
		if findingURN == "" {
			continue
		}
		attrs := grcOverlayAttributes(cypherListMapString(item, "finding_attributes_json"))
		ruleID := strings.TrimSpace(attrs["rule_id"])
		if strings.HasPrefix(strings.ToLower(ruleID), "grc-") {
			continue
		}
		findings = append(findings, grcOverlayOperationalFinding{
			findingURN:    findingURN,
			findingLabel:  cypherListMapString(item, "finding_label"),
			resourceURN:   cypherListMapString(item, "resource_urn"),
			resourceType:  cypherListMapString(item, "resource_type"),
			resourceLabel: cypherListMapString(item, "resource_label"),
			severity:      normalizeFindingSeverity(firstNonEmpty(attrs["severity"], attrs["risk_severity"])),
			ruleID:        ruleID,
			controlRefs:   grcOverlayParseControlRefs(attrs["control_refs"]),
		})
	}
	return findings
}

func grcOverlayOperationalFindingTelemetry(findings map[string]grcOverlayOperationalFinding) ([]string, []string, []string, []string, []string) {
	findingURNs := map[string]struct{}{}
	findingLabels := map[string]struct{}{}
	resourceURNs := map[string]struct{}{}
	resourceLabels := map[string]struct{}{}
	severities := map[string]struct{}{}
	for _, finding := range findings {
		if finding.findingURN != "" {
			findingURNs[finding.findingURN] = struct{}{}
		}
		if finding.findingLabel != "" {
			findingLabels[finding.findingLabel] = struct{}{}
		}
		if finding.resourceURN != "" {
			resourceURNs[finding.resourceURN] = struct{}{}
		}
		if finding.resourceLabel != "" {
			resourceLabels[finding.resourceLabel] = struct{}{}
		}
		if finding.severity != "" {
			severities[finding.severity] = struct{}{}
		}
	}
	return sortedKeys(findingURNs), sortedKeys(findingLabels), sortedKeys(resourceURNs), sortedKeys(resourceLabels), sortedKeys(severities)
}

func grcOverlayHighestSeverity(values []string, fallback string) string {
	best := normalizeFindingSeverity(fallback)
	bestRank := grcOverlaySeverityRank(best)
	for _, value := range values {
		severity := normalizeFindingSeverity(value)
		rank := grcOverlaySeverityRank(severity)
		if rank > bestRank {
			best = severity
			bestRank = rank
		}
	}
	return best
}

func grcOverlaySeverityRank(severity string) int {
	switch normalizeFindingSeverity(severity) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func grcOverlayOperationalFindingMatchesControl(finding grcOverlayOperationalFinding, controlLabel string, controlAttrs map[string]string) bool {
	controlIDs := grcOverlayControlIDSet(controlAttrs, controlLabel)
	for _, ref := range finding.controlRefs {
		if _, ok := controlIDs[strings.ToUpper(strings.TrimSpace(ref.ControlID))]; ok {
			return true
		}
		full := strings.ToUpper(strings.TrimSpace(ref.FrameworkName) + ":" + strings.TrimSpace(ref.ControlID))
		if _, ok := controlIDs[full]; ok {
			return true
		}
	}
	return false
}

func grcOverlayControlIDSet(attrs map[string]string, controlLabel string) map[string]struct{} {
	values := []string{
		attrs["control_external_id"],
		attrs["control_external_ids"],
		attrs["control_id"],
		attrs["control_ids"],
		attrs["policy_id"],
		controlLabel,
	}
	ids := map[string]struct{}{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			ids[strings.ToUpper(trimmed)] = struct{}{}
			if idx := strings.LastIndex(trimmed, ":"); idx >= 0 && idx+1 < len(trimmed) {
				ids[strings.ToUpper(strings.TrimSpace(trimmed[idx+1:]))] = struct{}{}
			}
		}
	}
	return ids
}

func grcOverlayParseControlRefs(raw string) []ports.FindingControlRef {
	refs := []ports.FindingControlRef{}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		idx := strings.LastIndex(token, ":")
		if idx <= 0 || idx+1 >= len(token) {
			continue
		}
		ref := ports.FindingControlRef{
			FrameworkName: strings.TrimSpace(token[:idx]),
			ControlID:     strings.TrimSpace(token[idx+1:]),
		}
		if ref.FrameworkName == "" || ref.ControlID == "" {
			continue
		}
		key := strings.ToUpper(ref.FrameworkName + "\x00" + ref.ControlID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func grcOverlayControlRefs(attrs map[string]string, controlLabel string, findings map[string]grcOverlayOperationalFinding, fallbacks []ports.FindingControlRef) []ports.FindingControlRef {
	controlID := firstNonEmpty(attrs["control_external_id"], attrs["control_id"], attrs["policy_id"], controlLabel)
	framework := firstNonEmpty(attrs["framework_name"], attrs["framework"], attrs["framework_id"])
	if controlID == "" || framework == "" {
		if refs := grcOverlayMatchedControlRefs(findings, controlLabel, attrs); len(refs) > 0 {
			return refs
		}
		return cloneFindingControlRefs(fallbacks)
	}
	return []ports.FindingControlRef{{FrameworkName: framework, ControlID: controlID}}
}

func grcOverlayMatchedControlRefs(findings map[string]grcOverlayOperationalFinding, controlLabel string, attrs map[string]string) []ports.FindingControlRef {
	controlIDs := grcOverlayControlIDSet(attrs, controlLabel)
	refs := []ports.FindingControlRef{}
	seen := map[string]struct{}{}
	for _, finding := range findings {
		for _, ref := range finding.controlRefs {
			if _, ok := controlIDs[strings.ToUpper(strings.TrimSpace(ref.ControlID))]; !ok {
				continue
			}
			key := strings.ToUpper(strings.TrimSpace(ref.FrameworkName) + "\x00" + strings.TrimSpace(ref.ControlID))
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			refs = append(refs, ref)
		}
	}
	return refs
}
