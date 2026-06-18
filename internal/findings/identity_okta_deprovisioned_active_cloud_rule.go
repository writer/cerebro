package findings

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var _ GraphRule = (*deprovisionedOktaActiveCloudAccessRule)(nil)

const (
	identityDeprovisionedOktaActiveCloudAccessRuleID = "identity-okta-deprovisioned-active-cloud-access"
	identityDeprovisionedOktaActiveCloudAccessKind   = "finding.identity_okta_deprovisioned_active_cloud_access"
	identityDeprovisionedOktaActiveCloudQueryLimit   = 500
)

var identityDeprovisionedOktaActiveCloudPrincipalTypes = []string{
	grcOverlayEntityTypeAWSUser,
	grcOverlayEntityTypeGCPUser,
	grcOverlayEntityTypeAzureUser,
	grcOverlayEntityTypeGoogleWorkspaceUser,
}

type deprovisionedOktaActiveCloudAccessRule struct {
	definition RuleDefinition
}

func newDeprovisionedOktaActiveCloudAccessRule() Rule {
	return &deprovisionedOktaActiveCloudAccessRule{
		definition: RuleDefinition{
			ID:          identityDeprovisionedOktaActiveCloudAccessRuleID,
			Name:        "Deprovisioned Okta Identity Still Has Cloud Access",
			Description: "Detect Okta identities marked deprovisioned, suspended, or inactive whose email-backed cloud/SaaS principal still has recent activity or privileged access.",
			SourceID:    "okta",
			EventKinds: []string{
				"okta.user",
				"aws.cloudtrail",
				"aws.iam_role_assignment",
				"aws.effective_permission",
				"google_workspace.audit",
				"google_workspace.role_assignment",
				"gcp.audit",
				"gcp.iam_role_assignment",
				"gcp.effective_permission",
				"azure.activity_log",
				"azure.directory_role_assignment",
				"azure.iam_role_assignment",
				"azure.effective_permission",
			},
			OutputKind: identityDeprovisionedOktaActiveCloudAccessKind,
			Severity:   "CRITICAL",
			Status:     findingStatusOpen,
			Maturity:   "test",
			Tags: []string{
				"identity",
				"offboarding",
				"cloud",
				"graph-rule",
				"attack.t1078",
			},
			References: []string{
				"https://help.okta.com/en-us/content/topics/users-groups-profiles/usgp-user-lifecycle.htm",
				"https://attack.mitre.org/techniques/T1078/",
			},
			FalsePositives: []string{
				"Break-glass account intentionally retained during offboarding with a documented, time-bound exception.",
				"Identity-provider or cloud-inventory sync lag immediately after a lifecycle transition.",
			},
			Runbook: "Confirm the Okta identity is offboarded, revoke the linked cloud/SaaS principal or its privileged grants, rotate credentials created by the account, and document any approved exception.",
			FingerprintFields: []string{
				"okta_user_urn",
				"principal_urn",
			},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
				{FrameworkName: "SOC 2", ControlID: "CC6.6"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
			},
			Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
		},
	}
}

func (r *deprovisionedOktaActiveCloudAccessRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *deprovisionedOktaActiveCloudAccessRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	switch sourceID {
	case "okta":
		return family == "user"
	case "aws":
		switch family {
		case "cloudtrail", "access_key", "iam_role_assignment", "iam_role_trust", "effective_permission":
			return true
		}
	case "google_workspace":
		switch family {
		case "audit", "role_assignment", "user":
			return true
		}
	case "gcp":
		switch family {
		case "audit", "iam_role_assignment", "effective_permission", "service_account_impersonation":
			return true
		}
	case "azure":
		switch family {
		case "activity_log", "directory_role_assignment", "iam_role_assignment", "effective_permission":
			return true
		}
	}
	return false
}

func (r *deprovisionedOktaActiveCloudAccessRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *deprovisionedOktaActiveCloudAccessRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil {
		return ports.CypherQueryRequest{}
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (o:Entity {entity_type: 'okta.user', tenant_id: $tenant_id})
      -[okta_identity:RELATION {relation: 'represents_identity'}]->(identity:Entity)
      <-[principal_identity:RELATION {relation: 'represents_identity'}]-(principal:Entity {tenant_id: $tenant_id})
WHERE principal.entity_type IN $principal_types
  AND (toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"DEPROVISIONED"'
    OR toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"SUSPENDED"'
    OR toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"INACTIVE"')
WITH o, okta_identity, identity, principal, principal_identity
OPTIONAL MATCH (principal)-[access:RELATION]->(resource:Entity)
WHERE access.relation IN $access_relations
WITH o, okta_identity, identity, principal, principal_identity,
     collect(DISTINCT {
       relation: coalesce(access.relation, ''),
       resource_urn: coalesce(resource.urn, ''),
       resource_type: coalesce(resource.entity_type, ''),
       resource_label: coalesce(resource.label, ''),
       attributes_json: coalesce(access.attributes_json, '')
     }) AS access_edges
RETURN o.urn AS okta_user_urn,
       o.label AS okta_user_label,
       coalesce(o.attributes_json, '') AS okta_attributes_json,
       identity.urn AS identity_urn,
       identity.label AS identity_label,
       principal.urn AS principal_urn,
       principal.label AS principal_label,
       principal.entity_type AS principal_entity_type,
       coalesce(principal.attributes_json, '') AS principal_attributes_json,
       coalesce(okta_identity.attributes_json, '') AS okta_identity_attributes_json,
       coalesce(principal_identity.attributes_json, '') AS principal_identity_attributes_json,
       access_edges
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id":        tenantID,
			"principal_types":  identityDeprovisionedOktaActiveCloudPrincipalTypes,
			"access_relations": grcOverlayActiveAccessRelations,
			"row_limit":        int64(identityDeprovisionedOktaActiveCloudQueryLimit),
		},
		RowLimit: identityDeprovisionedOktaActiveCloudQueryLimit,
	}
}

func (r *deprovisionedOktaActiveCloudAccessRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*deprovisionedOktaActiveCloudGroup{}
	keys := []string{}
	for _, row := range rows {
		oktaURN := cypherRowString(row, "okta_user_urn")
		principalURN := cypherRowString(row, "principal_urn")
		if oktaURN == "" || principalURN == "" {
			continue
		}
		oktaStatus := extractOktaStatus(cypherRowString(row, "okta_attributes_json"))
		if oktaStatus == "" {
			continue
		}
		if !grcOverlayFreshEmailBridge(cypherRowString(row, "okta_identity_attributes_json"), cypherRowString(row, "principal_identity_attributes_json"), now) {
			continue
		}
		accesses := grcOverlayAccessesFromRow(row, now, false)
		if len(accesses) == 0 {
			continue
		}
		key := oktaURN + "\x00" + principalURN
		group, ok := groups[key]
		if !ok {
			group = &deprovisionedOktaActiveCloudGroup{
				oktaUserURN:        oktaURN,
				oktaUserLabel:      cypherRowString(row, "okta_user_label"),
				oktaStatus:         oktaStatus,
				identityURNs:       map[string]struct{}{},
				identityLabels:     map[string]struct{}{},
				principalURN:       principalURN,
				principalLabel:     cypherRowString(row, "principal_label"),
				principalType:      cypherRowString(row, "principal_entity_type"),
				principalAttrsJSON: cypherRowString(row, "principal_attributes_json"),
				accesses:           map[string]grcOverlayAccess{},
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

type deprovisionedOktaActiveCloudGroup struct {
	oktaUserURN        string
	oktaUserLabel      string
	oktaStatus         string
	identityURNs       map[string]struct{}
	identityLabels     map[string]struct{}
	principalURN       string
	principalLabel     string
	principalType      string
	principalAttrsJSON string
	accesses           map[string]grcOverlayAccess
}

func (r *deprovisionedOktaActiveCloudAccessRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *deprovisionedOktaActiveCloudGroup, now time.Time) *ports.FindingRecord {
	accessURNs, accessLabels, accessTypes, accessRelations := grcOverlayAccessTelemetry(group.accesses)
	identityURNs := sortedKeys(group.identityURNs)
	identityLabels := sortedKeys(group.identityLabels)
	resourceURNs := deduplicateStrings(append(append([]string{group.oktaUserURN, group.principalURN}, identityURNs...), accessURNs...))
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, group.oktaUserURN, group.principalURN)
	oktaLabel := firstNonEmpty(group.oktaUserLabel, group.oktaUserURN)
	principalLabel := firstNonEmpty(group.principalLabel, group.principalURN)
	summary := fmt.Sprintf("Deprovisioned Okta identity %s is still linked to %s principal %s with %d active access path(s)", oktaLabel, firstNonEmpty(group.principalType, "cloud"), principalLabel, len(group.accesses))
	attributes := map[string]string{
		"primary_resource_urn":   group.oktaUserURN,
		"okta_user_urn":          group.oktaUserURN,
		"okta_user_label":        group.oktaUserLabel,
		"okta_status":            group.oktaStatus,
		"identity_urns":          strings.Join(identityURNs, ","),
		"identity_labels":        strings.Join(identityLabels, ","),
		"principal_urn":          group.principalURN,
		"principal_label":        group.principalLabel,
		"principal_entity_type":  group.principalType,
		"access_count":           fmt.Sprintf("%d", len(group.accesses)),
		"access_resource_urns":   strings.Join(accessURNs, ","),
		"access_resource_labels": strings.Join(accessLabels, ","),
		"access_resource_types":  strings.Join(accessTypes, ","),
		"access_relations":       strings.Join(accessRelations, ","),
		"graph_actions_allowed":  "identity.okta.suspend_user",
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
		Status:          r.definition.Status,
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
