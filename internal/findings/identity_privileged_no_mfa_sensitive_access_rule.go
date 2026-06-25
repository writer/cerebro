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

var _ GraphRule = (*identityPrivilegedNoMFAAccessRule)(nil)

const (
	identityPrivilegedNoMFAAccessKind     = "finding.identity_privileged_no_mfa_sensitive_access"
	identityPrivilegedNoMFAAccessRowLimit = 250
	identityPrivilegedNoMFAActedOnWindow  = 90 * 24 * time.Hour
)

type identityPrivilegedNoMFAAccessRule struct {
	definition RuleDefinition
}

type identityPrivilegedNoMFAAccessGroup struct {
	userURN        string
	userEntityType string
	userLabel      string
	userAttrs      map[string]string
	resources      map[string]identityPrivilegedNoMFAAccessResource
}

type identityPrivilegedNoMFAAccessResource struct {
	urn                   string
	entityType            string
	label                 string
	accessRelation        string
	accessAttributes      map[string]string
	sensitivityURN        string
	sensitivityEntityType string
	sensitivityLabel      string
	sensitivityRelation   string
	sensitivityAttributes map[string]string
}

func newIdentityPrivilegedNoMFAAccessRule() Rule {
	definition := identityDurableStateRuleDefinition(identityRuleDefinition(
		identityPrivilegedNoMFAAccessRuleID,
		"Identity Privileged No-MFA Account With Sensitive Access",
		"Detect source-backed privileged no-MFA identities that currently have access to crown-jewel or sensitive classified resources in the graph; AWS IAM and Azure user MFA posture require source-adapter extensions before those user entity types are included.",
		"HIGH",
		identityPrivilegedNoMFAAccessKind,
		[]string{"identity", "graph-join", "privileged-access", "mfa"},
	), "user")
	definition.EventKinds = []string{
		"asset.crown_jewel",
		"asset.data_sensitivity",
		"aws.iam_role_assignment",
		"azure.app_role_assignment",
		"azure.directory_role_assignment",
		"azure.iam_role_assignment",
		"gcp.iam_role_assignment",
		"gcp.service_account",
		"google_workspace.role_assignment",
		"google_workspace.user",
		"okta.admin_role",
		"okta.app_assignment",
		"okta.user",
	}
	definition.FalsePositives = []string{
		"Break-glass identity with approved compensating controls and time-bound exception.",
		"Resource incorrectly tagged as crown-jewel or sensitive classification in the graph.",
	}
	definition.Runbook = "Enroll MFA for the identity or remove its privileged access to the sensitive resource. Validate the resource classification/tag and revoke any stale access edge in the identity or cloud provider."
	return &identityPrivilegedNoMFAAccessRule{definition: definition}
}

func (r *identityPrivilegedNoMFAAccessRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *identityPrivilegedNoMFAAccessRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil || strings.TrimSpace(runtime.GetSourceId()) == "" {
		return false
	}
	kind := runtimeConfiguredEventKind(runtime)
	if kind == "" {
		return false
	}
	return identityKindAllowed(kind, r.definition.EventKinds)
}

func (r *identityPrivilegedNoMFAAccessRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *identityPrivilegedNoMFAAccessRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil || strings.TrimSpace(runtime.GetTenantId()) == "" {
		return ports.CypherQueryRequest{}
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	actedOnSince := time.Now().UTC().Add(-identityPrivilegedNoMFAActedOnWindow).Format(time.RFC3339)
	return ports.CypherQueryRequest{
		Query: `MATCH (marker:Entity {tenant_id: $tenant_id})
WHERE marker.entity_type IN ['asset.tag', 'data.classification']
MATCH (resource:Entity {tenant_id: $tenant_id})-[sensitivity:RELATION]->(marker)
MATCH (user:Entity {tenant_id: $tenant_id})-[access:RELATION]->(resource)
WITH user, access, resource, sensitivity, marker,
     toLower(coalesce(user.attributes_json, '')) AS user_attrs,
     coalesce(access.attributes_json, '') AS access_attrs
WHERE user.entity_type IN ['okta.user','google_workspace.user','gcp.service_account']
  AND access.relation IN ['acted_on','assigned_to','can_admin','can_perform']
  AND (
    access.relation <> 'acted_on'
    OR (
      CASE
      WHEN access_attrs CONTAINS '"observed_at":"' THEN split(split(access_attrs, '"observed_at":"')[1], '"')[0]
      WHEN access_attrs CONTAINS '"at":"' THEN split(split(access_attrs, '"at":"')[1], '"')[0]
      WHEN access_attrs CONTAINS '"last_observed_at":"' THEN split(split(access_attrs, '"last_observed_at":"')[1], '"')[0]
      ELSE ''
      END
    ) > $acted_on_since
  )
  AND (
    user_attrs CONTAINS '"is_admin":"true"'
    OR user_attrs CONTAINS '"is_admin":true'
    OR user_attrs CONTAINS '"is_delegated_admin":"true"'
    OR user_attrs CONTAINS '"is_delegated_admin":true'
  )
  AND (
    user_attrs CONTAINS '"mfa_enrolled":"false"'
    OR user_attrs CONTAINS '"mfa_enrolled":false'
    OR user_attrs CONTAINS '"mfa_enforced":"false"'
    OR user_attrs CONTAINS '"mfa_enforced":false'
    OR user_attrs CONTAINS '"is_enrolled_in_2sv":"false"'
    OR user_attrs CONTAINS '"is_enrolled_in_2sv":false'
    OR user_attrs CONTAINS '"is_enforced_in_2sv":"false"'
    OR user_attrs CONTAINS '"is_enforced_in_2sv":false'
  )
  AND (
    (sensitivity.relation = 'tagged_as' AND marker.entity_type = 'asset.tag' AND toLower(marker.label) = 'crown_jewel')
    OR
    (sensitivity.relation = 'has_classification' AND marker.entity_type = 'data.classification' AND toLower(marker.label) IN ['confidential','restricted','regulated','pii','phi','pci'])
  )
RETURN user.urn AS user_urn,
       user.entity_type AS user_entity_type,
       user.label AS user_label,
       coalesce(user.attributes_json, '') AS user_attributes_json,
       resource.urn AS resource_urn,
       resource.entity_type AS resource_entity_type,
       resource.label AS resource_label,
       access.relation AS access_relation,
       coalesce(access.attributes_json, '') AS access_attributes_json,
       sensitivity.relation AS sensitivity_relation,
       marker.urn AS sensitivity_urn,
       marker.entity_type AS sensitivity_entity_type,
       marker.label AS sensitivity_label,
       coalesce(sensitivity.attributes_json, '') AS sensitivity_attributes_json
ORDER BY user.label, resource.label, marker.label
LIMIT $row_limit`,
		Params: map[string]any{
			"acted_on_since": actedOnSince,
			"tenant_id":      tenantID,
			"row_limit":      int64(identityPrivilegedNoMFAAccessRowLimit),
		},
		RowLimit: identityPrivilegedNoMFAAccessRowLimit,
	}
}

func (r *identityPrivilegedNoMFAAccessRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	groups := map[string]*identityPrivilegedNoMFAAccessGroup{}
	keys := []string{}
	now := time.Now().UTC()
	for _, row := range rows {
		userURN := cypherRowString(row, "user_urn")
		resourceURN := cypherRowString(row, "resource_urn")
		if userURN == "" || resourceURN == "" {
			continue
		}
		userEntityType := cypherRowString(row, "user_entity_type")
		if !identityPrivilegedNoMFAUserEntityTypeSupported(userEntityType) {
			continue
		}
		userAttrs := edgeStringAttributes(cypherRowString(row, "user_attributes_json"))
		if !identityPrivilegedNoMFAUserMatches(userAttrs) {
			continue
		}
		accessRelation := cypherRowString(row, "access_relation")
		accessAttributes := edgeStringAttributes(cypherRowString(row, "access_attributes_json"))
		if !identityPrivilegedNoMFAAccessRelationActionable(accessRelation, accessAttributes, now) {
			continue
		}
		sensitivityRelation := cypherRowString(row, "sensitivity_relation")
		sensitivityEntityType := cypherRowString(row, "sensitivity_entity_type")
		sensitivityLabel := cypherRowString(row, "sensitivity_label")
		if !identityPrivilegedNoMFASensitiveMarker(sensitivityRelation, sensitivityEntityType, sensitivityLabel) {
			continue
		}
		group, ok := groups[userURN]
		if !ok {
			group = &identityPrivilegedNoMFAAccessGroup{
				userURN:        userURN,
				userEntityType: userEntityType,
				userLabel:      cypherRowString(row, "user_label"),
				userAttrs:      userAttrs,
				resources:      map[string]identityPrivilegedNoMFAAccessResource{},
			}
			groups[userURN] = group
			keys = append(keys, userURN)
		}
		key := resourceURN + "\x00" + sensitivityRelation + "\x00" + cypherRowString(row, "sensitivity_urn")
		if _, exists := group.resources[key]; exists {
			continue
		}
		group.resources[key] = identityPrivilegedNoMFAAccessResource{
			urn:                   resourceURN,
			entityType:            cypherRowString(row, "resource_entity_type"),
			label:                 cypherRowString(row, "resource_label"),
			accessRelation:        accessRelation,
			accessAttributes:      accessAttributes,
			sensitivityURN:        cypherRowString(row, "sensitivity_urn"),
			sensitivityEntityType: sensitivityEntityType,
			sensitivityLabel:      sensitivityLabel,
			sensitivityRelation:   sensitivityRelation,
			sensitivityAttributes: edgeStringAttributes(cypherRowString(row, "sensitivity_attributes_json")),
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.resources) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

func identityPrivilegedNoMFAUserMatches(attrs map[string]string) bool {
	if len(attrs) == 0 {
		return false
	}
	return (findingAttributeBool(attrs, "is_admin") || findingAttributeBool(attrs, "is_delegated_admin")) &&
		identityMFAExplicitlyDisabled(attrs)
}

func identityPrivilegedNoMFAUserEntityTypeSupported(entityType string) bool {
	switch strings.TrimSpace(entityType) {
	case "okta.user", "google_workspace.user", "gcp.service_account":
		return true
	default:
		return false
	}
}

func identityPrivilegedNoMFAAccessRelation(relation string) bool {
	switch strings.TrimSpace(relation) {
	case "acted_on", "assigned_to", "can_admin", "can_perform":
		return true
	default:
		return false
	}
}

func identityPrivilegedNoMFAAccessRelationActionable(relation string, attributes map[string]string, now time.Time) bool {
	normalized := strings.TrimSpace(relation)
	if !identityPrivilegedNoMFAAccessRelation(normalized) {
		return false
	}
	if normalized != "acted_on" {
		return true
	}
	return identityPrivilegedNoMFAActedOnRecent(attributes, now)
}

func identityPrivilegedNoMFAActedOnRecent(attributes map[string]string, now time.Time) bool {
	raw := strings.TrimSpace(firstNonEmpty(attributes["observed_at"], attributes["at"], attributes["last_observed_at"]))
	if raw == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return false
		}
	}
	return parsed.UTC().After(now.UTC().Add(-identityPrivilegedNoMFAActedOnWindow))
}

func identityPrivilegedNoMFASensitiveMarker(relation string, entityType string, label string) bool {
	normalizedRelation := strings.TrimSpace(relation)
	normalizedType := strings.TrimSpace(entityType)
	normalizedLabel := strings.ToLower(strings.TrimSpace(label))
	if normalizedRelation == "tagged_as" && normalizedType == "asset.tag" {
		return normalizedLabel == "crown_jewel"
	}
	if normalizedRelation != "has_classification" || normalizedType != "data.classification" {
		return false
	}
	switch normalizedLabel {
	case "confidential", "restricted", "regulated", "pii", "phi", "pci":
		return true
	default:
		return false
	}
}

func (r *identityPrivilegedNoMFAAccessRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *identityPrivilegedNoMFAAccessGroup, now time.Time) *ports.FindingRecord {
	resourceKeys := make([]string, 0, len(group.resources))
	for key := range group.resources {
		resourceKeys = append(resourceKeys, key)
	}
	sort.Strings(resourceKeys)
	resourceURNs := []string{group.userURN}
	sensitiveResourceURNs := map[string]struct{}{}
	sensitiveResourceLabels := map[string]struct{}{}
	sensitiveResourceTypes := map[string]struct{}{}
	sensitivityURNs := map[string]struct{}{}
	sensitivityLabels := map[string]struct{}{}
	accessRelations := map[string]struct{}{}
	graphRows := make([]*cerebrov1.GraphEvidenceRow, 0, len(resourceKeys))
	for _, key := range resourceKeys {
		resource := group.resources[key]
		if resource.urn == "" {
			continue
		}
		sensitiveResourceURNs[resource.urn] = struct{}{}
		resourceURNs = append(resourceURNs, resource.urn)
		if resource.label != "" {
			sensitiveResourceLabels[resource.label] = struct{}{}
		}
		if resource.entityType != "" {
			sensitiveResourceTypes[resource.entityType] = struct{}{}
		}
		if resource.sensitivityURN != "" {
			sensitivityURNs[resource.sensitivityURN] = struct{}{}
			resourceURNs = append(resourceURNs, resource.sensitivityURN)
		}
		if resource.sensitivityLabel != "" {
			sensitivityLabels[strings.ToLower(resource.sensitivityLabel)] = struct{}{}
		}
		if resource.accessRelation != "" {
			accessRelations[resource.accessRelation] = struct{}{}
		}
		graphRows = append(graphRows, newGraphEvidenceRow("identity_privileged_no_mfa_sensitive_access", map[string]string{
			"access_relation":    resource.accessRelation,
			"resource":           firstNonEmpty(resource.label, resource.urn),
			"sensitivity_label":  resource.sensitivityLabel,
			"sensitivity_source": resource.sensitivityRelation,
			"user":               firstNonEmpty(group.userLabel, group.userURN),
		},
			newGraphEvidencePath(group.userURN, group.userLabel, group.userEntityType, resource.accessRelation, resource.urn, resource.label, resource.entityType, compactStringMap(resource.accessAttributes)),
			newGraphEvidencePath(resource.urn, resource.label, resource.entityType, resource.sensitivityRelation, resource.sensitivityURN, resource.sensitivityLabel, resource.sensitivityEntityType, compactStringMap(resource.sensitivityAttributes)),
		))
	}
	sensitiveURNList := sortedKeys(sensitiveResourceURNs)
	summary := fmt.Sprintf("Privileged identity %s lacks MFA and has access to %d sensitive resource(s)", firstNonEmpty(group.userLabel, group.userURN), len(sensitiveURNList))
	attributes := map[string]string{
		"access_relations":          strings.Join(sortedKeys(accessRelations), ","),
		"is_admin":                  group.userAttrs["is_admin"],
		"is_delegated_admin":        group.userAttrs["is_delegated_admin"],
		"mfa_enrolled":              group.userAttrs["mfa_enrolled"],
		"primary_resource_urn":      group.userURN,
		"sensitive_resource_count":  fmt.Sprintf("%d", len(sensitiveURNList)),
		"sensitive_resource_labels": strings.Join(sortedKeys(sensitiveResourceLabels), ","),
		"sensitive_resource_types":  strings.Join(sortedKeys(sensitiveResourceTypes), ","),
		"sensitive_resource_urns":   strings.Join(sensitiveURNList, ","),
		"sensitivity_labels":        strings.Join(sortedKeys(sensitivityLabels), ","),
		"sensitivity_urns":          strings.Join(sortedKeys(sensitivityURNs), ","),
		"source_runtime_id":         strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant":     tenantID,
		"user":                      group.userURN,
		"user_entity_type":          group.userEntityType,
		"user_label":                group.userLabel,
		"user_urn":                  group.userURN,
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	fingerprint := hashFindingFingerprint(r.definition.ID, group.userURN)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          tenantID,
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            r.definition.ID,
		Title:             r.definition.Name,
		Severity:          r.definition.Severity,
		Status:            r.definition.Status,
		Summary:           summary,
		ResourceURNs:      deduplicateStrings(resourceURNs),
		CheckID:           r.definition.ID,
		CheckName:         r.definition.Name,
		ControlRefs:       cloneFindingControlRefs(r.definition.ControlRefs),
		GraphEvidenceRows: graphRows,
		Attributes:        attributes,
		FirstObservedAt:   now,
		LastObservedAt:    now,
	}
}
