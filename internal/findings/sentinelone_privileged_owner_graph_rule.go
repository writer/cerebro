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

var _ GraphRule = (*sentinelOneInfectedPrivilegedOwnerRule)(nil)

const (
	sentinelOneInfectedPrivilegedOwnerRuleID = "sentinelone-infected-endpoint-privileged-owner"
	sentinelOneInfectedPrivilegedOwnerKind   = "finding.sentinelone_infected_endpoint_privileged_owner"
)

var sentinelOnePrivilegedOwnerPrincipalTypes = []string{
	grcOverlayEntityTypeOktaUser,
	grcOverlayEntityTypeGitHubUser,
	grcOverlayEntityTypeGoogleWorkspaceUser,
	grcOverlayEntityTypeAWSUser,
	grcOverlayEntityTypeGCPUser,
	grcOverlayEntityTypeAzureUser,
}

type sentinelOneInfectedPrivilegedOwnerRule struct {
	definition RuleDefinition
}

func newSentinelOneInfectedPrivilegedOwnerRule() Rule {
	return &sentinelOneInfectedPrivilegedOwnerRule{
		definition: RuleDefinition{
			ID:          sentinelOneInfectedPrivilegedOwnerRuleID,
			Name:        "Infected SentinelOne Endpoint Owned By Privileged Identity",
			Description: "Detect active SentinelOne endpoint infection evidence where the endpoint owner resolves to a privileged identity in a connected control plane.",
			SourceID:    "sentinelone",
			EventKinds: []string{
				"sentinelone.agent",
				"sentinelone.threat",
				"okta.admin_role",
				"github.audit",
				"google_workspace.role_assignment",
				"aws.iam_role_assignment",
				"aws.effective_permission",
				"gcp.iam_role_assignment",
				"gcp.effective_permission",
				"azure.directory_role_assignment",
				"azure.iam_role_assignment",
				"azure.effective_permission",
			},
			OutputKind: sentinelOneInfectedPrivilegedOwnerKind,
			Severity:   "CRITICAL",
			Status:     findingStatusOpen,
			Maturity:   "test",
			Tags: []string{
				"sentinelone",
				"endpoint",
				"identity",
				"privilege",
				"graph-rule",
				"attack.t1078",
			},
			References: []string{
				"https://attack.mitre.org/techniques/T1078/",
				"https://attack.mitre.org/techniques/T1566/",
			},
			FalsePositives: []string{
				"Endpoint owner metadata is stale and no longer represents the current assignee.",
				"Privileged role is break-glass only and disabled by compensating controls with documented exception.",
			},
			Runbook: "Prioritize containment of the infected endpoint, validate the owner identity's privileged grants, revoke or constrain active sessions, and rotate credentials used from the host.",
			FingerprintFields: []string{
				"agent_urn",
				"principal_urn",
			},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.6"},
				{FrameworkName: "SOC 2", ControlID: "CC7.2"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.8.7"},
			},
			Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
		},
	}
}

func (r *sentinelOneInfectedPrivilegedOwnerRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *sentinelOneInfectedPrivilegedOwnerRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	switch sourceID {
	case "sentinelone":
		return family == "agent" || family == "threat"
	case "okta":
		return family == "admin_role" || family == "user"
	case "github":
		return family == "audit"
	case "google_workspace":
		return family == "role_assignment" || family == "user"
	case "aws":
		return family == "iam_role_assignment" || family == "effective_permission"
	case "gcp":
		return family == "iam_role_assignment" || family == "effective_permission"
	case "azure":
		return family == "directory_role_assignment" || family == "iam_role_assignment" || family == "effective_permission"
	default:
		return false
	}
}

func (r *sentinelOneInfectedPrivilegedOwnerRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *sentinelOneInfectedPrivilegedOwnerRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil {
		return ports.CypherQueryRequest{}
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (agent:Entity {entity_type: 'sentinelone.agent', tenant_id: $tenant_id})
OPTIONAL MATCH (agent)-[affected:RELATION {relation: 'affected_by'}]->(threat:Entity {entity_type: 'sentinelone.threat', tenant_id: $tenant_id})
WITH agent, collect({
       urn: threat.urn,
       label: coalesce(threat.label, ''),
       entity_type: coalesce(threat.entity_type, ''),
       attributes_json: coalesce(threat.attributes_json, ''),
       affected_attributes_json: coalesce(affected.attributes_json, '')
     }) AS threats
MATCH (agent)-[owned:RELATION {relation: 'owned_by'}]->(identity:Entity)
      <-[principal_identity:RELATION {relation: 'represents_identity'}]-(principal:Entity {tenant_id: $tenant_id})
WHERE principal.entity_type IN $principal_types
MATCH (principal)-[privilege:RELATION]->(privileged_resource:Entity)
WHERE privilege.relation IN $privilege_relations
WITH agent, threats, owned, identity, principal, principal_identity,
     collect(DISTINCT {
       relation: coalesce(privilege.relation, ''),
       resource_urn: coalesce(privileged_resource.urn, ''),
       resource_type: coalesce(privileged_resource.entity_type, ''),
       resource_label: coalesce(privileged_resource.label, ''),
       attributes_json: coalesce(privilege.attributes_json, '')
     }) AS privilege_edges
RETURN agent.urn AS agent_urn,
       agent.label AS agent_label,
       coalesce(agent.attributes_json, '') AS agent_attributes_json,
       threats,
       coalesce(owned.attributes_json, '') AS owned_attributes_json,
       identity.urn AS identity_urn,
       identity.label AS identity_label,
       principal.urn AS principal_urn,
       principal.label AS principal_label,
       principal.entity_type AS principal_entity_type,
       coalesce(principal_identity.attributes_json, '') AS principal_identity_attributes_json,
       privilege_edges
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id":           tenantID,
			"principal_types":     sentinelOnePrivilegedOwnerPrincipalTypes,
			"privilege_relations": grcOverlayPrivilegedRelations,
			"row_limit":           int64(sentinelOneGraphQueryRowLimit),
		},
		RowLimit: sentinelOneGraphQueryRowLimit,
	}
}

func (r *sentinelOneInfectedPrivilegedOwnerRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*sentinelOnePrivilegedOwnerGroup{}
	keys := []string{}
	for _, row := range rows {
		agentURN := cypherRowString(row, "agent_urn")
		principalURN := cypherRowString(row, "principal_urn")
		if agentURN == "" || principalURN == "" {
			continue
		}
		agentAttrs := edgeStringAttributes(cypherRowString(row, "agent_attributes_json"))
		activeThreats := sentinelOneActiveThreatsFromRow(row)
		agentInfected := findingAttributeBool(agentAttrs, "is_infected", "infected") || sentinelOneIntAttribute(agentAttrs, "active_threats") > 0
		if !agentInfected && !sentinelOneGraphThreatsHaveInfectionEvidence(activeThreats) {
			continue
		}
		if !edgeIsRecent(cypherRowString(row, "owned_attributes_json"), now, grcOverlayIdentityRecencyWindow) {
			continue
		}
		principalIdentityJSON := cypherRowString(row, "principal_identity_attributes_json")
		if !edgeIsRecent(principalIdentityJSON, now, grcOverlayIdentityRecencyWindow) || !identifierMatchIsEmail(principalIdentityJSON) {
			continue
		}
		privileges := grcOverlayAccessesFromRowKey(row, "privilege_edges", now, true)
		if len(privileges) == 0 {
			continue
		}
		key := agentURN + "\x00" + principalURN
		group, ok := groups[key]
		if !ok {
			group = &sentinelOnePrivilegedOwnerGroup{
				agentURN:        agentURN,
				agentLabel:      cypherRowString(row, "agent_label"),
				agentAttrs:      agentAttrs,
				identityURNs:    map[string]struct{}{},
				identityLabels:  map[string]struct{}{},
				principalURN:    principalURN,
				principalLabel:  cypherRowString(row, "principal_label"),
				principalType:   cypherRowString(row, "principal_entity_type"),
				threats:         map[string]sentinelOneGraphThreat{},
				privilegedEdges: map[string]grcOverlayAccess{},
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
		for _, threat := range activeThreats {
			group.threats[threat.URN] = threat
		}
		for _, privilege := range privileges {
			group.privilegedEdges[privilege.resourceURN+"|"+privilege.relation] = privilege
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.privilegedEdges) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

type sentinelOnePrivilegedOwnerGroup struct {
	agentURN        string
	agentLabel      string
	agentAttrs      map[string]string
	identityURNs    map[string]struct{}
	identityLabels  map[string]struct{}
	principalURN    string
	principalLabel  string
	principalType   string
	threats         map[string]sentinelOneGraphThreat
	privilegedEdges map[string]grcOverlayAccess
}

func (r *sentinelOneInfectedPrivilegedOwnerRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *sentinelOnePrivilegedOwnerGroup, now time.Time) *ports.FindingRecord {
	threatURNs := sortedKeysFromThreatMap(group.threats)
	identityURNs := sortedKeys(group.identityURNs)
	identityLabels := sortedKeys(group.identityLabels)
	privilegeURNs, privilegeLabels, privilegeTypes, privilegeRelations := grcOverlayAccessTelemetry(group.privilegedEdges)
	resourceURNs := deduplicateStrings(append(append(append([]string{group.agentURN, group.principalURN}, identityURNs...), threatURNs...), privilegeURNs...))
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, group.agentURN, group.principalURN)
	agentLabel := firstNonEmpty(group.agentLabel, group.agentAttrs["computer_name"], group.agentURN)
	principalLabel := firstNonEmpty(group.principalLabel, group.principalURN)
	attributes := map[string]string{
		"primary_resource_urn":       group.agentURN,
		"agent_urn":                  group.agentURN,
		"agent_label":                group.agentLabel,
		"agent_id":                   group.agentAttrs["agent_id"],
		"computer_name":              group.agentAttrs["computer_name"],
		"is_infected":                group.agentAttrs["is_infected"],
		"active_threats":             firstNonEmpty(group.agentAttrs["active_threats"], fmt.Sprintf("%d", len(group.threats))),
		"active_threat_count":        fmt.Sprintf("%d", len(group.threats)),
		"active_threat_urns":         strings.Join(threatURNs, ","),
		"identity_urns":              strings.Join(identityURNs, ","),
		"identity_labels":            strings.Join(identityLabels, ","),
		"principal_urn":              group.principalURN,
		"principal_label":            group.principalLabel,
		"principal_entity_type":      group.principalType,
		"privileged_resource_urns":   strings.Join(privilegeURNs, ","),
		"privileged_resource_labels": strings.Join(privilegeLabels, ","),
		"privileged_resource_types":  strings.Join(privilegeTypes, ","),
		"privileged_relations":       strings.Join(privilegeRelations, ","),
		"source_runtime_id":          strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant":      tenantID,
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
		Summary:         fmt.Sprintf("Infected SentinelOne endpoint %s is owned by privileged %s identity %s", agentLabel, firstNonEmpty(group.principalType, "external"), principalLabel),
		ResourceURNs:    resourceURNs,
		ControlRefs:     cloneFindingControlRefs(r.definition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: now,
		LastObservedAt:  now,
		CheckID:         r.definition.ID,
		CheckName:       r.definition.Name,
	}
}

func sortedKeysFromThreatMap(values map[string]sentinelOneGraphThreat) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, strings.TrimSpace(key))
		}
	}
	sort.Strings(keys)
	return keys
}
