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

const (
	sentinelOneGraphQueryRowLimit      = 2000
	sentinelOneGraphEvidenceAgentLimit = 100
)

type sentinelOneEndpointActiveInfectionGraphRule struct {
	definition RuleDefinition
}

func (r *sentinelOneEndpointActiveInfectionGraphRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *sentinelOneEndpointActiveInfectionGraphRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return sentinelOneGraphRuleSupportsRuntime(runtime, "agent", "threat")
}

func (r *sentinelOneEndpointActiveInfectionGraphRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *sentinelOneEndpointActiveInfectionGraphRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil || strings.TrimSpace(runtime.GetTenantId()) == "" {
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
RETURN agent.urn AS agent_urn,
       agent.label AS agent_label,
       coalesce(agent.attributes_json, '') AS agent_attributes_json,
       threats
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id": strings.TrimSpace(runtime.GetTenantId()),
			"row_limit": int64(sentinelOneGraphQueryRowLimit),
		},
		RowLimit: sentinelOneGraphQueryRowLimit,
	}
}

func (r *sentinelOneEndpointActiveInfectionGraphRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	findings := make([]*ports.FindingRecord, 0, len(rows))
	for _, row := range rows {
		agentURN := cypherRowString(row, "agent_urn")
		if agentURN == "" {
			continue
		}
		agentAttrs := edgeStringAttributes(cypherRowString(row, "agent_attributes_json"))
		activeThreats := sentinelOneActiveThreatsFromRow(row)
		agentInfected := findingAttributeBool(agentAttrs, "is_infected", "infected") || sentinelOneIntAttribute(agentAttrs) > 0
		if !agentInfected && !sentinelOneGraphThreatsHaveInfectionEvidence(activeThreats) {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, agentURN, cypherRowString(row, "agent_label"), agentAttrs, activeThreats, now))
	}
	return findings, nil
}

func sentinelOneActiveThreatsFromRow(row ports.CypherRow) []sentinelOneGraphThreat {
	threats := make([]sentinelOneGraphThreat, 0)
	for _, item := range cypherRowList(row, "threats") {
		threatURN := strings.TrimSpace(cypherListMapString(item, "urn"))
		if threatURN == "" {
			continue
		}
		threatAttrs := edgeStringAttributes(cypherListMapString(item, "attributes_json"))
		edgeAttrs := edgeStringAttributes(cypherListMapString(item, "affected_attributes_json"))
		merged := mergeFindingAttributeMaps(threatAttrs, edgeAttrs)
		if sentinelOneFalsePositive(merged) || !sentinelOneThreatOpen(merged) {
			continue
		}
		threats = append(threats, sentinelOneGraphThreat{
			URN:        threatURN,
			Label:      cypherListMapString(item, "label"),
			EntityType: firstNonEmpty(cypherListMapString(item, "entity_type"), sentinelOneThreatEntityType),
			Attributes: merged,
		})
	}
	sort.Slice(threats, func(i, j int) bool {
		return threats[i].URN < threats[j].URN
	})
	return threats
}

func (r *sentinelOneEndpointActiveInfectionGraphRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, agentURN string, agentLabel string, agentAttrs map[string]string, threats []sentinelOneGraphThreat, now time.Time) *ports.FindingRecord {
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, agentURN)
	threatURNs := make([]string, 0, len(threats))
	threatNames := make([]string, 0, len(threats))
	threatIDs := make([]string, 0, len(threats))
	incidentStatuses := map[string]struct{}{}
	mitigationStatuses := map[string]struct{}{}
	eventIDs := map[string]struct{}{}
	resourceURNs := []string{agentURN}
	graphRows := make([]*cerebrov1.GraphEvidenceRow, 0, len(threats)+1)
	for _, threat := range threats {
		threatURNs = append(threatURNs, threat.URN)
		resourceURNs = append(resourceURNs, threat.URN)
		if threat.Label != "" {
			threatNames = append(threatNames, threat.Label)
		}
		if id := strings.TrimSpace(threat.Attributes["threat_id"]); id != "" {
			threatIDs = append(threatIDs, id)
		}
		if status := strings.TrimSpace(threat.Attributes["incident_status"]); status != "" {
			incidentStatuses[status] = struct{}{}
		}
		if status := strings.TrimSpace(threat.Attributes["mitigation_status"]); status != "" {
			mitigationStatuses[status] = struct{}{}
		}
		if eventID := strings.TrimSpace(threat.Attributes["event_id"]); eventID != "" {
			eventIDs[eventID] = struct{}{}
		}
		graphRows = append(graphRows, newGraphEvidenceRow("active_sentinelone_threat", map[string]string{
			"agent_urn":         agentURN,
			"agent_label":       agentLabel,
			"threat_urn":        threat.URN,
			"threat_label":      threat.Label,
			"incident_status":   threat.Attributes["incident_status"],
			"mitigation_status": threat.Attributes["mitigation_status"],
			"classification":    threat.Attributes["classification"],
			"event_id":          threat.Attributes["event_id"],
		}, newGraphEvidencePath(agentURN, agentLabel, sentinelOneAgentEntityType, "affected_by", threat.URN, threat.Label, threat.EntityType, compactStringMap(threat.Attributes))))
	}
	if agentEventID := strings.TrimSpace(agentAttrs["event_id"]); agentEventID != "" {
		eventIDs[agentEventID] = struct{}{}
	}
	if siteID := strings.TrimSpace(agentAttrs["site_id"]); siteID != "" {
		resourceURNs = append(resourceURNs, sentinelOneProjectionURN(tenantID, "sentinelone_site", siteID))
	}
	if groupID := strings.TrimSpace(agentAttrs["group_id"]); groupID != "" {
		resourceURNs = append(resourceURNs, sentinelOneProjectionURN(tenantID, "sentinelone_group", groupID))
	}
	if len(graphRows) == 0 {
		graphRows = append(graphRows, newGraphEvidenceRow("infected_sentinelone_agent", map[string]string{
			"agent_urn":      agentURN,
			"agent_label":    agentLabel,
			"is_infected":    agentAttrs["is_infected"],
			"active_threats": agentAttrs["active_threats"],
			"event_id":       agentAttrs["event_id"],
		}))
	}
	sort.Strings(threatURNs)
	sort.Strings(threatNames)
	sort.Strings(threatIDs)
	attributes := map[string]string{
		"action":                 sentinelOneEndpointActiveInfectionAction,
		"primary_resource_urn":   agentURN,
		"resource_id":            firstNonEmpty(agentAttrs["agent_id"], lastURNSegment(agentURN)),
		"resource_label":         firstNonEmpty(agentLabel, agentAttrs["computer_name"], agentAttrs["agent_id"]),
		"resource_type":          sentinelOneAgentEntityType,
		"agent_id":               agentAttrs["agent_id"],
		"computer_name":          firstNonEmpty(agentAttrs["computer_name"], agentLabel),
		"agent_os_name":          firstNonEmpty(agentAttrs["agent_os_name"], agentAttrs["os_name"]),
		"agent_os_type":          firstNonEmpty(agentAttrs["agent_os_type"], agentAttrs["os_type"]),
		"is_infected":            agentAttrs["is_infected"],
		"active_threats":         firstNonEmpty(agentAttrs["active_threats"], fmt.Sprintf("%d", len(threats))),
		"active_threat_count":    fmt.Sprintf("%d", len(threats)),
		"active_threat_urns":     strings.Join(threatURNs, ","),
		"active_threat_ids":      strings.Join(threatIDs, ","),
		"active_threat_names":    strings.Join(threatNames, ","),
		"incident_statuses":      strings.Join(sortedStringSet(incidentStatuses), ","),
		"mitigation_statuses":    strings.Join(sortedStringSet(mitigationStatuses), ","),
		"site_id":                agentAttrs["site_id"],
		"site_name":              agentAttrs["site_name"],
		"group_id":               agentAttrs["group_id"],
		"group_name":             agentAttrs["group_name"],
		"source_runtime_id":      strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant":  tenantID,
		"graph_evidence_summary": fmt.Sprintf("%d active threat(s) linked to current endpoint infection state", len(threats)),
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	label := firstNonEmpty(agentLabel, agentAttrs["computer_name"], agentAttrs["agent_id"], agentURN)
	summaryThreat := firstNonEmpty(strings.Join(threatNames, ", "), fmt.Sprintf("%s active threat(s)", attributes["active_threats"]))
	return &ports.FindingRecord{
		ID:                         fingerprint,
		Fingerprint:                fingerprint,
		TenantID:                   tenantID,
		RuntimeID:                  strings.TrimSpace(runtime.GetId()),
		RuleID:                     r.definition.ID,
		Title:                      r.definition.Name,
		Severity:                   sentinelOneGraphInfectionSeverity(agentAttrs, threats),
		Status:                     r.definition.Status,
		Summary:                    fmt.Sprintf("SentinelOne endpoint %s has active infection evidence from %s", label, summaryThreat),
		ResourceURNs:               deduplicateStrings(resourceURNs),
		EventIDs:                   sortedStringSet(eventIDs),
		ObservedPolicyIDs:          []string{firstNonEmpty(agentAttrs["agent_id"], agentURN)},
		PolicyID:                   firstNonEmpty(agentAttrs["agent_id"], agentURN),
		PolicyName:                 label,
		CheckID:                    r.definition.ID,
		CheckName:                  r.definition.Name,
		ControlRefs:                cloneFindingControlRefs(r.definition.ControlRefs),
		FindingPersistenceEnvelope: ports.FindingPersistenceEnvelope{GraphEvidenceRows: graphRows},
		Attributes:                 attributes,
		FirstObservedAt:            now,
		LastObservedAt:             now,
	}
}

type sentinelOneAgentStaleGraphRule struct {
	definition RuleDefinition
}

func (r *sentinelOneAgentStaleGraphRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *sentinelOneAgentStaleGraphRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return sentinelOneGraphRuleSupportsRuntime(runtime, "agent")
}

func (r *sentinelOneAgentStaleGraphRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *sentinelOneAgentStaleGraphRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil || strings.TrimSpace(runtime.GetTenantId()) == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (agent:Entity {entity_type: 'sentinelone.agent', tenant_id: $tenant_id})
RETURN agent.urn AS agent_urn,
       agent.label AS agent_label,
       coalesce(agent.attributes_json, '') AS agent_attributes_json
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id": strings.TrimSpace(runtime.GetTenantId()),
			"row_limit": int64(sentinelOneGraphQueryRowLimit),
		},
		RowLimit: sentinelOneGraphQueryRowLimit,
	}
}

func (r *sentinelOneAgentStaleGraphRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*sentinelOneStaleAgentGroup{}
	keys := make([]string, 0)
	for _, row := range rows {
		agentURN := cypherRowString(row, "agent_urn")
		if agentURN == "" {
			continue
		}
		agentAttrs := edgeStringAttributes(cypherRowString(row, "agent_attributes_json"))
		if sentinelOneAgentRetired(agentAttrs) {
			continue
		}
		lastActive, ok := sentinelOneParseTimestamp(agentAttrs["last_active_date"])
		if !ok {
			continue
		}
		age := now.Sub(lastActive.UTC())
		if age <= sentinelOneAgentStaleThreshold {
			continue
		}
		bucket := sentinelOneStaleAgentBucket(age)
		scopeURN, scopeLabel, scopeType := sentinelOneStaleAgentScope(tenantID, agentAttrs)
		key := scopeURN + "|" + bucket.ID
		group, ok := groups[key]
		if !ok {
			group = &sentinelOneStaleAgentGroup{
				ScopeURN:   scopeURN,
				ScopeLabel: scopeLabel,
				ScopeType:  scopeType,
				Bucket:     bucket,
			}
			groups[key] = group
			keys = append(keys, key)
		}
		group.Agents = append(group.Agents, sentinelOneStaleAgent{
			URN:        agentURN,
			Label:      cypherRowString(row, "agent_label"),
			LastActive: lastActive.UTC(),
			Attributes: agentAttrs,
		})
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.Agents) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

func (r *sentinelOneAgentStaleGraphRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *sentinelOneStaleAgentGroup, now time.Time) *ports.FindingRecord {
	sort.Slice(group.Agents, func(i, j int) bool {
		return group.Agents[i].LastActive.Before(group.Agents[j].LastActive)
	})
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, group.ScopeURN, group.Bucket.ID)
	agentURNs := make([]string, 0, len(group.Agents))
	agentLabels := make([]string, 0, len(group.Agents))
	eventIDs := map[string]struct{}{}
	graphRows := make([]*cerebrov1.GraphEvidenceRow, 0, minInt(len(group.Agents), sentinelOneGraphEvidenceAgentLimit))
	for index, agent := range group.Agents {
		agentURNs = append(agentURNs, agent.URN)
		if agent.Label != "" {
			agentLabels = append(agentLabels, agent.Label)
		}
		if eventID := strings.TrimSpace(agent.Attributes["event_id"]); eventID != "" {
			eventIDs[eventID] = struct{}{}
		}
		if index < sentinelOneGraphEvidenceAgentLimit {
			graphRows = append(graphRows, newGraphEvidenceRow("stale_sentinelone_agent", map[string]string{
				"agent_urn":        agent.URN,
				"agent_label":      agent.Label,
				"scope_urn":        group.ScopeURN,
				"scope_label":      group.ScopeLabel,
				"staleness_bucket": group.Bucket.ID,
				"last_active_date": agent.LastActive.Format(time.RFC3339),
			}, newGraphEvidencePath(agent.URN, agent.Label, sentinelOneAgentEntityType, sentinelOneStaleScopeRelation(group.ScopeType), group.ScopeURN, group.ScopeLabel, group.ScopeType, map[string]string{
				"last_active_date": agent.LastActive.Format(time.RFC3339),
				"event_id":         agent.Attributes["event_id"],
			})))
		}
	}
	sort.Strings(agentURNs)
	sort.Strings(agentLabels)
	newest := group.Agents[len(group.Agents)-1].LastActive
	oldest := group.Agents[0].LastActive
	attributes := map[string]string{
		"action":                  sentinelOneAgentStaleAction,
		"primary_resource_urn":    group.ScopeURN,
		"resource_label":          group.ScopeLabel,
		"resource_type":           group.ScopeType,
		"scope_urn":               group.ScopeURN,
		"scope_label":             group.ScopeLabel,
		"scope_type":              group.ScopeType,
		"staleness_bucket":        group.Bucket.ID,
		"staleness_bucket_label":  group.Bucket.Label,
		"agent_count":             fmt.Sprintf("%d", len(group.Agents)),
		"agent_urns":              strings.Join(agentURNs, ","),
		"agent_labels":            strings.Join(limitStrings(agentLabels, 50), ","),
		"oldest_last_active_date": oldest.Format(time.RFC3339),
		"newest_last_active_date": newest.Format(time.RFC3339),
		"evidence_rows_truncated": fmt.Sprintf("%t", len(group.Agents) > sentinelOneGraphEvidenceAgentLimit),
		"source_runtime_id":       strings.TrimSpace(runtime.GetId()),
		"source_runtime_tenant":   tenantID,
		"graph_evidence_summary":  fmt.Sprintf("%d stale SentinelOne agent(s) grouped by %s and %s", len(group.Agents), group.ScopeLabel, group.Bucket.Label),
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	summary := fmt.Sprintf("SentinelOne %s has %d stale agent(s) last active %s", group.ScopeLabel, len(group.Agents), group.Bucket.Label)
	return &ports.FindingRecord{
		ID:                         fingerprint,
		Fingerprint:                fingerprint,
		TenantID:                   tenantID,
		RuntimeID:                  strings.TrimSpace(runtime.GetId()),
		RuleID:                     r.definition.ID,
		Title:                      r.definition.Name,
		Severity:                   group.Bucket.Severity,
		Status:                     r.definition.Status,
		Summary:                    summary,
		ResourceURNs:               []string{group.ScopeURN},
		EventIDs:                   sortedStringSet(eventIDs),
		ObservedPolicyIDs:          []string{group.ScopeURN + ":" + group.Bucket.ID},
		PolicyID:                   group.ScopeURN + ":" + group.Bucket.ID,
		PolicyName:                 group.ScopeLabel + " " + group.Bucket.Label,
		CheckID:                    r.definition.ID,
		CheckName:                  r.definition.Name,
		ControlRefs:                cloneFindingControlRefs(r.definition.ControlRefs),
		FindingPersistenceEnvelope: ports.FindingPersistenceEnvelope{GraphEvidenceRows: graphRows},
		Attributes:                 attributes,
		FirstObservedAt:            now,
		LastObservedAt:             now,
	}
}

type sentinelOneGraphThreat struct {
	URN        string
	Label      string
	EntityType string
	Attributes map[string]string
}

type sentinelOneStaleAgent struct {
	URN        string
	Label      string
	LastActive time.Time
	Attributes map[string]string
}

type sentinelOneStaleAgentGroup struct {
	ScopeURN   string
	ScopeLabel string
	ScopeType  string
	Bucket     sentinelOneStaleBucket
	Agents     []sentinelOneStaleAgent
}

type sentinelOneStaleBucket struct {
	ID       string
	Label    string
	Severity string
}

func sentinelOneGraphRuleSupportsRuntime(runtime *cerebrov1.SourceRuntime, families ...string) bool {
	if runtime == nil || !strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), "sentinelone") {
		return false
	}
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	if family == "" {
		family = "threat"
	}
	for _, supported := range families {
		if family == strings.ToLower(strings.TrimSpace(supported)) {
			return true
		}
	}
	return false
}

func sentinelOneGraphInfectionSeverity(agentAttrs map[string]string, threats []sentinelOneGraphThreat) string {
	if sentinelOneIntAttribute(agentAttrs) > 1 || len(threats) > 1 {
		return "CRITICAL"
	}
	for _, threat := range threats {
		if findingAttributeBool(threat.Attributes, "is_fileless") {
			return "CRITICAL"
		}
	}
	return "HIGH"
}

func sentinelOneGraphThreatsHaveInfectionEvidence(threats []sentinelOneGraphThreat) bool {
	for _, threat := range threats {
		if findingAttributeBool(threat.Attributes, "is_infected", "infected") || sentinelOneIntAttribute(threat.Attributes) > 0 {
			return true
		}
	}
	return false
}

func sentinelOneStaleAgentBucket(age time.Duration) sentinelOneStaleBucket {
	switch {
	case age > 90*24*time.Hour:
		return sentinelOneStaleBucket{ID: "stale_gt_90d", Label: "more than 90 days ago", Severity: "CRITICAL"}
	case age > 30*24*time.Hour:
		return sentinelOneStaleBucket{ID: "stale_31_90d", Label: "31-90 days ago", Severity: "HIGH"}
	default:
		return sentinelOneStaleBucket{ID: "stale_14_30d", Label: "14-30 days ago", Severity: "MEDIUM"}
	}
}

func sentinelOneStaleAgentScope(tenantID string, attrs map[string]string) (string, string, string) {
	if groupID := strings.TrimSpace(attrs["group_id"]); groupID != "" {
		return sentinelOneProjectionURN(tenantID, "sentinelone_group", groupID), firstNonEmpty(attrs["group_name"], groupID), "sentinelone.group"
	}
	if siteID := strings.TrimSpace(attrs["site_id"]); siteID != "" {
		return sentinelOneProjectionURN(tenantID, "sentinelone_site", siteID), firstNonEmpty(attrs["site_name"], siteID), "sentinelone.site"
	}
	return sentinelOneProjectionURN(tenantID, "sentinelone_scope", "tenant"), tenantID, "sentinelone.scope"
}

func sentinelOneStaleScopeRelation(scopeType string) string {
	if scopeType == "sentinelone.site" {
		return "belongs_to"
	}
	if scopeType == "sentinelone.group" {
		return "member_of"
	}
	return "scoped_to"
}

func sentinelOneProjectionURN(tenantID string, kind string, parts ...string) string {
	values := []string{"urn", "cerebro", strings.TrimSpace(tenantID), strings.TrimSpace(kind)}
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return strings.Join(values, ":")
}

func mergeFindingAttributeMaps(primary map[string]string, secondary map[string]string) map[string]string {
	merged := make(map[string]string, len(primary)+len(secondary))
	for key, value := range secondary {
		if strings.TrimSpace(value) != "" {
			merged[key] = value
		}
	}
	for key, value := range primary {
		if strings.TrimSpace(value) != "" {
			merged[key] = value
		}
	}
	return merged
}

func limitStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func lastURNSegment(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}
