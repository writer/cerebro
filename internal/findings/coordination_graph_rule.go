package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	coordinationGraphRowLimit             = 500
	coordinationGraphConcentrationMinimum = 5
	coordinationGraphRelatedResourceLimit = 20
)

type coordinationGraphRule struct {
	definition RuleDefinition
	sourceID   string
	families   map[string]map[string]struct{}
	query      string
	params     map[string]any
}

func newCoordinationGraphRules() []Rule {
	return []Rule{
		newGRCSourceConcentratedOpenFindingsRule(),
		newGRCFailingControlTestUnhealthyIntegrationRule(),
		newGRCControlMissingEvidenceCoverageRule(),
		newGRCDocumentNeedsOwnerOrUploadRule(),
		newGRCIsolatedTargetEnrichmentGapRule(),
		newFindingIsolatedOpenAnchorRule(),
		newGraphAWSEC2ENILinkMissingRule(),
		newResourceMultipleOpenFindingsRule(),
	}
}

func isCoordinationGraphRuleID(ruleID string) bool {
	switch strings.TrimSpace(ruleID) {
	case "grc-source-integration-concentrated-open-findings",
		"grc-failing-control-test-unhealthy-integration",
		"grc-control-missing-evidence-coverage",
		"grc-document-needs-owner-or-upload",
		"grc-isolated-target-enrichment-gap",
		"finding-isolated-open-anchor",
		"graph-orphan-nonfinding-node",
		graphAWSEC2ENILinkMissingRuleID,
		githubProgrammaticCredentialReviewRuleID,
		githubOrgOwnerConcentrationRuleID,
		oktaOAuthPublicClientReviewRuleID,
		oktaAuthenticatorWeakFactorRuleID,
		oktaThreatInsightNotBlockingRuleID,
		sentinelOneAgentNotUpToDateRuleID,
		sentinelOneUnmitigatedThreatRuleID,
		cloudCurrentPublicExposureReviewRuleID,
		cloudExposedPrivilegedComputeRoleRuleID,
		"graph-resource-multiple-open-findings":
		return true
	default:
		return false
	}
}

func newGRCSourceConcentratedOpenFindingsRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          "grc-source-integration-concentrated-open-findings",
		Name:        "GRC Source Integration Concentrated Open Findings",
		Description: "Detect GRC source integrations that accumulate many active findings and should be prioritized as a coordinated remediation surface.",
		SourceID:    "grc",
		EventKinds:  []string{"grc.integration", "grc.vulnerability", "grc.vulnerable_asset"},
		OutputKind:  "finding.grc_source_integration_concentrated_open_findings",
		Severity:    "HIGH",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"grc", "graph-rule", "coordination", "prioritization"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"Multiple findings may represent duplicate upstream vulnerability records on the same integration.",
			"The source integration may be intentionally broad and owned by an active remediation program.",
		},
		Runbook:           "Review the integration owner, cluster the active findings by vulnerability and target, and drive remediation at the source integration level rather than ticketing each duplicate individually.",
		FingerprintFields: []string{"source_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
		},
	}, map[string][]string{"grc": {"integration", "vulnerability", "vulnerable_asset"}}, `MATCH (source:Entity {tenant_id: $tenant_id, entity_type: 'source'})
MATCH (source)-[:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE coalesce(finding.attributes_json, '') CONTAINS '"status":"open"'
WITH source, finding
ORDER BY finding.urn
WITH source, collect(DISTINCT finding) AS findings, count(DISTINCT finding) AS finding_count
WHERE finding_count >= $finding_threshold
RETURN source.urn AS primary_urn,
       source.label AS primary_label,
       source.entity_type AS primary_type,
       source.urn AS fingerprint_key,
       'HIGH' AS severity,
       'Source integration has ' + toString(finding_count) + ' open finding(s)' AS summary,
       'Prioritize remediation at the source integration level' AS action,
       [source.urn] AS resource_urns,
       [f IN findings[0..20] | {urn: f.urn, label: f.label, entity_type: f.entity_type, relation: 'has_finding', attributes_json: coalesce(f.attributes_json, '')}] AS evidence
ORDER BY finding_count DESC, source.urn
LIMIT $row_limit`, map[string]any{"finding_threshold": int64(coordinationGraphConcentrationMinimum)})
}

func newGRCFailingControlTestUnhealthyIntegrationRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          "grc-failing-control-test-unhealthy-integration",
		Name:        "GRC Failing Control Test On Unhealthy Integration",
		Description: "Detect failing GRC control-test evidence that belongs to an integration with disabled or errored connections.",
		SourceID:    "grc",
		EventKinds:  []string{"grc.control_test", "grc.integration"},
		OutputKind:  "finding.grc_failing_control_test_unhealthy_integration",
		Severity:    "HIGH",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"grc", "control", "integration", "graph-rule"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"The integration error count may be stale if the upstream GRC provider has not refreshed connection status yet.",
		},
		Runbook:           "Repair the unhealthy source integration, rerun the failing control test, and verify whether the control failure clears once evidence collection is healthy.",
		FingerprintFields: []string{"test_urn", "integration_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.2"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.15"},
		},
	}, map[string][]string{"grc": {"control_test", "integration"}}, `MATCH (test:Entity {tenant_id: $tenant_id, source_id: 'grc', entity_type: 'evidence'})
MATCH (test)-[:RELATION {relation: 'belongs_to'}]->(source:Entity {tenant_id: $tenant_id, entity_type: 'source'})
WHERE coalesce(test.attributes_json, '') CONTAINS '"status":"NEEDS_ATTENTION"'
  AND (coalesce(source.attributes_json, '') CONTAINS '"connection_error_count":"1"' OR coalesce(source.attributes_json, '') CONTAINS '"disabled_connection_count":"1"')
RETURN test.urn AS primary_urn,
       test.label AS primary_label,
       test.entity_type AS primary_type,
       test.urn + '|' + source.urn AS fingerprint_key,
       'HIGH' AS severity,
       'Failing control test depends on unhealthy integration ' + coalesce(source.label, source.urn) AS summary,
       'Fix the integration health before treating the control failure as authoritative' AS action,
       [test.urn, source.urn] AS resource_urns,
       [{urn: source.urn, label: source.label, entity_type: source.entity_type, relation: 'belongs_to', attributes_json: coalesce(source.attributes_json, '')}] AS evidence
ORDER BY test.urn, source.urn
LIMIT $row_limit`, nil)
}

func newGRCControlMissingEvidenceCoverageRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          "grc-control-missing-evidence-coverage",
		Name:        "GRC Control Missing Evidence Coverage",
		Description: "Detect GRC controls that have an owner but no linked control-test evidence in the graph.",
		SourceID:    "grc",
		EventKinds:  []string{"grc.control", "grc.control_test"},
		OutputKind:  "finding.grc_control_missing_evidence_coverage",
		Severity:    "MEDIUM",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"grc", "control", "evidence", "graph-rule"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"The control may be manually assessed outside Vanta or intentionally not test-backed.",
		},
		Runbook:           "Confirm whether the control should have automated or manual test evidence, then map the control test or document the accepted exception.",
		FingerprintFields: []string{"control_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC1.2"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.36"},
		},
	}, map[string][]string{"grc": {"control", "control_test"}}, `MATCH (control:Entity {tenant_id: $tenant_id, source_id: 'grc', entity_type: 'policy'})
WHERE coalesce(control.attributes_json, '') CONTAINS '"policy_type":"control"'
  AND coalesce(control.attributes_json, '') CONTAINS '"owner_id":'
  AND NOT EXISTS {
    MATCH (:Entity {tenant_id: $tenant_id, entity_type: 'evidence'})-[:RELATION {relation: 'supports'}]->(control)
  }
RETURN control.urn AS primary_urn,
       control.label AS primary_label,
       control.entity_type AS primary_type,
       control.urn AS fingerprint_key,
       'MEDIUM' AS severity,
       'Owned GRC control has no linked test evidence' AS summary,
       'Map the control to test evidence or document why it is manually assessed' AS action,
       [control.urn] AS resource_urns,
       [] AS evidence
ORDER BY control.urn
LIMIT $row_limit`, nil)
}

func newGRCDocumentNeedsOwnerOrUploadRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          "grc-document-needs-owner-or-upload",
		Name:        "GRC Document Needs Owner Or Upload",
		Description: "Detect GRC document records that still need a document upload or lack an accountable owner.",
		SourceID:    "grc",
		EventKinds:  []string{"grc.document"},
		OutputKind:  "finding.grc_document_needs_owner_or_upload",
		Severity:    "MEDIUM",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"grc", "document", "ownership", "graph-rule"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"Some document placeholders may intentionally track future evidence collection.",
		},
		Runbook:           "Assign an owner for the document, upload the missing evidence, or close the placeholder if the document is no longer required.",
		FingerprintFields: []string{"document_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC2.2"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.37"},
		},
	}, map[string][]string{"grc": {"document"}}, `MATCH (doc:Entity {tenant_id: $tenant_id, source_id: 'grc', entity_type: 'document'})
WHERE coalesce(doc.attributes_json, '') CONTAINS '"upload_status":"Needs document"'
   OR NOT (doc)-[:RELATION {relation: 'owned_by'}]->(:Entity {tenant_id: $tenant_id})
RETURN doc.urn AS primary_urn,
       doc.label AS primary_label,
       doc.entity_type AS primary_type,
       doc.urn AS fingerprint_key,
       'MEDIUM' AS severity,
       'GRC document needs upload or owner' AS summary,
       'Assign an owner and complete the missing document evidence' AS action,
       [doc.urn] AS resource_urns,
       [] AS evidence
ORDER BY doc.urn
LIMIT $row_limit`, nil)
}

func newGRCIsolatedTargetEnrichmentGapRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          "grc-isolated-target-enrichment-gap",
		Name:        "GRC Target Enrichment Gap",
		Description: "Detect GRC vulnerable-asset targets that are isolated and therefore cannot coordinate to assets, sources, vulnerabilities, or packages.",
		SourceID:    "grc",
		EventKinds:  []string{"grc.vulnerable_asset"},
		OutputKind:  "finding.grc_isolated_target_enrichment_gap",
		Severity:    "LOW",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"grc", "graph-hygiene", "enrichment", "graph-rule"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"Some upstream targets may be placeholders that intentionally lack asset, integration, or vulnerability references.",
		},
		Runbook:           "Inspect the upstream vulnerable asset payload and add host, IP, platform resource, integration, vulnerability, or package fields so the target can be coordinated.",
		FingerprintFields: []string{"target_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
		},
	}, map[string][]string{"grc": {"vulnerable_asset"}}, `MATCH (target:Entity {tenant_id: $tenant_id, source_id: 'grc', entity_type: 'grc.target'})
WHERE NOT (target)-[:RELATION]-()
RETURN target.urn AS primary_urn,
       target.label AS primary_label,
       target.entity_type AS primary_type,
       target.urn AS fingerprint_key,
       'LOW' AS severity,
       'GRC target has no graph relationships' AS summary,
       'Enrich the target with representable asset, integration, vulnerability, or package references' AS action,
       [target.urn] AS resource_urns,
       [] AS evidence
ORDER BY target.urn
LIMIT $row_limit`, nil)
}

func newFindingIsolatedOpenAnchorRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
		ID:          "finding-isolated-open-anchor",
		Name:        "Open Finding Isolated From Resources",
		Description: "Detect open finding anchors that have no graph resource relationship.",
		SourceID:    "graph",
		EventKinds:  []string{"finding"},
		OutputKind:  "finding.graph_isolated_open_finding_anchor",
		Severity:    "LOW",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"finding", "graph-hygiene", "graph-rule"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"Resolved or suppressed historical finding anchors may intentionally remain without active resource links.",
		},
		Runbook:           "Check why the rule emitted no ResourceURNs for an open finding, fix the rule projection context, or resolve stale anchors.",
		FingerprintFields: []string{"finding_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.35"},
		},
	}, nil, `MATCH (finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE NOT (finding)-[:RELATION]-()
  AND coalesce(finding.attributes_json, '') CONTAINS '"status":"open"'
RETURN finding.urn AS primary_urn,
       finding.label AS primary_label,
       finding.entity_type AS primary_type,
       finding.urn AS fingerprint_key,
       'LOW' AS severity,
       'Open finding has no graph resource anchor' AS summary,
       'Fix ResourceURN projection or resolve the stale finding anchor' AS action,
       [finding.urn] AS resource_urns,
       [] AS evidence
ORDER BY finding.urn
LIMIT $row_limit`, nil)
}

func newResourceMultipleOpenFindingsRule() Rule {
	definition := RuleDefinition{
		ID:          "graph-resource-multiple-open-findings",
		Name:        "Graph Resource Has Multiple Open Findings",
		Description: "Retired graph meta-finding retained so stale open findings auto-resolve; multiple open findings on a resource is triage context, not a standalone risk.",
		SourceID:    "graph",
		EventKinds:  []string{"finding"},
		OutputKind:  "finding.graph_resource_multiple_open_findings",
		Severity:    "INFO",
		Status:      "retired",
		Maturity:    RuleMaturityRetired,
		Tags:        []string{"finding", "coordination", "graph-rule", "prioritization", "retired", "cleanup"},
		References:  []string{"https://www.iso.org/standard/27001"},
		FalsePositives: []string{
			"Multiple findings on one resource are expected during coordinated remediation and should be modeled as case context rather than a separate finding.",
		},
		Runbook:           "Use the underlying open findings or case context as the remediation queue; this meta-finding no longer emits.",
		FingerprintFields: []string{"resource_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.7"},
		},
		Lifecycle: Lifecycle{Kind: LifecycleRetired, Anchor: AnchorNone},
	}
	return newCoordinationGraphRule(definition, nil, "", nil)
}

func newCoordinationGraphRule(definition RuleDefinition, families map[string][]string, query string, params map[string]any) Rule {
	if definition.Lifecycle.Kind == "" {
		definition.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored}
	}
	allowed := map[string]map[string]struct{}{}
	for sourceID, sourceFamilies := range families {
		sourceID = strings.ToLower(strings.TrimSpace(sourceID))
		if sourceID == "" {
			continue
		}
		allowed[sourceID] = map[string]struct{}{}
		for _, family := range sourceFamilies {
			if family = strings.ToLower(strings.TrimSpace(family)); family != "" {
				allowed[sourceID][family] = struct{}{}
			}
		}
	}
	return &coordinationGraphRule{
		definition: definition,
		sourceID:   strings.TrimSpace(definition.SourceID),
		families:   allowed,
		query:      query,
		params:     params,
	}
}

func (r *coordinationGraphRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *coordinationGraphRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *coordinationGraphRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	if len(r.families) == 0 {
		ruleSourceID := strings.ToLower(strings.TrimSpace(r.sourceID))
		return ruleSourceID == "" || sourceID == ruleSourceID
	}
	allowedFamilies, ok := r.families[sourceID]
	if !ok {
		return false
	}
	if len(allowedFamilies) == 0 {
		return true
	}
	_, ok = allowedFamilies[strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))]
	return ok
}

func (r *coordinationGraphRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *coordinationGraphRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if r == nil || runtime == nil || strings.TrimSpace(runtime.GetTenantId()) == "" {
		return ports.CypherQueryRequest{}
	}
	if r.definition.Lifecycle.Kind == LifecycleRetired {
		return ports.CypherQueryRequest{}
	}
	params := map[string]any{
		"tenant_id": strings.TrimSpace(runtime.GetTenantId()),
		"row_limit": int64(coordinationGraphRowLimit),
	}
	for key, value := range r.params {
		params[key] = value
	}
	return ports.CypherQueryRequest{Query: r.query, Params: params, RowLimit: coordinationGraphRowLimit}
}

func (r *coordinationGraphRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	if r.definition.Lifecycle.Kind == LifecycleRetired {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	findings := make([]*ports.FindingRecord, 0, len(rows))
	for _, row := range rows {
		primaryURN := cypherRowString(row, "primary_urn")
		if primaryURN == "" {
			continue
		}
		fingerprintKey := firstNonEmpty(cypherRowString(row, "fingerprint_key"), primaryURN)
		fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, fingerprintKey)
		severity := firstNonEmpty(cypherRowString(row, "severity"), r.definition.Severity)
		summary := firstNonEmpty(cypherRowString(row, "summary"), fmt.Sprintf("%s on %s", r.definition.Name, primaryURN))
		action := firstNonEmpty(cypherRowString(row, "action"), "Review the graph evidence and remediate the shared control gap.")
		resourceURNs := limitedCoordinationResourceURNs(primaryURN, coordinationRowStrings(row, "resource_urns"))
		attributes := map[string]string{
			"action":               action,
			"graph_rule":           "true",
			"graph_evidence_count": fmt.Sprintf("%d", len(cypherRowList(row, "evidence"))),
			"primary_resource_urn": primaryURN,
			"resource_label":       cypherRowString(row, "primary_label"),
			"resource_type":        cypherRowString(row, "primary_type"),
			"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		}
		for key, value := range r.definition.AttributeMap() {
			attributes["rule_"+key] = value
		}
		for key, value := range coordinationRowStringMap(row, "finding_attributes") {
			if _, exists := attributes[key]; !exists {
				attributes[key] = value
			}
		}
		trimEmptyAttributes(attributes)
		findings = append(findings, &ports.FindingRecord{
			ID:                fingerprint,
			Fingerprint:       fingerprint,
			TenantID:          tenantID,
			RuntimeID:         strings.TrimSpace(runtime.GetId()),
			RuleID:            r.definition.ID,
			Title:             r.definition.Name,
			Severity:          severity,
			Status:            r.definition.Status,
			Summary:           summary,
			ResourceURNs:      resourceURNs,
			CheckID:           r.definition.ID,
			CheckName:         r.definition.Name,
			ControlRefs:       cloneFindingControlRefs(r.definition.ControlRefs),
			GraphEvidenceRows: coordinationGraphEvidenceRows(primaryURN, cypherRowString(row, "primary_label"), cypherRowString(row, "primary_type"), row),
			Attributes:        attributes,
			FirstObservedAt:   now,
			LastObservedAt:    now,
		})
	}
	return findings, nil
}

func limitedCoordinationResourceURNs(primaryURN string, relatedURNs []string) []string {
	primaryURN = strings.TrimSpace(primaryURN)
	resourceURNs := []string{primaryURN}
	for _, relatedURN := range relatedURNs {
		relatedURN = strings.TrimSpace(relatedURN)
		if relatedURN == "" || relatedURN != primaryURN && isFindingResourceURN(relatedURN) {
			continue
		}
		resourceURNs = append(resourceURNs, relatedURN)
	}
	resourceURNs = deduplicateStrings(resourceURNs)
	limit := coordinationGraphRelatedResourceLimit + 1
	if len(resourceURNs) > limit {
		resourceURNs = resourceURNs[:limit]
	}
	return resourceURNs
}

func isFindingResourceURN(urn string) bool {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	return len(parts) >= 4 && parts[0] == "urn" && parts[1] == "cerebro" && parts[3] == "finding"
}

func coordinationRowStrings(row ports.CypherRow, key string) []string {
	values := cypherRowList(row, key)
	result := make([]string, 0, len(values))
	for _, value := range values {
		text := strings.TrimSpace(fmt.Sprintf("%v", value))
		if text != "" && text != "<nil>" {
			result = append(result, text)
		}
	}
	return result
}

func coordinationRowStringMap(row ports.CypherRow, key string) map[string]string {
	if row.Values == nil {
		return nil
	}
	value, ok := row.Values[key]
	if !ok || value == nil {
		return nil
	}
	result := map[string]string{}
	switch typed := value.(type) {
	case map[string]string:
		for key, value := range typed {
			result[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	case map[string]any:
		for key, value := range typed {
			result[strings.TrimSpace(key)] = strings.TrimSpace(fmt.Sprintf("%v", value))
		}
	default:
		return nil
	}
	trimEmptyAttributes(result)
	if len(result) == 0 {
		return nil
	}
	return result
}

func coordinationGraphEvidenceRows(primaryURN string, primaryLabel string, primaryType string, row ports.CypherRow) []*cerebrov1.GraphEvidenceRow {
	evidence := cypherRowList(row, "evidence")
	rows := make([]*cerebrov1.GraphEvidenceRow, 0, len(evidence))
	for _, item := range evidence {
		urn := cypherListMapString(item, "urn")
		if urn == "" {
			continue
		}
		label := cypherListMapString(item, "label")
		entityType := cypherListMapString(item, "entity_type")
		relation := firstNonEmpty(cypherListMapString(item, "relation"), "related_to")
		rows = append(rows, newGraphEvidenceRow("coordination_graph_evidence", map[string]string{
			"evidence_urn":   urn,
			"evidence_label": label,
			"evidence_type":  entityType,
			"relation":       relation,
		}, newGraphEvidencePath(primaryURN, primaryLabel, primaryType, relation, urn, label, entityType, edgeStringAttributes(cypherListMapString(item, "attributes_json")))))
	}
	return rows
}
