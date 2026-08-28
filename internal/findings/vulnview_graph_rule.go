package findings

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	vulnViewExternalAssetConcentratedSignalRuleID = "vulnview-external-asset-concentrated-signal"
	vulnViewGraphQueryRowLimit                    = 2000
	vulnViewGraphEvidenceLimit                    = 20
	vulnViewConcentratedEvidenceThreshold         = 5
)

type vulnViewExternalAssetConcentratedSignalRule struct {
	definition RuleDefinition
}

type vulnViewGraphEvidence struct {
	URN        string
	Label      string
	EntityType string
	Severity   string
	Signal     string
	Attributes map[string]string
}

func newVulnViewExternalAssetConcentratedSignalRule() Rule {
	return &vulnViewExternalAssetConcentratedSignalRule{definition: RuleDefinition{
		ID:          vulnViewExternalAssetConcentratedSignalRuleID,
		Name:        "VulnView External Asset Concentrated Signal",
		Description: "Aggregate VulnView graph evidence to prioritize external assets with medium-or-higher or repeated attack-surface signals.",
		SourceID:    "vulnview",
		EventKinds:  []string{"vulnview.vulnerability", "vulnview.dns_alert"},
		OutputKind:  "finding.vulnview_external_asset_concentrated_signal",
		Severity:    "dynamic",
		Status:      findingStatusOpen,
		Maturity:    "test",
		Tags:        []string{"vulnview", "graph", "attack-surface", "prioritization"},
		References:  []string{"https://owasp.org/www-project-web-security-testing-guide/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
		FalsePositives: []string{
			"External asset is intentionally exposed and covered by compensating controls.",
			"Multiple scanner signals represent duplicates for the same vulnerability instance.",
		},
		Runbook:           "Prioritize the external asset owner, validate the highest severity evidence, deduplicate repeated findings, and remediate or accept the aggregate risk.",
		FingerprintFields: []string{"asset_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
		},
		Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
	}}
}

func (r *vulnViewExternalAssetConcentratedSignalRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *vulnViewExternalAssetConcentratedSignalRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil || !strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), "vulnview") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"])) {
	case "vulnerability", "dns_alert":
		return true
	default:
		return false
	}
}

func (r *vulnViewExternalAssetConcentratedSignalRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *vulnViewExternalAssetConcentratedSignalRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil || strings.TrimSpace(runtime.GetTenantId()) == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (asset:Entity {entity_type: 'external.asset', tenant_id: $tenant_id, source_id: 'vulnview'})
MATCH (asset)-[evidence_rel:RELATION {relation: 'has_evidence', source_id: 'vulnview'}]->(evidence:Entity {tenant_id: $tenant_id, source_id: 'vulnview'})
WHERE evidence.entity_type IN ['vulnview.finding', 'vulnview.dns_alert']
WITH asset, collect({
       urn: evidence.urn,
       label: coalesce(evidence.label, ''),
       entity_type: coalesce(evidence.entity_type, ''),
       attributes_json: coalesce(evidence.attributes_json, ''),
       evidence_attributes_json: coalesce(evidence_rel.attributes_json, '')
     }) AS evidence,
     count(evidence) AS evidence_count,
     max(CASE
       WHEN toLower(coalesce(evidence.attributes_json, '')) CONTAINS '"severity":"critical"' THEN 5
       WHEN toLower(coalesce(evidence.attributes_json, '')) CONTAINS '"severity":"high"' THEN 4
       WHEN toLower(coalesce(evidence.attributes_json, '')) CONTAINS '"severity":"medium"' THEN 3
       WHEN toLower(coalesce(evidence.attributes_json, '')) CONTAINS '"severity":"moderate"' THEN 3
       WHEN toLower(coalesce(evidence.attributes_json, '')) CONTAINS '"severity":"low"' THEN 2
       WHEN toLower(coalesce(evidence.attributes_json, '')) CONTAINS '"severity":"info"' THEN 1
       WHEN toLower(coalesce(evidence.attributes_json, '')) CONTAINS '"severity":"informational"' THEN 1
       ELSE 0
     END) AS max_severity_rank
WHERE evidence_count >= $evidence_threshold OR max_severity_rank >= $severity_threshold
RETURN asset.urn AS asset_urn,
       asset.label AS asset_label,
       coalesce(asset.attributes_json, '') AS asset_attributes_json,
       evidence
ORDER BY max_severity_rank DESC, evidence_count DESC, asset.urn
LIMIT $row_limit`,
		Params: map[string]any{
			"evidence_threshold": int64(vulnViewConcentratedEvidenceThreshold),
			"row_limit":          int64(vulnViewGraphQueryRowLimit),
			"severity_threshold": int64(vulnViewSeverityRank("MEDIUM")),
			"tenant_id":          strings.TrimSpace(runtime.GetTenantId()),
		},
		RowLimit: vulnViewGraphQueryRowLimit,
	}
}

func (r *vulnViewExternalAssetConcentratedSignalRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
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
		assetURN := cypherRowString(row, "asset_urn")
		if assetURN == "" {
			continue
		}
		assetAttrs := edgeStringAttributes(cypherRowString(row, "asset_attributes_json"))
		evidence := vulnViewEvidenceFromRow(row)
		findingCount, dnsCount, maxSeverity := vulnViewEvidenceSummary(evidence)
		evidenceCount := findingCount + dnsCount
		if !vulnViewAssetSignalQualifies(evidenceCount, maxSeverity) {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, assetURN, cypherRowString(row, "asset_label"), assetAttrs, evidence, findingCount, dnsCount, maxSeverity, now))
	}
	return findings, nil
}

func vulnViewEvidenceFromRow(row ports.CypherRow) []vulnViewGraphEvidence {
	evidence := []vulnViewGraphEvidence{}
	for _, item := range cypherRowList(row, "evidence") {
		urn := cypherListMapString(item, "urn")
		entityType := cypherListMapString(item, "entity_type")
		if urn == "" || (entityType != "vulnview.finding" && entityType != "vulnview.dns_alert") {
			continue
		}
		attrs := mergeFindingAttributeMaps(
			edgeStringAttributes(cypherListMapString(item, "attributes_json")),
			edgeStringAttributes(cypherListMapString(item, "evidence_attributes_json")),
		)
		evidence = append(evidence, vulnViewGraphEvidence{
			URN:        urn,
			Label:      cypherListMapString(item, "label"),
			EntityType: entityType,
			Severity:   vulnViewNormalizeEvidenceSeverity(attrs["severity"]),
			Signal:     firstNonEmpty(attrs["template_id"], attrs["alert"], attrs["name"], attrs["external_id"]),
			Attributes: attrs,
		})
	}
	sort.Slice(evidence, func(i, j int) bool {
		leftRank := vulnViewSeverityRank(evidence[i].Severity)
		rightRank := vulnViewSeverityRank(evidence[j].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		return evidence[i].URN < evidence[j].URN
	})
	return evidence
}

func vulnViewEvidenceSummary(evidence []vulnViewGraphEvidence) (int, int, string) {
	findingCount := 0
	dnsCount := 0
	maxSeverity := ""
	for _, item := range evidence {
		switch item.EntityType {
		case "vulnview.finding":
			findingCount++
		case "vulnview.dns_alert":
			dnsCount++
		}
		if vulnViewSeverityRank(item.Severity) > vulnViewSeverityRank(maxSeverity) {
			maxSeverity = item.Severity
		}
	}
	return findingCount, dnsCount, maxSeverity
}

func vulnViewAssetSignalQualifies(evidenceCount int, maxSeverity string) bool {
	return vulnViewSeverityRank(maxSeverity) >= vulnViewSeverityRank("MEDIUM") || evidenceCount >= vulnViewConcentratedEvidenceThreshold
}

func (r *vulnViewExternalAssetConcentratedSignalRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, assetURN string, assetLabel string, assetAttrs map[string]string, evidence []vulnViewGraphEvidence, findingCount int, dnsCount int, maxSeverity string, now time.Time) *ports.FindingRecord {
	fingerprint := hashFindingFingerprint(r.definition.ID, tenantID, assetURN)
	resourceURNs := []string{assetURN}
	eventIDs := map[string]struct{}{}
	signals := map[string]struct{}{}
	graphRows := make([]*cerebrov1.GraphEvidenceRow, 0, len(evidence))
	for index, item := range evidence {
		resourceURNs = append(resourceURNs, item.URN)
		if item.Signal != "" {
			signals[item.Signal] = struct{}{}
		}
		if eventID := strings.TrimSpace(item.Attributes["event_id"]); eventID != "" {
			eventIDs[eventID] = struct{}{}
		}
		if index >= vulnViewGraphEvidenceLimit {
			continue
		}
		graphRows = append(graphRows, newGraphEvidenceRow("vulnview_asset_evidence", map[string]string{
			"asset_urn":      assetURN,
			"asset_label":    assetLabel,
			"evidence_urn":   item.URN,
			"evidence_label": item.Label,
			"evidence_type":  item.EntityType,
			"severity":       item.Severity,
			"signal":         item.Signal,
			"event_id":       item.Attributes["event_id"],
		}, newGraphEvidencePath(assetURN, assetLabel, "external.asset", "has_evidence", item.URN, item.Label, item.EntityType, compactStringMap(item.Attributes))))
	}
	signalList := sortedStringSet(signals)
	attributes := map[string]string{
		"action":                 "Prioritize external asset with concentrated VulnView evidence",
		"asset_host":             firstNonEmpty(assetAttrs["asset_id"], assetAttrs["host"], assetLabel),
		"dns_alert_count":        strconv.Itoa(dnsCount),
		"evidence_count":         strconv.Itoa(findingCount + dnsCount),
		"finding_count":          strconv.Itoa(findingCount),
		"graph_evidence_summary": fmt.Sprintf("%d VulnView finding(s), %d DNS alert(s)", findingCount, dnsCount),
		"max_severity":           maxSeverity,
		"primary_resource_urn":   assetURN,
		"resource_label":         firstNonEmpty(assetLabel, assetAttrs["asset_id"], assetURN),
		"resource_type":          "external.asset",
		"signals":                strings.Join(signalList, ","),
		"source_runtime_id":      strings.TrimSpace(runtime.GetId()),
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	label := firstNonEmpty(assetLabel, assetAttrs["asset_id"], assetURN)
	return &ports.FindingRecord{
		ID:                         fingerprint,
		Fingerprint:                fingerprint,
		TenantID:                   tenantID,
		RuntimeID:                  strings.TrimSpace(runtime.GetId()),
		RuleID:                     r.definition.ID,
		Title:                      r.definition.Name,
		Severity:                   vulnViewConcentratedSignalSeverity(maxSeverity),
		Status:                     r.definition.Status,
		Summary:                    fmt.Sprintf("VulnView external asset %s has %d correlated signal(s)", label, findingCount+dnsCount),
		ResourceURNs:               deduplicateStrings(resourceURNs),
		EventIDs:                   sortedStringSet(eventIDs),
		ObservedPolicyIDs:          signalList,
		PolicyID:                   firstNonEmpty(strings.Join(signalList, ","), assetURN),
		PolicyName:                 firstNonEmpty(strings.Join(signalList, ", "), "VulnView graph evidence"),
		CheckID:                    r.definition.ID,
		CheckName:                  r.definition.Name,
		ControlRefs:                cloneFindingControlRefs(r.definition.ControlRefs),
		FindingPersistenceEnvelope: ports.FindingPersistenceEnvelope{GraphEvidenceRows: graphRows},
		Attributes:                 attributes,
		FirstObservedAt:            now,
		LastObservedAt:             now,
	}
}

func vulnViewConcentratedSignalSeverity(maxSeverity string) string {
	if vulnViewSeverityRank(maxSeverity) >= vulnViewSeverityRank("MEDIUM") {
		return vulnViewNormalizeEvidenceSeverity(maxSeverity)
	}
	return "MEDIUM"
}

func vulnViewNormalizeEvidenceSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "info", "informational":
		return "INFO"
	default:
		return ""
	}
}

func vulnViewSeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO", "INFORMATIONAL":
		return 1
	default:
		return 0
	}
}
