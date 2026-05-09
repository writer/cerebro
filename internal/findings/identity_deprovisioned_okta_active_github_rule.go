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

var _ GraphRule = (*deprovisionedOktaActiveGitHubRule)(nil)

const (
	identityDeprovisionedOktaActiveGitHubRuleID = "identity-okta-deprovisioned-active-in-github"
	identityDeprovisionedOktaActiveGitHubKind   = "finding.identity_okta_deprovisioned_active_in_github"
	identityDeprovisionedOktaQueryRowLimit      = 500
)

// deprovisionedOktaActiveGitHubRule fires when an Okta user whose lifecycle status is
// deprovisioned, suspended, or otherwise inactive still resolves to an active GitHub
// account that has acted on a repository or other GitHub resource. The rule runs
// against the projected graph because no single source-event can answer this question:
// it requires joining Okta lifecycle state with GitHub audit-derived identity edges.
type deprovisionedOktaActiveGitHubRule struct {
	definition RuleDefinition
}

func newDeprovisionedOktaActiveGitHubRule() Rule {
	return &deprovisionedOktaActiveGitHubRule{
		definition: RuleDefinition{
			ID:          identityDeprovisionedOktaActiveGitHubRuleID,
			Name:        "Deprovisioned Okta Identity Still Active In GitHub",
			Description: "Detect Okta identities marked deprovisioned, suspended, or inactive whose linked GitHub account is still acting on repositories or organization resources.",
			SourceID:    "okta",
			EventKinds:  []string{"okta.user", "github.audit"},
			OutputKind:  identityDeprovisionedOktaActiveGitHubKind,
			Severity:    "CRITICAL",
			Status:      findingStatusOpen,
			Maturity:    "test",
			Tags: []string{
				"identity",
				"offboarding",
				"github",
				"graph-rule",
				"attack.t1078",
			},
			References: []string{
				"https://help.okta.com/en-us/content/topics/users-groups-profiles/usgp-user-lifecycle.htm",
				"https://docs.github.com/en/enterprise-cloud@latest/admin/identity-and-access-management/iam-configuration-reference/audit-log-events-for-your-enterprise",
			},
			FalsePositives: []string{
				"Service or break-glass account intentionally retained in GitHub during an off-boarding grace window with documented exception.",
				"Delayed Okta lifecycle propagation immediately after a status change; window typically closes within one sync cycle.",
			},
			Runbook:           "Confirm the Okta identity is truly off-boarded, revoke or suspend the linked GitHub account, rotate any tokens it created, and document the gap that allowed continued access.",
			FingerprintFields: []string{"runtime_id", "okta_user_urn", "identity_urn", "github_user_urn"},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
				{FrameworkName: "HIPAA", ControlID: "164.308(a)(3)(ii)(C)"},
			},
		},
	}
}

func (r *deprovisionedOktaActiveGitHubRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *deprovisionedOktaActiveGitHubRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), r.definition.SourceID)
}

// Evaluate is the event-driven hook required by Rule. Graph rules emit no findings during the
// per-event replay path; the graph-rule evaluator drives them via EvaluateRows instead.
func (r *deprovisionedOktaActiveGitHubRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *deprovisionedOktaActiveGitHubRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil {
		return ports.CypherQueryRequest{}
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	if tenantID == "" || runtimeID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: `MATCH (o:Entity {entity_type: 'okta.user', tenant_id: $tenant_id})
       -[oi:RELATION {relation: 'represents_identity'}]->(id:Entity)
       <-[gi:RELATION {relation: 'represents_identity'}]-(g:Entity {entity_type: 'github.user', tenant_id: $tenant_id})
       -[acted:RELATION {relation: 'acted_on'}]->(target:Entity)
WHERE coalesce(o.attributes_json, '') CONTAINS $okta_runtime_marker
  AND (toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"DEPROVISIONED"'
       OR toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"SUSPENDED"'
       OR toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"INACTIVE"')
RETURN o.urn AS okta_user_urn,
       o.label AS okta_user_label,
       coalesce(o.attributes_json, '') AS okta_attributes_json,
       id.urn AS identity_urn,
       id.label AS identity_label,
       g.urn AS github_user_urn,
       g.label AS github_user_label,
       target.urn AS target_urn,
       target.entity_type AS target_entity_type,
       target.label AS target_label,
       coalesce(acted.attributes_json, '') AS acted_attributes_json
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id":           tenantID,
			"okta_runtime_marker": fmt.Sprintf("%q:%q", "source_runtime_id", runtimeID),
			"row_limit":           int64(identityDeprovisionedOktaQueryRowLimit),
		},
		RowLimit: identityDeprovisionedOktaQueryRowLimit,
	}
}

func (r *deprovisionedOktaActiveGitHubRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*deprovisionedOktaGroup{}
	keys := make([]string, 0)
	for _, row := range rows {
		oktaUserURN := cypherRowString(row, "okta_user_urn")
		identityURN := cypherRowString(row, "identity_urn")
		githubUserURN := cypherRowString(row, "github_user_urn")
		if oktaUserURN == "" || identityURN == "" || githubUserURN == "" {
			continue
		}
		key := oktaUserURN + "\x00" + identityURN + "\x00" + githubUserURN
		group, ok := groups[key]
		if !ok {
			group = &deprovisionedOktaGroup{
				oktaUserURN:        oktaUserURN,
				oktaUserLabel:      cypherRowString(row, "okta_user_label"),
				oktaAttributesJSON: cypherRowString(row, "okta_attributes_json"),
				identityURN:        identityURN,
				identityLabel:      cypherRowString(row, "identity_label"),
				githubUserURN:      githubUserURN,
				githubUserLabel:    cypherRowString(row, "github_user_label"),
				targets:            map[string]deprovisionedOktaTarget{},
			}
			groups[key] = group
			keys = append(keys, key)
		}
		targetURN := cypherRowString(row, "target_urn")
		if targetURN == "" {
			continue
		}
		if _, exists := group.targets[targetURN]; exists {
			continue
		}
		group.targets[targetURN] = deprovisionedOktaTarget{
			urn:        targetURN,
			entityType: cypherRowString(row, "target_entity_type"),
			label:      cypherRowString(row, "target_label"),
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

type deprovisionedOktaGroup struct {
	oktaUserURN        string
	oktaUserLabel      string
	oktaAttributesJSON string
	identityURN        string
	identityLabel      string
	githubUserURN      string
	githubUserLabel    string
	targets            map[string]deprovisionedOktaTarget
}

type deprovisionedOktaTarget struct {
	urn        string
	entityType string
	label      string
}

func (r *deprovisionedOktaActiveGitHubRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *deprovisionedOktaGroup, now time.Time) *ports.FindingRecord {
	runtimeID := strings.TrimSpace(runtime.GetId())
	fingerprint := hashFindingFingerprint(
		r.definition.ID,
		tenantID,
		runtimeID,
		group.oktaUserURN,
		group.identityURN,
		group.githubUserURN,
	)
	resourceURNs := []string{group.identityURN, group.oktaUserURN, group.githubUserURN}
	targetURNs := make([]string, 0, len(group.targets))
	targetLabels := make([]string, 0, len(group.targets))
	targetTypes := make(map[string]struct{}, len(group.targets))
	for urn, target := range group.targets {
		targetURNs = append(targetURNs, urn)
		if trimmed := strings.TrimSpace(target.label); trimmed != "" {
			targetLabels = append(targetLabels, trimmed)
		}
		if trimmed := strings.TrimSpace(target.entityType); trimmed != "" {
			targetTypes[trimmed] = struct{}{}
		}
	}
	sort.Strings(targetURNs)
	sort.Strings(targetLabels)
	resourceURNs = append(resourceURNs, targetURNs...)
	identityLabel := firstNonEmpty(group.identityLabel, group.oktaUserLabel, group.githubUserLabel, "identity")
	summary := fmt.Sprintf(
		"Deprovisioned Okta identity %s remains active in GitHub as %s and has acted on %d resource(s)",
		identityLabel,
		firstNonEmpty(group.githubUserLabel, group.githubUserURN),
		len(targetURNs),
	)
	attributes := map[string]string{
		"primary_resource_urn":  group.identityURN,
		"identity_urn":          group.identityURN,
		"identity_label":        group.identityLabel,
		"okta_user_urn":         group.oktaUserURN,
		"okta_user_label":       group.oktaUserLabel,
		"okta_status":           extractOktaStatus(group.oktaAttributesJSON),
		"github_user_urn":       group.githubUserURN,
		"github_user_label":     group.githubUserLabel,
		"target_count":          fmt.Sprintf("%d", len(targetURNs)),
		"target_urns":           strings.Join(targetURNs, ","),
		"target_labels":         strings.Join(targetLabels, ","),
		"target_entity_types":   strings.Join(sortedKeys(targetTypes), ","),
		"source_runtime_id":     runtimeID,
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
		RuntimeID:       runtimeID,
		RuleID:          r.definition.ID,
		Title:           r.definition.Name,
		Severity:        r.definition.Severity,
		Status:          r.definition.Status,
		Summary:         summary,
		ResourceURNs:    deduplicateStrings(resourceURNs),
		ControlRefs:     cloneFindingControlRefs(r.definition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: now,
		LastObservedAt:  now,
		CheckID:         r.definition.ID,
		CheckName:       r.definition.Name,
	}
}

func extractOktaStatus(attributesJSON string) string {
	if attributesJSON == "" {
		return ""
	}
	upper := strings.ToUpper(attributesJSON)
	for _, status := range []string{"DEPROVISIONED", "SUSPENDED", "INACTIVE"} {
		if strings.Contains(upper, "\"STATUS\":\""+status+"\"") {
			return status
		}
	}
	return ""
}

func cypherRowString(row ports.CypherRow, key string) string {
	if row.Values == nil {
		return ""
	}
	value, ok := row.Values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func deduplicateStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
