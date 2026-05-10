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

var _ GraphRule = (*githubActiveWithoutOktaLinkRule)(nil)

const (
	identityGitHubActiveWithoutOktaLinkRuleID    = "identity-github-active-without-okta-link"
	identityGitHubActiveWithoutOktaLinkKind      = "finding.identity_github_active_without_okta_link"
	identityGitHubActiveWithoutOktaQueryRowLimit = 500
	// identityGitHubActiveWithoutOktaRecencyWindow scopes "still active in
	// GitHub" to recent activity. acted_on edges carry an `at` attribute
	// stamped from the audit event's OccurredAt; rows whose latest `at` is
	// older than this window, or that pre-date the at-stamping projector
	// change and have no `at` at all, are treated as stale history rather
	// than current access. Without this, a single historical commit would
	// hold the finding open indefinitely.
	identityGitHubActiveWithoutOktaRecencyWindow = 30 * 24 * time.Hour
)

// githubActiveWithoutOktaLinkRule fires when a GitHub identity is currently active
// against repositories or organization resources but has no represents_identity
// path back to an Okta user in the same tenant. Common offenders: personal
// GitHub accounts that bypass corporate SAML/SSO, accounts created before SSO
// enforcement that were never linked, or external collaborators whose
// employment was never reflected in the corporate IdP. The rule runs against
// the projected graph because no single source-event carries this information:
// it requires verifying the absence of a cross-source identity bridge.
type githubActiveWithoutOktaLinkRule struct {
	definition RuleDefinition
}

func newGitHubActiveWithoutOktaLinkRule() Rule {
	return &githubActiveWithoutOktaLinkRule{
		definition: RuleDefinition{
			ID:          identityGitHubActiveWithoutOktaLinkRuleID,
			Name:        "Active GitHub Identity With No Linked Okta Identity",
			Description: "Detect GitHub accounts acting on repositories or organization resources whose identifiers do not bridge to any Okta user in the same tenant, indicating shadow access that bypasses the corporate IdP.",
			SourceID:    "github",
			EventKinds:  []string{"github.audit", "okta.user"},
			OutputKind:  identityGitHubActiveWithoutOktaLinkKind,
			Severity:    "HIGH",
			Status:      findingStatusOpen,
			Maturity:    "test",
			Tags: []string{
				"identity",
				"shadow-access",
				"github",
				"sso-bypass",
				"graph-rule",
				"attack.t1078.004",
			},
			References: []string{
				"https://docs.github.com/en/enterprise-cloud@latest/admin/identity-and-access-management/iam-configuration-reference/saml-configuration-reference",
				"https://help.okta.com/en-us/content/topics/users-groups-profiles/usgp-user-lifecycle.htm",
			},
			FalsePositives: []string{
				"Service or automation account intentionally retained outside Okta with documented exception (e.g. break-glass, deploy bot).",
				"Recently created GitHub user observed before the next Okta inventory sync; the gap should close inside one sync cycle.",
				"External contributor not represented in the corporate IdP whose access is governed by repository-level controls.",
			},
			Runbook: "Confirm whether the GitHub account belongs to a current employee, link it to the corresponding Okta identity (or onboard the user into Okta), or remove the account's access if it is not authorized.",
			// The fingerprint is keyed on github_user_urn only. The graph
			// projector upserts github.user nodes by (tenant_id, login), so
			// the same offender produces one stable URN regardless of which
			// runtime ingested the audit event that produced the row. Adding
			// runtime_id or target_urn would split a single shadow account
			// into one finding per repo it touched.
			FingerprintFields: []string{"github_user_urn"},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
				{FrameworkName: "SOC 2", ControlID: "CC6.6"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
			},
		},
	}
}

func (r *githubActiveWithoutOktaLinkRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

// SupportsRuntime narrows graph-rule triggers to the runtime families whose
// ingest can actually change the inputs of this rule's cypher: github
// family=audit (acted_on edges from github.user) and okta family=user
// (represents_identity edges from the okta side that determine whether a link
// to github exists). Accepting unrelated github runtime families would let,
// say, github.pull_request be the first observer and pin runtime_id onto the
// persisted record, hiding the finding from `/source-runtimes/{github-audit}/findings`
// even though the audit runtime is what produced the data.
func (r *githubActiveWithoutOktaLinkRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	switch sourceID {
	case "github":
		return family == "audit"
	case "okta":
		return family == "user"
	default:
		return false
	}
}

// Evaluate is the event-driven hook required by Rule. Graph rules emit no
// findings during the per-event replay path; the graph-rule evaluator drives
// them via EvaluateRows instead.
func (r *githubActiveWithoutOktaLinkRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

// QueryFor scopes the cypher to the runtime's tenant only. The graph
// deliberately upserts every github.user node by (tenant_id, login) so audit
// runtimes share one node with merged attributes; runtime_id on github.user
// is therefore not a stable partition (the latest event wins via
// mergeGraphAttributes) and using it as a predicate would alias activity from
// one audit runtime onto another. The rule is fundamentally tenant-scoped:
// the answer to "is this GitHub identity bridged to any Okta user?" is the
// same for any github runtime in the tenant.
//
// The NOT EXISTS subquery checks whether ANY okta.user in the same tenant
// shares an identity node with the github.user. The match-type filter
// (email-only) used by the deprovisioned-okta-active rule is intentionally
// NOT applied here: this rule asks "is there *any* identity bridge?" and
// surfacing a github user that only shares a username with an okta user is
// safer to suppress than a coincidental username collision is to report. A
// tighter rule would risk flooding the queue every time a brand new external
// account showed up in the audit log.
func (r *githubActiveWithoutOktaLinkRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil {
		return ports.CypherQueryRequest{}
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		// The cypher returns one row per (github_user, target). EvaluateRows
		// applies the recency filter, the bot-account filter, and the
		// per-github-user grouping; we deliberately do not push the recency
		// check into Cypher so the filter lives in one place that has unit-
		// test coverage (the acted_on attributes JSON is opaque on Neo4j).
		Query: `MATCH (g:Entity {entity_type: 'github.user', tenant_id: $tenant_id})
       -[acted:RELATION {relation: 'acted_on'}]->(target:Entity)
WHERE NOT EXISTS {
  MATCH (g)-[:RELATION {relation: 'represents_identity'}]->(:Entity)
        <-[:RELATION {relation: 'represents_identity'}]-(o:Entity {entity_type: 'okta.user', tenant_id: $tenant_id})
}
RETURN g.urn AS github_user_urn,
       g.label AS github_user_label,
       coalesce(g.attributes_json, '') AS github_attributes_json,
       target.urn AS target_urn,
       target.entity_type AS target_entity_type,
       target.label AS target_label,
       coalesce(acted.attributes_json, '') AS acted_attributes_json
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id": tenantID,
			"row_limit": int64(identityGitHubActiveWithoutOktaQueryRowLimit),
		},
		RowLimit: identityGitHubActiveWithoutOktaQueryRowLimit,
	}
}

func (r *githubActiveWithoutOktaLinkRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now().UTC()
	groups := map[string]*githubActiveWithoutOktaGroup{}
	keys := make([]string, 0)
	for _, row := range rows {
		githubUserURN := cypherRowString(row, "github_user_urn")
		if githubUserURN == "" {
			continue
		}
		targetURN := cypherRowString(row, "target_urn")
		if targetURN == "" {
			continue
		}
		// Bot logins (dependabot[bot], github-actions[bot], renovate[bot], etc.)
		// commit and act on resources but are not real human identities. They
		// will never be in Okta by design, so emitting on them would flood
		// the queue with non-actionable findings. The check is on the github
		// user label (which the projector populates from the audit `actor`
		// field) so it sees the raw login string the audit log carried.
		githubUserLabel := cypherRowString(row, "github_user_label")
		if isGitHubBotLogin(githubUserLabel) {
			continue
		}
		// `acted_on` edges projected before the at-stamp change have no `at`,
		// and any edge whose latest action is older than the recency window
		// is stale history. Either way, this row is not evidence of current
		// GitHub access for the unlinked identity, so drop it before it can
		// pin the group open.
		if !edgeIsRecent(cypherRowString(row, "acted_attributes_json"), now, identityGitHubActiveWithoutOktaRecencyWindow) {
			continue
		}
		group, ok := groups[githubUserURN]
		if !ok {
			group = &githubActiveWithoutOktaGroup{
				githubUserURN:        githubUserURN,
				githubUserLabel:      githubUserLabel,
				githubAttributesJSON: cypherRowString(row, "github_attributes_json"),
				targets:              map[string]githubActiveWithoutOktaTarget{},
			}
			groups[githubUserURN] = group
			keys = append(keys, githubUserURN)
		}
		if _, exists := group.targets[targetURN]; exists {
			continue
		}
		group.targets[targetURN] = githubActiveWithoutOktaTarget{
			urn:        targetURN,
			entityType: cypherRowString(row, "target_entity_type"),
			label:      cypherRowString(row, "target_label"),
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.targets) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

// isGitHubBotLogin recognises the subset of GitHub login conventions that
// flag accounts as automation rather than employee identities. These never
// belong in Okta and would otherwise emit a CRITICAL-volume of false
// positives every time the audit log records a bot action.
//
// The patterns are intentionally narrow: the GitHub Apps convention reserves
// the `[bot]` suffix for App-issued identities (which is why
// `dependabot[bot]` and `github-actions[bot]` show up in audit `actor`
// fields), and the prefix list covers the well-known third-party automation
// vendors that mint GitHub-App-backed bots (Dependabot, GitHub Actions,
// Renovate, Mergify, RenovateBot via repo-scoped tokens) without sweeping in
// arbitrary user logins that happen to start with the same letters.
func isGitHubBotLogin(login string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(login))
	if trimmed == "" {
		return false
	}
	if strings.HasSuffix(trimmed, "[bot]") {
		return true
	}
	switch trimmed {
	case "dependabot", "github-actions", "renovate", "renovate-bot", "mergify", "mergify-bot":
		return true
	}
	return false
}

type githubActiveWithoutOktaGroup struct {
	githubUserURN        string
	githubUserLabel      string
	githubAttributesJSON string
	targets              map[string]githubActiveWithoutOktaTarget
}

type githubActiveWithoutOktaTarget struct {
	urn        string
	entityType string
	label      string
}

func (r *githubActiveWithoutOktaLinkRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *githubActiveWithoutOktaGroup, now time.Time) *ports.FindingRecord {
	triggeringRuntimeID := strings.TrimSpace(runtime.GetId())
	// The fingerprint is keyed on (rule, tenant, github_user) only.
	//
	//   * runtime_id is omitted because the graph projects github.user nodes
	//     by (tenant_id, login), so two github runtimes touching the same
	//     user share one node and would produce the same fingerprint anyway;
	//     including runtime_id would split a single tenant-scoped finding
	//     into duplicates the moment another github audit runtime synced.
	//     Postgres' UpsertFinding ON CONFLICT pins runtime_id to the first
	//     observer.
	//   * target_urn is omitted because one shadow account typically touches
	//     many resources; the full set of touched targets is preserved in the
	//     finding attributes for telemetry and used to compose the summary.
	fingerprint := hashFindingFingerprint(
		r.definition.ID,
		tenantID,
		group.githubUserURN,
	)
	resourceURNs := []string{group.githubUserURN}
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
	primaryGitHubLabel := firstNonEmpty(group.githubUserLabel, group.githubUserURN)
	summary := fmt.Sprintf(
		"GitHub identity %s is active in %d resource(s) but is not linked to any Okta user in this tenant",
		primaryGitHubLabel,
		len(targetURNs),
	)
	attributes := map[string]string{
		"primary_resource_urn":  group.githubUserURN,
		"github_user_urn":       group.githubUserURN,
		"github_user_label":     group.githubUserLabel,
		"target_count":          fmt.Sprintf("%d", len(targetURNs)),
		"target_urns":           strings.Join(targetURNs, ","),
		"target_labels":         strings.Join(targetLabels, ","),
		"target_entity_types":   strings.Join(sortedKeys(targetTypes), ","),
		"source_runtime_id":     triggeringRuntimeID,
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
		RuntimeID:       triggeringRuntimeID,
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
