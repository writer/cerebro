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

var _ GraphRule = (*deprovisionedOktaActiveGitHubRule)(nil)

const (
	identityDeprovisionedOktaActiveGitHubRuleID = "identity-okta-deprovisioned-active-in-github"
	identityDeprovisionedOktaActiveGitHubKind   = "finding.identity_okta_deprovisioned_active_in_github"
	identityDeprovisionedOktaQueryRowLimit      = 500
	// identityDeprovisionedOktaRecencyWindow scopes "still active in GitHub" to
	// recent activity. acted_on edges carry an `at` attribute populated from the
	// audit event's OccurredAt; rows whose latest `at` is older than this window,
	// or that pre-date the at-stamping projector change and have no `at` at all,
	// are treated as stale history rather than current access. This prevents a
	// single pre-offboarding action from holding the finding open indefinitely.
	identityDeprovisionedOktaRecencyWindow = 30 * 24 * time.Hour
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
			Runbook: "Confirm the Okta identity is truly off-boarded, revoke or suspend the linked GitHub account, rotate any tokens it created, and document the gap that allowed continued access.",
			// The fingerprint is (okta_user, github_user) only. The graph projector attaches the same
			// account pair to multiple `identity` nodes when okta.user has distinct email and login,
			// or when github.audit links both `actor` and `external_identity_nameid`; including
			// identity_urn in the fingerprint would split one offboarding gap into two CRITICAL
			// findings that differ only by which identity node the join walked through. The full
			// list of matched identity URNs is preserved in the finding attributes for telemetry.
			FingerprintFields: []string{"okta_user_urn", "github_user_urn"},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
				{FrameworkName: "HIPAA", ControlID: "164.308(a)(3)(ii)(C)"},
			},
			Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
		},
	}
}

func (r *deprovisionedOktaActiveGitHubRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

// SupportsRuntime narrows graph-rule triggers to the runtime families whose ingest can
// actually change the inputs of this rule's cypher: okta family=user (lifecycle status
// on okta.user nodes) and github family=audit (acted_on edges from github.user).
//
// Source runtimes within a single source_id are family-scoped (e.g. github.audit,
// github.pull_request, github.dependabot_alert; okta.user, okta.audit, okta.group_membership)
// and only the families above touch the data this rule reads. Accepting every runtime
// in the family would let, say, a github.pull_request ingest be the first trigger that
// observes an existing offender — buildFinding would then stamp that pull-request runtime
// onto the persisted record and Postgres' UpsertFinding ON CONFLICT would pin it there,
// hiding the finding from `/source-runtimes/{github-audit}/findings` even though the audit
// runtime is what produced the data and is what an investigator would inspect.
func (r *deprovisionedOktaActiveGitHubRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	switch sourceID {
	case "okta":
		return family == "user"
	case "github":
		return family == "audit"
	default:
		return false
	}
}

// Evaluate is the event-driven hook required by Rule. Graph rules emit no findings during the
// per-event replay path; the graph-rule evaluator drives them via EvaluateRows instead.
func (r *deprovisionedOktaActiveGitHubRule) Evaluate(_ context.Context, _ *cerebrov1.SourceRuntime, _ *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

// QueryFor scopes the cypher to the runtime's tenant only. The graph deliberately upserts
// every okta.user node by `(tenant_id, user_id)` so inventory and audit runtimes share one
// node with merged attributes; runtime_id on okta.user is therefore not a stable partition
// (the latest event wins via mergeGraphAttributes) and using it as a predicate would alias
// inventory-derived `status` onto the audit runtime that touched the node last. The rule is
// fundamentally tenant-scoped: the answer to "is this deprovisioned okta identity still
// active in github?" is the same for any okta runtime in the tenant.
func (r *deprovisionedOktaActiveGitHubRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil {
		return ports.CypherQueryRequest{}
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		// The cypher returns one row per (okta_user, identity, github_user, target);
		// EvaluateRows applies the recency filter and grouping. We deliberately do
		// not push the recency check into Cypher so we can keep the filter in one
		// place and have unit-test coverage on it (the represents_identity attrs
		// JSON is opaque on the Neo4j side).
		Query: `MATCH (o:Entity {entity_type: 'okta.user', tenant_id: $tenant_id})
       -[oi:RELATION {relation: 'represents_identity'}]->(id:Entity)
       <-[gi:RELATION {relation: 'represents_identity'}]-(g:Entity {entity_type: 'github.user', tenant_id: $tenant_id})
       -[acted:RELATION {relation: 'acted_on'}]->(target:Entity)
WHERE toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"DEPROVISIONED"'
   OR toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"SUSPENDED"'
   OR toUpper(coalesce(o.attributes_json, '')) CONTAINS '"STATUS":"INACTIVE"'
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
       coalesce(acted.attributes_json, '') AS acted_attributes_json,
       coalesce(oi.attributes_json, '') AS okta_identity_attributes_json,
       coalesce(gi.attributes_json, '') AS github_identity_attributes_json
LIMIT $row_limit`,
		Params: map[string]any{
			"tenant_id": tenantID,
			"row_limit": int64(identityDeprovisionedOktaQueryRowLimit),
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
		targetURN := cypherRowString(row, "target_urn")
		if targetURN == "" {
			continue
		}
		// `acted_on` edges projected before the at-stamp change have no `at`,
		// and any edge whose latest action is older than the recency window is
		// stale history. Either way, this row is not evidence of current GitHub
		// access for the deprovisioned identity, so drop it before it can pin
		// the group open.
		if !edgeIsRecent(cypherRowString(row, "acted_attributes_json"), now, identityDeprovisionedOktaRecencyWindow) {
			continue
		}
		// represents_identity edges are upsert-only — graph ingest never retracts
		// them when an Okta email/login or GitHub external_identity_nameid is
		// renamed. After a rename, both the okta.user and the github.user remain
		// linked to the stale identity node, and a join through that node would
		// keep emitting (or reopening) findings even though the current Okta and
		// GitHub identifiers no longer match. Each represents_identity edge
		// therefore carries an `at` attribute that the latest source event
		// re-asserted (chronological max under the neo4j store's mergeAttribute
		// rule); rows whose okta-side OR github-side identifier link has not
		// been re-observed inside the recency window are treated as stale and
		// dropped, mirroring the acted_on check.
		oktaIdentityJSON := cypherRowString(row, "okta_identity_attributes_json")
		githubIdentityJSON := cypherRowString(row, "github_identity_attributes_json")
		if !edgeIsRecent(oktaIdentityJSON, now, identityDeprovisionedOktaRecencyWindow) {
			continue
		}
		if !edgeIsRecent(githubIdentityJSON, now, identityDeprovisionedOktaRecencyWindow) {
			continue
		}
		// Reject login-only identity matches on either side. The projector
		// emits a represents_identity edge for every identifier value, including
		// raw GitHub usernames where identifierEvidenceAttributes assigns
		// match_type=login at confidence=0.60. Two unrelated people who happen
		// to share a username (e.g. okta login "alice" vs github login "alice")
		// would otherwise satisfy the join through the shared identity:login
		// node and produce a CRITICAL false positive. Require the match on both
		// sides to be email-based (exact_email or extracted_email, both 0.85+),
		// which is what guarantees the accounts belong to the same person.
		if !identifierMatchIsEmail(oktaIdentityJSON) || !identifierMatchIsEmail(githubIdentityJSON) {
			continue
		}
		// Group on the Okta/GitHub account pair only. The cypher join can walk
		// through multiple `identity` nodes for the same pair (okta.user links
		// both email and login when they differ; github.audit links both `actor`
		// and `external_identity_nameid`), so keying on identityURN here would
		// split one offboarding gap into duplicate findings. The full set of
		// identity URNs matched for this pair is preserved on the group so we
		// can surface it as telemetry on the finding.
		key := oktaUserURN + "\x00" + githubUserURN
		group, ok := groups[key]
		if !ok {
			group = &deprovisionedOktaGroup{
				oktaUserURN:        oktaUserURN,
				oktaUserLabel:      cypherRowString(row, "okta_user_label"),
				oktaAttributesJSON: cypherRowString(row, "okta_attributes_json"),
				githubUserURN:      githubUserURN,
				githubUserLabel:    cypherRowString(row, "github_user_label"),
				identityURNs:       map[string]struct{}{},
				identityLabels:     map[string]struct{}{},
				targets:            map[string]deprovisionedOktaTarget{},
			}
			groups[key] = group
			keys = append(keys, key)
		}
		group.identityURNs[identityURN] = struct{}{}
		if label := cypherRowString(row, "identity_label"); label != "" {
			group.identityLabels[label] = struct{}{}
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
		if group == nil || len(group.targets) == 0 {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

// identifierMatchIsEmail decides whether a represents_identity edge proves
// account ownership rather than just a coincidental identifier overlap.
//
// The projector (see identifierEvidenceAttributes) emits a represents_identity
// edge for every identifier value it observes, including raw GitHub usernames
// where match_type=login is stamped at confidence=0.60. That signal is enough
// to surface the link in the graph, but it is not enough to fuse two accounts:
// two unrelated people can both pick the username "alice", and a login-walked
// join `(okta.user)-[oi]->(identity:login:alice)<-[gi]-(github.user)` would
// then satisfy this rule's cypher and emit a CRITICAL finding against an
// unrelated GitHub account.
//
// Email-based matches (exact_email at 0.95, extracted_email at 0.85) are the
// only identifier signals we accept here: they require the projector to have
// observed a real email address on each side, which in practice does not
// collide across people the way usernames do. Empty/malformed JSON, missing
// match_type, and any non-email value (including login) all return false so
// the rule refuses to fire on weak identity evidence.
func identifierMatchIsEmail(attributesJSON string) bool {
	trimmed := strings.TrimSpace(attributesJSON)
	if trimmed == "" {
		return false
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(trimmed), &attrs); err != nil {
		return false
	}
	switch strings.TrimSpace(attrs["match_type"]) {
	case "exact_email", "extracted_email":
		return true
	default:
		return false
	}
}

// edgeIsRecent decides whether a graph edge has been re-observed inside the
// recency window. Edge attributes are JSON-encoded by the projector and carry
// an `at` attribute (RFC3339 UTC) populated from each source event's OccurredAt;
// the neo4j store's mergeAttributeValue keeps the chronological max so the field
// reflects the latest re-assertion of the edge regardless of ingestion order.
//
// Edges projected before the at-stamping change have no `at` at all and are
// treated identically to stale: we cannot prove recency, so we refuse to fire
// on them. The same helper is used for both `acted_on` (current GitHub access)
// and `represents_identity` (current identifier link); the rule must require
// all three relations along the path to be recent so a pre-rename identifier
// graph cannot keep emitting findings indefinitely.
func edgeIsRecent(attributesJSON string, now time.Time, window time.Duration) bool {
	trimmed := strings.TrimSpace(attributesJSON)
	if trimmed == "" {
		return false
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(trimmed), &attrs); err != nil {
		return false
	}
	raw := strings.TrimSpace(attrs["at"])
	if raw == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return now.UTC().Sub(parsed.UTC()) <= window
}

type deprovisionedOktaGroup struct {
	oktaUserURN        string
	oktaUserLabel      string
	oktaAttributesJSON string
	githubUserURN      string
	githubUserLabel    string
	identityURNs       map[string]struct{}
	identityLabels     map[string]struct{}
	targets            map[string]deprovisionedOktaTarget
}

type deprovisionedOktaTarget struct {
	urn        string
	entityType string
	label      string
}

func (r *deprovisionedOktaActiveGitHubRule) buildFinding(runtime *cerebrov1.SourceRuntime, tenantID string, group *deprovisionedOktaGroup, now time.Time) *ports.FindingRecord {
	triggeringRuntimeID := strings.TrimSpace(runtime.GetId())
	// The fingerprint is keyed on (rule, tenant, okta_user, github_user) only.
	//
	//   * runtime_id is omitted because the graph projects okta.user nodes by
	//     (tenant_id, user_id), so two okta runtimes touching the same user share
	//     one node and would produce the same fingerprint anyway; including
	//     runtime_id would split a single tenant-scoped finding into duplicates
	//     the moment another okta runtime synced. The same fingerprint can be
	//     emitted by either an okta or a github trigger, so Postgres'
	//     UpsertFinding (`runtime_id = findings.runtime_id`) pins runtime_id to
	//     the first observer and keeps the row addressable through runtime APIs.
	//   * identity_urn is omitted because the projector links the same Okta/GitHub
	//     account pair to multiple `identity` nodes (email + login when they
	//     differ on okta.user, actor + external_identity_nameid on github.audit).
	//     Including identity_urn would split one offboarding gap into two
	//     CRITICAL findings for the same account pair.
	fingerprint := hashFindingFingerprint(
		r.definition.ID,
		tenantID,
		group.oktaUserURN,
		group.githubUserURN,
	)
	identityURNs := sortedKeys(group.identityURNs)
	identityLabels := sortedKeys(group.identityLabels)
	resourceURNs := []string{group.oktaUserURN, group.githubUserURN}
	resourceURNs = append(resourceURNs, identityURNs...)
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
	primaryIdentityLabel := firstNonEmpty(append(append([]string{}, identityLabels...), group.oktaUserLabel, group.githubUserLabel, "identity")...)
	summary := fmt.Sprintf(
		"Deprovisioned Okta identity %s remains active in GitHub as %s and has acted on %d resource(s)",
		primaryIdentityLabel,
		firstNonEmpty(group.githubUserLabel, group.githubUserURN),
		len(targetURNs),
	)
	attributes := map[string]string{
		"primary_resource_urn":  group.oktaUserURN,
		"identity_urns":         strings.Join(identityURNs, ","),
		"identity_labels":       strings.Join(identityLabels, ","),
		"okta_user_urn":         group.oktaUserURN,
		"okta_user_label":       group.oktaUserLabel,
		"okta_status":           extractOktaStatus(group.oktaAttributesJSON),
		"github_user_urn":       group.githubUserURN,
		"github_user_label":     group.githubUserLabel,
		"target_count":          fmt.Sprintf("%d", len(targetURNs)),
		"target_urns":           strings.Join(targetURNs, ","),
		"target_labels":         strings.Join(targetLabels, ","),
		"target_entity_types":   strings.Join(sortedKeys(targetTypes), ","),
		"graph_actions_allowed": "identity.okta.suspend_user,identity.okta.unsuspend_user",
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
