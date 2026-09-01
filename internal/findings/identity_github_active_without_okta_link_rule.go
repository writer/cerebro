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
			Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
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
// The cypher returns ONE row per github user. Both the acted_on targets and
// the candidate represents_identity bridges are collapsed into list-typed
// columns via collect(). EvaluateRows then applies the bridge-recency check
// and the acted_on recency filter on the per-row lists. The match-type
// filter (email-only) used by the deprovisioned-okta-active rule is
// intentionally NOT applied here: this rule asks "is there *any* fresh
// identity bridge?" and surfacing a github user that only shares a username
// with an okta user is safer to suppress than a coincidental username
// collision is to report as HIGH. A tighter rule would risk flooding the
// queue every time a brand new external account showed up in the audit log.
//
// We deliberately do NOT use a NOT EXISTS subquery to express the absence
// check: represents_identity edges are upsert-only and never retracted when
// an Okta login/email or GitHub external_identity_nameid is renamed, so a
// stale historical bridge would satisfy NOT EXISTS forever and silently
// suppress this finding even after the live identity link is gone. The
// projector therefore stamps every represents_identity edge with an `at`
// attribute, and EvaluateRows rejects bridges whose `at` is outside the
// recency window so a stale bridge cannot mask current shadow access.
//
// One-row-per-github-user is also a hard requirement for the row limit: a
// naive (g, target) × candidate-bridge fan-out can consume the entire
// $row_limit budget on a single prolific account or a user with multiple
// historical email/login renames, pushing every other shadow github user
// out of the result set so their findings silently never emit. The graph
// store does not page truncated reads, only flags them, so collapsing the
// fan-out at the cypher layer is the only safe way to keep the rule
// scaling beyond the few-hundred-account regime.
func (r *githubActiveWithoutOktaLinkRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil {
		return ports.CypherQueryRequest{}
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	if tenantID == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		// One row per github user. `targets` carries the collapsed
		// list of acted_on targets (with the per-edge attributes
		// JSON for the recency check), and `bridges` carries the
		// collapsed list of candidate represents_identity bridges,
		// each preserving the pairing between the github-side and
		// okta-side edge attributes. EvaluateRows iterates both
		// lists; we deliberately keep the recency check in Go so
		// the at-attribute parser lives in one place with unit-test
		// coverage (the attributes_json values are opaque on Neo4j
		// pre-5.x without apoc).
		//
		// The leading `WHERE NOT EXISTS { ... github.org ... }` clause
		// suppresses pre-fix phantom `github.user:<org>` nodes that
		// were minted before the projector started routing
		// `actor_type=Organization` / `actor_id == org_id` events
		// through `github.org`. Those phantoms carry no `actor_type`
		// on their `attributes_json` (the audit-actor resolver did
		// not run on actor_id-stamped rows on the pre-fix code path)
		// and would never re-stamp after the projector fix because
		// every new org-self event now lands on the `github.org` node
		// instead. Filtering by label-overlap with the tenant's
		// `github.org` set excludes them at the cypher layer so they
		// cannot reach EvaluateRows. The match is case-insensitive
		// to defend against the GitHub username/org-slug case-folding
		// rule (`writer` vs `Writer` vs `WriterInternal` all surface
		// in audit logs in their original casing). We keep the
		// node-side `actor_type=Organization` branch in
		// `githubActorIsAutomation` as defense in depth in case a
		// future projector change ever re-stamps the phantom node.
		Query: `MATCH (g:Entity {entity_type: 'github.user', tenant_id: $tenant_id})
WHERE NOT EXISTS {
  MATCH (org:Entity {entity_type: 'github.org', tenant_id: $tenant_id})
  WHERE toLower(coalesce(org.label, '')) = toLower(coalesce(g.label, ''))
}
MATCH (g)-[acted:RELATION {relation: 'acted_on'}]->(target:Entity)
WITH g, collect(DISTINCT {
       urn: target.urn,
       entity_type: coalesce(target.entity_type, ''),
       label: coalesce(target.label, ''),
       attributes_json: coalesce(target.attributes_json, ''),
       acted_attributes_json: coalesce(acted.attributes_json, '')
     }) AS targets
OPTIONAL MATCH (g)-[gi:RELATION {relation: 'represents_identity'}]->(identity:Entity)
              <-[oi:RELATION {relation: 'represents_identity'}]-(okta:Entity {entity_type: 'okta.user', tenant_id: $tenant_id})
WITH g, targets, collect({
       identity_urn: coalesce(identity.urn, ''),
       identity_label: coalesce(identity.label, ''),
       okta_urn: coalesce(okta.urn, ''),
       okta_label: coalesce(okta.label, ''),
       github_identity_attributes_json: coalesce(gi.attributes_json, ''),
       okta_identity_attributes_json:   coalesce(oi.attributes_json, '')
     }) AS bridges
RETURN g.urn AS github_user_urn,
       g.label AS github_user_label,
       coalesce(g.attributes_json, '') AS github_attributes_json,
       targets,
       bridges
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
		// Suppress automation actors using the GitHub-stamped schema flags
		// the source projector forwards onto every github.user node:
		//
		//   * actor_is_bot=true is GitHub's own classification for GitHub App
		//     identities (the `<vendor>[bot]` accounts that surface in audit
		//     `actor` fields — dependabot[bot], github-actions[bot],
		//     renovate[bot], coderabbitai[bot], factory-droid[bot], etc.).
		//   * actor_is_agent=true covers fine-grained PAT / installation-token
		//     agent actions that GitHub categorises as automated.
		//
		// These accounts will never be in Okta by design; emitting on them
		// would flood the queue with non-actionable findings. Trusting the
		// schema avoids the maintenance burden of a hand-maintained vendor
		// allowlist (every new GitHub App vendor would otherwise require a
		// code change) and stays correct as the audit log API gains new
		// classifications.
		//
		// The complementary org-as-actor pattern (audit events whose
		// `actor_id == org_id`, e.g. `integration_installation.version_updated`
		// system events) is filtered at the projector layer by routing the
		// `acted_on` edge from the github.org node instead of minting a
		// `github.user:<org>` shadow node, so this rule never sees those rows.
		githubUserLabel := cypherRowString(row, "github_user_label")
		githubAttributesJSON := cypherRowString(row, "github_attributes_json")
		if githubActorIsAutomation(githubAttributesJSON) {
			continue
		}
		// Defense in depth for phantom github.user nodes whose
		// `attributes_json` was projected before audit.go always
		// resolved the actor (so the node carries no `actor_type`),
		// but whose `acted_on` edges have since been re-stamped by
		// the v2.1.14+ projector. The projector writes `actor_type`
		// onto every `acted_on` edge it merges, so a recent
		// edge-side automation classification is a reliable signal
		// that the user is non-linkable even when the node-side
		// blob has not yet caught up (mergeGraphAttributes is
		// latest-wins per-key, so the node IS supposed to converge
		// on the same value — but a single early evaluation cycle
		// after a fresh audit ingest can run before the per-key
		// merge has rotated the node blob, especially when the
		// graph rule eval immediately follows source ingest in the
		// same orchestrator iteration). We keep this check after
		// the node-level check so that the cheaper, single-blob
		// classification still short-circuits before we touch the
		// per-target list.
		if githubRecentEdgeMarksAutomation(cypherRowList(row, "targets"), now, identityGitHubActiveWithoutOktaRecencyWindow) {
			continue
		}
		// The cypher emits one row per github user; rows for the same
		// user across multiple bounded rule reads are an unusual
		// case (it can happen if the Go-side caller composes more than
		// one read), but we still merge defensively into the same
		// group so the recency contract holds regardless of arrival
		// shape.
		group, ok := groups[githubUserURN]
		if !ok {
			group = &githubActiveWithoutOktaGroup{
				githubUserURN:        githubUserURN,
				githubUserLabel:      githubUserLabel,
				githubAttributesJSON: githubAttributesJSON,
				targets:              map[string]githubActiveWithoutOktaTarget{},
			}
			groups[githubUserURN] = group
			keys = append(keys, githubUserURN)
		}
		// represents_identity edges are upsert-only — graph ingest never
		// retracts them when an Okta email/login or GitHub
		// external_identity_nameid is renamed. A bridge whose okta-side AND
		// github-side identifier links have BOTH been re-observed inside
		// the recency window is evidence of a current bridge. Exact-email
		// GitHub SAML bridges are also durable as long as the Okta email side
		// is fresh: GitHub audit often omits external identity fields on
		// subsequent git.fetch/git.clone activity, but a stamped exact email
		// link to a currently projected Okta email still proves the account is
		// linkable through corporate identity.
		//
		// We must check the pairing on the SAME bridge candidate: a
		// fresh github-side edge on bridge A combined with a fresh
		// okta-side edge on bridge B (a different identity node) is two
		// stale renamed bridges, not one current bridge.
		for _, bridge := range cypherRowList(row, "bridges") {
			githubIdentityJSON := cypherListMapString(bridge, "github_identity_attributes_json")
			oktaIdentityJSON := cypherListMapString(bridge, "okta_identity_attributes_json")
			if githubBridgeProvesCurrentOktaLink(githubIdentityJSON, oktaIdentityJSON, now) {
				group.hasCurrentBridge = true
				break
			}
			group.bridgeClues = append(group.bridgeClues, githubBridgeClueFromCypher(bridge, githubIdentityJSON, oktaIdentityJSON))
		}
		// `acted_on` edges projected before the at-stamp change have no
		// `at`, and any edge whose latest action is older than the recency
		// window is stale history. Either way, that target is not evidence
		// of current GitHub access for the unlinked identity, so we skip
		// it. The targets list is collected from cypher; iterating it here
		// gives one O(n) pass with the same semantics as the previous
		// row-per-target form.
		for _, target := range cypherRowList(row, "targets") {
			actedAttributesJSON := cypherListMapString(target, "acted_attributes_json")
			if !edgeIsRecent(actedAttributesJSON, now, identityGitHubActiveWithoutOktaRecencyWindow) {
				continue
			}
			if !githubActedOnIsCurrentAccessEvidence(actedAttributesJSON) {
				continue
			}
			targetURN := strings.TrimSpace(cypherListMapString(target, "urn"))
			if targetURN == "" {
				continue
			}
			if _, exists := group.targets[targetURN]; exists {
				continue
			}
			actedAttrs := edgeStringAttributes(actedAttributesJSON)
			targetAttrs := edgeStringAttributes(cypherListMapString(target, "attributes_json"))
			group.targets[targetURN] = githubActiveWithoutOktaTarget{
				urn:        targetURN,
				entityType: cypherListMapString(target, "entity_type"),
				label:      cypherListMapString(target, "label"),
				action:     actedAttrs["action"],
				accessedAt: actedAttrs["at"],
				eventID:    actedAttrs["event_id"],
				attributes: targetAttrs,
				edgeAttrs:  actedAttrs,
			}
		}
	}
	sort.Strings(keys)
	findings := make([]*ports.FindingRecord, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		if group == nil || len(group.targets) == 0 {
			continue
		}
		// A current cross-source bridge proves the github user is
		// linked to an okta user; the rule's premise (shadow access)
		// no longer applies, so suppress the finding even if the
		// group accumulated targets. Non-current bridges leave
		// hasCurrentBridge=false and the group emits as expected.
		if group.hasCurrentBridge {
			continue
		}
		findings = append(findings, r.buildFinding(runtime, tenantID, group, now))
	}
	return findings, nil
}

// cypherRowList extracts a list-typed cypher result column. The Neo4j Go
// driver returns `collect(...)` results as `[]any` whose elements are
// scalars, maps, or nested lists depending on the projected expression.
// Returns nil for missing or non-list columns so callers can range over the
// result safely without nil checks.
func cypherRowList(row ports.CypherRow, key string) []any {
	if row.Values == nil {
		return nil
	}
	value, ok := row.Values[key]
	if !ok || value == nil {
		return nil
	}
	if list, ok := value.([]any); ok {
		return list
	}
	return nil
}

// cypherListMapString reads a string field from a map literal element of a
// collected cypher list. Map literal projections (`collect({a: ..., b: ...})`)
// come back as `map[string]any` from the Neo4j Go driver. The trim mirrors
// cypherRowString so empty / whitespace-only attributes_json values feed
// edgeIsRecent the way the row-shaped path used to.
func cypherListMapString(item any, key string) string {
	m, ok := item.(map[string]any)
	if !ok {
		return ""
	}
	value, ok := m[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func githubBridgeProvesCurrentOktaLink(githubIdentityJSON string, oktaIdentityJSON string, now time.Time) bool {
	if edgeIsRecent(githubIdentityJSON, now, identityGitHubActiveWithoutOktaRecencyWindow) &&
		edgeIsRecent(oktaIdentityJSON, now, identityGitHubActiveWithoutOktaRecencyWindow) {
		return true
	}
	oktaAttrs := edgeStringAttributes(oktaIdentityJSON)
	if !edgeIsRecent(oktaIdentityJSON, now, identityGitHubActiveWithoutOktaRecencyWindow) {
		return false
	}
	githubAttrs := edgeStringAttributes(githubIdentityJSON)
	if !edgeHasValidAt(githubAttrs) {
		return false
	}
	return exactEmailBridgeMatches(githubAttrs, oktaAttrs)
}

func edgeStringAttributes(attributesJSON string) map[string]string {
	trimmed := strings.TrimSpace(attributesJSON)
	if trimmed == "" {
		return nil
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(trimmed), &attrs); err != nil {
		return nil
	}
	return attrs
}

func edgeHasValidAt(attrs map[string]string) bool {
	raw := strings.TrimSpace(attrs["at"])
	if raw == "" {
		return false
	}
	_, err := time.Parse(time.RFC3339, raw)
	return err == nil
}

func exactEmailBridgeMatches(githubAttrs map[string]string, oktaAttrs map[string]string) bool {
	githubValue := normalizedExactEmailIdentifier(githubAttrs)
	if githubValue == "" {
		return false
	}
	return githubValue == normalizedExactEmailIdentifier(oktaAttrs)
}

func normalizedExactEmailIdentifier(attrs map[string]string) string {
	if !strings.EqualFold(strings.TrimSpace(attrs["match_type"]), "exact_email") {
		return ""
	}
	if identifierType := strings.TrimSpace(attrs["identifier_type"]); identifierType != "" && !strings.EqualFold(identifierType, "email") {
		return ""
	}
	value := strings.ToLower(strings.TrimSpace(attrs["identifier_value"]))
	if !strings.Contains(value, "@") {
		return ""
	}
	return value
}

// githubActorIsAutomation returns true when a github.user node's
// attributes_json carries an explicit GitHub-stamped automation flag or
// is otherwise structurally not a person that could be linked to Okta.
// The source projector forwards three boolean/enumerated classifications
// from the audit log API and the GitHub /users resolution onto every
// github.user node:
//
//   - actor_is_bot is the audit-log boolean GitHub stamps on
//     first-party App identities (dependabot[bot], github-actions[bot],
//     coderabbitai[bot], etc.). It is NOT set for many third-party Apps,
//     so the rule must not depend on it alone.
//   - actor_is_agent covers fine-grained PAT / installation-token agent
//     actions GitHub categorises as automated.
//   - actor_type comes from the /users/{login} resolution and is the
//     authoritative classifier across all GitHub App accounts. Type=Bot
//     covers every App-issued identity uniformly; Type=Organization
//     means the audit row was emitted by the org acting on itself (a
//     stale phantom github.user node from before the org-self projector
//     fix) and is never a real person to link; Type=Unresolved means
//     GitHub returned 404 for the login, which happens for deleted or
//     retired App accounts (pullrequest[bot] after uninstall, etc.) and
//     for placeholder logins like deploy_key. None of these are
//     linkable to a human Okta identity, so all three suppress the
//     finding.
//
// Comparing GitHub-native classifications avoids a hardcoded vendor
// allowlist and stays correct as new App integrations come online.
//
// We accept the values verbatim from the audit log (strings, lower-cased
// "true"/"false" in practice) and trim/compare case-insensitively so a
// future API revision that returns "True" or "TRUE" still works. Empty or
// malformed JSON is treated as "not classified as automation" — better to
// surface a finding for review than to silently suppress a real shadow
// account because the attributes blob was corrupt.
func githubActorIsAutomation(attributesJSON string) bool {
	trimmed := strings.TrimSpace(attributesJSON)
	if trimmed == "" {
		return false
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(trimmed), &attrs); err != nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(attrs["actor_is_bot"]), "true") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(attrs["actor_is_agent"]), "true") {
		return true
	}
	return githubActorTypeClassifiesAutomation(attrs["actor_type"])
}

// githubActorTypeClassifiesAutomation centralises the actor_type → automation
// mapping so the node-side (`attributes_json` on github.user) and the
// edge-side (`attributes_json` on acted_on) checks agree on the same set
// of non-linkable types: Bot (GitHub App), Organization (org acting on
// itself — stale phantom github.user pre-fix path), and Unresolved (GitHub
// returned 404 for /users/{login}, e.g. retired GitHub Apps or synthetic
// placeholder logins like deploy_key). The compare is case-insensitive to
// defend against future API casing changes.
func githubActorTypeClassifiesAutomation(actorType string) bool {
	switch strings.ToLower(strings.TrimSpace(actorType)) {
	case "bot", "organization", "unresolved":
		return true
	}
	return false
}

// githubRecentEdgeMarksAutomation returns true when any acted_on edge
// within the recency window classifies its actor as automation. The
// projector stamps `actor_type` onto every acted_on edge it merges, so a
// recent edge with `actor_type=Bot/Organization/Unresolved` is a reliable
// signal that the user is non-linkable even when the github.user node's
// `attributes_json` has not yet caught up with the per-key merge.
func githubRecentEdgeMarksAutomation(targets []any, now time.Time, window time.Duration) bool {
	for _, target := range targets {
		attrs := cypherListMapString(target, "acted_attributes_json")
		if !edgeIsRecent(attrs, now, window) {
			continue
		}
		if githubEdgeActorTypeIsAutomation(attrs) {
			return true
		}
	}
	return false
}

// githubEdgeActorTypeIsAutomation parses the acted_on edge's
// `attributes_json` and reports whether its `actor_type` field classifies
// the actor as automation. The edge schema does not currently carry
// `actor_is_bot` or `actor_is_agent` (those are stamped only on the
// github.user node), so this check focuses on the resolver-stamped
// `actor_type` field exclusively. Returns false for malformed / empty
// JSON: the rule defaults to surfacing for review rather than silently
// suppressing a real shadow account whose edge blob is corrupt.
func githubEdgeActorTypeIsAutomation(attributesJSON string) bool {
	trimmed := strings.TrimSpace(attributesJSON)
	if trimmed == "" {
		return false
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(trimmed), &attrs); err != nil {
		return false
	}
	return githubActorTypeClassifiesAutomation(attrs["actor_type"])
}

func githubActedOnIsCurrentAccessEvidence(attributesJSON string) bool {
	trimmed := strings.TrimSpace(attributesJSON)
	if trimmed == "" {
		return false
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(trimmed), &attrs); err != nil {
		return false
	}
	return githubAuditActionIndicatesCurrentAccess(attrs["action"])
}

func githubAuditActionIndicatesCurrentAccess(action string) bool {
	normalized := strings.ToLower(strings.TrimSpace(action))
	if normalized == "" {
		return false
	}
	switch normalized {
	case "workflows.completed_workflow_run",
		"workflows.created_workflow_run",
		"workflows.prepared_workflow_job",
		"org_credential_authorization.deauthorize":
		return false
	default:
		return true
	}
}

type githubActiveWithoutOktaGroup struct {
	githubUserURN        string
	githubUserLabel      string
	githubAttributesJSON string
	targets              map[string]githubActiveWithoutOktaTarget
	bridgeClues          []map[string]string
	// hasCurrentBridge captures whether ANY row for this github user carried
	// a represents_identity bridge proving the user is linked to an okta user,
	// so the shadow-access premise no longer applies.
	hasCurrentBridge bool
}

type githubActiveWithoutOktaTarget struct {
	urn        string
	entityType string
	label      string
	action     string
	accessedAt string
	eventID    string
	attributes map[string]string
	edgeAttrs  map[string]string
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
	accessActions := make(map[string]struct{}, len(group.targets))
	accessEventIDs := make(map[string]struct{}, len(group.targets))
	targetDetails := make([]map[string]string, 0, len(group.targets))
	graphRows := make([]*cerebrov1.GraphEvidenceRow, 0, len(group.targets))
	var latestAccessAt string
	githubAttrs := edgeStringAttributes(group.githubAttributesJSON)
	for urn, target := range group.targets {
		targetURNs = append(targetURNs, urn)
		if trimmed := strings.TrimSpace(target.label); trimmed != "" {
			targetLabels = append(targetLabels, trimmed)
		}
		if trimmed := strings.TrimSpace(target.entityType); trimmed != "" {
			targetTypes[trimmed] = struct{}{}
		}
		if action := strings.TrimSpace(target.action); action != "" {
			accessActions[action] = struct{}{}
		}
		if eventID := strings.TrimSpace(target.eventID); eventID != "" {
			accessEventIDs[eventID] = struct{}{}
		}
		latestAccessAt = maxRFC3339String(latestAccessAt, target.accessedAt)
		targetDetails = append(targetDetails, map[string]string{
			"urn":         target.urn,
			"label":       target.label,
			"entity_type": target.entityType,
			"action":      target.action,
			"at":          target.accessedAt,
			"event_id":    target.eventID,
			"repository":  target.attributes["repository"],
			"visibility":  target.attributes["visibility"],
		})
		graphRows = append(graphRows, newGraphEvidenceRow("github_unlinked_access", map[string]string{
			"github_user_urn":   group.githubUserURN,
			"github_user_label": group.githubUserLabel,
			"target_urn":        target.urn,
			"target_label":      target.label,
			"action":            target.action,
			"at":                target.accessedAt,
			"event_id":          target.eventID,
		}, newGraphEvidencePath(group.githubUserURN, group.githubUserLabel, "github.user", "acted_on", target.urn, target.label, target.entityType, target.edgeAttrs)))
	}
	sort.Strings(targetURNs)
	sort.Strings(targetLabels)
	sort.Slice(targetDetails, func(i, j int) bool {
		return targetDetails[i]["urn"] < targetDetails[j]["urn"]
	})
	resourceURNs = append(resourceURNs, targetURNs...)
	primaryGitHubLabel := firstNonEmpty(group.githubUserLabel, group.githubUserURN)
	summary := fmt.Sprintf(
		"GitHub identity %s is active in %d resource(s) but is not linked to any Okta user in this tenant",
		primaryGitHubLabel,
		len(targetURNs),
	)
	attributes := map[string]string{
		"primary_resource_urn":              group.githubUserURN,
		"github_user_urn":                   group.githubUserURN,
		"github_user_label":                 group.githubUserLabel,
		"target_count":                      fmt.Sprintf("%d", len(targetURNs)),
		"target_urns":                       strings.Join(targetURNs, ","),
		"target_labels":                     strings.Join(targetLabels, ","),
		"target_entity_types":               strings.Join(sortedKeys(targetTypes), ","),
		"latest_access_at":                  latestAccessAt,
		"access_actions":                    strings.Join(sortedStringSet(accessActions), ","),
		"access_event_ids":                  strings.Join(sortedStringSet(accessEventIDs), ","),
		"target_access_details":             stringMapJSON(targetDetails),
		"bridge_clues":                      stringMapJSON(group.bridgeClues),
		"github_actor_type":                 githubAttrs["actor_type"],
		"github_actor_id":                   githubAttrs["actor_id"],
		"github_external_identity_nameid":   githubAttrs["external_identity_nameid"],
		"github_external_identity_username": githubAttrs["external_identity_username"],
		"source_runtime_id":                 triggeringRuntimeID,
		"source_runtime_tenant":             tenantID,
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return &ports.FindingRecord{
		ID:                         fingerprint,
		Fingerprint:                fingerprint,
		TenantID:                   tenantID,
		RuntimeID:                  triggeringRuntimeID,
		RuleID:                     r.definition.ID,
		Title:                      r.definition.Name,
		Severity:                   r.definition.Severity,
		Status:                     r.definition.Status,
		Summary:                    summary,
		ResourceURNs:               deduplicateStrings(resourceURNs),
		EventIDs:                   sortedStringSet(accessEventIDs),
		ControlRefs:                cloneFindingControlRefs(r.definition.ControlRefs),
		FindingPersistenceEnvelope: ports.FindingPersistenceEnvelope{GraphEvidenceRows: graphRows},
		Attributes:                 attributes,
		FirstObservedAt:            now,
		LastObservedAt:             now,
		CheckID:                    r.definition.ID,
		CheckName:                  r.definition.Name,
	}
}

func githubBridgeClueFromCypher(bridge any, githubIdentityJSON string, oktaIdentityJSON string) map[string]string {
	githubAttrs := edgeStringAttributes(githubIdentityJSON)
	oktaAttrs := edgeStringAttributes(oktaIdentityJSON)
	return map[string]string{
		"identity_urn":            cypherListMapString(bridge, "identity_urn"),
		"identity_label":          cypherListMapString(bridge, "identity_label"),
		"okta_urn":                cypherListMapString(bridge, "okta_urn"),
		"okta_label":              cypherListMapString(bridge, "okta_label"),
		"github_match_type":       githubAttrs["match_type"],
		"github_identifier_type":  githubAttrs["identifier_type"],
		"github_identifier_value": githubAttrs["identifier_value"],
		"github_observed_at":      githubAttrs["at"],
		"okta_match_type":         oktaAttrs["match_type"],
		"okta_identifier_type":    oktaAttrs["identifier_type"],
		"okta_identifier_value":   oktaAttrs["identifier_value"],
		"okta_observed_at":        oktaAttrs["at"],
	}
}

func maxRFC3339String(existing string, incoming string) string {
	existing = strings.TrimSpace(existing)
	incoming = strings.TrimSpace(incoming)
	if existing == "" {
		return incoming
	}
	if incoming == "" {
		return existing
	}
	existingT, existingErr := time.Parse(time.RFC3339, existing)
	incomingT, incomingErr := time.Parse(time.RFC3339, incoming)
	if existingErr != nil || incomingErr != nil {
		return incoming
	}
	if incomingT.After(existingT) {
		return incoming
	}
	return existing
}
