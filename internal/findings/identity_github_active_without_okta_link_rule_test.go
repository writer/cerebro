package findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func githubActiveWithoutOktaRuleFixedNow() time.Time {
	return time.Date(2025, time.March, 5, 12, 0, 0, 0, time.UTC)
}

func TestGitHubActiveWithoutOktaLinkRuleQueryScopesByTenant(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	request := rule.QueryFor(runtime)
	if request.Query == "" {
		t.Fatal("QueryFor() returned empty query for fully-populated runtime")
	}
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("Params[tenant_id] = %v, want writer", got)
	}
	// The rule deliberately does NOT use a NOT EXISTS subquery for the
	// represents_identity bridge: that would treat upsert-only stale
	// edges as evidence of a current link and silently suppress the
	// finding after a rename. The cypher must OPTIONAL MATCH the
	// bridge and surface the edge attributes so EvaluateRows can apply
	// the recency check. (NOT EXISTS is still used for the
	// github.org overlap filter on github.user phantoms — that is a
	// different node-set entirely and is asserted separately below.)
	for _, line := range strings.Split(request.Query, "\n") {
		if strings.Contains(line, "represents_identity") && strings.Contains(line, "NOT EXISTS") {
			t.Fatalf("Query uses NOT EXISTS for the represents_identity bridge; stale upsert-only edges would mask shadow access after a rename. Must OPTIONAL MATCH and check `at` recency in EvaluateRows. Offending line:\n%s\nFull query:\n%s", line, request.Query)
		}
	}
	if !strings.Contains(request.Query, "OPTIONAL MATCH") {
		t.Fatalf("Query missing OPTIONAL MATCH for the represents_identity bridge:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "github_identity_attributes_json") {
		t.Fatalf("Query missing github-side bridge attributes_json projection; EvaluateRows needs it to apply the bridge recency filter:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "okta_identity_attributes_json") {
		t.Fatalf("Query missing okta-side bridge attributes_json projection; EvaluateRows needs both sides to confirm a fresh bridge:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "github.user") {
		t.Fatalf("Query missing github.user entity type predicate:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "okta.user") {
		t.Fatalf("Query missing okta.user entity type predicate in the bridge OPTIONAL MATCH:\n%s", request.Query)
	}
	// Phantom `github.user:<org>` nodes minted before the projector
	// started routing org-self actor events through `github.org`
	// stay in the graph forever: they carry no `actor_type` on
	// `attributes_json` (the audit-actor resolver did not run on
	// actor_id-stamped rows pre-fix) and every new org-self event
	// re-routes through `github.org` instead of re-stamping the
	// phantom. The rule must suppress them at the cypher layer or
	// they would keep producing false positives until graph
	// cleanup. The label-overlap filter excludes any github.user
	// whose label matches an existing github.org label in the same
	// tenant; this is the only signal that survives a stale
	// `attributes_json` blob.
	if !strings.Contains(request.Query, "github.org") {
		t.Fatalf("Query missing github.org overlap filter; phantom github.user:<org> rows would keep producing false positives until manual graph cleanup. Query:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "NOT EXISTS") {
		t.Fatalf("Query missing `NOT EXISTS { ... github.org ... }` suppression clause; the rule must reject phantom github.user nodes whose label matches a github.org in the same tenant. Query:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "toLower(") {
		t.Fatalf("Query missing case-insensitive label comparison; GitHub usernames and org slugs round-trip with original casing (e.g. `writer` vs `WriterInternal`), so the overlap predicate must lower-case both sides. Query:\n%s", request.Query)
	}
	// Both target and bridge fan-outs MUST be collapsed via collect()
	// before LIMIT $row_limit clamps the result set. Without the
	// collapse, a single prolific shadow account or a user with several
	// renamed identity bridges can consume the entire row budget and
	// push every other shadow github user out of the result set; the
	// graph store does not page truncated reads, so the dropped users
	// would silently never produce findings.
	if !strings.Contains(request.Query, "collect(") {
		t.Fatalf("Query missing collect() aggregation; targets and bridges must be collapsed before LIMIT or one prolific user can starve the rest. Query:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "AS targets") {
		t.Fatalf("Query missing `AS targets` projection (collapsed target list); EvaluateRows iterates the per-row targets list:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "AS bridges") {
		t.Fatalf("Query missing `AS bridges` projection (collapsed bridge list); EvaluateRows iterates the per-row bridges list:\n%s", request.Query)
	}
	if request.RowLimit != identityGitHubActiveWithoutOktaQueryRowLimit {
		t.Fatalf("RowLimit = %d, want %d", request.RowLimit, identityGitHubActiveWithoutOktaQueryRowLimit)
	}
}

func TestGitHubActiveWithoutOktaLinkRuleQueryRequiresTenant(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	if request := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github"}); request.Query != "" {
		t.Fatalf("QueryFor() returned populated query without tenant id; rule must refuse to scan: %#v", request)
	}
}

// The rule's cypher checks GitHub activity against Okta presence, so the
// finding can change after a fresh ingest from EITHER side. SupportsRuntime
// must accept both or detections lag until the next time the other source
// happens to sync.
func TestGitHubActiveWithoutOktaLinkRuleSupportsBothGitHubAndOkta(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	withFamily := func(sourceID, family string) *cerebrov1.SourceRuntime {
		return &cerebrov1.SourceRuntime{SourceId: sourceID, Config: map[string]string{"family": family}}
	}
	cases := map[string]struct {
		runtime *cerebrov1.SourceRuntime
		want    bool
	}{
		"github audit runtime":          {withFamily("github", "audit"), true},
		"okta user runtime":             {withFamily("okta", "user"), true},
		"GITHUB audit upper case":       {withFamily("GITHUB", "AUDIT"), true},
		"github pull-request runtime":   {withFamily("github", "pull_request"), false},
		"github dependabot runtime":     {withFamily("github", "dependabot_alert"), false},
		"okta audit runtime":            {withFamily("okta", "audit"), false},
		"okta group runtime":            {withFamily("okta", "group_membership"), false},
		"okta runtime missing family":   {&cerebrov1.SourceRuntime{SourceId: "okta"}, false},
		"github runtime missing family": {&cerebrov1.SourceRuntime{SourceId: "github"}, false},
		"unrelated source":              {withFamily("aws", "iam_user"), false},
		"empty source":                  {&cerebrov1.SourceRuntime{}, false},
		"nil runtime":                   {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rule.SupportsRuntime(tc.runtime); got != tc.want {
				t.Fatalf("SupportsRuntime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func githubActiveWithoutOktaRuleGroupWithTargets(targetURNs ...string) *githubActiveWithoutOktaGroup {
	targets := map[string]githubActiveWithoutOktaTarget{}
	for _, urn := range targetURNs {
		targets[urn] = githubActiveWithoutOktaTarget{urn: urn, entityType: "github.code.repository", label: urn}
	}
	return &githubActiveWithoutOktaGroup{
		githubUserURN:        "urn:cerebro:writer:github.user:alice",
		githubUserLabel:      "alice",
		githubAttributesJSON: `{"login":"alice"}`,
		targets:              targets,
	}
}

// The fingerprint is the persistence key for a finding row; if it drifts
// across runs the same offender produces a fresh CRITICAL/HIGH alert every
// evaluation cycle instead of reopening the existing one. This pins
// fingerprint stability for the rule's identity-shaped inputs (rule + tenant
// + github_user_urn) directly on buildFinding.
func TestGitHubActiveWithoutOktaLinkRuleFingerprintIsStableAcrossRuns(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	group := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_code_repository:writer/cerebro")
	first := rule.buildFinding(runtime, "writer", group, githubActiveWithoutOktaRuleFixedNow())
	second := rule.buildFinding(runtime, "writer", group, githubActiveWithoutOktaRuleFixedNow())
	if first.ID != second.ID {
		t.Fatalf("finding ID drifted across evaluations: %q vs %q (fingerprint must hash stable inputs only)", first.ID, second.ID)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("finding fingerprint drifted: %q vs %q", first.Fingerprint, second.Fingerprint)
	}
}

// The rule stamps the triggering runtime onto the persisted record so the
// finding stays addressable through the real runtime-scoped read paths
// (Service.ListFindings, ListEvidence, reports, GRC). The store pins
// runtime_id on first insert via UpsertFinding's ON CONFLICT clause, so the
// row does not flip when both GitHub and Okta triggers reevaluate the same
// offender; that behavior is exercised in the postgres store tests. Here we
// just assert the rule's contract: stamp the real triggering runtime, never
// a synthetic value.
func TestGitHubActiveWithoutOktaLinkRuleFindingStampsTriggeringRuntimeID(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	group := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_code_repository:writer/cerebro")
	githubTriggered := rule.buildFinding(&cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}, "writer", group, githubActiveWithoutOktaRuleFixedNow())
	oktaTriggered := rule.buildFinding(&cerebrov1.SourceRuntime{Id: "writer-okta-user", SourceId: "okta", TenantId: "writer"}, "writer", group, githubActiveWithoutOktaRuleFixedNow())
	if got := githubTriggered.RuntimeID; got != "writer-github-audit" {
		t.Fatalf("github-triggered RuntimeID = %q, want real triggering runtime; synthetic ids would make the finding unreachable through runtime-scoped APIs", got)
	}
	if got := oktaTriggered.RuntimeID; got != "writer-okta-user" {
		t.Fatalf("okta-triggered RuntimeID = %q, want real triggering runtime", got)
	}
	// Both triggers MUST share the same fingerprint; pinning to first-observed
	// happens at the store layer so subsequent triggers keep the original
	// runtime instead of flipping.
	if githubTriggered.Fingerprint != oktaTriggered.Fingerprint {
		t.Fatalf("fingerprints differ across triggering runtimes (github=%q okta=%q); same offender must produce same id so the store can pin runtime", githubTriggered.Fingerprint, oktaTriggered.Fingerprint)
	}
	if got := githubTriggered.Attributes["source_runtime_id"]; got != "writer-github-audit" {
		t.Fatalf("attributes[source_runtime_id] = %q, want triggering runtime preserved for telemetry", got)
	}
}

// Two GitHub audit runtimes (e.g. writer + writerinternal scoped to the same
// tenant in dev) project to the same github.user node by (tenant_id, login),
// so the same offender must collapse onto one tenant-scoped finding.
// Including runtime_id in the fingerprint would split this into duplicates
// the moment a second github runtime synced.
func TestGitHubActiveWithoutOktaLinkRuleFingerprintCollapsesAcrossGitHubRuntimes(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtimeA := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	runtimeB := &cerebrov1.SourceRuntime{Id: "writer-github-audit-writerinternal", SourceId: "github", TenantId: "writer"}
	group := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_code_repository:writer/cerebro")
	a := rule.buildFinding(runtimeA, "writer", group, githubActiveWithoutOktaRuleFixedNow())
	b := rule.buildFinding(runtimeB, "writer", group, githubActiveWithoutOktaRuleFixedNow())
	if a.ID != b.ID {
		t.Fatalf("findings split across github runtimes for the same offender (a=%q b=%q); rule is tenant-scoped and must produce one finding per (tenant, github_user)", a.ID, b.ID)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprints split across github runtimes: %q vs %q", a.Fingerprint, b.Fingerprint)
	}
}

// One shadow GitHub account typically touches many resources. The full set
// is preserved as telemetry on the finding, but the fingerprint must NOT
// include target_urn or one shadow account would produce one finding per
// repo it touched.
func TestGitHubActiveWithoutOktaLinkRuleFingerprintIgnoresTargetSet(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	oneTarget := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_code_repository:writer/cerebro")
	threeTargets := githubActiveWithoutOktaRuleGroupWithTargets(
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
		"urn:cerebro:writer:github_code_repository:writer/palmyra",
		"urn:cerebro:writer:github_code_repository:writer/some-other-repo",
	)
	first := rule.buildFinding(runtime, "writer", oneTarget, githubActiveWithoutOktaRuleFixedNow())
	second := rule.buildFinding(runtime, "writer", threeTargets, githubActiveWithoutOktaRuleFixedNow())
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprint changes with the target set (%q vs %q); the set of touched repos is telemetry, not identity", first.Fingerprint, second.Fingerprint)
	}
}

// Two distinct GitHub users must produce two distinct findings or the alert
// queue would collapse different shadow accounts onto a single row.
func TestGitHubActiveWithoutOktaLinkRuleFingerprintSeparatesGitHubUsers(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	groupAlice := &githubActiveWithoutOktaGroup{
		githubUserURN:   "urn:cerebro:writer:github.user:alice",
		githubUserLabel: "alice",
		targets:         map[string]githubActiveWithoutOktaTarget{"urn:cerebro:writer:github_code_repository:writer/cerebro": {urn: "urn:cerebro:writer:github_code_repository:writer/cerebro"}},
	}
	groupBob := &githubActiveWithoutOktaGroup{
		githubUserURN:   "urn:cerebro:writer:github.user:bob",
		githubUserLabel: "bob",
		targets:         map[string]githubActiveWithoutOktaTarget{"urn:cerebro:writer:github_code_repository:writer/cerebro": {urn: "urn:cerebro:writer:github_code_repository:writer/cerebro"}},
	}
	a := rule.buildFinding(runtime, "writer", groupAlice, githubActiveWithoutOktaRuleFixedNow())
	b := rule.buildFinding(runtime, "writer", groupBob, githubActiveWithoutOktaRuleFixedNow())
	if a.ID == b.ID {
		t.Fatalf("two distinct shadow github users collapsed onto the same finding (id=%q); fingerprint must include github_user_urn", a.ID)
	}
}

func githubActiveWithoutOktaRuleActedAttrs(at time.Time) string {
	return githubActiveWithoutOktaRuleActedAttrsForAction("git.clone", at)
}

func githubActiveWithoutOktaRuleActedAttrsForAction(action string, at time.Time) string {
	payload := map[string]string{
		"action":   action,
		"event_id": "github-audit-evt",
	}
	if !at.IsZero() {
		payload["at"] = at.UTC().Format(time.RFC3339)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// githubActiveWithoutOktaRuleRow builds the simple single-target single-bridge
// row used by most tests. The cypher returns one row per github user with
// `targets` and `bridges` as collected lists; this helper wraps the single
// scalar values into one-element lists so existing test scenarios (single
// target, no/single bridge) still exercise the production decode path.
func githubActiveWithoutOktaRuleRow(actedAttributesJSON, githubUserURN, githubUserLabel, targetURN string) ports.CypherRow {
	return githubActiveWithoutOktaRuleRowWithBridge(actedAttributesJSON, githubUserURN, githubUserLabel, targetURN, "", "")
}

// githubActiveWithoutOktaRuleRowWithBridge is the full row builder; tests
// that exercise the bridge-recency contract use it to inject the
// represents_identity edge attributes_json on each side. Empty bridge JSON
// on both sides reproduces the single-element list cypher emits when the
// OPTIONAL MATCH misses (every coalesce(...) returns ”).
func githubActiveWithoutOktaRuleRowWithBridge(actedAttributesJSON, githubUserURN, githubUserLabel, targetURN, githubIdentityJSON, oktaIdentityJSON string) ports.CypherRow {
	return githubActiveWithoutOktaRuleRowFull(
		githubUserURN,
		githubUserLabel,
		[]githubActiveWithoutOktaTestTarget{{
			urn:                 targetURN,
			entityType:          "github.code.repository",
			label:               "writer/cerebro",
			actedAttributesJSON: actedAttributesJSON,
		}},
		[]githubActiveWithoutOktaTestBridge{{
			githubIdentityAttributesJSON: githubIdentityJSON,
			oktaIdentityAttributesJSON:   oktaIdentityJSON,
		}},
	)
}

type githubActiveWithoutOktaTestTarget struct {
	urn                 string
	entityType          string
	label               string
	actedAttributesJSON string
}

type githubActiveWithoutOktaTestBridge struct {
	githubIdentityAttributesJSON string
	oktaIdentityAttributesJSON   string
}

// githubActiveWithoutOktaRuleRowFull mirrors what the production cypher
// returns: one row per github user, with `targets` and `bridges` as
// `[]any` whose elements are `map[string]any` (the Neo4j Go driver shape
// for collected map literals).
func githubActiveWithoutOktaRuleRowFull(githubUserURN, githubUserLabel string, targets []githubActiveWithoutOktaTestTarget, bridges []githubActiveWithoutOktaTestBridge) ports.CypherRow {
	targetList := make([]any, 0, len(targets))
	for _, target := range targets {
		targetList = append(targetList, map[string]any{
			"urn":                   target.urn,
			"entity_type":           target.entityType,
			"label":                 target.label,
			"acted_attributes_json": target.actedAttributesJSON,
		})
	}
	bridgeList := make([]any, 0, len(bridges))
	for _, bridge := range bridges {
		bridgeList = append(bridgeList, map[string]any{
			"github_identity_attributes_json": bridge.githubIdentityAttributesJSON,
			"okta_identity_attributes_json":   bridge.oktaIdentityAttributesJSON,
		})
	}
	return ports.CypherRow{Values: map[string]any{
		"github_user_urn":        githubUserURN,
		"github_user_label":      githubUserLabel,
		"github_attributes_json": `{"login":"` + githubUserLabel + `"}`,
		"targets":                targetList,
		"bridges":                bridgeList,
	}}
}

// githubActiveWithoutOktaRuleRowWithGitHubAttrs lets bot/agent suppression
// tests inject explicit attributes on the github.user node (e.g.
// actor_is_bot=true) so the rule's schema-driven automation check is
// exercised against the cypher row shape it sees in production. The
// production projector serialises github.user attributes as a JSON map
// keyed on attribute name; we emit the same string form here.
//
//nolint:unparam // Helper keeps target URN explicit to match the base row helper signature.
func githubActiveWithoutOktaRuleRowWithGitHubAttrs(actedAttributesJSON, githubUserURN, githubUserLabel, targetURN string, githubAttrs map[string]string) ports.CypherRow {
	row := githubActiveWithoutOktaRuleRow(actedAttributesJSON, githubUserURN, githubUserLabel, targetURN)
	encoded, err := json.Marshal(githubAttrs)
	if err != nil {
		panic(err)
	}
	row.Values["github_attributes_json"] = string(encoded)
	return row
}

// githubActiveWithoutOktaRuleBridgeAttrs builds a represents_identity edge's
// attributes_json with an optional `at` timestamp, matching what the
// neo4j store persists.
func githubActiveWithoutOktaRuleBridgeAttrs(at time.Time) string {
	return githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(at, "", "", "")
}

func githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(at time.Time, matchType string, identifierType string, identifierValue string) string {
	payload := map[string]string{}
	if !at.IsZero() {
		payload["at"] = at.UTC().Format(time.RFC3339)
	}
	if matchType != "" {
		payload["match_type"] = matchType
	}
	if identifierType != "" {
		payload["identifier_type"] = identifierType
	}
	if identifierValue != "" {
		payload["identifier_value"] = identifierValue
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// Recent acted_on edges are the only source of truth that an unlinked GitHub
// identity is "still active" right now. Without this, the rule could only
// ever say "this user has touched github at some point in history", which
// is true forever once a single edge exists and would keep findings open
// indefinitely.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsEmitsForRecentActedOn(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	row := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1 (recent acted_on must trigger)", len(findings))
	}
	got := findings[0]
	if got.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", got.Severity)
	}
	if !strings.Contains(got.Summary, "alice") {
		t.Fatalf("Summary missing GitHub login; got %q", got.Summary)
	}
}

// An edge whose latest action is older than the recency window is stale
// history, not current access. Without this filter, a single historical
// commit from before the user offboarded would keep the finding open
// indefinitely.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsRejectsStaleActedOn(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	row := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-90*24*time.Hour)),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0 (stale acted_on must not trigger)", len(findings))
	}
}

// Edges projected before the at-stamp change have no `at` attribute. We
// cannot prove recency on those rows, so the rule must refuse to fire on
// them rather than treat absence of evidence as evidence of activity.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsRejectsActedOnWithoutAt(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	row := githubActiveWithoutOktaRuleRow(
		`{"action":"git.clone","event_id":"github-audit-evt"}`,
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0 (acted_on without `at` must not trigger; we cannot prove recency)", len(findings))
	}
}

// Not every recent audit edge proves current GitHub access. Workflow lifecycle
// records like `workflows.created_workflow_run` / `completed_workflow_run` are
// frequently emitted on behalf of the actor named on a commit, and live data
// showed several otherwise-human accounts whose only recent evidence was these
// passive workflow rows. Treating them as HIGH shadow access creates weak
// findings. Revocation-only rows such as
// `org_credential_authorization.deauthorize` are also not evidence that the
// account currently retains access; they are evidence of access being removed.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsRejectsPassiveAndRevocationActions(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	for _, action := range []string{
		"workflows.completed_workflow_run",
		"workflows.created_workflow_run",
		"workflows.prepared_workflow_job",
		"org_credential_authorization.deauthorize",
	} {
		t.Run(action, func(t *testing.T) {
			row := githubActiveWithoutOktaRuleRow(
				githubActiveWithoutOktaRuleActedAttrsForAction(action, now.Add(-1*time.Hour)),
				"urn:cerebro:writer:github.user:alice",
				"alice",
				"urn:cerebro:writer:github_code_repository:writer/cerebro",
			)
			findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("EvaluateRows() returned %d findings, want 0 for passive/revocation action %q", len(findings), action)
			}
		})
	}
}

func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsAcceptsStrongAccessActions(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	for _, action := range []string{
		"git.fetch",
		"git.clone",
		"git.push",
		"org.sso_response",
		"org_credential_authorization.grant",
		"pull_request_review.submit",
	} {
		t.Run(action, func(t *testing.T) {
			row := githubActiveWithoutOktaRuleRow(
				githubActiveWithoutOktaRuleActedAttrsForAction(action, now.Add(-1*time.Hour)),
				"urn:cerebro:writer:github.user:alice",
				"alice",
				"urn:cerebro:writer:github_code_repository:writer/cerebro",
			)
			findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("EvaluateRows() returned %d findings, want 1 for strong access action %q", len(findings), action)
			}
		})
	}
}

// GitHub stamps actor_is_bot=true on every audit event whose actor is a
// GitHub App identity (the `<vendor>[bot]` accounts). The source projector
// forwards that flag verbatim onto the github.user node attributes; rows
// carrying it must be suppressed because App identities will never be in
// Okta and would otherwise flood the queue with non-actionable findings.
//
// The suppression is keyed off the schema flag rather than the login string
// so the rule stays correct without a hand-maintained vendor allowlist and
// without paying a per-vendor maintenance tax as new GitHub App
// integrations come online (dependabot[bot], github-actions[bot],
// renovate[bot], coderabbitai[bot], factory-droid[bot], …).
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsSkipsActorIsBot(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	rows := []ports.CypherRow{}
	for _, login := range []string{
		"dependabot[bot]",
		"github-actions[bot]",
		"renovate[bot]",
		"coderabbitai[bot]",
		"factory-droid[bot]",
		"future-vendor-no-allowlist[bot]",
	} {
		rows = append(rows, githubActiveWithoutOktaRuleRowWithGitHubAttrs(
			githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
			"urn:cerebro:writer:github.user:"+strings.ToLower(login),
			login,
			"urn:cerebro:writer:github_code_repository:writer/cerebro",
			map[string]string{"login": login, "actor_is_bot": "true"},
		))
	}
	findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0 (actor_is_bot=true must be filtered)", len(findings))
	}
}

// actor_type=Organization on a github.user node means the audit row
// surfaced the org acting on itself (org-self events such as
// integration_installation.version_updated). New events with org-self
// actors route through the github.org projection path; stale github.user
// nodes from the pre-fix projection still carry edges but the resolved
// actor_type lets the rule suppress them rather than asking a human to
// "link the writer organisation to Okta".
//
// actor_type=Unresolved means GitHub returned 404 for /users/{login} when
// the source resolver tried to classify it. That happens for retired
// GitHub Apps (pullrequest[bot] after uninstall) and for the deploy_key
// placeholder login: in both cases the account no longer exists as a
// linkable identity so the finding is non-actionable.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsSkipsOrganizationAndUnresolvedActorTypes(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	cases := []struct {
		login string
		attrs map[string]string
	}{
		{login: "writer", attrs: map[string]string{"login": "writer", "actor_type": "Organization"}},
		{login: "writer", attrs: map[string]string{"login": "writer", "actor_type": "organization"}},
		{login: "deploy_key", attrs: map[string]string{"login": "deploy_key", "actor_type": "Unresolved"}},
		{login: "pullrequest[bot]", attrs: map[string]string{"login": "pullrequest[bot]", "actor_type": "unresolved"}},
	}
	for _, tc := range cases {
		row := githubActiveWithoutOktaRuleRowWithGitHubAttrs(
			githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
			"urn:cerebro:writer:github.user:"+tc.login,
			tc.login,
			"urn:cerebro:writer:github_code_repository:writer/cerebro",
			tc.attrs,
		)
		findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
		if err != nil {
			t.Fatalf("EvaluateRows() error = %v: attrs=%v", err, tc.attrs)
		}
		if len(findings) != 0 {
			t.Fatalf("EvaluateRows() returned %d findings for actor_type=%q, want 0 (non-user actor_types must be filtered)", len(findings), tc.attrs["actor_type"])
		}
	}
}

// actor_is_agent=true is GitHub's classification for fine-grained PAT and
// installation-token agent actions. The flag is stamped by the audit log API
// itself; the rule suppresses on it for the same reason it suppresses
// actor_is_bot: agents will never be in Okta and would otherwise flood the
// queue with non-actionable findings.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsSkipsActorIsAgent(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	row := githubActiveWithoutOktaRuleRowWithGitHubAttrs(
		githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
		"urn:cerebro:writer:github.user:fine-grained-pat-agent",
		"fine-grained-pat-agent",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
		map[string]string{"login": "fine-grained-pat-agent", "actor_is_agent": "true"},
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0 (actor_is_agent=true must be filtered)", len(findings))
	}
}

// A future API revision might emit "True" or "TRUE" instead of "true". The
// suppression must stay case-insensitive so a casing change at GitHub's end
// doesn't silently re-open every bot finding.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsSkipsActorIsAutomationCaseInsensitive(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	cases := []map[string]string{
		{"login": "alice", "actor_is_bot": "True"},
		{"login": "alice", "actor_is_bot": "TRUE"},
		{"login": "alice", "actor_is_agent": "True"},
		{"login": "alice", "actor_is_agent": "TRUE"},
	}
	for _, attrs := range cases {
		row := githubActiveWithoutOktaRuleRowWithGitHubAttrs(
			githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
			"urn:cerebro:writer:github.user:alice",
			"alice",
			"urn:cerebro:writer:github_code_repository:writer/cerebro",
			attrs,
		)
		findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
		if err != nil {
			t.Fatalf("EvaluateRows() error = %v: attrs=%v", err, attrs)
		}
		if len(findings) != 0 {
			t.Fatalf("EvaluateRows() returned %d findings, want 0 for attrs=%v (case-insensitive 'true' must suppress)", len(findings), attrs)
		}
	}
}

// Real GitHub usernames whose logins coincidentally look bot-adjacent (e.g.
// `renovate-team-lead`, `dependable-alice`, `github-actionsperson`) must NOT
// be suppressed. The schema flags are absent for these accounts, so the
// rule trusts the GitHub-side classification and continues to emit shadow-
// access findings. This also covers the failure mode where a real shadow
// account happens to carry `actor_is_bot=false` / `actor_is_agent=false`
// explicitly: those values must NOT suppress.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsAcceptsHumanLoginsWithoutAutomationFlags(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	rows := []ports.CypherRow{}
	cases := []struct {
		login string
		attrs map[string]string
	}{
		{login: "renovate-team-lead", attrs: map[string]string{"login": "renovate-team-lead"}},
		{login: "dependable-alice", attrs: map[string]string{"login": "dependable-alice", "actor_is_bot": "false"}},
		{login: "github-actionsperson", attrs: map[string]string{"login": "github-actionsperson", "actor_is_agent": "false"}},
		{login: "explicit-false-both", attrs: map[string]string{"login": "explicit-false-both", "actor_is_bot": "false", "actor_is_agent": "false"}},
	}
	for _, tc := range cases {
		rows = append(rows, githubActiveWithoutOktaRuleRowWithGitHubAttrs(
			githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
			"urn:cerebro:writer:github.user:"+tc.login,
			tc.login,
			"urn:cerebro:writer:github_code_repository:writer/cerebro",
			tc.attrs,
		))
	}
	findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != len(cases) {
		t.Fatalf("EvaluateRows() returned %d findings, want %d (real users without automation flags must NOT be suppressed)", len(findings), len(cases))
	}
}

// The cypher returns one row per (github_user, target). The same shadow
// account often touches many resources, so EvaluateRows must collapse them
// into one finding (with the full target list as telemetry) instead of
// emitting one finding per repo.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsCollapsesTargetsPerGitHubUser(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	at := time.Now().UTC().Add(-1 * time.Hour)
	rowOne := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(at),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
	)
	rowTwo := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(at),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/palmyra",
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{rowOne, rowTwo})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1; same github user must collapse across targets", got)
	}
	finding := findings[0]
	if got, want := finding.Attributes["target_count"], "2"; got != want {
		t.Fatalf("target_count = %q, want %q", got, want)
	}
	if got, want := finding.Attributes["target_urns"], "urn:cerebro:writer:github_code_repository:writer/cerebro,urn:cerebro:writer:github_code_repository:writer/palmyra"; got != want {
		t.Fatalf("target_urns = %q, want %q (full set must be retained as telemetry)", got, want)
	}
}

// Two different shadow github users must produce two distinct findings,
// sorted by the github user URN so the output is deterministic and
// reproducible across runs.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsEmitsDeterministicOrder(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	at := time.Now().UTC().Add(-1 * time.Hour)
	rowBob := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(at),
		"urn:cerebro:writer:github.user:bob",
		"bob",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
	)
	rowAlice := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(at),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{rowBob, rowAlice})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 2 {
		t.Fatalf("EvaluateRows() returned %d findings, want 2", got)
	}
	if got := findings[0].Attributes["github_user_label"]; got != "alice" {
		t.Fatalf("findings[0] github_user_label = %q, want alice (output must be sorted by github_user_urn)", got)
	}
	if got := findings[1].Attributes["github_user_label"]; got != "bob" {
		t.Fatalf("findings[1] github_user_label = %q, want bob", got)
	}
}

// Empty / missing rows must not produce findings; the rule contract is to
// emit only on real graph evidence.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsHandlesEmptyAndPartialRows(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	cases := map[string][]ports.CypherRow{
		"nil rows":                nil,
		"empty rows":              {},
		"row missing github user": {{Values: map[string]any{"target_urn": "urn:cerebro:writer:github_code_repository:writer/cerebro"}}},
		"row missing target":      {{Values: map[string]any{"github_user_urn": "urn:cerebro:writer:github.user:alice", "github_user_label": "alice"}}},
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("EvaluateRows() returned %d findings, want 0 for %s", len(findings), name)
			}
		})
	}
}

// The rule emits no findings when there is no tenant id; the cypher would be
// empty too, but EvaluateRows defends against being driven directly with
// rows from a malformed runtime.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsRequiresTenant(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github"}
	row := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0 (no tenant id)", len(findings))
	}
}

// represents_identity edges are upsert-only: the projector never retracts
// them when an Okta login/email or GitHub external_identity_nameid is
// renamed. After a rename, both sides remain joined to the obsolete
// identity node forever. A NOT EXISTS subquery would treat that stale
// bridge as evidence of a current link and suppress this finding
// indefinitely. The rule must therefore reject bridges whose `at` is
// outside the recency window: stale-only bridges leave hasFreshBridge
// false and the group emits as expected.
func TestGitHubActiveWithoutOktaLinkRuleStaleBridgeDoesNotSuppress(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	staleAt := now.Add(-90 * 24 * time.Hour)
	row := githubActiveWithoutOktaRuleRowWithBridge(
		githubActiveWithoutOktaRuleActedAttrs(now.Add(-1*time.Hour)),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
		githubActiveWithoutOktaRuleBridgeAttrs(staleAt),
		githubActiveWithoutOktaRuleBridgeAttrs(staleAt),
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1; stale bridge edges must NOT suppress shadow access (otherwise renames would silently mask findings forever)", len(findings))
	}
}

// A bridge whose okta-side AND github-side identifier edges have BOTH been
// re-asserted inside the recency window proves the github user is currently
// linked to an okta user via fresh identifiers. Shadow-access premise no
// longer applies, so the group must be suppressed.
func TestGitHubActiveWithoutOktaLinkRuleFreshBridgeOnBothSidesSuppresses(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	freshAt := now.Add(-1 * time.Hour)
	row := githubActiveWithoutOktaRuleRowWithBridge(
		githubActiveWithoutOktaRuleActedAttrs(freshAt),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
		githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
		githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0; a fresh bridge on both sides proves the github user is linked to an okta user, the rule must suppress", len(findings))
	}
}

func TestGitHubActiveWithoutOktaLinkRuleDurableExactEmailBridgeSuppresses(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	freshAt := now.Add(-1 * time.Hour)
	staleAt := now.Add(-90 * 24 * time.Hour)
	row := githubActiveWithoutOktaRuleRowWithBridge(
		githubActiveWithoutOktaRuleActedAttrs(freshAt),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
		githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(staleAt, "exact_email", "email", "alice@writer.com"),
		githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(freshAt, "exact_email", "email", "alice@writer.com"),
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0; a stamped exact-email GitHub bridge to a freshly projected Okta email proves the account is linked even when later git activity omits external identity fields", len(findings))
	}
}

func TestGitHubActiveWithoutOktaLinkRuleDurableBridgeRequiresExactEmailAndFreshOkta(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	freshAt := now.Add(-1 * time.Hour)
	staleAt := now.Add(-90 * 24 * time.Hour)
	cases := map[string]struct {
		githubBridgeJSON string
		oktaBridgeJSON   string
	}{
		"login bridge is not durable": {
			githubBridgeJSON: githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(staleAt, "login", "login", "alice"),
			oktaBridgeJSON:   githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(freshAt, "login", "login", "alice"),
		},
		"fresh okta side is required": {
			githubBridgeJSON: githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(staleAt, "exact_email", "email", "alice@writer.com"),
			oktaBridgeJSON:   githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(staleAt, "exact_email", "email", "alice@writer.com"),
		},
		"email values must match": {
			githubBridgeJSON: githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(staleAt, "exact_email", "email", "alice@writer.com"),
			oktaBridgeJSON:   githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(freshAt, "exact_email", "email", "bob@writer.com"),
		},
		"github side still needs a stamped observation": {
			githubBridgeJSON: githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(time.Time{}, "exact_email", "email", "alice@writer.com"),
			oktaBridgeJSON:   githubActiveWithoutOktaRuleBridgeAttrsWithIdentifier(freshAt, "exact_email", "email", "alice@writer.com"),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			row := githubActiveWithoutOktaRuleRowWithBridge(
				githubActiveWithoutOktaRuleActedAttrs(freshAt),
				"urn:cerebro:writer:github.user:alice",
				"alice",
				"urn:cerebro:writer:github_code_repository:writer/cerebro",
				tc.githubBridgeJSON,
				tc.oktaBridgeJSON,
			)
			findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("EvaluateRows() returned %d findings, want 1 for %q; only stamped exact-email GitHub bridges with a fresh matching Okta email are durable", len(findings), name)
			}
		})
	}
}

// One-sided fresh bridges (only the github→identity OR only the okta→identity
// edge has been re-asserted recently) are NOT proof of a current link: the
// missing side is exactly the kind of stale upsert this rule defends against.
// Without requiring both sides, a renamed Okta login that left the okta-side
// edge frozen would be enough to suppress the finding the moment a fresh
// github.audit event re-asserted the github-side edge.
func TestGitHubActiveWithoutOktaLinkRuleOneSidedBridgeDoesNotSuppress(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	freshAt := now.Add(-1 * time.Hour)
	staleAt := now.Add(-90 * 24 * time.Hour)
	cases := map[string]struct {
		githubBridgeJSON string
		oktaBridgeJSON   string
	}{
		"only github side fresh": {
			githubBridgeJSON: githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
			oktaBridgeJSON:   githubActiveWithoutOktaRuleBridgeAttrs(staleAt),
		},
		"only okta side fresh": {
			githubBridgeJSON: githubActiveWithoutOktaRuleBridgeAttrs(staleAt),
			oktaBridgeJSON:   githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
		},
		"github side fresh, okta side missing at": {
			githubBridgeJSON: githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
			oktaBridgeJSON:   `{}`,
		},
		"okta side fresh, github side missing at": {
			githubBridgeJSON: `{}`,
			oktaBridgeJSON:   githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			row := githubActiveWithoutOktaRuleRowWithBridge(
				githubActiveWithoutOktaRuleActedAttrs(freshAt),
				"urn:cerebro:writer:github.user:alice",
				"alice",
				"urn:cerebro:writer:github_code_repository:writer/cerebro",
				tc.githubBridgeJSON,
				tc.oktaBridgeJSON,
			)
			findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("EvaluateRows() returned %d findings, want 1 for %q; one-sided fresh bridge is not proof of a current link", len(findings), name)
			}
		})
	}
}

// The cypher returns one row per (github_user, target, candidate okta
// bridge). A given github user can therefore arrive across multiple rows
// where some have a bridge and some don't (e.g. the OPTIONAL MATCH miss
// row + a row that hit the bridge). The order rows are processed in is
// not stable across runs because Neo4j does not guarantee row order.
//
// EvaluateRows must therefore set hasFreshBridge=true if ANY row for the
// github user carries a fresh bridge, regardless of whether the bridge
// row arrived first or last. Otherwise, suppression would depend on
// ordering luck and the same offender would oscillate between "suppressed"
// and "open" across evaluation cycles.
func TestGitHubActiveWithoutOktaLinkRuleFreshBridgeArrivesAfterNoBridgeRow(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	freshAt := now.Add(-1 * time.Hour)
	rowNoBridge := githubActiveWithoutOktaRuleRowWithBridge(
		githubActiveWithoutOktaRuleActedAttrs(freshAt),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/cerebro",
		"",
		"",
	)
	rowFreshBridge := githubActiveWithoutOktaRuleRowWithBridge(
		githubActiveWithoutOktaRuleActedAttrs(freshAt),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_code_repository:writer/palmyra",
		githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
		githubActiveWithoutOktaRuleBridgeAttrs(freshAt),
	)
	for name, rows := range map[string][]ports.CypherRow{
		"no-bridge row first":    {rowNoBridge, rowFreshBridge},
		"fresh-bridge row first": {rowFreshBridge, rowNoBridge},
	} {
		t.Run(name, func(t *testing.T) {
			findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("EvaluateRows() returned %d findings, want 0 for %q; ANY fresh bridge across rows for the same github user must suppress regardless of arrival order", len(findings), name)
			}
		})
	}
}

// The cypher emits ONE row per github user with the targets list collected
// inside it. EvaluateRows must scan the per-row targets list so a single
// shadow account that has touched many resources still produces ONE finding
// with the full target list as telemetry. The list-shaped fan-out is what
// makes the 500-row LIMIT scale to 500 distinct shadow users instead of
// being consumed by one prolific account's targets and bridges.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsConsumesTargetsList(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	freshAt := time.Now().UTC().Add(-1 * time.Hour)
	row := githubActiveWithoutOktaRuleRowFull(
		"urn:cerebro:writer:github.user:alice",
		"alice",
		[]githubActiveWithoutOktaTestTarget{
			{urn: "urn:cerebro:writer:github_code_repository:writer/cerebro", entityType: "github.code.repository", label: "writer/cerebro", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(freshAt)},
			{urn: "urn:cerebro:writer:github_code_repository:writer/palmyra", entityType: "github.code.repository", label: "writer/palmyra", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(freshAt)},
			{urn: "urn:cerebro:writer:github_code_repository:writer/some-other-repo", entityType: "github.code.repository", label: "writer/some-other-repo", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(freshAt)},
		},
		nil,
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1; one row per github user with N targets must collapse to ONE finding", got)
	}
	finding := findings[0]
	if got, want := finding.Attributes["target_count"], "3"; got != want {
		t.Fatalf("target_count = %q, want %q", got, want)
	}
	if got, want := finding.Attributes["target_urns"], "urn:cerebro:writer:github_code_repository:writer/cerebro,urn:cerebro:writer:github_code_repository:writer/palmyra,urn:cerebro:writer:github_code_repository:writer/some-other-repo"; got != want {
		t.Fatalf("target_urns = %q, want %q (full target list must be retained as telemetry)", got, want)
	}
}

// Per-target acted_on recency is enforced inside the targets list scan: a
// row whose targets list mixes fresh and stale entries must only retain
// the fresh ones. Stale targets are not evidence of current access and
// must not pin the finding open.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsFiltersStaleTargetsInList(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	row := githubActiveWithoutOktaRuleRowFull(
		"urn:cerebro:writer:github.user:alice",
		"alice",
		[]githubActiveWithoutOktaTestTarget{
			{urn: "urn:cerebro:writer:github_code_repository:writer/fresh", entityType: "github.code.repository", label: "writer/fresh", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(now.Add(-1 * time.Hour))},
			{urn: "urn:cerebro:writer:github_code_repository:writer/stale", entityType: "github.code.repository", label: "writer/stale", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(now.Add(-90 * 24 * time.Hour))},
			{urn: "urn:cerebro:writer:github_code_repository:writer/missing-at", entityType: "github.code.repository", label: "writer/missing-at", actedAttributesJSON: `{"action":"git.clone"}`},
		},
		nil,
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1", got)
	}
	finding := findings[0]
	if got, want := finding.Attributes["target_count"], "1"; got != want {
		t.Fatalf("target_count = %q, want %q (only the fresh target should remain)", got, want)
	}
	if got, want := finding.Attributes["target_urns"], "urn:cerebro:writer:github_code_repository:writer/fresh"; got != want {
		t.Fatalf("target_urns = %q, want %q", got, want)
	}
}

// The bridges list can carry multiple candidate bridges (e.g. one per
// historical email/login). Suppression must trip on ANY bridge whose
// github-side AND okta-side identifier edges have BOTH been re-asserted
// inside the recency window; stale bridges in the list must not contribute
// proof, and a fresh github-side edge on bridge A combined with a fresh
// okta-side edge on bridge B (different identity nodes) is two stale
// renamed bridges, NOT one current bridge.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsBridgesListPairing(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	freshAt := now.Add(-1 * time.Hour)
	staleAt := now.Add(-90 * 24 * time.Hour)
	cases := map[string]struct {
		bridges      []githubActiveWithoutOktaTestBridge
		wantSuppress bool
	}{
		"only stale bridges in list": {
			bridges: []githubActiveWithoutOktaTestBridge{
				{githubActiveWithoutOktaRuleBridgeAttrs(staleAt), githubActiveWithoutOktaRuleBridgeAttrs(staleAt)},
				{githubActiveWithoutOktaRuleBridgeAttrs(staleAt), githubActiveWithoutOktaRuleBridgeAttrs(staleAt)},
			},
			wantSuppress: false,
		},
		"one fresh-both-sides bridge among stale": {
			bridges: []githubActiveWithoutOktaTestBridge{
				{githubActiveWithoutOktaRuleBridgeAttrs(staleAt), githubActiveWithoutOktaRuleBridgeAttrs(staleAt)},
				{githubActiveWithoutOktaRuleBridgeAttrs(freshAt), githubActiveWithoutOktaRuleBridgeAttrs(freshAt)},
				{githubActiveWithoutOktaRuleBridgeAttrs(staleAt), githubActiveWithoutOktaRuleBridgeAttrs(staleAt)},
			},
			wantSuppress: true,
		},
		"only one-sided fresh bridges in list": {
			bridges: []githubActiveWithoutOktaTestBridge{
				{githubActiveWithoutOktaRuleBridgeAttrs(freshAt), githubActiveWithoutOktaRuleBridgeAttrs(staleAt)},
				{githubActiveWithoutOktaRuleBridgeAttrs(staleAt), githubActiveWithoutOktaRuleBridgeAttrs(freshAt)},
			},
			wantSuppress: false,
		},
		"empty bridges list (OPTIONAL MATCH miss)": {
			bridges:      nil,
			wantSuppress: false,
		},
		"single OPTIONAL MATCH miss element (cypher coalesce)": {
			bridges: []githubActiveWithoutOktaTestBridge{
				{"", ""},
			},
			wantSuppress: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			row := githubActiveWithoutOktaRuleRowFull(
				"urn:cerebro:writer:github.user:alice",
				"alice",
				[]githubActiveWithoutOktaTestTarget{{
					urn:                 "urn:cerebro:writer:github_code_repository:writer/cerebro",
					entityType:          "github.code.repository",
					label:               "writer/cerebro",
					actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(freshAt),
				}},
				tc.bridges,
			)
			findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			gotN := len(findings)
			wantN := 1
			if tc.wantSuppress {
				wantN = 0
			}
			if gotN != wantN {
				t.Fatalf("EvaluateRows() returned %d findings, want %d for %q", gotN, wantN, name)
			}
		})
	}
}

// Phantom github.user nodes that survived from before audit.go always
// resolved actors do not carry `actor_type` on their `attributes_json`,
// but new audit events under the v2.1.14+ projector stamp `actor_type`
// onto every acted_on edge they merge. A recent edge that classifies
// the actor as automation (Bot / Organization / Unresolved) is therefore
// a reliable signal that the user is non-linkable, even when the node's
// blob has not yet caught up via mergeGraphAttributes. EvaluateRows
// must honour the edge-side classification or the rule keeps emitting
// findings for accounts that have already been classified out by the
// resolver. The test exercises the canonical phantom logins from live
// data (deploy_key, pullrequest[bot], socket-security[bot], the writer
// org acting on itself before the org-self routing fix).
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsEdgeActorTypeSuppressesPhantom(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	freshAt := now.Add(-1 * time.Hour)
	cases := []struct {
		name        string
		login       string
		edgeAttrs   string
		nodeAttrs   map[string]string
		wantEmit    bool
		description string
	}{
		{
			name:      "phantom node stale, fresh edge Bot",
			login:     "socket-security[bot]",
			edgeAttrs: `{"action":"git.clone","actor_type":"Bot","at":"` + freshAt.Format(time.RFC3339) + `"}`,
			nodeAttrs: map[string]string{"login": "socket-security[bot]"},
			wantEmit:  false,
		},
		{
			name:      "phantom node stale, fresh edge Unresolved",
			login:     "deploy_key",
			edgeAttrs: `{"action":"git.clone","actor_type":"Unresolved","at":"` + freshAt.Format(time.RFC3339) + `"}`,
			nodeAttrs: map[string]string{"login": "deploy_key"},
			wantEmit:  false,
		},
		{
			name:      "phantom node stale, fresh edge Organization",
			login:     "writer",
			edgeAttrs: `{"action":"git.clone","actor_type":"Organization","at":"` + freshAt.Format(time.RFC3339) + `"}`,
			nodeAttrs: map[string]string{"login": "writer"},
			wantEmit:  false,
		},
		{
			name:      "phantom node stale, fresh edge lower-case bot",
			login:     "pullrequest[bot]",
			edgeAttrs: `{"action":"git.clone","actor_type":"bot","at":"` + freshAt.Format(time.RFC3339) + `"}`,
			nodeAttrs: map[string]string{"login": "pullrequest[bot]"},
			wantEmit:  false,
		},
		{
			name:        "real user, fresh edge User must NOT suppress",
			login:       "samjulien",
			edgeAttrs:   `{"action":"git.clone","actor_type":"User","at":"` + freshAt.Format(time.RFC3339) + `"}`,
			nodeAttrs:   map[string]string{"login": "samjulien", "actor_type": "User"},
			wantEmit:    true,
			description: "actor_type=User means a real human actor, finding must emit",
		},
		{
			name:        "phantom node stale, edge actor_type empty must NOT suppress",
			login:       "alice",
			edgeAttrs:   `{"action":"git.clone","at":"` + freshAt.Format(time.RFC3339) + `"}`,
			nodeAttrs:   map[string]string{"login": "alice"},
			wantEmit:    true,
			description: "no actor_type classification on either side; rule defaults to surfacing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := githubActiveWithoutOktaRuleRowWithGitHubAttrs(
				tc.edgeAttrs,
				"urn:cerebro:writer:github.user:"+tc.login,
				tc.login,
				"urn:cerebro:writer:github_code_repository:writer/cerebro",
				tc.nodeAttrs,
			)
			findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			gotN := len(findings)
			wantN := 0
			if tc.wantEmit {
				wantN = 1
			}
			if gotN != wantN {
				t.Fatalf("EvaluateRows() returned %d findings, want %d for %s (%s)", gotN, wantN, tc.name, tc.description)
			}
		})
	}
}

// Edge-side automation classifications must respect the recency window.
// A stale edge with actor_type=Bot from years ago is not evidence that
// the user is currently automation — the audit log API could have
// re-classified the login as a human user since then. We only suppress
// on automation markers that survived the recency cutoff.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsStaleEdgeAutomationDoesNotSuppress(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	now := time.Now().UTC()
	staleAt := now.Add(-90 * 24 * time.Hour)
	freshAt := now.Add(-1 * time.Hour)
	row := githubActiveWithoutOktaRuleRowFull(
		"urn:cerebro:writer:github.user:alice",
		"alice",
		[]githubActiveWithoutOktaTestTarget{
			{
				urn:                 "urn:cerebro:writer:github_code_repository:writer/cerebro",
				entityType:          "github.code.repository",
				label:               "writer/cerebro",
				actedAttributesJSON: `{"action":"git.clone","actor_type":"Bot","at":"` + staleAt.Format(time.RFC3339) + `"}`,
			},
			{
				urn:                 "urn:cerebro:writer:github_code_repository:writer/palmyra",
				entityType:          "github.code.repository",
				label:               "writer/palmyra",
				actedAttributesJSON: `{"action":"git.clone","at":"` + freshAt.Format(time.RFC3339) + `"}`,
			},
		},
		nil,
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1; stale Bot edge must NOT suppress when a fresh non-bot edge exists for the same user", len(findings))
	}
	finding := findings[0]
	if got, want := finding.Attributes["target_count"], "1"; got != want {
		t.Fatalf("target_count = %q, want %q (only the fresh non-bot edge should remain)", got, want)
	}
}

// githubEdgeActorTypeIsAutomation parses the acted_on edge's
// `attributes_json` and reports whether its `actor_type` field classifies
// the actor as automation. The helper is shared with the node-side check
// via githubActorTypeClassifiesAutomation; this table pins:
//
//   - the canonical Bot/Organization/Unresolved classifications suppress
//   - case variations are honoured
//   - User and other types do NOT suppress
//   - empty, malformed, or non-actor_type JSON falls open
func TestGitHubEdgeActorTypeIsAutomation(t *testing.T) {
	cases := map[string]struct {
		attributesJSON string
		want           bool
	}{
		"edge actor_type Bot":              {`{"actor_type":"Bot"}`, true},
		"edge actor_type bot lowercase":    {`{"actor_type":"bot"}`, true},
		"edge actor_type Organization":     {`{"actor_type":"Organization"}`, true},
		"edge actor_type org lower":        {`{"actor_type":"organization"}`, true},
		"edge actor_type Unresolved":       {`{"actor_type":"Unresolved"}`, true},
		"edge actor_type unresolved lower": {`{"actor_type":"unresolved"}`, true},
		"edge actor_type whitespace bot":   {`{"actor_type":"  Bot  "}`, true},
		"edge actor_type User":             {`{"actor_type":"User"}`, false},
		"edge actor_type empty":            {`{"actor_type":""}`, false},
		"edge no actor_type":               {`{"action":"git.clone"}`, false},
		"empty JSON object":                {`{}`, false},
		"empty string":                     {``, false},
		"whitespace string":                {`   `, false},
		"malformed JSON":                   {`{not valid`, false},
		"non-object JSON":                  {`"string"`, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := githubEdgeActorTypeIsAutomation(tc.attributesJSON); got != tc.want {
				t.Fatalf("githubEdgeActorTypeIsAutomation(%q) = %v, want %v", tc.attributesJSON, got, tc.want)
			}
		})
	}
}

// githubActorIsAutomation reads the github-stamped automation flags off the
// node's attributes_json blob; the rule depends on these signals to suppress
// bot/agent rows without resorting to a hardcoded vendor allowlist. The
// table here pins:
//
//   - both true-shaped flags suppress (bot and agent)
//   - case variations of "true" are honoured (a future API revision returning
//     "True"/"TRUE" must not silently re-open every bot finding)
//   - false / absent / unrelated values do NOT suppress (we surface the
//     finding for review rather than swallow a real shadow account because
//     the attribute was malformed or missing)
//   - malformed JSON / empty input is treated as "not classified as
//     automation", same fail-open posture
func TestGitHubActorIsAutomation(t *testing.T) {
	cases := map[string]struct {
		attributesJSON string
		want           bool
	}{
		"actor_is_bot true":             {`{"actor_is_bot":"true"}`, true},
		"actor_is_bot TRUE upper":       {`{"actor_is_bot":"TRUE"}`, true},
		"actor_is_bot True mixed":       {`{"actor_is_bot":"True"}`, true},
		"actor_is_bot true with spaces": {`{"actor_is_bot":"  true  "}`, true},
		"actor_is_agent true":           {`{"actor_is_agent":"true"}`, true},
		"actor_is_agent TRUE upper":     {`{"actor_is_agent":"TRUE"}`, true},
		"actor_type bot":                {`{"actor_type":"Bot"}`, true},
		"actor_type bot lowercase":      {`{"actor_type":"bot"}`, true},
		"actor_type bot mixed case":     {`{"actor_type":"  Bot  "}`, true},
		"actor_type organization":       {`{"actor_type":"Organization"}`, true},
		"actor_type org lowercase":      {`{"actor_type":"organization"}`, true},
		"actor_type unresolved":         {`{"actor_type":"Unresolved"}`, true},
		"actor_type unresolved lower":   {`{"actor_type":"unresolved"}`, true},
		"both flags true":               {`{"actor_is_bot":"true","actor_is_agent":"true"}`, true},
		"only bot true, agent false":    {`{"actor_is_bot":"true","actor_is_agent":"false"}`, true},
		"only agent true, bot false":    {`{"actor_is_bot":"false","actor_is_agent":"true"}`, true},
		"both flags false":              {`{"actor_is_bot":"false","actor_is_agent":"false"}`, false},
		"bot flag absent":               {`{"login":"alice"}`, false},
		"actor_type user":               {`{"actor_type":"User"}`, false},
		"actor_type user with id":       {`{"actor_type":"User","actor_id":"42"}`, false},
		"bot flag empty string":         {`{"actor_is_bot":""}`, false},
		"bot flag arbitrary value":      {`{"actor_is_bot":"maybe"}`, false},
		"empty JSON object":             {`{}`, false},
		"empty string":                  {``, false},
		"whitespace string":             {`   `, false},
		"malformed JSON":                {`{not valid json`, false},
		"non-object JSON":               {`"string"`, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := githubActorIsAutomation(tc.attributesJSON); got != tc.want {
				t.Fatalf("githubActorIsAutomation(%q) = %v, want %v", tc.attributesJSON, got, tc.want)
			}
		})
	}
}
