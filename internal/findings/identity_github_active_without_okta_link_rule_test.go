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
	// the recency check.
	if strings.Contains(request.Query, "NOT EXISTS") {
		t.Fatalf("Query uses NOT EXISTS for bridge check; stale represents_identity edges would mask shadow access. Must OPTIONAL MATCH and check `at` recency in EvaluateRows:\n%s", request.Query)
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
		targets[urn] = githubActiveWithoutOktaTarget{urn: urn, entityType: "github.repo", label: urn}
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
	group := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_repo:writer/cerebro")
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
	group := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_repo:writer/cerebro")
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
	group := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_repo:writer/cerebro")
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
	oneTarget := githubActiveWithoutOktaRuleGroupWithTargets("urn:cerebro:writer:github_repo:writer/cerebro")
	threeTargets := githubActiveWithoutOktaRuleGroupWithTargets(
		"urn:cerebro:writer:github_repo:writer/cerebro",
		"urn:cerebro:writer:github_repo:writer/palmyra",
		"urn:cerebro:writer:github_repo:writer/some-other-repo",
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
		targets:         map[string]githubActiveWithoutOktaTarget{"urn:cerebro:writer:github_repo:writer/cerebro": {urn: "urn:cerebro:writer:github_repo:writer/cerebro"}},
	}
	groupBob := &githubActiveWithoutOktaGroup{
		githubUserURN:   "urn:cerebro:writer:github.user:bob",
		githubUserLabel: "bob",
		targets:         map[string]githubActiveWithoutOktaTarget{"urn:cerebro:writer:github_repo:writer/cerebro": {urn: "urn:cerebro:writer:github_repo:writer/cerebro"}},
	}
	a := rule.buildFinding(runtime, "writer", groupAlice, githubActiveWithoutOktaRuleFixedNow())
	b := rule.buildFinding(runtime, "writer", groupBob, githubActiveWithoutOktaRuleFixedNow())
	if a.ID == b.ID {
		t.Fatalf("two distinct shadow github users collapsed onto the same finding (id=%q); fingerprint must include github_user_urn", a.ID)
	}
}

func githubActiveWithoutOktaRuleActedAttrs(at time.Time) string {
	payload := map[string]string{
		"action":   "git.clone",
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
			entityType:          "github.repo",
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

// githubActiveWithoutOktaRuleBridgeAttrs builds a represents_identity edge's
// attributes_json with an optional `at` timestamp, matching what the
// neo4j store persists.
func githubActiveWithoutOktaRuleBridgeAttrs(at time.Time) string {
	payload := map[string]string{}
	if !at.IsZero() {
		payload["at"] = at.UTC().Format(time.RFC3339)
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
	)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0 (acted_on without `at` must not trigger; we cannot prove recency)", len(findings))
	}
}

// Bot logins (dependabot[bot], github-actions[bot], renovate, etc.) are
// automation accounts and will never be in Okta by design. Surfacing them as
// shadow access would flood the queue with non-actionable findings; the rule
// must filter them at evaluation time.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsSkipsBotLogins(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	rows := []ports.CypherRow{}
	for _, login := range []string{
		"dependabot[bot]",
		"github-actions[bot]",
		"renovate[bot]",
		"dependabot",
		"github-actions",
		"renovate",
		"renovate-bot",
		"mergify[bot]",
		"DEPENDABOT[BOT]",
	} {
		rows = append(rows, githubActiveWithoutOktaRuleRow(
			githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
			"urn:cerebro:writer:github.user:"+strings.ToLower(login),
			login,
			"urn:cerebro:writer:github_repo:writer/cerebro",
		))
	}
	findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0 (bot logins must be filtered)", len(findings))
	}
}

// Many real GitHub usernames legitimately look like nothing in particular
// even though they don't bridge to Okta yet (e.g. external collaborators on
// a private repo, recent hires whose Okta inventory hasn't synced). The bot
// filter must NOT swallow human-shaped logins that merely contain a vendor
// name or look bot-adjacent.
func TestGitHubActiveWithoutOktaLinkRuleEvaluateRowsAcceptsHumanLoginsThatLookBotAdjacent(t *testing.T) {
	rule := newGitHubActiveWithoutOktaLinkRule().(*githubActiveWithoutOktaLinkRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}
	rows := []ports.CypherRow{}
	humanLogins := []string{"renovate-team-lead", "dependable-alice", "github-actionsperson"}
	for _, login := range humanLogins {
		rows = append(rows, githubActiveWithoutOktaRuleRow(
			githubActiveWithoutOktaRuleActedAttrs(time.Now().UTC().Add(-1*time.Hour)),
			"urn:cerebro:writer:github.user:"+login,
			login,
			"urn:cerebro:writer:github_repo:writer/cerebro",
		))
	}
	findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != len(humanLogins) {
		t.Fatalf("EvaluateRows() returned %d findings, want %d (human-shaped logins must NOT be filtered as bots)", len(findings), len(humanLogins))
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
	)
	rowTwo := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(at),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_repo:writer/palmyra",
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
	if got, want := finding.Attributes["target_urns"], "urn:cerebro:writer:github_repo:writer/cerebro,urn:cerebro:writer:github_repo:writer/palmyra"; got != want {
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
	)
	rowAlice := githubActiveWithoutOktaRuleRow(
		githubActiveWithoutOktaRuleActedAttrs(at),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_repo:writer/cerebro",
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
		"row missing github user": {{Values: map[string]any{"target_urn": "urn:cerebro:writer:github_repo:writer/cerebro"}}},
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
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
				"urn:cerebro:writer:github_repo:writer/cerebro",
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
		"urn:cerebro:writer:github_repo:writer/cerebro",
		"",
		"",
	)
	rowFreshBridge := githubActiveWithoutOktaRuleRowWithBridge(
		githubActiveWithoutOktaRuleActedAttrs(freshAt),
		"urn:cerebro:writer:github.user:alice",
		"alice",
		"urn:cerebro:writer:github_repo:writer/palmyra",
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
			{urn: "urn:cerebro:writer:github_repo:writer/cerebro", entityType: "github.repo", label: "writer/cerebro", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(freshAt)},
			{urn: "urn:cerebro:writer:github_repo:writer/palmyra", entityType: "github.repo", label: "writer/palmyra", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(freshAt)},
			{urn: "urn:cerebro:writer:github_repo:writer/some-other-repo", entityType: "github.repo", label: "writer/some-other-repo", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(freshAt)},
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
	if got, want := finding.Attributes["target_urns"], "urn:cerebro:writer:github_repo:writer/cerebro,urn:cerebro:writer:github_repo:writer/palmyra,urn:cerebro:writer:github_repo:writer/some-other-repo"; got != want {
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
			{urn: "urn:cerebro:writer:github_repo:writer/fresh", entityType: "github.repo", label: "writer/fresh", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(now.Add(-1 * time.Hour))},
			{urn: "urn:cerebro:writer:github_repo:writer/stale", entityType: "github.repo", label: "writer/stale", actedAttributesJSON: githubActiveWithoutOktaRuleActedAttrs(now.Add(-90 * 24 * time.Hour))},
			{urn: "urn:cerebro:writer:github_repo:writer/missing-at", entityType: "github.repo", label: "writer/missing-at", actedAttributesJSON: `{"action":"git.clone"}`},
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
	if got, want := finding.Attributes["target_urns"], "urn:cerebro:writer:github_repo:writer/fresh"; got != want {
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
					urn:                 "urn:cerebro:writer:github_repo:writer/cerebro",
					entityType:          "github.repo",
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

func TestIsGitHubBotLogin(t *testing.T) {
	cases := map[string]bool{
		"dependabot[bot]":      true,
		"github-actions[bot]":  true,
		"renovate[bot]":        true,
		"renovate":             true,
		"dependabot":           true,
		"github-actions":       true,
		"renovate-bot":         true,
		"mergify":              true,
		"mergify-bot":          true,
		"MERGIFY[BOT]":         true,
		"  dependabot[bot]  ":  true,
		"":                     false,
		"alice":                false,
		"alice-bot-fan":        false,
		"renovate-team-lead":   false,
		"dependable-alice":     false,
		"github-actionsperson": false,
	}
	for login, want := range cases {
		t.Run(login, func(t *testing.T) {
			if got := isGitHubBotLogin(login); got != want {
				t.Fatalf("isGitHubBotLogin(%q) = %v, want %v", login, got, want)
			}
		})
	}
}
