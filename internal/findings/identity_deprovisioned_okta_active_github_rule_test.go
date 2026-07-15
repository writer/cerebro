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

func deprovisionedOktaRuleFixedNow() time.Time {
	return time.Date(2025, time.March, 5, 12, 0, 0, 0, time.UTC)
}

func TestDeprovisionedOktaActiveGitHubRuleQueryScopesByTenant(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	request := rule.QueryFor(runtime)
	if request.Query == "" {
		t.Fatal("QueryFor() returned empty query for fully-populated runtime")
	}
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("Params[tenant_id] = %v, want writer", got)
	}
	if _, hasMarker := request.Params["okta_runtime_marker"]; hasMarker {
		t.Fatalf("Params unexpectedly contained okta_runtime_marker; the okta.user node merges runtime ids across syncs so a marker filter would alias inventory status onto whichever runtime touched the node last")
	}
	if strings.Contains(request.Query, "okta_runtime_marker") {
		t.Fatalf("Query references okta_runtime_marker; rule must be tenant-scoped only:\n%s", request.Query)
	}
	if !strings.Contains(strings.ToUpper(request.Query), `"STATUS":"DEPROVISIONED"`) {
		t.Fatalf("Query missing deprovisioned status predicate:\n%s", request.Query)
	}
	if request.RowLimit != identityDeprovisionedOktaQueryRowLimit {
		t.Fatalf("RowLimit = %d, want %d", request.RowLimit, identityDeprovisionedOktaQueryRowLimit)
	}
}

func TestDeprovisionedOktaActiveGitHubRuleQueryRequiresTenant(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	if request := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta"}); request.Query != "" {
		t.Fatalf("QueryFor() returned populated query without tenant id; rule must refuse to scan: %#v", request)
	}
}

// The rule's cypher joins okta.user lifecycle state with github.user acted_on edges, so the
// finding can change after a fresh ingest from EITHER side. SupportsRuntime must accept both
// or detections lag until the next time the other source happens to sync.
func TestDeprovisionedOktaActiveGitHubRuleSupportsBothOktaAndGitHub(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	withFamily := func(sourceID, family string) *cerebrov1.SourceRuntime {
		return &cerebrov1.SourceRuntime{SourceId: sourceID, Config: map[string]string{"family": family}}
	}
	cases := map[string]struct {
		runtime *cerebrov1.SourceRuntime
		want    bool
	}{
		"okta user runtime":             {withFamily("okta", "user"), true},
		"github audit runtime":          {withFamily("github", "audit"), true},
		"OKTA user upper case":          {withFamily("OKTA", "USER"), true},
		"okta audit runtime":            {withFamily("okta", "audit"), false},
		"okta group runtime":            {withFamily("okta", "group_membership"), false},
		"github pull-request runtime":   {withFamily("github", "pull_request"), false},
		"github dependabot runtime":     {withFamily("github", "dependabot_alert"), false},
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

func deprovisionedOktaRuleGroupWithIdentities(identityURNs ...string) *deprovisionedOktaGroup {
	identities := map[string]struct{}{}
	for _, urn := range identityURNs {
		identities[urn] = struct{}{}
	}
	return &deprovisionedOktaGroup{
		oktaUserURN:    "urn:cerebro:writer:okta.user:alice@writer.com",
		githubUserURN:  "urn:cerebro:writer:github.user:alice",
		identityURNs:   identities,
		identityLabels: map[string]struct{}{},
	}
}

func TestDeprovisionedOktaActiveGitHubRuleFingerprintIsStableAcrossRuns(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	group := deprovisionedOktaRuleGroupWithIdentities("urn:cerebro:writer:identity:email:alice@writer.com")
	first := rule.buildFinding(runtime, "writer", group, deprovisionedOktaRuleFixedNow())
	second := rule.buildFinding(runtime, "writer", group, deprovisionedOktaRuleFixedNow())
	if first.ID != second.ID {
		t.Fatalf("finding ID drifted across evaluations: %q vs %q (fingerprint must hash stable inputs only)", first.ID, second.ID)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("finding fingerprint drifted: %q vs %q", first.Fingerprint, second.Fingerprint)
	}
}

func TestDeprovisionedOktaActiveGitHubRuleDoesNotAdvertiseGraphAction(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	group := deprovisionedOktaRuleGroupWithIdentities("urn:cerebro:writer:identity:email:alice@writer.com")
	finding := rule.buildFinding(runtime, "writer", group, deprovisionedOktaRuleFixedNow())
	if got, ok := finding.Attributes["graph_actions_allowed"]; ok {
		t.Fatalf("graph_actions_allowed = %q, want attribute omitted until a downstream remediation is certified", got)
	}
}

// The rule stamps the triggering runtime onto the persisted record so the finding stays
// addressable through the real runtime-scoped read paths (Service.ListFindings, ListEvidence,
// reports, GRC). The store pins runtime_id on first insert via UpsertFinding's ON CONFLICT
// clause, so the row does not flip when both Okta and GitHub triggers reevaluate the same
// offender; that behavior is exercised in the postgres store tests. Here we just assert
// the rule's contract: stamp the real triggering runtime, never a synthetic value.
func TestDeprovisionedOktaActiveGitHubRuleFindingStampsTriggeringRuntimeID(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	group := deprovisionedOktaRuleGroupWithIdentities("urn:cerebro:writer:identity:email:alice@writer.com")
	oktaTriggered := rule.buildFinding(&cerebrov1.SourceRuntime{Id: "writer-okta-inventory", SourceId: "okta", TenantId: "writer"}, "writer", group, deprovisionedOktaRuleFixedNow())
	githubTriggered := rule.buildFinding(&cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}, "writer", group, deprovisionedOktaRuleFixedNow())
	if got := oktaTriggered.RuntimeID; got != "writer-okta-inventory" {
		t.Fatalf("okta-triggered RuntimeID = %q, want real triggering runtime; synthetic ids would make the finding unreachable through runtime-scoped APIs", got)
	}
	if got := githubTriggered.RuntimeID; got != "writer-github-audit" {
		t.Fatalf("github-triggered RuntimeID = %q, want real triggering runtime", got)
	}
	// Both triggers MUST share the same fingerprint; pinning to first-observed happens at
	// the store layer so subsequent triggers keep the original runtime instead of flipping.
	if oktaTriggered.Fingerprint != githubTriggered.Fingerprint {
		t.Fatalf("fingerprints differ across triggering runtimes (okta=%q github=%q); same offender must produce same id so the store can pin runtime", oktaTriggered.Fingerprint, githubTriggered.Fingerprint)
	}
	if got := oktaTriggered.Attributes["source_runtime_id"]; got != "writer-okta-inventory" {
		t.Fatalf("attributes[source_runtime_id] = %q, want triggering runtime preserved for telemetry", got)
	}
}

// Two okta runtimes (e.g. inventory + audit) project to the same okta.user node by
// (tenant_id, user_id), so the same offender must collapse onto one tenant-scoped finding.
// Including runtime_id in the fingerprint would split this into duplicates the moment a
// second okta runtime synced.
func TestDeprovisionedOktaActiveGitHubRuleFingerprintCollapsesAcrossOktaRuntimes(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtimeA := &cerebrov1.SourceRuntime{Id: "writer-okta-inventory", SourceId: "okta", TenantId: "writer"}
	runtimeB := &cerebrov1.SourceRuntime{Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"}
	group := deprovisionedOktaRuleGroupWithIdentities("urn:cerebro:writer:identity:email:alice@writer.com")
	a := rule.buildFinding(runtimeA, "writer", group, deprovisionedOktaRuleFixedNow())
	b := rule.buildFinding(runtimeB, "writer", group, deprovisionedOktaRuleFixedNow())
	if a.ID != b.ID {
		t.Fatalf("findings split across okta runtimes for the same offender (a=%q b=%q); rule is tenant-scoped and must produce one finding per (tenant, okta_user, github_user)", a.ID, b.ID)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprints split across okta runtimes: %q vs %q", a.Fingerprint, b.Fingerprint)
	}
}

func TestDeprovisionedOktaActiveGitHubRuleFingerprintSeparatesOktaUsers(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-inventory", SourceId: "okta", TenantId: "writer"}
	identityURN := "urn:cerebro:writer:identity:email:shared@writer.com"
	githubURN := "urn:cerebro:writer:github.user:shared"
	groupOne := &deprovisionedOktaGroup{
		oktaUserURN:    "urn:cerebro:writer:okta.user:alice@writer.com",
		githubUserURN:  githubURN,
		identityURNs:   map[string]struct{}{identityURN: {}},
		identityLabels: map[string]struct{}{},
	}
	groupTwo := &deprovisionedOktaGroup{
		oktaUserURN:    "urn:cerebro:writer:okta.user:bob@writer.com",
		githubUserURN:  githubURN,
		identityURNs:   map[string]struct{}{identityURN: {}},
		identityLabels: map[string]struct{}{},
	}
	a := rule.buildFinding(runtime, "writer", groupOne, deprovisionedOktaRuleFixedNow())
	b := rule.buildFinding(runtime, "writer", groupTwo, deprovisionedOktaRuleFixedNow())
	if a.ID == b.ID {
		t.Fatalf("two distinct deprovisioned okta users collapsed onto the same finding (id=%q); fingerprint must include okta_user_urn", a.ID)
	}
}

// The graph projector links the same Okta/GitHub account pair to multiple `identity`
// nodes when okta.user has distinct email and login attributes, or when github.audit
// links both `actor` and `external_identity_nameid`. The rule's cypher join then
// emits one row per identity node, but those rows describe the same offboarding gap.
// This test pins that the rule collapses them onto a single CRITICAL finding rather
// than emitting one per identity node.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsCollapsesDuplicateIdentitiesPerAccountPair(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	emailRow := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	loginRow := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	loginRow.Values["identity_urn"] = "urn:cerebro:writer:identity:login:alice"
	loginRow.Values["identity_label"] = "alice"
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{emailRow, loginRow})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1; same Okta/GitHub pair must collapse across identity nodes (got: %#v)", got, findings)
	}
	finding := findings[0]
	if got, want := finding.Attributes["identity_urns"], "urn:cerebro:writer:identity:email:alice@writer.com,urn:cerebro:writer:identity:login:alice"; got != want {
		t.Fatalf("identity_urns = %q, want %q (full set must be retained as telemetry)", got, want)
	}
}

// The fingerprint must be invariant to which identity node the cypher walked
// through, otherwise reprocessing the same offboarding gap from a different
// identity ordering would create a fresh CRITICAL finding instead of
// reopening the existing one. This pins the contract on buildFinding directly.
func TestDeprovisionedOktaActiveGitHubRuleFingerprintIgnoresIdentityNode(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	emailGroup := deprovisionedOktaRuleGroupWithIdentities("urn:cerebro:writer:identity:email:alice@writer.com")
	loginGroup := deprovisionedOktaRuleGroupWithIdentities("urn:cerebro:writer:identity:login:alice")
	bothGroup := deprovisionedOktaRuleGroupWithIdentities(
		"urn:cerebro:writer:identity:email:alice@writer.com",
		"urn:cerebro:writer:identity:login:alice",
	)
	emailFinding := rule.buildFinding(runtime, "writer", emailGroup, deprovisionedOktaRuleFixedNow())
	loginFinding := rule.buildFinding(runtime, "writer", loginGroup, deprovisionedOktaRuleFixedNow())
	bothFinding := rule.buildFinding(runtime, "writer", bothGroup, deprovisionedOktaRuleFixedNow())
	if emailFinding.Fingerprint != loginFinding.Fingerprint {
		t.Fatalf("fingerprint changes with identity node (email=%q login=%q); same Okta/GitHub pair must produce one fingerprint regardless of which identity node was traversed", emailFinding.Fingerprint, loginFinding.Fingerprint)
	}
	if emailFinding.Fingerprint != bothFinding.Fingerprint {
		t.Fatalf("fingerprint changes when both identity nodes match (single=%q both=%q); the set of matched identities is telemetry, not identity", emailFinding.Fingerprint, bothFinding.Fingerprint)
	}
}

func deprovisionedOktaRuleActedAttrs(at time.Time) string {
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

// deprovisionedOktaRuleEmailIdentityAttrs mirrors the represents_identity edge
// payload that identifierEvidenceAttributes emits when the projector resolves
// an identifier as an email (match_type=exact_email at confidence=0.95). The
// rule rejects any other match_type, so test rows must use this shape to land
// in the email-only acceptance branch.
func deprovisionedOktaRuleEmailIdentityAttrs(at time.Time) string {
	return deprovisionedOktaRuleIdentityAttrs("email", "alice@writer.com", "exact_email", "0.95", at)
}

// deprovisionedOktaRuleLoginIdentityAttrs mirrors the represents_identity edge
// payload that identifierEvidenceAttributes emits for raw GitHub usernames
// (match_type=login at confidence=0.60). A username collision must not produce
// a CRITICAL finding even when both `at` stamps are recent, so this fixture
// exists specifically to drive the login-rejection regression tests.
func deprovisionedOktaRuleLoginIdentityAttrs(at time.Time) string {
	return deprovisionedOktaRuleIdentityAttrs("login", "alice", "login", "0.60", at)
}

func deprovisionedOktaRuleIdentityAttrs(identifierType, identifierValue, matchType, confidence string, at time.Time) string {
	payload := map[string]string{
		"confidence":       confidence,
		"evidence_type":    "shared_identifier",
		"identifier_type":  identifierType,
		"identifier_value": identifierValue,
		"match_type":       matchType,
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

func deprovisionedOktaRuleRow(actedAttributesJSON string) ports.CypherRow {
	recentEmail := deprovisionedOktaRuleEmailIdentityAttrs(time.Now().UTC().Add(-1 * time.Hour))
	return ports.CypherRow{Values: map[string]any{
		"okta_user_urn":                   "urn:cerebro:writer:okta.user:alice@writer.com",
		"okta_user_label":                 "Alice",
		"okta_attributes_json":            `{"status":"DEPROVISIONED"}`,
		"identity_urn":                    "urn:cerebro:writer:identity:email:alice@writer.com",
		"identity_label":                  "alice@writer.com",
		"github_user_urn":                 "urn:cerebro:writer:github.user:alice",
		"github_user_label":               "alice",
		"target_urn":                      "urn:cerebro:writer:github_code_repository:writer/cerebro",
		"target_entity_type":              "github_code_repository",
		"target_label":                    "writer/cerebro",
		"acted_attributes_json":           actedAttributesJSON,
		"okta_identity_attributes_json":   recentEmail,
		"github_identity_attributes_json": recentEmail,
	}}
}

// Recent acted_on edges are the only source of truth that a deprovisioned identity is
// "still active" right now. Without this, the rule could only ever say "this user has
// touched github at some point in history", which is true forever once a single edge
// exists and would keep findings open indefinitely.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsEmitsForRecentActedOn(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1 (recent acted_on must trigger)", len(findings))
	}
}

// An edge whose latest action is older than the recency window is stale history,
// not current access. The previous behavior treated it as proof of activity and
// kept the finding open even after the GitHub account was suspended; this regression
// test pins the new contract: stale-only groups produce no finding so the
// deprovisioning surface auto-resolves once activity stops.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsSkipsStaleActedOn(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	staleAt := time.Now().UTC().Add(-(identityDeprovisionedOktaRecencyWindow + 24*time.Hour))
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(staleAt))
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings for stale acted_on edge, want 0; rule must require recent activity", len(findings))
	}
}

// Acted_on edges projected before the at-stamp change have no `at` attribute at all.
// We refuse to fire on those rather than papering over them with a synthetic timestamp:
// the rule cannot prove the activity is recent, so it must not claim "still active".
// Once the projector backfills, rows reappear with `at` and the rule re-emits naturally.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsSkipsUnstampedActedOn(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	row := deprovisionedOktaRuleRow(`{"action":"git.clone","event_id":"legacy"}`)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings for legacy acted_on edge without `at`, want 0", len(findings))
	}
}

// A user can have many acted_on edges where some are recent and some are stale (e.g.
// touched repo A last week, repo B two years ago). We must still emit the finding,
// but only attribute it to the recent target(s); reporting the stale target would
// mislead the responder into thinking the user is still pulling from a repo they
// haven't touched in years.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsKeepsRecentDropsStaleWithinSameGroup(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	recentRow := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-2 * time.Hour)))
	staleAt := time.Now().UTC().Add(-(identityDeprovisionedOktaRecencyWindow + 7*24*time.Hour))
	staleRow := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(staleAt))
	staleRow.Values["target_urn"] = "urn:cerebro:writer:github_code_repository:writer/legacy"
	staleRow.Values["target_label"] = "writer/legacy"
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{recentRow, staleRow})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1 (group has at least one recent target)", len(findings))
	}
	finding := findings[0]
	if got := finding.Attributes["target_count"]; got != "1" {
		t.Fatalf("target_count = %q, want 1; stale-only target must not be reported", got)
	}
	if got := finding.Attributes["target_urns"]; got != "urn:cerebro:writer:github_code_repository:writer/cerebro" {
		t.Fatalf("target_urns = %q, want only the recent target", got)
	}
}

// A malformed `at` (not RFC3339) is treated the same as a missing one: we cannot
// prove recency, so we do not fire. This guards against future projector bugs that
// might write a non-conforming string and silently keep a finding open.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsSkipsMalformedAt(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	row := deprovisionedOktaRuleRow(`{"action":"git.clone","event_id":"weird","at":"yesterday"}`)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings with unparseable `at`, want 0", len(findings))
	}
}

// represents_identity edges are upsert-only: when an Okta email/login (or a
// GitHub external_identity_nameid) is renamed, the old identity node stays
// linked to both accounts in the graph. The cypher `(o)-[oi]->(id)<-[gi]-(g)`
// would otherwise keep matching through the stale identity node forever and
// the rule would emit (or fail to auto-resolve) findings for accounts whose
// current identifiers no longer overlap. We require BOTH the okta-side and
// github-side identifier links to have been re-asserted within the recency
// window before treating the join as evidence.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsSkipsStaleOktaIdentifierEdge(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	staleAt := time.Now().UTC().Add(-(identityDeprovisionedOktaRecencyWindow + 24*time.Hour))
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	row.Values["okta_identity_attributes_json"] = deprovisionedOktaRuleActedAttrs(staleAt)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings with stale okta represents_identity edge, want 0; rename-stale joins must not keep findings open", len(findings))
	}
}

func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsSkipsStaleGitHubIdentifierEdge(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	staleAt := time.Now().UTC().Add(-(identityDeprovisionedOktaRecencyWindow + 24*time.Hour))
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	row.Values["github_identity_attributes_json"] = deprovisionedOktaRuleActedAttrs(staleAt)
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings with stale github represents_identity edge, want 0", len(findings))
	}
}

// represents_identity edges projected before the at-stamp change have no `at`
// at all. We refuse to fire on those for the same reason as missing-at acted_on
// edges: we cannot prove the identifier link is current, so we cannot honestly
// claim the deprovisioned account is "still active". Once the projector
// backfills, these rows reappear with `at` and the rule re-emits naturally.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsSkipsUnstampedIdentifierEdges(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	row.Values["okta_identity_attributes_json"] = `{"identifier_type":"email","identifier_value":"alice@writer.com"}`
	row.Values["github_identity_attributes_json"] = `{"identifier_type":"login","identifier_value":"alice"}`
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings for legacy identifier edges without `at`, want 0", len(findings))
	}
}

// The projector emits a represents_identity edge for every identifier value,
// including raw GitHub usernames where match_type=login is stamped at
// confidence=0.60. Two unrelated people who happen to share a username
// (e.g. okta login "alice" vs github login "alice") would otherwise satisfy
// the rule's cypher join through the shared identity:login node and produce
// a CRITICAL false positive against an unrelated GitHub account. The rule
// must require the identifier match on BOTH sides to be email-based
// (exact_email/extracted_email), even when both edges are recent.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsRejectsLoginOnlyMatch(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	loginAttrs := deprovisionedOktaRuleLoginIdentityAttrs(time.Now().UTC().Add(-1 * time.Hour))
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	row.Values["identity_urn"] = "urn:cerebro:writer:identity:login:alice"
	row.Values["identity_label"] = "alice"
	row.Values["okta_identity_attributes_json"] = loginAttrs
	row.Values["github_identity_attributes_json"] = loginAttrs
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings for login-only identifier match, want 0; username collision must not produce a CRITICAL finding", len(findings))
	}
}

// Asymmetric variant: one side is a high-confidence email match, the other a
// login. That is still not enough — the join only proves account ownership
// when both endpoints anchor on a shared email, so a single login leg breaks
// the proof and the rule must refuse to fire.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsRejectsLoginOnOktaSide(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	row.Values["okta_identity_attributes_json"] = deprovisionedOktaRuleLoginIdentityAttrs(time.Now().UTC().Add(-1 * time.Hour))
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings when okta-side identifier match is login-only, want 0; both sides must anchor on an email", len(findings))
	}
}

func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsRejectsLoginOnGitHubSide(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	row.Values["github_identity_attributes_json"] = deprovisionedOktaRuleLoginIdentityAttrs(time.Now().UTC().Add(-1 * time.Hour))
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings when github-side identifier match is login-only, want 0; both sides must anchor on an email", len(findings))
	}
}

// A GitHub-side extracted_email match (e.g. derived from a noreply email) is a
// 0.85-confidence email signal — strong enough that the rule should treat it
// like exact_email and emit. This pins the contract that the email gate covers
// both email match types, not just exact_email, so the projector's existing
// extracted_email path does not silently lose findings.
func TestDeprovisionedOktaActiveGitHubRuleEvaluateRowsAcceptsExtractedEmailMatch(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	row := deprovisionedOktaRuleRow(deprovisionedOktaRuleActedAttrs(time.Now().UTC().Add(-1 * time.Hour)))
	row.Values["github_identity_attributes_json"] = deprovisionedOktaRuleIdentityAttrs("email", "alice@writer.com", "extracted_email", "0.85", time.Now().UTC().Add(-1*time.Hour))
	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings for extracted_email match, want 1; extracted_email is a high-confidence email signal", len(findings))
	}
}
