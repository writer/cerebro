package findings

import (
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
	cases := map[string]struct {
		runtime *cerebrov1.SourceRuntime
		want    bool
	}{
		"okta runtime":     {&cerebrov1.SourceRuntime{SourceId: "okta"}, true},
		"github runtime":   {&cerebrov1.SourceRuntime{SourceId: "github"}, true},
		"OKTA upper case":  {&cerebrov1.SourceRuntime{SourceId: "OKTA"}, true},
		"unrelated source": {&cerebrov1.SourceRuntime{SourceId: "aws"}, false},
		"empty source":     {&cerebrov1.SourceRuntime{}, false},
		"nil runtime":      {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rule.SupportsRuntime(tc.runtime); got != tc.want {
				t.Fatalf("SupportsRuntime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeprovisionedOktaActiveGitHubRuleFingerprintIsStableAcrossRuns(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	group := &deprovisionedOktaGroup{
		oktaUserURN:   "urn:cerebro:writer:okta.user:alice@writer.com",
		identityURN:   "urn:cerebro:writer:identity:email:alice@writer.com",
		githubUserURN: "urn:cerebro:writer:github.user:alice",
	}
	first := rule.buildFinding(runtime, "writer", group, deprovisionedOktaRuleFixedNow())
	second := rule.buildFinding(runtime, "writer", group, deprovisionedOktaRuleFixedNow())
	if first.ID != second.ID {
		t.Fatalf("finding ID drifted across evaluations: %q vs %q (fingerprint must hash stable inputs only)", first.ID, second.ID)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("finding fingerprint drifted: %q vs %q", first.Fingerprint, second.Fingerprint)
	}
}

// The persisted runtime_id on graph-rule findings must be a stable synthetic value, not
// the runtime that happened to trigger this evaluation, because the same fingerprint can
// be emitted by either an okta or a github runtime and UpsertFinding would otherwise flip
// the row between them every iteration.
func TestDeprovisionedOktaActiveGitHubRuleFindingPinsRuntimeID(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	group := &deprovisionedOktaGroup{
		oktaUserURN:   "urn:cerebro:writer:okta.user:alice@writer.com",
		identityURN:   "urn:cerebro:writer:identity:email:alice@writer.com",
		githubUserURN: "urn:cerebro:writer:github.user:alice",
	}
	oktaTriggered := rule.buildFinding(&cerebrov1.SourceRuntime{Id: "writer-okta-inventory", SourceId: "okta", TenantId: "writer"}, "writer", group, deprovisionedOktaRuleFixedNow())
	githubTriggered := rule.buildFinding(&cerebrov1.SourceRuntime{Id: "writer-github-audit", SourceId: "github", TenantId: "writer"}, "writer", group, deprovisionedOktaRuleFixedNow())
	if got := oktaTriggered.RuntimeID; !strings.HasPrefix(got, GraphRuleRuntimePrefix) {
		t.Fatalf("RuntimeID = %q, want prefix %q (synthetic graph-rule runtime keeps the row stable across triggering runtimes)", got, GraphRuleRuntimePrefix)
	}
	if oktaTriggered.RuntimeID != githubTriggered.RuntimeID {
		t.Fatalf("RuntimeID flipped across triggering runtimes (okta=%q github=%q); UpsertFinding would rebind the row each iteration", oktaTriggered.RuntimeID, githubTriggered.RuntimeID)
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
	group := &deprovisionedOktaGroup{
		oktaUserURN:   "urn:cerebro:writer:okta.user:alice@writer.com",
		identityURN:   "urn:cerebro:writer:identity:email:alice@writer.com",
		githubUserURN: "urn:cerebro:writer:github.user:alice",
	}
	a := rule.buildFinding(runtimeA, "writer", group, deprovisionedOktaRuleFixedNow())
	b := rule.buildFinding(runtimeB, "writer", group, deprovisionedOktaRuleFixedNow())
	if a.ID != b.ID {
		t.Fatalf("findings split across okta runtimes for the same offender (a=%q b=%q); rule is tenant-scoped and must produce one finding per (tenant, okta_user, identity, github_user)", a.ID, b.ID)
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
		oktaUserURN:   "urn:cerebro:writer:okta.user:alice@writer.com",
		identityURN:   identityURN,
		githubUserURN: githubURN,
	}
	groupTwo := &deprovisionedOktaGroup{
		oktaUserURN:   "urn:cerebro:writer:okta.user:bob@writer.com",
		identityURN:   identityURN,
		githubUserURN: githubURN,
	}
	a := rule.buildFinding(runtime, "writer", groupOne, deprovisionedOktaRuleFixedNow())
	b := rule.buildFinding(runtime, "writer", groupTwo, deprovisionedOktaRuleFixedNow())
	if a.ID == b.ID {
		t.Fatalf("two distinct deprovisioned okta users collapsed onto the same finding (id=%q); fingerprint must include okta_user_urn", a.ID)
	}
}
