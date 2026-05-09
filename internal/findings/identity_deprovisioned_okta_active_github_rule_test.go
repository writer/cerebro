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

func TestDeprovisionedOktaActiveGitHubRuleQueryScopesByRuntime(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	request := rule.QueryFor(runtime)
	if request.Query == "" {
		t.Fatal("QueryFor() returned empty query for fully-populated runtime")
	}
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("Params[tenant_id] = %v, want writer", got)
	}
	marker, ok := request.Params["okta_runtime_marker"].(string)
	if !ok {
		t.Fatalf("Params[okta_runtime_marker] type = %T, want string", request.Params["okta_runtime_marker"])
	}
	if !strings.Contains(marker, "writer-okta-prod") {
		t.Fatalf("Params[okta_runtime_marker] = %q, want to contain runtime id %q", marker, "writer-okta-prod")
	}
	if !strings.Contains(marker, "source_runtime_id") {
		t.Fatalf("Params[okta_runtime_marker] = %q, want to contain attribute key %q", marker, "source_runtime_id")
	}
	if !strings.Contains(request.Query, "$okta_runtime_marker") {
		t.Fatalf("Query missing $okta_runtime_marker predicate; without it findings cross runtimes:\n%s", request.Query)
	}
	if request.RowLimit != identityDeprovisionedOktaQueryRowLimit {
		t.Fatalf("RowLimit = %d, want %d", request.RowLimit, identityDeprovisionedOktaQueryRowLimit)
	}
}

func TestDeprovisionedOktaActiveGitHubRuleQueryRequiresRuntimeIdentity(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	cases := map[string]*cerebrov1.SourceRuntime{
		"missing tenant":  {Id: "writer-okta-prod", SourceId: "okta"},
		"missing runtime": {SourceId: "okta", TenantId: "writer"},
	}
	for name, runtime := range cases {
		t.Run(name, func(t *testing.T) {
			if request := rule.QueryFor(runtime); request.Query != "" {
				t.Fatalf("QueryFor(%s) returned populated query; rule must refuse to scan without tenant+runtime: %#v", name, request)
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

func TestDeprovisionedOktaActiveGitHubRuleFingerprintSeparatesRuntimes(t *testing.T) {
	rule := newDeprovisionedOktaActiveGitHubRule().(*deprovisionedOktaActiveGitHubRule)
	runtimeA := &cerebrov1.SourceRuntime{Id: "writer-okta-prod", SourceId: "okta", TenantId: "writer"}
	runtimeB := &cerebrov1.SourceRuntime{Id: "writer-okta-sandbox", SourceId: "okta", TenantId: "writer"}
	group := &deprovisionedOktaGroup{
		oktaUserURN:   "urn:cerebro:writer:okta.user:alice@writer.com",
		identityURN:   "urn:cerebro:writer:identity:email:alice@writer.com",
		githubUserURN: "urn:cerebro:writer:github.user:alice",
	}
	a := rule.buildFinding(runtimeA, "writer", group, deprovisionedOktaRuleFixedNow())
	b := rule.buildFinding(runtimeB, "writer", group, deprovisionedOktaRuleFixedNow())
	if a.ID == b.ID {
		t.Fatalf("findings collide across runtimes (id=%q); two okta runtimes touching the same identity must produce distinct finding IDs", a.ID)
	}
	if a.Fingerprint == b.Fingerprint {
		t.Fatalf("fingerprint identical across runtimes: %q", a.Fingerprint)
	}
}
