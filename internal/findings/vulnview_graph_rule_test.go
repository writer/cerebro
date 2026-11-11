package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestVulnViewExternalAssetConcentratedSignalRetired(t *testing.T) {
	rule := newVulnViewExternalAssetConcentratedSignalRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("vulnview-external-asset-concentrated-signal does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.ID != vulnViewExternalAssetConcentratedSignalRuleID {
		t.Fatalf("RuleMetadata().ID = %q, want %q", definition.ID, vulnViewExternalAssetConcentratedSignalRuleID)
	}
	if definition.Lifecycle.Kind != LifecycleRetired || definition.Lifecycle.Anchor != AnchorNone {
		t.Fatalf("Lifecycle = %+v, want retired/none", definition.Lifecycle)
	}
	if definition.Maturity != RuleMaturityRetired {
		t.Fatalf("Maturity = %q, want %q", definition.Maturity, RuleMaturityRetired)
	}
	if err := definition.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatal("retired vulnview concentrated-signal rule does not implement GraphRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-finding-nuclei", SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "finding", "source": "nuclei"}}
	if request := graphRule.QueryFor(runtime); request.Query != "" {
		t.Fatalf("QueryFor() = %+v, want an empty query so graph_rule_service.go resolves stale open findings instead of re-querying", request)
	}
}

// TestVulnViewExternalAssetConcentratedSignalSupportsRuntimeUnchanged pins
// that the same VulnView external-attack-surface finding-family runtimes
// that used to carry open rows under this rule id still make the rule
// applicable after retirement, so graph-rule evaluation (and therefore
// stale-row auto-resolution, see graph_rule_service.go's
// retiredGraphRule/resolveStaleGraphFindings) keeps running for them;
// cloud_identity/prowler/github runtimes remain out of scope (Contract C8).
func TestVulnViewExternalAssetConcentratedSignalSupportsRuntimeUnchanged(t *testing.T) {
	rule := newVulnViewExternalAssetConcentratedSignalRule()
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{"nuclei", true},
		{"caido", true},
		{"port", true},
		{"dns", true},
		{"cloud_identity", false},
		{"prowler", false},
		{"github", false},
	} {
		runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-finding-" + tc.source, SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "finding", "source": tc.source}}
		if got := rule.SupportsRuntime(runtime); got != tc.want {
			t.Fatalf("SupportsRuntime(source=%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

// TestVulnViewExternalAssetConcentratedSignalNeverEmitsFromEvidenceRows pins
// that even if graph evidence rows were ever produced for a VulnView
// external-asset evidence query (e.g. a stale cache or a future regression
// reintroducing QueryFor), EvaluateRows never turns concentrated evidence
// into a standalone finding (North Star §10.2: concentrated same-asset
// signal counts are not attack-path composition).
func TestVulnViewExternalAssetConcentratedSignalNeverEmitsFromEvidenceRows(t *testing.T) {
	graphRule := newVulnViewExternalAssetConcentratedSignalRule().(GraphRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-finding-nuclei", SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "finding", "source": "nuclei"}}
	rows := []ports.CypherRow{{Values: map[string]any{
		"asset_urn":             "urn:cerebro:writer:external_asset:app.writer.com",
		"asset_label":           "app.writer.com",
		"asset_attributes_json": `{"asset_id":"app.writer.com"}`,
		"evidence": []any{
			map[string]any{
				"urn":                      "urn:cerebro:writer:vulnview_finding:1",
				"entity_type":              "vulnview.finding",
				"label":                    "exposed-panel",
				"attributes_json":          `{"severity":"critical","check_id":"exposed-panel","source":"nuclei"}`,
				"evidence_attributes_json": `{"event_id":"evt-1"}`,
			},
		},
	}}}
	findings, err := graphRule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d finding(s), want 0", len(findings))
	}
}
