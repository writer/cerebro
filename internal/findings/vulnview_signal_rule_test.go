package findings

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestVulnViewActionableExternalFindingRetired(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("vulnview-actionable-external-finding does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.ID != vulnViewActionableExternalFindingRuleID {
		t.Fatalf("RuleMetadata().ID = %q, want %q", definition.ID, vulnViewActionableExternalFindingRuleID)
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
	retirementRule, ok := rule.(openFindingRetirementRule)
	if !ok || !retirementRule.RetiresOpenFindings() {
		t.Fatalf("RetiresOpenFindings(%q) = false, want true so stale open findings are resolved", rule.Spec().GetId())
	}
}

// TestVulnViewActionableExternalFindingNeverOpensOrReopens pins the North
// Star cutover (§10.2): a single upstream VulnView finding never becomes a
// standalone Cerebro finding, for any source lifecycle transition --
// initial open, fixed, reopened, accepted-risk, false-positive-triaged,
// triage-expired, or a replayed/reordered numeric version of any of these.
// The source observation (vulnview.finding) and its triage/version are
// projected and preserved independently of this rule (internal/sourceprojection/vulnview.go);
// this rule must never re-derive an active Cerebro verdict from them.
func TestVulnViewActionableExternalFindingNeverOpensOrReopens(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-finding-nuclei", SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "finding", "source": "nuclei"}}
	occurredAt := timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	cases := []struct {
		name        string
		status      string
		version     string
		triageState string
	}{
		{"open_critical", "open", "1", ""},
		{"fixed", "fixed", "2", ""},
		{"reopened", "open", "3", ""},
		{"accepted_risk", "open", "4", "accepted"},
		{"false_positive", "open", "5", "false_positive"},
		{"triage_expired", "open", "6", "expired"},
		{"replayed_older_version_after_fixed", "open", "1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]string{
				"asset_urn":  "urn:cerebro:writer:external_asset:admin.writer.com",
				"finding_id": "scan-1:exposed-panel:admin.writer.com",
				"source":     "nuclei",
				"check_id":   "exposed-panel",
				"title":      "Exposed Admin Panel",
				"severity":   "high",
				"status":     tc.status,
				"asset":      "admin.writer.com",
				"asset_id":   "admin.writer.com",
				"version":    tc.version,
			}
			if tc.triageState != "" {
				attrs["triage_state"] = tc.triageState
			}
			event := &cerebrov1.EventEnvelope{
				Id: "vulnview-" + tc.name, TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
				OccurredAt: occurredAt,
				Attributes: attrs,
			}
			records, err := rule.Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate() returned %d finding(s), want 0", len(records))
			}
		})
	}
}

// TestVulnViewActionableExternalFindingNeverOpensAcrossAllAttackSurfaceSources
// repeats the strongest historical trigger (open, actionable severity)
// across every VulnView external attack-surface source that used to match
// this rule before retirement.
func TestVulnViewActionableExternalFindingNeverOpensAcrossAllAttackSurfaceSources(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	for _, source := range []string{"nuclei", "caido", "port", "dns"} {
		t.Run(source, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: "example-vulnview-" + source, SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": "finding", "source": source}}
			event := &cerebrov1.EventEnvelope{
				Id: "vulnview-" + source, TenantId: "writer", SourceId: "vulnview", Kind: "vulnview.finding",
				OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
				Attributes: map[string]string{
					"asset_urn":  "urn:cerebro:writer:external_asset:admin.writer.com",
					"finding_id": "scan-1:check:admin.writer.com",
					"source":     source,
					"check_id":   "check",
					"severity":   "critical",
					"status":     "open",
				},
			}
			records, err := rule.Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate() returned %d finding(s), want 0", len(records))
			}
		})
	}
}
