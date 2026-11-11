package findings

import (
	"context"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
)

const vulnViewExternalAssetConcentratedSignalRuleID = "vulnview-external-asset-concentrated-signal"

type vulnViewExternalAssetConcentratedSignalRule struct {
	definition RuleDefinition
}

// newVulnViewExternalAssetConcentratedSignalRule retires the VulnView
// same-asset signal-count aggregate. Per North Star §10.2, the mere count of
// upstream VulnView findings sharing an asset does not, by itself, compose
// an attack path and must not manufacture a standalone Cerebro finding
// presented as attack-path composition; a genuinely distinct composed path
// has its own existing graph-rule contract. VulnView findings remain
// authoritative source observations and graph evidence
// (external.asset -[has_evidence]-> vulnview.finding, see
// internal/sourceprojection/vulnview.go) only.
//
// The rule keeps its id/name/output-kind/control-refs and the graph-rule
// retirement convention: QueryFor always returns an empty query, so
// graph_rule_service.go's retiredGraphRule/resolveStaleGraphFindings
// resolves any open rows under this rule id -- tenant+rule scoped, not
// limited to the evaluating runtime -- whenever the graph-rule evaluation
// runs for a supporting runtime. Rows in a tenant with no currently
// evaluated supporting runtime (e.g. only legacy
// writer-vulnview-vulnerability/writer-vulnview-dns-alert runtimes) are
// retired through the existing `cerebro closeout` procedure instead
// (internal/findings/closeout.go CloseoutSelector).
func newVulnViewExternalAssetConcentratedSignalRule() Rule {
	return &vulnViewExternalAssetConcentratedSignalRule{definition: RuleDefinition{
		ID:          vulnViewExternalAssetConcentratedSignalRuleID,
		Name:        "VulnView External Asset Concentrated Signal",
		Description: "Retired: concentrated VulnView evidence on an external asset no longer manufactures a standalone Cerebro finding. Retained so stale open findings auto-resolve; durable coverage stays with the VulnView source observation and graph evidence.",
		SourceID:    "vulnview",
		EventKinds:  []string{"vulnview.finding"},
		OutputKind:  "finding.vulnview_external_asset_concentrated_signal",
		Severity:    "dynamic",
		Status:      "retired",
		Maturity:    RuleMaturityRetired,
		Tags:        []string{"vulnview", "graph", "attack-surface", "prioritization", "retired", "cleanup"},
		References:  []string{"https://owasp.org/www-project-web-security-testing-guide/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
		FalsePositives: []string{
			"Retired rule: findings previously opened here are preserved as VulnView source observations, not standalone Cerebro verdicts.",
		},
		Runbook:           "Triage VulnView findings and asset exposure at the source; VulnView evidence remains attached to the asset in the graph.",
		FingerprintFields: []string{"asset_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
		},
		Lifecycle: Lifecycle{Kind: LifecycleRetired, Anchor: AnchorNone},
	}}
}

func (r *vulnViewExternalAssetConcentratedSignalRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

// SupportsRuntime is unchanged from the rule's pre-retirement shape so the
// same VulnView external-attack-surface finding-family runtimes that used
// to carry open rows under this rule id keep triggering graph-rule
// evaluation -- and therefore stale-row auto-resolution -- going forward.
func (r *vulnViewExternalAssetConcentratedSignalRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil || !strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), "vulnview") {
		return false
	}
	if strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"])) != "finding" {
		return false
	}
	return sourceprojection.VulnViewExternalAttackSurfaceSource(runtime.GetConfig()["source"])
}

func (r *vulnViewExternalAssetConcentratedSignalRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *vulnViewExternalAssetConcentratedSignalRule) QueryFor(*cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	return ports.CypherQueryRequest{}
}

func (r *vulnViewExternalAssetConcentratedSignalRule) EvaluateRows(context.Context, *cerebrov1.SourceRuntime, []ports.CypherRow) ([]*ports.FindingRecord, error) {
	return nil, nil
}
