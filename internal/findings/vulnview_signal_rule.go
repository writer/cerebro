package findings

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const vulnViewActionableExternalFindingRuleID = "vulnview-actionable-external-finding"

// newVulnViewActionableExternalFindingRule retires the one-to-one VulnView
// external-attack-surface finding mirror. Per North Star §10.2, a single
// upstream VulnView finding does not become a standalone Cerebro finding by
// itself; VulnView findings remain authoritative, triaged source
// observations (vulnview.finding, projected by
// internal/sourceprojection/vulnview.go) and graph evidence only. The rule
// keeps its id/name/output-kind/control-refs so:
//   - catalog clients still discover the id (no 404 on existing dashboards);
//   - the findings service sees the retirement marker and resolves any open
//     findings under this rule id for the runtime being (re-)evaluated
//     (RetiresOpenFindings / resolveRetiredOpenFindings in
//     internal/findings/service_closeout.go), without depending on a
//     bounded replay of the original events;
//   - rows from runtimes no longer evaluated (legacy
//     writer-vulnview-vulnerability/writer-vulnview-dns-alert, or any
//     runtime that stopped emitting vulnview.finding) are retired through
//     the existing `cerebro closeout` procedure instead
//     (internal/findings/closeout.go CloseoutSelector).
//
// The wrapper's `match` and `build` are both no-ops; `build` returns nil for
// extra safety in case `match` is ever flipped on by accident.
func newVulnViewActionableExternalFindingRule() Rule {
	definition := vulnViewActionableExternalFindingDefinition()
	definition.Description = "Retired: a single VulnView external attack-surface finding no longer manufactures a standalone Cerebro finding. Retained so stale open findings auto-resolve; durable coverage stays with the VulnView source observation and graph evidence."
	definition.Maturity = RuleMaturityRetired
	definition.Lifecycle = Lifecycle{Kind: LifecycleRetired, Anchor: AnchorNone}
	definition.Tags = appendUniqueString(cloneStringSlice(definition.Tags), "retired", "cleanup")
	return newEventRule(eventRuleConfig{
		definition:         definition,
		sourceID:           definition.SourceID,
		retireOpenFindings: true,
		match:              func(*cerebrov1.EventEnvelope) bool { return false },
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return nil, nil
		},
	})
}

// vulnViewActionableExternalFindingDefinition is the rule's original
// (pre-retirement) shape. It is retained only as the base the retirement
// wrapper above layers onto -- id, name, output kind, control refs, and
// fingerprint fields must stay stable for catalog/audit continuity.
func vulnViewActionableExternalFindingDefinition() RuleDefinition {
	return RuleDefinition{
		ID:                 vulnViewActionableExternalFindingRuleID,
		Name:               "VulnView Actionable External Finding",
		Description:        "Detect open VulnView external attack-surface findings that require AppSec triage.",
		SourceID:           "vulnview",
		EventKinds:         []string{"vulnview.finding"},
		OutputKind:         "finding.vulnview_actionable_external_finding",
		Severity:           "dynamic",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"vulnview", "appsec", "attack-surface"},
		References:         []string{"https://owasp.org/www-project-web-security-testing-guide/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
		FalsePositives:     []string{"Finding is a duplicate, asset is intentionally exposed with compensating controls, or scanner severity was manually downgraded after validation."},
		Runbook:            "Validate exploitability and asset ownership, link duplicate external findings, patch or mitigate the exposed service, and document accepted risk.",
		RequiredAttributes: []string{"severity", "status"},
		FingerprintFields:  []string{"asset_urn", "check_id"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
		},
		Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
	}
}
