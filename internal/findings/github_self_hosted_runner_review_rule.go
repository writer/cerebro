package findings

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const githubSelfHostedRunnerReviewRuleID = "github-self-hosted-runner-review-needed"

func newGitHubSelfHostedRunnerReviewRule() Rule {
	definition := githubSelfHostedRunnerReviewDefinition()
	definition.Description = "Retired GitHub runner review rule retained so noisy open findings can be cleaned up without recreating them."
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

func githubSelfHostedRunnerReviewDefinition() RuleDefinition {
	return RuleDefinition{
		ID:                githubSelfHostedRunnerReviewRuleID,
		Name:              "GitHub Self-Hosted Runner Needs Review",
		Description:       "Detect active non-ephemeral or untrusted GitHub self-hosted runners from projected runner state.",
		SourceID:          "github",
		EventKinds:        []string{"github.audit"},
		OutputKind:        "finding.github_self_hosted_runner_review_needed",
		Severity:          "MEDIUM",
		Status:            findingStatusOpen,
		Maturity:          "test",
		Tags:              []string{"github", "actions", "self-hosted-runner", "supply-chain", "graph-rule", "attack.t1195"},
		References:        []string{"https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners"},
		FalsePositives:    []string{"Approved persistent runner pools with documented owner, hardening baseline, and network isolation."},
		Runbook:           "Validate runner ownership, scope, host trust, ephemeral posture, and recent jobs; remove or isolate unauthorized runners.",
		FingerprintFields: []string{"runner_urn"},
		ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}, {FrameworkName: "ISO 27001:2022", ControlID: "A.8.9"}},
		Lifecycle:         Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
	}
}
