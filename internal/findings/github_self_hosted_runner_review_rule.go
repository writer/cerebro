package findings

import "github.com/writer/cerebro/internal/ports"

const githubSelfHostedRunnerReviewRuleID = "github-self-hosted-runner-review-needed"

func newGitHubSelfHostedRunnerReviewRule() Rule {
	return newCoordinationGraphRule(RuleDefinition{
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
	}, map[string][]string{"github": {"audit"}}, `MATCH (runner:Entity {tenant_id: $tenant_id, entity_type: 'github.runner'})
WHERE NOT coalesce(runner.attributes_json, '') CONTAINS '"runner_status":"inactive"'
  AND (
    NOT coalesce(runner.attributes_json, '') CONTAINS '"runner_ephemeral":"true"'
    OR coalesce(runner.attributes_json, '') CONTAINS '"runner_untrusted":"true"'
    OR coalesce(runner.attributes_json, '') CONTAINS '"host_trusted":"false"'
  )
OPTIONAL MATCH (runner)-[scopeRel:RELATION {relation: 'belongs_to'}]->(scope:Entity {tenant_id: $tenant_id})
RETURN runner.urn AS primary_urn,
       runner.label AS primary_label,
       runner.entity_type AS primary_type,
       runner.urn AS fingerprint_key,
       CASE
         WHEN coalesce(runner.attributes_json, '') CONTAINS '"runner_untrusted":"true"' OR coalesce(runner.attributes_json, '') CONTAINS '"host_trusted":"false"' THEN 'HIGH'
         ELSE 'MEDIUM'
       END AS severity,
       'GitHub self-hosted runner ' + coalesce(runner.label, runner.urn) + ' needs security review' AS summary,
       'Validate runner ownership, trust, isolation, and ephemeral posture; remove unauthorized persistent runners' AS action,
       CASE WHEN scope.urn IS NULL THEN [runner.urn] ELSE [runner.urn, scope.urn] END AS resource_urns,
       CASE WHEN scope.urn IS NULL THEN [] ELSE [{urn: scope.urn, label: scope.label, entity_type: scope.entity_type, relation: 'belongs_to', attributes_json: coalesce(scopeRel.attributes_json, '')}] END AS evidence
ORDER BY severity DESC, runner.label, runner.urn
LIMIT $row_limit`, nil)
}
