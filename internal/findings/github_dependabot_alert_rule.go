package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	githubDependabotOpenAlertRuleID    = "github-dependabot-open-alert"
	githubDependabotOpenAlertTitle     = "GitHub Dependabot Open Alert"
	githubDependabotOpenAlertStatus    = findingStatusOpen
	githubDependabotOpenAlertCheckID   = "github-dependabot-open-alert"
	githubDependabotOpenAlertCheckName = "GitHub Dependabot Open Alert"
)

var githubDependabotOpenAlertControlRefs = []ports.FindingControlRef{
	{
		FrameworkName: "SOC 2",
		ControlID:     "CC7.1",
	},
	{
		FrameworkName: "ISO 27001:2022",
		ControlID:     "A.12.6",
	},
}

var githubDependabotOpenAlertDefinition = RuleDefinition{
	ID:                 githubDependabotOpenAlertRuleID,
	Name:               githubDependabotOpenAlertTitle,
	Description:        "Detect open GitHub Dependabot alerts replayed from one source runtime.",
	SourceID:           "github",
	EventKinds:         []string{"github.dependabot_alert"},
	OutputKind:         "finding.github_dependabot_open_alert",
	Severity:           "dynamic",
	Status:             githubDependabotOpenAlertStatus,
	Maturity:           "test",
	Tags:               []string{"github", "dependabot", "vulnerability", "supply-chain", "attack.initial-access"},
	References:         []string{"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts"},
	FalsePositives:     []string{"Accepted risk or non-exploitable vulnerable dependency in a non-runtime path."},
	Runbook:            "Review affected package, advisory, vulnerable range, and repository usage; upgrade to the first patched version or document accepted risk.",
	RequiredAttributes: []string{"repository", "alert_number", "state"},
	FingerprintFields:  []string{"repository", "alert_number"},
	ControlRefs:        githubDependabotOpenAlertControlRefs,
}

var githubDependabotAlertKindMatcher = eventKindMatcher(githubDependabotOpenAlertDefinition.EventKinds...)

func newGitHubDependabotOpenAlertRule() Rule {
	return newEventRule(eventRuleConfig{
		definition: githubDependabotOpenAlertDefinition,
		match:      matchesGitHubDependabotOpenAlert,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return githubDependabotOpenAlertFinding(ctx, event, runtime.GetId())
		},
	})
}

func matchesGitHubDependabotOpenAlert(event *cerebrov1.EventEnvelope) bool {
	if !githubDependabotAlertKindMatcher(event) {
		return false
	}
	attributes := eventAttributes(event)
	return strings.EqualFold(strings.TrimSpace(attributes["state"]), findingStatusOpen) &&
		hasRequiredAttributes(event, "repository", "alert_number")
}

func githubDependabotOpenAlertFinding(ctx context.Context, event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryEntityType:  "github.dependabot_alert",
		CollectAllEntities: true,
	})
	if err != nil {
		return nil, fmt.Errorf("project finding context for event %q: %w", event.GetId(), err)
	}
	attributes := event.GetAttributes()
	policyID := firstNonEmpty(strings.TrimSpace(attributes["advisory_ghsa_id"]), strings.TrimSpace(attributes["advisory_cve_id"]))
	observedPolicyIDs := []string{}
	if policyID != "" {
		observedPolicyIDs = append(observedPolicyIDs, policyID)
	}
	findingAttributes := map[string]string{
		"advisory_cve_id":          strings.TrimSpace(attributes["advisory_cve_id"]),
		"advisory_ghsa_id":         strings.TrimSpace(attributes["advisory_ghsa_id"]),
		"alert_number":             strings.TrimSpace(attributes["alert_number"]),
		"ecosystem":                strings.TrimSpace(attributes["ecosystem"]),
		"event_id":                 strings.TrimSpace(event.GetId()),
		"html_url":                 strings.TrimSpace(attributes["html_url"]),
		"package":                  strings.TrimSpace(attributes["package"]),
		"primary_resource_urn":     projectedContext.PrimaryResourceURN,
		"repository":               strings.TrimSpace(attributes["repository"]),
		"severity":                 strings.TrimSpace(attributes["severity"]),
		"source_runtime_id":        strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]),
		"state":                    strings.TrimSpace(attributes["state"]),
		"vulnerable_version_range": strings.TrimSpace(attributes["vulnerable_version_range"]),
	}
	for key, value := range githubDependabotOpenAlertDefinition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(
		githubDependabotOpenAlertRuleID,
		attributes["repository"],
		attributes["alert_number"],
	)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtimeID),
		RuleID:            githubDependabotOpenAlertRuleID,
		Title:             githubDependabotOpenAlertTitle,
		Severity:          normalizeFindingSeverity(attributes["severity"]),
		Status:            githubDependabotOpenAlertStatus,
		Summary:           githubDependabotAlertSummary(attributes, projectedContext.ResourceLabel),
		ResourceURNs:      projectedContext.ResourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          policyID,
		PolicyName:        firstNonEmpty(strings.TrimSpace(attributes["advisory_ghsa_id"]), strings.TrimSpace(attributes["advisory_cve_id"]), projectedContext.ResourceLabel),
		CheckID:           githubDependabotOpenAlertCheckID,
		CheckName:         githubDependabotOpenAlertCheckName,
		ControlRefs:       cloneFindingControlRefs(githubDependabotOpenAlertDefinition.ControlRefs),
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func githubDependabotAlertSummary(attributes map[string]string, primaryResourceLabel string) string {
	severity := normalizeFindingSeverity(attributes["severity"])
	repository := firstNonEmpty(attributes["repository"], "unknown repository")
	packageName := firstNonEmpty(attributes["package"], "unknown package")
	advisory := firstNonEmpty(attributes["advisory_ghsa_id"], attributes["advisory_cve_id"], primaryResourceLabel, "Dependabot alert")
	return fmt.Sprintf("%s Dependabot alert %s affects %s in %s", severity, advisory, packageName, repository)
}

func normalizeFindingSeverity(value string) string {
	severity := strings.ToUpper(strings.TrimSpace(value))
	if severity == "" {
		return "MEDIUM"
	}
	return severity
}
