package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
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

type githubDependabotOpenAlertRule struct{}

func newGitHubDependabotOpenAlertRule() Rule {
	return &githubDependabotOpenAlertRule{}
}

func (*githubDependabotOpenAlertRule) Spec() *cerebrov1.RuleSpec {
	return &cerebrov1.RuleSpec{
		Id:          githubDependabotOpenAlertRuleID,
		Name:        githubDependabotOpenAlertTitle,
		Description: "Detect open GitHub Dependabot alerts replayed from one source runtime.",
		InputStreamIds: []string{
			"source-runtime-replay",
		},
		OutputKinds: []string{
			"finding.github_dependabot_open_alert",
		},
	}
}

func (*githubDependabotOpenAlertRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return runtime != nil && strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), "github")
}

func (*githubDependabotOpenAlertRule) Evaluate(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if runtime == nil {
		return nil, errors.New("source runtime is required")
	}
	if !matchesGitHubDependabotOpenAlert(event) {
		return nil, nil
	}
	record, err := githubDependabotOpenAlertFinding(ctx, event, runtime.GetId())
	if err != nil {
		return nil, err
	}
	return []*ports.FindingRecord{record}, nil
}

func matchesGitHubDependabotOpenAlert(event *cerebrov1.EventEnvelope) bool {
	if event == nil || !strings.EqualFold(strings.TrimSpace(event.GetKind()), "github.dependabot_alert") {
		return false
	}
	attributes := event.GetAttributes()
	return strings.EqualFold(strings.TrimSpace(attributes["state"]), findingStatusOpen) &&
		strings.TrimSpace(attributes["repository"]) != "" &&
		strings.TrimSpace(attributes["alert_number"]) != ""
}

func githubDependabotOpenAlertFinding(ctx context.Context, event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	resourceURNs, primaryResourceURN, primaryResourceLabel, err := githubDependabotAlertContext(ctx, event)
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
		"primary_resource_urn":     primaryResourceURN,
		"repository":               strings.TrimSpace(attributes["repository"]),
		"severity":                 strings.TrimSpace(attributes["severity"]),
		"source_runtime_id":        strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]),
		"state":                    strings.TrimSpace(attributes["state"]),
		"vulnerable_version_range": strings.TrimSpace(attributes["vulnerable_version_range"]),
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
		Summary:           githubDependabotAlertSummary(attributes, primaryResourceLabel),
		ResourceURNs:      resourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          policyID,
		PolicyName:        firstNonEmpty(strings.TrimSpace(attributes["advisory_ghsa_id"]), strings.TrimSpace(attributes["advisory_cve_id"]), primaryResourceLabel),
		CheckID:           githubDependabotOpenAlertCheckID,
		CheckName:         githubDependabotOpenAlertCheckName,
		ControlRefs:       cloneFindingControlRefs(githubDependabotOpenAlertControlRefs),
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func githubDependabotAlertContext(ctx context.Context, event *cerebrov1.EventEnvelope) ([]string, string, string, error) {
	recorder := &projectionRecorder{
		entities: make(map[string]*ports.ProjectedEntity),
		links:    make(map[string]*ports.ProjectedLink),
	}
	if ctx == nil {
		return nil, "", "", errors.New("context is required")
	}
	if _, err := sourceprojection.New(nil, recorder).Project(ctx, event); err != nil {
		return nil, "", "", err
	}
	resourceURNs := make([]string, 0, len(recorder.entities))
	seenURNs := make(map[string]struct{}, len(recorder.entities))
	var primaryURN string
	var primaryLabel string
	for _, entity := range recorder.entities {
		if entity == nil {
			continue
		}
		urn := strings.TrimSpace(entity.URN)
		if urn == "" {
			continue
		}
		if _, ok := seenURNs[urn]; !ok {
			seenURNs[urn] = struct{}{}
			resourceURNs = append(resourceURNs, urn)
		}
		if primaryURN == "" && strings.EqualFold(strings.TrimSpace(entity.EntityType), "github.dependabot_alert") {
			primaryURN = urn
			primaryLabel = strings.TrimSpace(entity.Label)
		}
	}
	slices.Sort(resourceURNs)
	if primaryURN == "" && len(resourceURNs) != 0 {
		primaryURN = resourceURNs[0]
	}
	return resourceURNs, primaryURN, primaryLabel, nil
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
