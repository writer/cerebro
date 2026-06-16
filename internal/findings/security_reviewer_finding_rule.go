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
	securityReviewerFindingRuleID  = "security-reviewer-reported-finding"
	securityReviewerFindingTitle   = "Security Reviewer Reported Finding"
	securityReviewerFindingSource  = "security_reviewer"
	securityReviewerFindingCheckID = "security-reviewer-finding"
)

var securityReviewerFindingControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
}

var securityReviewerFindingDefinition = RuleDefinition{
	ID:             securityReviewerFindingRuleID,
	Name:           securityReviewerFindingTitle,
	Description:    "Represent validated security-reviewer output as deterministic finding records for candidate review and promotion.",
	SourceID:       securityReviewerFindingSource,
	EventKinds:     []string{"security_reviewer.finding", "security_reviewer.review_finding", "droid.review_finding"},
	OutputKind:     "finding.security_reviewer_reported",
	Severity:       "dynamic",
	Status:         findingStatusOpen,
	Maturity:       RuleMaturityCandidate,
	Tags:           []string{"code-review", "security-reviewer", "finding-candidate", "software-supply-chain"},
	References:     []string{"https://owasp.org/www-project-code-review-guide/"},
	FalsePositives: []string{"Reviewer output that is advisory-only, already mitigated by changed code, or not exploitable after manual validation."},
	Runbook:        "Validate the reviewer evidence against the changed code, confirm exploitability and remediation owner, then promote or reject the candidate finding.",
	FingerprintFields: []string{
		"tenant_id",
		"review_subject",
		"reviewer_rule",
		"file",
		"line",
		"message",
	},
	ControlRefs: securityReviewerFindingControlRefs,
	Lifecycle:   Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var securityReviewerFindingKindMatcher = eventKindMatcher(securityReviewerFindingDefinition.EventKinds...)

func newSecurityReviewerFindingRule() Rule {
	return newEventRule(eventRuleConfig{
		definition: securityReviewerFindingDefinition,
		sourceID:   securityReviewerFindingSource,
		match:      matchesSecurityReviewerFinding,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return securityReviewerFinding(ctx, runtime, event)
		},
	})
}

func matchesSecurityReviewerFinding(event *cerebrov1.EventEnvelope) bool {
	if !securityReviewerFindingKindMatcher(event) {
		return false
	}
	attrs := eventAttributes(event)
	if securityReviewerMessage(attrs) == "" {
		return false
	}
	return securityReviewerStableAnchor(attrs) != ""
}

func securityReviewerFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	attrs := eventAttributes(event)
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		CollectAllLinkURNs: true,
		ResourceFallbacks: []string{
			attrs["resource_urn"],
			attrs["review_subject"],
			attrs["repository"],
			attrs["file"],
		},
	})
	if err != nil {
		return nil, fmt.Errorf("project security reviewer finding context for event %q: %w", event.GetId(), err)
	}
	reviewerRule := securityReviewerRule(attrs)
	message := securityReviewerMessage(attrs)
	reviewSubject := securityReviewerReviewSubject(attrs)
	file := strings.TrimSpace(attrs["file"])
	line := strings.TrimSpace(attrs["line"])
	severity := securityReviewerSeverity(attrs)
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	findingAttributes := map[string]string{
		"base_sha":             strings.TrimSpace(attrs["base_sha"]),
		"branch":               strings.TrimSpace(attrs["branch"]),
		"column":               strings.TrimSpace(attrs["column"]),
		"comment_url":          firstNonEmpty(attrs["comment_url"], attrs["url"], attrs["html_url"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"file":                 file,
		"head_sha":             strings.TrimSpace(attrs["head_sha"]),
		"line":                 line,
		"message":              message,
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
		"pull_request":         firstNonEmpty(attrs["pull_request"], attrs["pull_request_number"], attrs["pr_number"]),
		"repository":           strings.TrimSpace(attrs["repository"]),
		"review_subject":       reviewSubject,
		"reviewer":             firstNonEmpty(attrs["reviewer"], attrs["reviewer_id"], attrs["actor"]),
		"reviewer_rule":        reviewerRule,
		"reviewer_source":      firstNonEmpty(attrs["reviewer_source"], attrs["source"], attrs["tool"], "security-reviewer"),
		"security_reviewed_at": firstNonEmpty(attrs["reviewed_at"], attrs["detected_at"], attrs["observed_at"]),
		"severity":             severity,
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		"tenant_id":            strings.TrimSpace(event.GetTenantId()),
	}
	for key, value := range securityReviewerFindingDefinition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	graphRows := []*cerebrov1.GraphEvidenceRow{
		newGraphEvidenceRow("Security reviewer finding", map[string]string{
			"event_id":        strings.TrimSpace(event.GetId()),
			"file":            file,
			"line":            line,
			"message":         message,
			"review_subject":  reviewSubject,
			"reviewer_rule":   reviewerRule,
			"reviewer_source": findingAttributes["reviewer_source"],
			"severity":        severity,
		}),
	}
	fingerprint := hashFindingFingerprint(
		securityReviewerFindingRuleID,
		event.GetTenantId(),
		reviewSubject,
		reviewerRule,
		file,
		line,
		message,
	)
	observedPolicyIDs := []string{}
	if reviewerRule != "" {
		observedPolicyIDs = append(observedPolicyIDs, reviewerRule)
	}
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            securityReviewerFindingRuleID,
		Title:             securityReviewerFindingTitle,
		Severity:          severity,
		Status:            findingStatusOpen,
		Summary:           securityReviewerSummary(reviewerRule, file, line, message),
		ResourceURNs:      projectedContext.ResourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          reviewerRule,
		PolicyName:        reviewerRule,
		CheckID:           firstNonEmpty(reviewerRule, securityReviewerFindingCheckID),
		CheckName:         firstNonEmpty(reviewerRule, securityReviewerFindingTitle),
		ControlRefs:       cloneFindingControlRefs(securityReviewerFindingDefinition.ControlRefs),
		GraphEvidenceRows: graphRows,
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func securityReviewerStableAnchor(attrs map[string]string) string {
	return firstNonEmpty(
		securityReviewerReviewSubject(attrs),
		strings.TrimSpace(attrs["resource_urn"]),
		strings.TrimSpace(attrs["file"]),
		strings.TrimSpace(attrs["repository"]),
	)
}

func securityReviewerReviewSubject(attrs map[string]string) string {
	return firstNonEmpty(
		attrs["review_subject"],
		attrs["pull_request_url"],
		attrs["pull_request"],
		attrs["head_sha"],
		attrs["branch"],
		attrs["repository"],
	)
}

func securityReviewerRule(attrs map[string]string) string {
	return firstNonEmpty(attrs["rule"], attrs["rule_id"], attrs["check_id"], attrs["scanner_rule_id"], attrs["category"])
}

func securityReviewerMessage(attrs map[string]string) string {
	return firstNonEmpty(attrs["message"], attrs["summary"], attrs["title"], attrs["description"])
}

func securityReviewerSeverity(attrs map[string]string) string {
	switch strings.ToLower(firstNonEmpty(attrs["severity"], attrs["priority"], attrs["level"])) {
	case "critical", "p0", "blocker":
		return "CRITICAL"
	case "high", "p1", "error":
		return "HIGH"
	case "medium", "moderate", "p2", "warning":
		return "MEDIUM"
	case "low", "p3":
		return "LOW"
	case "info", "informational", "notice", "p4":
		return "INFO"
	default:
		return "MEDIUM"
	}
}

func securityReviewerSummary(rule string, file string, line string, message string) string {
	location := strings.TrimSpace(file)
	if location != "" && strings.TrimSpace(line) != "" {
		location += ":" + strings.TrimSpace(line)
	}
	if location == "" {
		location = "reviewed code"
	}
	label := firstNonEmpty(rule, "security reviewer")
	return fmt.Sprintf("%s reported %s in %s", label, message, location)
}
