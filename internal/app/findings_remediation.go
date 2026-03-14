package app

import (
	"context"
	"strings"

	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/remediation"
)

func (a *App) upsertFindingAndRemediate(ctx context.Context, finding policy.Finding) *findings.Finding {
	if a == nil || a.Findings == nil {
		return nil
	}

	stored := a.Findings.Upsert(ctx, finding)
	if stored == nil {
		return nil
	}

	// Trigger created-event remediation only on first observation.
	if stored.FirstSeen.Equal(stored.LastSeen) {
		a.evaluateRemediationForFinding(ctx, stored, remediation.TriggerFindingCreated)
	}
	return stored
}

func (a *App) evaluateRemediationForFinding(ctx context.Context, finding *findings.Finding, trigger remediation.TriggerType) {
	if a == nil || finding == nil || a.Remediation == nil || a.RemediationExecutor == nil {
		return
	}

	event := remediation.Event{
		Type:       trigger,
		FindingID:  finding.ID,
		Severity:   strings.ToLower(strings.TrimSpace(finding.Severity)),
		PolicyID:   finding.PolicyID,
		SignalType: finding.SignalType,
		Domain:     finding.Domain,
		EntityID:   finding.ResourceID,
		Data: map[string]any{
			"resource_id":          finding.ResourceID,
			"resource_name":        finding.ResourceName,
			"resource_type":        finding.ResourceType,
			"resource_external_id": finding.ResourceExternalID,
			"resource_region":      finding.ResourceRegion,
			"resource_status":      finding.ResourceStatus,
			"resource_platform":    strings.ToLower(strings.TrimSpace(finding.ResourcePlatform)),
			"resource_tags":        finding.ResourceTags,
			"resource":             finding.Resource,
			"resource_json":        finding.ResourceJSON,
			"title":                finding.Title,
			"description":          finding.Description,
			"remediation":          finding.Remediation,
			"subscription_id":      finding.SubscriptionID,
			"subscription_name":    finding.SubscriptionName,
			"project_ids":          append([]string(nil), finding.ProjectIDs...),
			"project_names":        append([]string(nil), finding.ProjectNames...),
			"entity_ids":           append([]string(nil), finding.EntityIDs...),
			"risk_categories":      append([]string(nil), finding.RiskCategories...),
			"threats":              append([]string(nil), finding.Threats...),
			"cloud_provider_url":   finding.CloudProviderURL,
		},
	}

	executions, err := a.Remediation.Evaluate(ctx, event)
	if err != nil {
		a.Logger.Warn("failed to evaluate remediation", "finding_id", finding.ID, "error", err)
		return
	}
	for _, execution := range executions {
		if err := a.RemediationExecutor.Execute(ctx, execution); err != nil {
			a.Logger.Warn("failed to execute remediation", "finding_id", finding.ID, "execution_id", execution.ID, "error", err)
		}
	}
}
