package findings

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/policy"
)

func frameworksAndCategories(pf policy.Finding) ([]string, []string) {
	frameworks := make([]string, 0, len(pf.Frameworks))
	securityCategories := make([]string, 0)
	for _, fm := range pf.Frameworks {
		frameworks = append(frameworks, fm.Name)
		for _, control := range fm.Controls {
			securityCategories = append(securityCategories, fm.Name+":"+control)
		}
	}
	return frameworks, securityCategories
}

func newFindingFromPolicyFinding(pf policy.Finding, now time.Time) *Finding {
	resourceID := pf.ResourceID
	if resourceID == "" {
		resourceID = extractResourceID(pf.Resource)
	}
	resourceType := pf.ResourceType
	if resourceType == "" {
		resourceType = extractResourceType(pf.Resource)
	}
	resourceName := pf.ResourceName
	if resourceName == "" {
		resourceName = extractResourceName(pf.Resource)
	}

	frameworks, securityCategories := frameworksAndCategories(pf)

	f := &Finding{
		ID:                 pf.ID,
		IssueID:            pf.ID,
		ControlID:          pf.ControlID,
		TenantID:           extractTenantID(pf.Resource),
		PolicyID:           pf.PolicyID,
		PolicyName:         pf.PolicyName,
		Title:              pf.Title,
		Severity:           pf.Severity,
		SignalType:         SignalTypeSecurity,
		Domain:             inferDomain(pf.PolicyID, resourceType),
		Status:             "OPEN",
		ResourceID:         resourceID,
		ResourceName:       resourceName,
		ResourceType:       resourceType,
		Resource:           pf.Resource,
		Description:        pf.Description,
		Remediation:        pf.Remediation,
		RiskCategories:     pf.RiskCategories,
		SecurityFrameworks: frameworks,
		SecurityCategories: securityCategories,
		ComplianceMappings: pf.Frameworks,
		MitreAttack:        pf.MitreAttack,
		CreatedAt:          now,
		UpdatedAt:          now,
		FirstSeen:          now,
		LastSeen:           now,
	}
	f.StatusChangedAt = &now
	return f
}

func applyPolicyFindingUpdate(existing *Finding, pf policy.Finding, now time.Time) string {
	previousStatus := normalizeStatus(existing.Status)
	existing.Status = previousStatus
	existing.LastSeen = now
	existing.UpdatedAt = now

	if pf.Description != "" {
		existing.Description = pf.Description
	}
	if pf.Severity != "" {
		existing.Severity = pf.Severity
	}
	if pf.ControlID != "" {
		existing.ControlID = pf.ControlID
	}
	if pf.Title != "" {
		existing.Title = pf.Title
	}
	if pf.Remediation != "" {
		existing.Remediation = pf.Remediation
	}
	if pf.PolicyID != "" {
		existing.PolicyID = pf.PolicyID
	}
	if pf.PolicyName != "" {
		existing.PolicyName = pf.PolicyName
	}
	if len(pf.Resource) > 0 {
		existing.Resource = pf.Resource
		invalidateResourceJSONCache(existing)
	}
	if existing.TenantID == "" {
		existing.TenantID = extractTenantID(pf.Resource)
	}
	if pf.ResourceID != "" {
		existing.ResourceID = pf.ResourceID
	}
	if pf.ResourceType != "" {
		existing.ResourceType = pf.ResourceType
	}
	if pf.ResourceName != "" {
		existing.ResourceName = pf.ResourceName
	}
	if len(pf.RiskCategories) > 0 {
		existing.RiskCategories = pf.RiskCategories
	}
	if len(pf.Frameworks) > 0 {
		frameworks, securityCategories := frameworksAndCategories(pf)
		existing.SecurityFrameworks = frameworks
		existing.SecurityCategories = securityCategories
		existing.ComplianceMappings = pf.Frameworks
	}
	if len(pf.MitreAttack) > 0 {
		existing.MitreAttack = pf.MitreAttack
	}
	if existing.SignalType == "" {
		existing.SignalType = SignalTypeSecurity
	}
	if existing.Domain == "" {
		existing.Domain = inferDomain(existing.PolicyID, existing.ResourceType)
	}

	if previousStatus == "RESOLVED" || previousStatus == "SNOOZED" {
		existing.Status = "OPEN"
		existing.ResolvedAt = nil
		existing.SnoozedUntil = nil
		existing.StatusChangedAt = &now
	}
	return previousStatus
}

func findingNeedsSemanticMatch(semanticDedup bool, semanticKey string) bool {
	return semanticDedup && strings.TrimSpace(semanticKey) != ""
}
