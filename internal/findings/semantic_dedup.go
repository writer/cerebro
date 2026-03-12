package findings

import (
	"strings"
	"unicode"

	"github.com/writer/cerebro/internal/policy"
)

const DefaultSemanticDedupEnabled = true

func semanticKeyForPolicyFinding(pf policy.Finding) string {
	resourceIdentity := semanticResourceIdentity(pf.ResourceID, pf.ResourceType, pf.ResourceName, pf.Resource)
	if resourceIdentity == "" {
		return ""
	}

	issueCategory := semanticIssueCategory(pf.ControlID, pf.Title, pf.Description, pf.PolicyName, pf.PolicyID)
	if issueCategory == "" {
		return ""
	}

	severity := normalizeSemanticToken(pf.Severity)
	if severity == "" {
		return ""
	}

	parts := []string{resourceIdentity, issueCategory, severity}
	if tenantID := normalizeSemanticToken(extractTenantID(pf.Resource)); tenantID != "" {
		parts = append([]string{tenantID}, parts...)
	}
	return strings.Join(parts, "|")
}

func semanticKeyForFinding(f *Finding) string {
	if f == nil {
		return ""
	}

	resourceIdentity := semanticResourceIdentity(f.ResourceID, f.ResourceType, f.ResourceName, f.Resource)
	if resourceIdentity == "" {
		return ""
	}

	issueCategory := semanticIssueCategory(f.ControlID, f.Title, f.Description, f.PolicyName, f.PolicyID)
	if issueCategory == "" {
		return ""
	}

	severity := normalizeSemanticToken(f.Severity)
	if severity == "" {
		return ""
	}

	parts := []string{resourceIdentity, issueCategory, severity}
	if tenantID := normalizeSemanticToken(f.TenantID); tenantID != "" {
		parts = append([]string{tenantID}, parts...)
	}
	return strings.Join(parts, "|")
}

func semanticResourceIdentity(resourceID, resourceType, resourceName string, resource map[string]interface{}) string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		resourceID = extractResourceID(resource)
	}
	if resourceID != "" {
		return normalizeSemanticToken(resourceID)
	}

	resourceType = strings.TrimSpace(resourceType)
	if resourceType == "" {
		resourceType = extractResourceType(resource)
	}
	resourceName = strings.TrimSpace(resourceName)
	if resourceName == "" {
		resourceName = extractResourceName(resource)
	}
	if resourceName == "" {
		return ""
	}
	if resourceType == "" {
		return normalizeSemanticToken(resourceName)
	}
	return normalizeSemanticToken(resourceType) + ":" + normalizeSemanticToken(resourceName)
}

func semanticIssueCategory(controlID, title, description, policyName, policyID string) string {
	switch {
	case strings.TrimSpace(controlID) != "":
		return "control:" + normalizeSemanticToken(controlID)
	case strings.TrimSpace(title) != "":
		return "title:" + normalizeSemanticToken(title)
	case strings.TrimSpace(policyName) != "":
		return "policy:" + normalizeSemanticToken(stripPolicyVersionSuffix(policyName))
	case strings.TrimSpace(policyID) != "":
		return "policy:" + normalizeSemanticToken(stripPolicyVersionSuffix(policyID))
	case strings.TrimSpace(description) != "":
		return "desc:" + normalizeSemanticToken(description)
	default:
		return ""
	}
}

func stripPolicyVersionSuffix(value string) string {
	tokens := strings.Split(normalizeSemanticToken(value), "-")
	if len(tokens) == 0 {
		return ""
	}
	for len(tokens) > 0 {
		last := tokens[len(tokens)-1]
		switch {
		case len(last) > 1 && last[0] == 'v' && allDigits(last[1:]):
			tokens = tokens[:len(tokens)-1]
		case allDigits(last):
			tokens = tokens[:len(tokens)-1]
			if len(tokens) > 0 {
				prev := tokens[len(tokens)-1]
				if prev == "v" || prev == "version" {
					tokens = tokens[:len(tokens)-1]
				}
			}
		default:
			return strings.Join(tokens, "-")
		}
	}
	return strings.Join(tokens, "-")
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func normalizeSemanticToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}

	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if lastDash {
			continue
		}
		b.WriteByte('-')
		lastDash = true
	}
	return strings.Trim(b.String(), "-")
}

func ensureFindingSemanticState(f *Finding) {
	if f == nil {
		return
	}
	if strings.TrimSpace(f.SemanticKey) == "" {
		f.SemanticKey = semanticKeyForFinding(f)
	}
	f.ObservedFindingIDs = appendUniqueStrings(f.ObservedFindingIDs, f.ID)
	f.ObservedPolicyIDs = appendUniqueStrings(f.ObservedPolicyIDs, f.PolicyID)
}

func refreshFindingSemanticState(f *Finding) {
	if f == nil {
		return
	}
	f.SemanticKey = semanticKeyForFinding(f)
	f.ObservedFindingIDs = appendUniqueStrings(f.ObservedFindingIDs, f.ID)
	f.ObservedPolicyIDs = appendUniqueStrings(f.ObservedPolicyIDs, f.PolicyID)
}

func applySemanticObservation(f *Finding, pf policy.Finding, semanticKey string) {
	if f == nil {
		return
	}
	if strings.TrimSpace(semanticKey) != "" {
		f.SemanticKey = semanticKey
	} else if strings.TrimSpace(f.SemanticKey) == "" {
		f.SemanticKey = semanticKeyForFinding(f)
	}
	f.ObservedFindingIDs = appendUniqueStrings(f.ObservedFindingIDs, f.ID, pf.ID)
	f.ObservedPolicyIDs = appendUniqueStrings(f.ObservedPolicyIDs, f.PolicyID, pf.PolicyID)
}

func appendUniqueStrings(existing []string, values ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]string, 0, len(existing)+len(values))
	for _, value := range existing {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
