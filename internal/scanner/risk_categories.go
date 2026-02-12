package scanner

import "strings"

func ParseRiskCategories(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func CanonicalizeRiskCategories(categories []string) map[string]bool {
	if len(categories) == 0 {
		return nil
	}
	canon := make(map[string]bool)
	for _, category := range categories {
		label := CanonicalizeRiskLabel(category)
		if label != "" {
			canon[label] = true
		}
	}
	if len(canon) == 0 {
		return nil
	}
	return canon
}

func CanonicalizeRiskLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	label = strings.Trim(label, "\"")
	label = strings.ToLower(label)
	label = strings.ReplaceAll(label, "-", "_")
	label = strings.ReplaceAll(label, " ", "_")
	label = strings.ReplaceAll(label, "__", "_")
	switch label {
	case "external_exposure", "public_exposure", "public_access", "internet_exposure":
		return "network_exposure"
	case "unprotected_data", "data_exposure", "data_access":
		return "sensitive_data"
	case "unprotected_principal":
		return "over_privilege"
	case "no_authentication", "no_auth":
		return "weak_authentication"
	case "confused_deputy":
		return "privilege_escalation"
	}
	return label
}

func ShouldSkipGraphToxicCombination(resourceID string, graphRisks map[string]bool, sqlRiskSets map[string][]map[string]bool) bool {
	if resourceID == "" || len(graphRisks) == 0 {
		return false
	}
	sets := sqlRiskSets[resourceID]
	if len(sets) == 0 {
		return false
	}
	for _, sqlSet := range sets {
		if riskSetSuperset(sqlSet, graphRisks) {
			return true
		}
	}
	return false
}

func NormalizeResourceID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.Trim(id, "\"")
	return id
}

func riskSetSuperset(superset map[string]bool, subset map[string]bool) bool {
	if len(subset) == 0 {
		return false
	}
	for key := range subset {
		if !superset[key] {
			return false
		}
	}
	return true
}
