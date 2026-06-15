package findings

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const FindingRiskFactorsAttribute = "risk_factors_json"

func riskFactorsFromReasons(reasons []string, finding *ports.FindingRecord, now time.Time) []ports.FindingRiskFactor {
	if finding == nil {
		return nil
	}
	observedAt := findingObservedAt(finding)
	if observedAt.IsZero() {
		observedAt = now
	}
	factors := make([]ports.FindingRiskFactor, 0, len(reasons))
	for _, reason := range uniqueSortedStrings(reasons) {
		factorID := riskFactorID(reason)
		if factorID == "" {
			continue
		}
		category, weight := riskFactorCategoryAndWeight(reason)
		factors = append(factors, ports.FindingRiskFactor{
			FactorID:             factorID,
			Category:             category,
			Weight:               weight,
			SeverityContribution: riskFactorSeverityContribution(weight),
			EvidenceRefs:         riskFactorEvidenceRefs(reason, finding),
			ObservedAt:           observedAt.UTC(),
			SuppressionScope:     "factor:" + factorID,
		})
	}
	return uniqueRiskFactors(factors)
}

func riskFactorID(reason string) string {
	value := strings.ToLower(strings.TrimSpace(reason))
	value = strings.NewReplacer(":", "_", " ", "_", "/", "_", ",", "_").Replace(value)
	value = strings.Trim(value, "_")
	if value == "" {
		return ""
	}
	return value
}

func riskFactorCategoryAndWeight(reason string) (string, int) {
	switch {
	case strings.HasPrefix(reason, "severity:"):
		return "likelihood_impact", 20
	case reason == "active":
		return "likelihood", 5
	case reason == "overdue":
		return "impact", 5
	case reason == "recent_24h":
		return "likelihood", 5
	case reason == "recent_7d":
		return "likelihood", 2
	case reason == "multiple_events":
		return "likelihood_confidence", 8
	case reason == "multiple_resources":
		return "impact", 8
	case reason == "mapped_controls":
		return "impact", 6
	case reason == "risky_action":
		return "likelihood", 12
	case reason == "critical_asset":
		return "impact", 35
	case reason == "external_exposure":
		return "likelihood", 35
	case reason == "privileged_actor":
		return "likelihood_impact", 25
	case reason == "active_threat":
		return "likelihood", 25
	case reason == "known_exploited":
		return "likelihood", 35
	case reason == "epss_high":
		return "likelihood", 25
	case reason == "epss_elevated":
		return "likelihood", 12
	case reason == "exploit_available":
		return "likelihood", 20
	case strings.HasPrefix(reason, "exploit_maturity:"):
		return "likelihood", 15
	case reason == "cvss_critical":
		return "likelihood_impact", 20
	case reason == "cvss_high":
		return "likelihood_impact", 10
	case reason == "sensitive_data":
		return "impact", 25
	case reason == "crown_jewel":
		return "impact", 35
	case reason == "regulated_or_sensitive_data":
		return "impact", 20
	case reason == "production_environment":
		return "impact", 15
	case reason == "privilege_or_control_plane":
		return "impact", 20
	case reason == "blast_radius":
		return "impact", 20
	case reason == "private_network_context":
		return "likelihood_cap", -10
	case reason == "graph_evidence":
		return "confidence", 5
	case reason == "limited_evidence":
		return "confidence", -15
	default:
		return "context", 1
	}
}

func riskFactorSeverityContribution(weight int) string {
	switch {
	case weight >= 25:
		return "high"
	case weight >= 10:
		return "medium"
	case weight > 0:
		return "low"
	case weight < 0:
		return "reduces_risk"
	default:
		return "none"
	}
}

func riskFactorEvidenceRefs(reason string, finding *ports.FindingRecord) []string {
	refs := []string{}
	addAttributes := func(keys ...string) {
		for _, key := range keys {
			if finding != nil && strings.TrimSpace(finding.Attributes[key]) != "" {
				refs = append(refs, "attribute:"+key)
			}
		}
	}
	switch {
	case strings.HasPrefix(reason, "severity:"):
		addAttributes(FindingSourceSeverityAttribute, "rule_severity")
		if len(refs) == 0 && strings.TrimSpace(finding.Severity) != "" {
			refs = append(refs, "field:severity")
		}
	case reason == "active":
		refs = append(refs, "field:status")
	case reason == "overdue":
		refs = append(refs, "field:due_at")
	case reason == "recent_24h", reason == "recent_7d":
		refs = append(refs, "field:last_observed_at")
	case reason == "multiple_events":
		for _, eventID := range uniqueSortedStrings(finding.EventIDs) {
			refs = append(refs, "event:"+eventID)
		}
	case reason == "multiple_resources":
		for _, urn := range uniqueSortedStrings(finding.ResourceURNs) {
			refs = append(refs, "resource:"+urn)
		}
	case reason == "mapped_controls":
		for _, control := range finding.ControlRefs {
			key := strings.TrimSpace(control.FrameworkName) + ":" + strings.TrimSpace(control.ControlID)
			if strings.Trim(key, ":") != "" {
				refs = append(refs, "control:"+key)
			}
		}
	case reason == "risky_action":
		addAttributes("action", "event_type", "operation")
	case reason == "critical_asset":
		addAttributes("asset_criticality", "criticality", "business_criticality", "tier")
	case reason == "external_exposure":
		addAttributes("internet_exposed", "public", "externally_exposed", "external_exposure", "is_public", "is_internet_facing")
	case reason == "privileged_actor":
		addAttributes("privileged", "actor_privileged", "admin", "is_admin", "has_admin")
	case reason == "active_threat":
		addAttributes("active_exploit", "active_threat", "exploit_detected", "credential_use", "token_exchange", "suspicious_process", "is_infected", "infected", "evidence_type", "evidence_kind", "signal", "action")
	case reason == "known_exploited":
		addAttributes("is_kev", "kev", "known_exploited", "known_exploited_vulnerability")
	case reason == "epss_high", reason == "epss_elevated":
		addAttributes("epss_score", "epss", "exploit_probability")
	case reason == "exploit_available":
		addAttributes("exploit_available", "public_exploit", "weaponized_exploit")
	case strings.HasPrefix(reason, "exploit_maturity:"):
		addAttributes("exploit_maturity", "exploit_status")
	case reason == "cvss_critical", reason == "cvss_high":
		addAttributes("cvss_score", "cvss", "base_score")
	case reason == "sensitive_data":
		addAttributes("data_classification", "sensitivity", "data_sensitivity")
	case reason == "crown_jewel":
		addAttributes("crown_jewel", "contains_secrets")
	case reason == "regulated_or_sensitive_data":
		addAttributes("contains_pii", "contains_phi", "contains_pci", "has_sensitive_data", "has_sensitive_data_access")
	case reason == "production_environment":
		addAttributes("environment", "env", "stage", "site_name")
	case reason == "privilege_or_control_plane":
		addAttributes("can_admin", "admin_reachable", "privileged_access", "has_admin_path", "action")
	case reason == "blast_radius":
		addAttributes("blast_radius", "affected_users", "reachable_resource_count", "admin_reachable_count", "sensitive_data_path_count")
	case reason == "private_network_context":
		addAttributes("private_network", "private_subnet", "network_scope", "cidr_scope", "ip_scope", "subnet_scope", "exposure_scope")
	case reason == "graph_evidence":
		for _, row := range finding.GraphEvidenceRows {
			if row.GetLabel() != "" {
				refs = append(refs, "graph_row:"+row.GetLabel())
			}
		}
	case reason == "limited_evidence":
		refs = append(refs, "field:resource_urns", "field:event_ids")
	}
	return uniqueSortedStrings(refs)
}

func uniqueRiskFactors(factors []ports.FindingRiskFactor) []ports.FindingRiskFactor {
	byID := map[string]ports.FindingRiskFactor{}
	for _, factor := range factors {
		factor.FactorID = strings.TrimSpace(factor.FactorID)
		if factor.FactorID == "" {
			continue
		}
		factor.Category = strings.TrimSpace(factor.Category)
		factor.SeverityContribution = strings.TrimSpace(factor.SeverityContribution)
		factor.EvidenceRefs = uniqueSortedStrings(factor.EvidenceRefs)
		factor.SuppressionScope = strings.TrimSpace(firstNonEmpty(factor.SuppressionScope, "factor:"+factor.FactorID))
		if existing, ok := byID[factor.FactorID]; ok {
			factor.EvidenceRefs = uniqueSortedStrings(append(existing.EvidenceRefs, factor.EvidenceRefs...))
			if existing.Weight > factor.Weight {
				factor.Weight = existing.Weight
			}
		}
		byID[factor.FactorID] = factor
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ports.FindingRiskFactor, 0, len(ids))
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out
}

func RiskFactorsJSON(factors []ports.FindingRiskFactor) string {
	factors = uniqueRiskFactors(factors)
	if len(factors) == 0 {
		return ""
	}
	data, err := json.Marshal(factors)
	if err != nil {
		return ""
	}
	return string(data)
}

func ParseRiskFactors(raw string) []ports.FindingRiskFactor {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var factors []ports.FindingRiskFactor
	if err := json.Unmarshal([]byte(raw), &factors); err != nil {
		return nil
	}
	return uniqueRiskFactors(factors)
}
