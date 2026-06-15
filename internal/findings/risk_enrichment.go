package findings

import (
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func enrichFindingRisk(record *ports.FindingRecord, _ *cerebrov1.SourceRuntime, now time.Time) *ports.FindingRecord {
	if record == nil {
		return nil
	}
	if record.Attributes == nil {
		record.Attributes = map[string]string{}
	}
	sourceSeverity := strings.ToUpper(strings.TrimSpace(firstNonEmpty(record.Attributes[FindingSourceSeverityAttribute], record.Attributes["rule_severity"], record.Severity)))
	setRiskStringAttribute(record.Attributes, FindingSourceSeverityAttribute, sourceSeverity)
	evaluation := AnalyzeFindingRiskContext(record, now)
	if record.LikelihoodScore <= 0 {
		record.LikelihoodScore = evaluation.LikelihoodScore
	}
	if record.ImpactScore <= 0 {
		record.ImpactScore = evaluation.ImpactScore
	}
	if record.ConfidenceScore <= 0 {
		record.ConfidenceScore = evaluation.ConfidenceScore
	}
	if strings.TrimSpace(record.LikelihoodLevel) == "" {
		record.LikelihoodLevel = riskLevelFromScore(record.LikelihoodScore)
	}
	if strings.TrimSpace(record.ImpactLevel) == "" {
		record.ImpactLevel = riskLevelFromScore(record.ImpactScore)
	}
	if record.RiskScore <= 0 {
		record.RiskScore = productRiskScore(record.LikelihoodScore, record.ImpactScore)
	}
	if strings.TrimSpace(record.RiskModelVersion) == "" {
		record.RiskModelVersion = defaultFindingRiskModelVersion
	}
	effectiveSeverity := EffectiveSeverityFromRiskScore(record.RiskScore)
	record.RiskReasons = uniqueSortedStrings(append(record.RiskReasons, evaluation.Reasons...))
	record.RiskFactors = uniqueRiskFactors(append(record.RiskFactors, evaluation.Factors...))
	setRiskStringAttribute(record.Attributes, FindingEffectiveSeverityAttribute, effectiveSeverity)
	setRiskAttribute(record.Attributes, "risk_score", record.RiskScore)
	setRiskAttribute(record.Attributes, "likelihood_score", record.LikelihoodScore)
	setRiskAttribute(record.Attributes, "impact_score", record.ImpactScore)
	setRiskAttribute(record.Attributes, "confidence_score", record.ConfidenceScore)
	setRiskStringAttribute(record.Attributes, "likelihood_level", record.LikelihoodLevel)
	setRiskStringAttribute(record.Attributes, "impact_level", record.ImpactLevel)
	setRiskStringAttribute(record.Attributes, "risk_model_version", record.RiskModelVersion)
	if len(record.RiskReasons) != 0 {
		record.Attributes["risk_reasons"] = strings.Join(record.RiskReasons, ",")
	}
	if factorsJSON := RiskFactorsJSON(record.RiskFactors); factorsJSON != "" {
		record.Attributes[FindingRiskFactorsAttribute] = factorsJSON
	}
	return record
}

func recomputeFindingRisk(record *ports.FindingRecord, now time.Time) *ports.FindingRecord {
	if record == nil {
		return nil
	}
	record.RiskScore = 0
	record.LikelihoodScore = 0
	record.ImpactScore = 0
	record.ConfidenceScore = 0
	record.LikelihoodLevel = ""
	record.ImpactLevel = ""
	record.RiskReasons = nil
	record.RiskFactors = nil
	record.RiskModelVersion = ""
	if record.Attributes != nil {
		delete(record.Attributes, "risk_score")
		delete(record.Attributes, "likelihood_score")
		delete(record.Attributes, "impact_score")
		delete(record.Attributes, "confidence_score")
		delete(record.Attributes, "likelihood_level")
		delete(record.Attributes, "impact_level")
		delete(record.Attributes, "risk_reasons")
		delete(record.Attributes, FindingRiskFactorsAttribute)
		delete(record.Attributes, "risk_model_version")
		delete(record.Attributes, FindingEffectiveSeverityAttribute)
	}
	return enrichFindingRisk(record, nil, now)
}

func findingRiskAttributes(record *ports.FindingRecord) map[string]string {
	if record == nil {
		return map[string]string{}
	}
	attributes := map[string]string{}
	attributes["risk_score"] = strconv.Itoa(clampScore(record.RiskScore))
	attributes[FindingEffectiveSeverityAttribute] = EffectiveSeverityFromRiskScore(record.RiskScore)
	attributes[FindingSourceSeverityAttribute] = strings.ToUpper(strings.TrimSpace(firstNonEmpty(record.Attributes[FindingSourceSeverityAttribute], record.Attributes["rule_severity"], record.Severity)))
	attributes["likelihood_score"] = strconv.Itoa(clampScore(record.LikelihoodScore))
	attributes["impact_score"] = strconv.Itoa(clampScore(record.ImpactScore))
	attributes["confidence_score"] = strconv.Itoa(clampScore(record.ConfidenceScore))
	attributes["likelihood_level"] = strings.TrimSpace(record.LikelihoodLevel)
	attributes["impact_level"] = strings.TrimSpace(record.ImpactLevel)
	attributes["risk_model_version"] = strings.TrimSpace(record.RiskModelVersion)
	attributes["risk_reasons"] = strings.Join(record.RiskReasons, ",")
	if factorsJSON := RiskFactorsJSON(record.RiskFactors); factorsJSON != "" {
		attributes[FindingRiskFactorsAttribute] = factorsJSON
	}
	return attributes
}

func setRiskAttribute(attributes map[string]string, key string, value int) {
	if value <= 0 {
		return
	}
	attributes[key] = strconv.Itoa(clampScore(value))
}

func setRiskStringAttribute(attributes map[string]string, key string, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		attributes[key] = trimmed
	}
}
