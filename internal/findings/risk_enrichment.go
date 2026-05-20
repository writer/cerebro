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
	record.RiskReasons = uniqueSortedStrings(append(record.RiskReasons, evaluation.Reasons...))
	if record.Attributes == nil {
		record.Attributes = map[string]string{}
	}
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
	return record
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
