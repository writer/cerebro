package assetrisk

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const maxReportedVulnerabilities = 5

// Exposure labels for a starting point.
const (
	ExposureInternet = "internet"
	ExposureInternal = "internal"
)

// VulnerabilityInput is one vulnerability attached to an entity, with the
// attributes of the edge that attached it.
type VulnerabilityInput struct {
	Entity         ports.CatalogEntity
	EdgeAttributes map[string]string
}

// VulnerabilitySignal explains the exploit probability given to one vulnerability.
type VulnerabilitySignal struct {
	URN            string   `json:"urn"`
	Label          string   `json:"label,omitempty"`
	CVE            string   `json:"cve,omitempty"`
	EPSS           *float64 `json:"epss,omitempty"`
	CVSS           *float64 `json:"cvss,omitempty"`
	KnownExploited bool     `json:"known_exploited"`
	RansomwareUse  bool     `json:"ransomware_use"`
	Probability    float64  `json:"probability"`
	Drivers        []string `json:"drivers"`
}

// CountermeasureHit is a countermeasure found on an entity.
type CountermeasureHit struct {
	Key       string  `json:"key"`
	Label     string  `json:"label"`
	Reduction float64 `json:"reduction"`
}

// NodeAssessment is what the model knows about one entity.
type NodeAssessment struct {
	URN                    string                `json:"urn"`
	EntityType             string                `json:"entity_type"`
	Label                  string                `json:"label,omitempty"`
	Value                  float64               `json:"value"`
	ValueDrivers           []string              `json:"value_drivers"`
	Exposure               string                `json:"exposure"`
	ExploitProbability     float64               `json:"exploit_probability"`
	VulnerabilitiesChecked bool                  `json:"vulnerabilities_checked"`
	VulnerabilityCount     int                   `json:"vulnerability_count"`
	Vulnerabilities        []VulnerabilitySignal `json:"vulnerabilities"`
	Countermeasures        []CountermeasureHit   `json:"countermeasures"`
	CountermeasureFactor   float64               `json:"countermeasure_factor"`
}

// AssessEntity values an entity and, when vulnerabilities were checked,
// combines them into the probability that the entity can be exploited.
func AssessEntity(model ports.AssetRiskModel, entity ports.CatalogEntity, vulnerabilities []VulnerabilityInput, vulnerabilitiesChecked bool) NodeAssessment {
	value, drivers := AssetValue(model, entity)
	countermeasures, factor := Countermeasures(model, entity)
	node := NodeAssessment{
		URN:                    entity.URN,
		EntityType:             entity.EntityType,
		Label:                  entity.Label,
		Value:                  value,
		ValueDrivers:           drivers,
		Exposure:               exposureOf(model, entity),
		VulnerabilitiesChecked: vulnerabilitiesChecked,
		Vulnerabilities:        []VulnerabilitySignal{},
		Countermeasures:        countermeasures,
		CountermeasureFactor:   factor,
	}
	signals := make([]VulnerabilitySignal, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		if signal, ok := ScoreVulnerability(model, vulnerability); ok {
			signals = append(signals, signal)
		}
	}
	slices.SortStableFunc(signals, func(a, b VulnerabilitySignal) int {
		if a.Probability != b.Probability {
			if a.Probability > b.Probability {
				return -1
			}
			return 1
		}
		return strings.Compare(a.URN, b.URN)
	})
	node.VulnerabilityCount = len(signals)
	considered := signals
	if len(considered) > model.Vulnerability.MaxPerAsset {
		considered = considered[:model.Vulnerability.MaxPerAsset]
	}
	node.ExploitProbability = model.Vulnerability.NoKnownVulnerability
	if len(considered) > 0 {
		safe := 1.0
		for _, signal := range considered {
			safe *= 1 - signal.Probability
		}
		node.ExploitProbability = 1 - safe
	}
	if len(signals) > maxReportedVulnerabilities {
		signals = signals[:maxReportedVulnerabilities]
	}
	node.Vulnerabilities = signals
	return node
}

// AssetValue returns how much an entity is worth to an attacker and why.
func AssetValue(model ports.AssetRiskModel, entity ports.CatalogEntity) (float64, []string) {
	values := model.AssetValue
	value := values.Default
	drivers := []string{}
	if key, kindValue, ok := matchKind(entity.EntityType, values.KindValues); ok {
		value = kindValue
		drivers = append(drivers, "kind:"+key)
	} else {
		drivers = append(drivers, "default")
	}
	for _, attribute := range values.ClassificationAttributes {
		for _, label := range splitList(entity.Attributes[attribute]) {
			if classValue, ok := values.Classifications[label]; ok && classValue > value {
				value = classValue
				drivers = append(drivers, "classification:"+label)
			}
		}
	}
	if isCrownJewel(entity.Attributes) && values.CrownJewel > value {
		value = values.CrownJewel
		drivers = append(drivers, "crown_jewel")
	}
	if isProduction(entity.Attributes) && values.ProductionBoost > 0 {
		value = math.Min(1, value+values.ProductionBoost)
		drivers = append(drivers, "production")
	}
	return value, drivers
}

// Countermeasures returns the countermeasures in place on an entity and the
// fraction of attack probability that survives them.
func Countermeasures(model ports.AssetRiskModel, entity ports.CatalogEntity) ([]CountermeasureHit, float64) {
	hits := []CountermeasureHit{}
	factor := 1.0
	for _, countermeasure := range model.Countermeasures {
		if len(countermeasure.AppliesTo) > 0 && !kindMatchesAny(entity.EntityType, countermeasure.AppliesTo) {
			continue
		}
		if !countermeasurePresent(countermeasure, entity.Attributes) {
			continue
		}
		hits = append(hits, CountermeasureHit{Key: countermeasure.Key, Label: countermeasure.Label, Reduction: countermeasure.Reduction})
		factor *= 1 - countermeasure.Reduction
	}
	return hits, factor
}

// ScoreVulnerability returns the exploit probability for one vulnerability.
// Vulnerabilities marked fixed on either the entity or the attaching edge are skipped.
func ScoreVulnerability(model ports.AssetRiskModel, input VulnerabilityInput) (VulnerabilitySignal, bool) {
	attrs := input.Entity.Attributes
	edge := input.EdgeAttributes
	if isResolvedStatus(firstValue(edge, "status", "state")) || isResolvedStatus(firstValue(attrs, "status", "state")) {
		return VulnerabilitySignal{}, false
	}
	vuln := model.Vulnerability
	signal := VulnerabilitySignal{
		URN:         input.Entity.URN,
		Label:       input.Entity.Label,
		CVE:         strings.ToUpper(firstValue(attrs, "cve", "cve_id", "vulnerability_id")),
		Probability: vuln.Base,
		Drivers:     []string{"base"},
	}
	raise := func(probability float64, driver string) {
		if probability > signal.Probability {
			signal.Probability = probability
			signal.Drivers = append(signal.Drivers, driver)
		}
	}
	if epss, ok := firstFloat(attrs, edge, "epss_score", "epss", "exploit_probability"); ok && epss >= 0 && epss <= 1 {
		signal.EPSS = &epss
		raise(epss*vuln.EPSSWeight, "epss")
	}
	cvss, hasCVSS := firstFloat(attrs, edge, "cvss_score", "cvss", "cvss_v3_score", "base_score")
	if !hasCVSS {
		cvss, hasCVSS = severityCVSS(firstValue(attrs, "severity"), firstValue(edge, "severity"))
	}
	if hasCVSS && cvss >= 0 && cvss <= 10 {
		signal.CVSS = &cvss
		switch {
		case cvss >= vuln.CVSSCritical:
			raise(vuln.CVSSCriticalProbability, "cvss_critical")
		case cvss >= vuln.CVSSHigh:
			raise(vuln.CVSSHighProbability, "cvss_high")
		}
	}
	if isTruthy(firstValue(attrs, "known_exploited", "is_kev", "kev", "cisa_kev")) || isTruthy(firstValue(edge, "known_exploited", "is_kev", "kev", "cisa_kev")) {
		signal.KnownExploited = true
		raise(vuln.KnownExploited, "known_exploited")
	}
	if ransomware := strings.ToLower(firstValue(attrs, "kev_ransomware_use", "ransomware_use")); ransomware == "known" || isTruthy(ransomware) {
		signal.RansomwareUse = true
		raise(vuln.RansomwareUse, "ransomware_use")
	}
	return signal, true
}

// EntryProbability is the probability that a starting point is compromised:
// either directly (phishing, credential theft) or by exploiting its
// vulnerabilities given its exposure, reduced by its countermeasures.
func EntryProbability(model ports.AssetRiskModel, node NodeAssessment) float64 {
	exposure := model.Exposure.Internal
	if node.Exposure == ExposureInternet {
		exposure = model.Exposure.Internet
	}
	exploited := 0.0
	if node.VulnerabilitiesChecked {
		exploited = node.ExploitProbability * exposure
	}
	direct := 1 - (1-model.Exposure.EntryProbability)*(1-exploited)
	return clampFraction(direct * node.CountermeasureFactor)
}

// StepProbability is the probability that an attacker holding one entity
// gains the next one over a relation.
func StepProbability(relation ports.AssetRiskRelation, target NodeAssessment) float64 {
	probability := relation.Probability * target.CountermeasureFactor
	if relation.RequiresExploit {
		probability *= target.ExploitProbability
	}
	return clampFraction(probability)
}

// Score converts a compromise probability and asset value into a 0-100 score.
func Score(probability, value float64) int {
	return int(math.Round(100 * clampFraction(probability) * clampFraction(value)))
}

// Level maps a score to a risk level using the model's thresholds.
func Level(model ports.AssetRiskModel, score int) string {
	switch {
	case score >= model.Thresholds.Critical:
		return "critical"
	case score >= model.Thresholds.High:
		return "high"
	case score >= model.Thresholds.Medium:
		return "medium"
	default:
		return "low"
	}
}

// IsVulnerabilityEntity reports whether an entity type describes a vulnerability record.
func IsVulnerabilityEntity(entityType string) bool {
	kind := strings.ToLower(entityType)
	return strings.Contains(kind, "vulnerab") || slices.Contains(kindSegments(kind), "cve")
}

func exposureOf(model ports.AssetRiskModel, entity ports.CatalogEntity) string {
	for _, attribute := range model.Exposure.InternetAttributes {
		if isTruthy(entity.Attributes[attribute]) {
			return ExposureInternet
		}
	}
	return ExposureInternal
}

func countermeasurePresent(countermeasure ports.AssetRiskCountermeasure, attrs map[string]string) bool {
	for _, attribute := range countermeasure.Attributes {
		value := strings.ToLower(strings.TrimSpace(attrs[attribute]))
		if value == "" {
			continue
		}
		if len(countermeasure.Values) == 0 {
			if isTruthy(value) {
				return true
			}
			continue
		}
		if slices.Contains(countermeasure.Values, value) {
			return true
		}
	}
	return false
}

// matchKind finds the most specific configured kind for an entity type. A
// key matches exactly, as a dotted prefix or suffix, or as one segment of the
// type (so "database" matches "aws.rds_database").
func matchKind(entityType string, values map[string]float64) (string, float64, bool) {
	kind := strings.ToLower(strings.TrimSpace(entityType))
	if kind == "" {
		return "", 0, false
	}
	if value, ok := values[kind]; ok {
		return kind, value, true
	}
	segments := kindSegments(kind)
	bestKey := ""
	bestValue := 0.0
	for key, value := range values {
		if !kindKeyMatches(kind, segments, key) {
			continue
		}
		if len(key) > len(bestKey) || (len(key) == len(bestKey) && (value > bestValue || (value == bestValue && key < bestKey))) {
			bestKey, bestValue = key, value
		}
	}
	return bestKey, bestValue, bestKey != ""
}

func kindMatchesAny(entityType string, keys []string) bool {
	kind := strings.ToLower(strings.TrimSpace(entityType))
	segments := kindSegments(kind)
	for _, key := range keys {
		if kind == key || kindKeyMatches(kind, segments, key) {
			return true
		}
	}
	return false
}

func kindKeyMatches(kind string, segments []string, key string) bool {
	if strings.ContainsAny(key, "._:/-") {
		return strings.HasSuffix(kind, "."+key) || strings.HasPrefix(kind, key+".")
	}
	return slices.Contains(segments, key)
}

func kindSegments(kind string) []string {
	return strings.FieldsFunc(kind, func(r rune) bool {
		return r == '.' || r == '_' || r == ':' || r == '/' || r == '-'
	})
}

func isCrownJewel(attrs map[string]string) bool {
	if isTruthy(attrs["crown_jewel"]) {
		return true
	}
	switch strings.ToLower(firstValue(attrs, "criticality", "business_criticality", "asset_criticality", "tier")) {
	case "critical", "tier0", "tier_0", "tier-0", "mission_critical":
		return true
	}
	return false
}

func isProduction(attrs map[string]string) bool {
	switch strings.ToLower(firstValue(attrs, "environment", "env", "stage")) {
	case "prod", "production", "prd":
		return true
	}
	return false
}

func isResolvedStatus(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fixed", "resolved", "closed", "remediated", "patched", "not_affected":
		return true
	}
	return false
}

func severityCVSS(values ...string) (float64, bool) {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "critical":
			return 9, true
		case "high":
			return 7, true
		case "medium", "moderate":
			return 5, true
		case "low":
			return 2, true
		}
	}
	return 0, false
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "y", "1", "on", "enabled", "active", "enforced", "installed":
		return true
	}
	return false
}

func firstValue(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return value
		}
	}
	return ""
}

func firstFloat(primary map[string]string, fallback map[string]string, keys ...string) (float64, bool) {
	for _, attrs := range []map[string]string{primary, fallback} {
		for _, key := range keys {
			raw := strings.TrimSpace(attrs[key])
			if raw == "" {
				continue
			}
			value, err := strconv.ParseFloat(raw, 64)
			if err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
				return value, true
			}
		}
	}
	return 0, false
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return r == ',' || r == ';' || r == '|' })
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func clampFraction(value float64) float64 {
	return math.Max(0, math.Min(1, value))
}
