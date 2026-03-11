package dspm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/policy"
)

const (
	PolicyIDRestrictedDataUnencrypted = "dspm-restricted-data-unencrypted"
	PolicyIDConfidentialDataPublic    = "dspm-confidential-data-public"
)

// ToPolicyFindings converts a DSPM scan result into platform policy findings.
func (r *ScanResult) ToPolicyFindings(target *ScanTarget) []policy.Finding {
	if r == nil {
		return nil
	}

	resolved := resolveScanTarget(target, r)
	if len(r.Findings) == 0 && len(r.ComplianceGaps) == 0 {
		return nil
	}

	result := make([]policy.Finding, 0, len(r.Findings)+len(r.ComplianceGaps)+2)

	for _, finding := range r.Findings {
		result = append(result, buildSensitiveDataFinding(r, resolved, finding))
	}

	if r.Classification == ClassificationRestricted && !resolved.IsEncrypted && len(r.Findings) > 0 {
		result = append(result, buildRestrictedUnencryptedFinding(r, resolved))
	}

	if isConfidentialOrHigher(r.Classification) && resolved.IsPublic && len(r.Findings) > 0 {
		result = append(result, buildPublicExposureFinding(r, resolved))
	}

	for _, gap := range r.ComplianceGaps {
		result = append(result, buildComplianceGapFinding(r, resolved, gap))
	}

	return result
}

type resolvedScanTarget struct {
	ID          string
	Type        string
	Name        string
	Provider    string
	Account     string
	Region      string
	ARN         string
	IsPublic    bool
	IsEncrypted bool
}

func resolveScanTarget(target *ScanTarget, result *ScanResult) resolvedScanTarget {
	out := resolvedScanTarget{
		Type: "data_store",
	}
	if target != nil {
		out.ID = strings.TrimSpace(target.ID)
		out.Type = strings.TrimSpace(target.Type)
		out.Name = strings.TrimSpace(target.Name)
		out.Provider = strings.TrimSpace(target.Provider)
		out.Account = strings.TrimSpace(target.Account)
		out.Region = strings.TrimSpace(target.Region)
		out.ARN = strings.TrimSpace(target.ARN)
		out.IsPublic = target.IsPublic
		out.IsEncrypted = target.IsEncrypted
	}
	if out.ID == "" {
		out.ID = strings.TrimSpace(result.TargetID)
	}
	if out.Name == "" {
		out.Name = strings.TrimSpace(result.TargetName)
	}
	if out.Provider == "" {
		out.Provider = strings.TrimSpace(result.Provider)
	}
	if out.Type == "" {
		out.Type = strings.TrimSpace(result.TargetType)
	}
	if out.ID == "" {
		out.ID = out.Name
	}
	if out.Name == "" {
		out.Name = out.ID
	}
	if out.Type == "" {
		out.Type = "data_store"
	}
	return out
}

func buildSensitiveDataFinding(scan *ScanResult, target resolvedScanTarget, finding SensitiveDataFinding) policy.Finding {
	resource := buildBaseResource(scan, target)
	resource["data_type"] = string(finding.DataType)
	resource["match_count"] = finding.MatchCount
	resource["confidence"] = finding.Confidence
	resource["risk"] = finding.Risk
	resource["locations"] = len(finding.Locations)

	dataType := formatDataType(finding.DataType)
	description := fmt.Sprintf(
		"Sensitive data type %s detected in %s with %d matches",
		dataType,
		target.Name,
		finding.MatchCount,
	)

	return policy.Finding{
		ID:             "dspm-sensitive-" + sanitizeIDPart(target.ID) + "-" + sanitizeIDPart(string(finding.DataType)),
		PolicyID:       "dspm-sensitive-data-" + sanitizeIDPart(string(finding.DataType)),
		PolicyName:     "DSPM Sensitive Data: " + dataType,
		Title:          "DSPM Sensitive Data: " + dataType,
		Severity:       severityForSensitiveFinding(finding, target),
		Description:    description,
		Remediation:    remediationForSensitiveFinding(finding, target),
		Resource:       resource,
		ResourceType:   "dspm/" + target.Type,
		ResourceID:     target.ID,
		ResourceName:   target.Name,
		RiskCategories: riskCategoriesForSensitiveFinding(target),
		Frameworks:     frameworkMappingsForSensitiveFinding(finding),
	}
}

func buildRestrictedUnencryptedFinding(scan *ScanResult, target resolvedScanTarget) policy.Finding {
	frameworks := mergeFrameworkMappings(
		frameworkMappingsFromFrameworks(frameworkUnion(scan.Findings)),
		[]policy.FrameworkMapping{{Name: "PCI DSS", Controls: []string{"3.5.1"}}, {Name: "HIPAA Security Rule", Controls: []string{"164.312(a)(2)(iv)"}}},
	)
	resource := buildBaseResource(scan, target)
	resource["risk_condition"] = "restricted_data_unencrypted"

	return policy.Finding{
		ID:           "dspm-restricted-unencrypted-" + sanitizeIDPart(target.ID),
		PolicyID:     PolicyIDRestrictedDataUnencrypted,
		PolicyName:   "DSPM Restricted Data Unencrypted",
		Title:        "DSPM Restricted Data Unencrypted",
		Severity:     "critical",
		Description:  "Restricted data is present in storage without encryption at rest",
		Remediation:  "Enable encryption at rest for this data store and rotate any exposed secrets.",
		Resource:     resource,
		ResourceType: "dspm/" + target.Type,
		ResourceID:   target.ID,
		ResourceName: target.Name,
		RiskCategories: []string{
			policy.RiskUnprotectedData,
			policy.RiskMisconfiguration,
		},
		Frameworks: frameworks,
	}
}

func buildPublicExposureFinding(scan *ScanResult, target resolvedScanTarget) policy.Finding {
	frameworks := mergeFrameworkMappings(
		frameworkMappingsFromFrameworks(frameworkUnion(scan.Findings)),
		[]policy.FrameworkMapping{{Name: "PCI DSS", Controls: []string{"1.3.1"}}, {Name: "HIPAA Security Rule", Controls: []string{"164.312(e)(1)"}}},
	)
	severity := "high"
	if scan.Classification == ClassificationRestricted {
		severity = "critical"
	}
	resource := buildBaseResource(scan, target)
	resource["risk_condition"] = "confidential_data_public"

	return policy.Finding{
		ID:           "dspm-confidential-public-" + sanitizeIDPart(target.ID),
		PolicyID:     PolicyIDConfidentialDataPublic,
		PolicyName:   "DSPM Confidential Data Public Exposure",
		Title:        "DSPM Confidential Data Public Exposure",
		Severity:     severity,
		Description:  "Sensitive data is stored in a publicly accessible data store",
		Remediation:  "Restrict public access to this data store and enforce least-privilege access controls.",
		Resource:     resource,
		ResourceType: "dspm/" + target.Type,
		ResourceID:   target.ID,
		ResourceName: target.Name,
		RiskCategories: []string{
			policy.RiskExternalExposure,
			policy.RiskDataExfiltration,
			policy.RiskUnprotectedData,
		},
		Frameworks: frameworks,
	}
}

func buildComplianceGapFinding(scan *ScanResult, target resolvedScanTarget, gap ComplianceGap) policy.Finding {
	resource := buildBaseResource(scan, target)
	resource["framework"] = string(gap.Framework)
	resource["requirement"] = gap.Requirement
	resource["gap_description"] = gap.Description

	mapping := frameworkMappingForGap(gap)

	return policy.Finding{
		ID:             "dspm-gap-" + sanitizeIDPart(target.ID) + "-" + sanitizeIDPart(string(gap.Framework)) + "-" + sanitizeIDPart(gap.Requirement),
		PolicyID:       "dspm-compliance-gap-" + sanitizeIDPart(string(gap.Framework)),
		PolicyName:     "DSPM Compliance Gap: " + strings.ToUpper(strings.ReplaceAll(string(gap.Framework), "_", " ")),
		Title:          "DSPM Compliance Gap: " + gap.Requirement,
		Severity:       normalizeSeverity(gap.Severity),
		Description:    gap.Description,
		Remediation:    "Address the control gap and implement compensating controls for the affected framework requirement.",
		Resource:       resource,
		ResourceType:   "dspm/" + target.Type,
		ResourceID:     target.ID,
		ResourceName:   target.Name,
		RiskCategories: []string{policy.RiskUnprotectedData, policy.RiskMisconfiguration},
		Frameworks:     []policy.FrameworkMapping{mapping},
	}
}

func buildBaseResource(scan *ScanResult, target resolvedScanTarget) map[string]interface{} {
	resource := map[string]interface{}{
		"target_id":       target.ID,
		"target_name":     target.Name,
		"target_type":     target.Type,
		"provider":        target.Provider,
		"account":         target.Account,
		"region":          target.Region,
		"arn":             target.ARN,
		"is_public":       target.IsPublic,
		"is_encrypted":    target.IsEncrypted,
		"classification":  string(scan.Classification),
		"dspm_risk_score": scan.RiskScore,
	}
	if scan.SampleSize > 0 {
		resource["sample_size"] = scan.SampleSize
	}
	if scan.ObjectsScanned > 0 {
		resource["objects_scanned"] = scan.ObjectsScanned
	}
	return resource
}

func severityForSensitiveFinding(finding SensitiveDataFinding, target resolvedScanTarget) string {
	switch finding.Classification {
	case ClassificationRestricted:
		if target.IsPublic {
			return "critical"
		}
		return "high"
	case ClassificationConfidential:
		if target.IsPublic {
			return "high"
		}
		return "medium"
	case ClassificationInternal:
		return "low"
	default:
		return "low"
	}
}

func remediationForSensitiveFinding(finding SensitiveDataFinding, target resolvedScanTarget) string {
	remediations := []string{
		"Review and restrict access to the affected data store.",
	}
	if !target.IsEncrypted {
		remediations = append(remediations, "Enable encryption at rest.")
	}
	if target.IsPublic {
		remediations = append(remediations, "Remove public access immediately.")
	}
	switch finding.DataType {
	case DataTypeCreditCard:
		remediations = append(remediations, "Tokenize or redact cardholder data.")
	case DataTypeHealthRecord:
		remediations = append(remediations, "Apply HIPAA safeguards for PHI handling.")
	case DataTypeAWSAccessKey, DataTypeAPIKey, DataTypePrivateKey, DataTypePassword, DataTypeJWT:
		remediations = append(remediations, "Rotate exposed credentials and revoke old secrets.")
	}
	return strings.Join(remediations, " ")
}

func riskCategoriesForSensitiveFinding(target resolvedScanTarget) []string {
	categories := []string{policy.RiskUnprotectedData}
	if target.IsPublic {
		categories = append(categories, policy.RiskExternalExposure, policy.RiskDataExfiltration)
	}
	if !target.IsEncrypted {
		categories = append(categories, policy.RiskMisconfiguration)
	}
	return categories
}

func frameworkMappingsForSensitiveFinding(finding SensitiveDataFinding) []policy.FrameworkMapping {
	return frameworkMappingsFromFrameworks(finding.Frameworks)
}

func frameworkMappingsFromFrameworks(frameworks []ComplianceFramework) []policy.FrameworkMapping {
	if len(frameworks) == 0 {
		return nil
	}
	controlsByFramework := map[string]map[string]struct{}{}

	for _, framework := range frameworks {
		mapping := defaultFrameworkMapping(framework)
		if mapping.Name == "" {
			continue
		}
		if _, ok := controlsByFramework[mapping.Name]; !ok {
			controlsByFramework[mapping.Name] = map[string]struct{}{}
		}
		for _, control := range mapping.Controls {
			if strings.TrimSpace(control) == "" {
				continue
			}
			controlsByFramework[mapping.Name][control] = struct{}{}
		}
	}

	if len(controlsByFramework) == 0 {
		return nil
	}

	names := make([]string, 0, len(controlsByFramework))
	for name := range controlsByFramework {
		names = append(names, name)
	}
	sort.Strings(names)

	mappings := make([]policy.FrameworkMapping, 0, len(names))
	for _, name := range names {
		controls := make([]string, 0, len(controlsByFramework[name]))
		for control := range controlsByFramework[name] {
			controls = append(controls, control)
		}
		sort.Strings(controls)
		mappings = append(mappings, policy.FrameworkMapping{Name: name, Controls: controls})
	}
	return mappings
}

func frameworkMappingForGap(gap ComplianceGap) policy.FrameworkMapping {
	base := defaultFrameworkMapping(gap.Framework)
	controls := append([]string{}, base.Controls...)
	if strings.TrimSpace(gap.Requirement) != "" {
		controls = append(controls, gap.Requirement)
	}
	if len(controls) == 0 {
		controls = []string{"unspecified"}
	}
	controls = uniqueSortedStrings(controls)
	return policy.FrameworkMapping{
		Name:     base.Name,
		Controls: controls,
	}
}

func defaultFrameworkMapping(framework ComplianceFramework) policy.FrameworkMapping {
	switch framework {
	case FrameworkPCI:
		return policy.FrameworkMapping{Name: "PCI DSS", Controls: []string{"3.5.1"}}
	case FrameworkHIPAA:
		return policy.FrameworkMapping{Name: "HIPAA Security Rule", Controls: []string{"164.312(a)(2)(iv)"}}
	case FrameworkGDPR:
		return policy.FrameworkMapping{Name: "GDPR", Controls: []string{"Article 32"}}
	case FrameworkSOC2:
		return policy.FrameworkMapping{Name: "SOC 2", Controls: []string{"CC6.7"}}
	case FrameworkCCPA:
		return policy.FrameworkMapping{Name: "CCPA", Controls: []string{"1798.150"}}
	default:
		return policy.FrameworkMapping{Name: strings.ToUpper(strings.ReplaceAll(string(framework), "_", " "))}
	}
}

func frameworkUnion(findings []SensitiveDataFinding) []ComplianceFramework {
	if len(findings) == 0 {
		return nil
	}
	set := make(map[ComplianceFramework]struct{})
	for _, finding := range findings {
		for _, framework := range finding.Frameworks {
			set[framework] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	frameworks := make([]ComplianceFramework, 0, len(set))
	for framework := range set {
		frameworks = append(frameworks, framework)
	}
	sort.Slice(frameworks, func(i, j int) bool {
		return frameworks[i] < frameworks[j]
	})
	return frameworks
}

func mergeFrameworkMappings(mappings ...[]policy.FrameworkMapping) []policy.FrameworkMapping {
	merged := map[string]map[string]struct{}{}
	for _, list := range mappings {
		for _, item := range list {
			name := strings.TrimSpace(item.Name)
			if name == "" {
				continue
			}
			if _, ok := merged[name]; !ok {
				merged[name] = map[string]struct{}{}
			}
			for _, control := range item.Controls {
				control = strings.TrimSpace(control)
				if control == "" {
					continue
				}
				merged[name][control] = struct{}{}
			}
		}
	}
	if len(merged) == 0 {
		return nil
	}
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]policy.FrameworkMapping, 0, len(names))
	for _, name := range names {
		controls := make([]string, 0, len(merged[name]))
		for control := range merged[name] {
			controls = append(controls, control)
		}
		sort.Strings(controls)
		out = append(out, policy.FrameworkMapping{Name: name, Controls: controls})
	}
	return out
}

func sanitizeIDPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(value))
	prevDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if prevDash {
			continue
		}
		b.WriteRune('-')
		prevDash = true
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "unknown"
	}
	return s
}

func formatDataType(dataType DataType) string {
	label := strings.ReplaceAll(string(dataType), "_", " ")
	label = strings.TrimSpace(label)
	if label == "" {
		return "Unknown"
	}
	parts := strings.Fields(label)
	for i := range parts {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, " ")
}

func uniqueSortedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func isConfidentialOrHigher(classification DataClassification) bool {
	return classification == ClassificationConfidential || classification == ClassificationRestricted
}
