package findings

import (
	"bytes"
	"fmt"
	"strings"

	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed builtin_rule_audit_extensions.yaml
var builtinRuleAuditExtensionsYAML []byte

var builtinRuleAuditExtensionSet builtinRuleAuditExtensions

func init() {
	extensions, err := loadBuiltinRuleAuditExtensions(builtinRuleAuditExtensionsYAML)
	if err != nil {
		panic(fmt.Sprintf("build builtin rule audit extensions: %v", err))
	}
	builtinRuleAuditExtensionSet = extensions
}

// builtinRuleAuditExtension carries the auditor-facing fields layered onto a
// non-policy built-in detection. It mirrors the policy_rule_extensions.yaml
// shape so policy and built-in detections expose the same audit-depth fields.
type builtinRuleAuditExtension struct {
	EvidenceType      string   `yaml:"evidence_type"`
	AssessmentMethods []string `yaml:"assessment_methods"`
	AuditorGuidance   string   `yaml:"auditor_guidance"`
	RiskStatement     string   `yaml:"risk_statement"`
	RemediationIntent string   `yaml:"remediation_intent"`
}

// builtinRuleAuditExtensions is the layered audit-depth overlay for non-policy
// built-in detections. Layers merge in order defaults -> anchors[lifecycle
// anchor] -> sources[source id] -> rules[rule id]; the rule's own definition
// values are the most specific layer and win over the overlay.
type builtinRuleAuditExtensions struct {
	Version  string                               `yaml:"version"`
	Defaults builtinRuleAuditExtension            `yaml:"defaults"`
	Anchors  map[string]builtinRuleAuditExtension `yaml:"anchors"`
	Sources  map[string]builtinRuleAuditExtension `yaml:"sources"`
	Rules    map[string]builtinRuleAuditExtension `yaml:"rules"`
}

func loadBuiltinRuleAuditExtensions(data []byte) (builtinRuleAuditExtensions, error) {
	var extensions builtinRuleAuditExtensions
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&extensions); err != nil {
		return builtinRuleAuditExtensions{}, fmt.Errorf("decode builtin rule audit extensions: %w", err)
	}
	if strings.TrimSpace(extensions.Version) == "" {
		return builtinRuleAuditExtensions{}, fmt.Errorf("builtin rule audit extensions version is required")
	}
	if missing := missingBuiltinRuleAuditFields(extensions.Defaults); len(missing) != 0 {
		return builtinRuleAuditExtensions{}, fmt.Errorf("builtin rule audit extension defaults missing %s", strings.Join(missing, ", "))
	}
	return extensions, nil
}

// resolve merges the audit-depth layers that apply to a definition.
func (e builtinRuleAuditExtensions) resolve(def RuleDefinition) builtinRuleAuditExtension {
	merged := builtinRuleAuditExtension{}
	merged = mergeBuiltinRuleAuditExtension(merged, e.Defaults)
	if anchor := strings.TrimSpace(string(def.Lifecycle.Anchor)); anchor != "" {
		merged = mergeBuiltinRuleAuditExtension(merged, e.Anchors[anchor])
	}
	if sourceID := strings.TrimSpace(def.SourceID); sourceID != "" {
		merged = mergeBuiltinRuleAuditExtension(merged, e.Sources[sourceID])
	}
	if id := strings.TrimSpace(def.ID); id != "" {
		merged = mergeBuiltinRuleAuditExtension(merged, e.Rules[id])
	}
	return merged
}

func mergeBuiltinRuleAuditExtension(base builtinRuleAuditExtension, next builtinRuleAuditExtension) builtinRuleAuditExtension {
	if value := strings.TrimSpace(next.EvidenceType); value != "" {
		base.EvidenceType = value
	}
	if value := strings.TrimSpace(next.AuditorGuidance); value != "" {
		base.AuditorGuidance = value
	}
	if value := strings.TrimSpace(next.RiskStatement); value != "" {
		base.RiskStatement = value
	}
	if value := strings.TrimSpace(next.RemediationIntent); value != "" {
		base.RemediationIntent = value
	}
	if methods := uniqueSortedStrings(next.AssessmentMethods); len(methods) != 0 {
		base.AssessmentMethods = methods
	}
	return base
}

// applyBuiltinRuleAuditDepth fills the audit-depth fields of a non-policy
// built-in detection from the layered overlay. Policy detections already carry
// audit depth from their generated catalog and are left unchanged. Any value the
// rule already declares wins over the overlay.
func applyBuiltinRuleAuditDepth(def RuleDefinition) RuleDefinition {
	if strings.EqualFold(strings.TrimSpace(def.SourceID), policyRuleSourceID) {
		return def
	}
	merged := builtinRuleAuditExtensionSet.resolve(def)
	if strings.TrimSpace(def.EvidenceType) == "" {
		def.EvidenceType = merged.EvidenceType
	}
	if strings.TrimSpace(def.AuditorGuidance) == "" {
		def.AuditorGuidance = merged.AuditorGuidance
	}
	if strings.TrimSpace(def.RiskStatement) == "" {
		def.RiskStatement = merged.RiskStatement
	}
	if strings.TrimSpace(def.RemediationIntent) == "" {
		def.RemediationIntent = merged.RemediationIntent
	}
	if len(uniqueSortedStrings(def.AssessmentMethods)) == 0 {
		def.AssessmentMethods = cloneStringSlice(merged.AssessmentMethods)
	}
	return def
}

// ValidatePublicDetectionAuditDepth reports detections missing any
// auditor-facing audit-depth field. Every detection in the generated catalog
// must carry an evidence type, assessment methods, auditor guidance, a risk
// statement, and a remediation intent so the all-finding compliance mapping is
// uniformly audit-ready and the non-policy audit-depth gap cannot regress.
func ValidatePublicDetectionAuditDepth(catalog PublicDetectionCatalog) []error {
	var errs []error
	for _, detection := range catalog.Detections {
		id := strings.TrimSpace(detection.ID)
		if id == "" {
			continue
		}
		for _, field := range missingBuiltinRuleAuditFields(builtinRuleAuditExtension{
			EvidenceType:      detection.EvidenceType,
			AssessmentMethods: detection.AssessmentMethods,
			AuditorGuidance:   detection.AuditorGuidance,
			RiskStatement:     detection.RiskStatement,
			RemediationIntent: detection.RemediationIntent,
		}) {
			errs = append(errs, fmt.Errorf("detection %q %s is required", id, field))
		}
	}
	return errs
}

func missingBuiltinRuleAuditFields(extension builtinRuleAuditExtension) []string {
	var missing []string
	if strings.TrimSpace(extension.EvidenceType) == "" {
		missing = append(missing, "evidence_type")
	}
	if len(uniqueSortedStrings(extension.AssessmentMethods)) == 0 {
		missing = append(missing, "assessment_methods")
	}
	if strings.TrimSpace(extension.AuditorGuidance) == "" {
		missing = append(missing, "auditor_guidance")
	}
	if strings.TrimSpace(extension.RiskStatement) == "" {
		missing = append(missing, "risk_statement")
	}
	if strings.TrimSpace(extension.RemediationIntent) == "" {
		missing = append(missing, "remediation_intent")
	}
	return missing
}
