// Package rulecatalog presents built-in policy rules, compiled detections,
// correlation patterns, and saved custom rules as one classified catalog.
package rulecatalog

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

// Origin records where a catalog rule is defined.
const (
	OriginBuiltinPolicy    = "builtin_policy"
	OriginBuiltinDetection = "builtin_detection"
	OriginCorrelation      = "correlation_pattern"
	OriginCustom           = "custom"
)

// Entry is the list view of one rule.
type Entry struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Summary         string   `json:"summary"`
	Severity        string   `json:"severity"`
	Origin          string   `json:"origin"`
	Domain          string   `json:"domain"`
	Posture         string   `json:"posture"`
	Provider        string   `json:"provider"`
	Category        string   `json:"category,omitempty"`
	ResourceType    string   `json:"resource_type,omitempty"`
	Evaluation      string   `json:"evaluation"`
	Detection       string   `json:"detection"`
	Enabled         bool     `json:"enabled"`
	Maturity        string   `json:"maturity,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Frameworks      []string `json:"frameworks,omitempty"`
	MITRETechniques []string `json:"mitre_techniques,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

// ControlRef maps a rule onto one framework control.
type ControlRef struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
}

// MITRERef maps a rule onto one ATT&CK technique.
type MITRERef struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
}

// Detail is the full view of one rule.
type Detail struct {
	Entry
	Description           string       `json:"description"`
	AttackDescription     string       `json:"attack_description"`
	Remediation           string       `json:"remediation"`
	RemediationSteps      []string     `json:"remediation_steps,omitempty"`
	Runbook               string       `json:"runbook,omitempty"`
	FalsePositives        []string     `json:"false_positives,omitempty"`
	References            []string     `json:"references,omitempty"`
	ControlRefs           []ControlRef `json:"control_refs,omitempty"`
	MITREAttack           []MITRERef   `json:"mitre_attack,omitempty"`
	Conditions            []string     `json:"conditions,omitempty"`
	Query                 string       `json:"query,omitempty"`
	GraphQuery            string       `json:"graph_query,omitempty"`
	GraphSourceKinds      []string     `json:"graph_source_kinds,omitempty"`
	CorrelatedRuleIDs     []string     `json:"correlated_rule_ids,omitempty"`
	CorrelationDimensions []string     `json:"correlation_dimensions,omitempty"`
	CorrelationWindow     string       `json:"correlation_window,omitempty"`
	FingerprintFields     []string     `json:"fingerprint_fields,omitempty"`
	Lifecycle             string       `json:"lifecycle,omitempty"`
	SourcePath            string       `json:"source_path,omitempty"`
	Document              string       `json:"document,omitempty"`
	Editable              bool         `json:"editable"`
	Testable              bool         `json:"testable"`
	CreatedBy             string       `json:"created_by,omitempty"`
	UpdatedBy             string       `json:"updated_by,omitempty"`
	CreatedAt             string       `json:"created_at,omitempty"`
}

var builtinCatalog struct {
	once    sync.Once
	details []Detail
	byID    map[string]int
}

// Builtin returns every built-in rule detail sorted by domain then ID.
// Callers must not mutate the returned slices.
func Builtin() []Detail {
	builtinCatalog.once.Do(loadBuiltin)
	return builtinCatalog.details
}

// BuiltinRule returns one built-in rule detail by ID.
func BuiltinRule(id string) (Detail, bool) {
	builtinCatalog.once.Do(loadBuiltin)
	index, ok := builtinCatalog.byID[strings.TrimSpace(id)]
	if !ok {
		return Detail{}, false
	}
	return builtinCatalog.details[index], true
}

// IsBuiltinID reports whether an ID is reserved by a built-in rule.
func IsBuiltinID(id string) bool {
	_, ok := BuiltinRule(id)
	return ok
}

func loadBuiltin() {
	details := []Detail{}
	seen := map[string]struct{}{}
	for _, source := range findings.BuiltinPolicyRuleSources() {
		detail := policyDetail(source)
		if detail.ID == "" {
			continue
		}
		seen[detail.ID] = struct{}{}
		details = append(details, detail)
	}
	for _, detection := range findings.BuiltinPublicDetectionCatalog().Detections {
		id := strings.TrimSpace(detection.ID)
		if _, ok := seen[id]; ok || id == "" {
			continue
		}
		seen[id] = struct{}{}
		details = append(details, detectionDetail(detection))
	}
	severityByID := map[string]string{}
	for _, detail := range details {
		severityByID[detail.ID] = detail.Severity
	}
	for _, pattern := range findings.BuiltinFindingCorrelationPatterns() {
		id := strings.TrimSpace(pattern.ID)
		if _, ok := seen[id]; ok || id == "" {
			continue
		}
		seen[id] = struct{}{}
		details = append(details, correlationDetail(pattern, severityByID))
	}
	sortDetails(details)
	byID := make(map[string]int, len(details))
	for index, detail := range details {
		byID[detail.ID] = index
	}
	builtinCatalog.details = details
	builtinCatalog.byID = byID
}

func sortDetails(details []Detail) {
	sort.SliceStable(details, func(i, j int) bool {
		if details[i].Domain != details[j].Domain {
			return domainOrder(details[i].Domain) < domainOrder(details[j].Domain)
		}
		return details[i].ID < details[j].ID
	})
}

func domainOrder(domain string) int {
	switch domain {
	case DomainPaaS:
		return 0
	case DomainSaaS:
		return 1
	case DomainIdentity:
		return 2
	default:
		return 3
	}
}

func policyDetail(source findings.PolicyRuleSource) Detail {
	definition := source.Definition
	tags := authoredTags(definition.Tags, source.Category, source.EvidenceMode)
	classification := ClassifyPolicy(source.Category, source.ResourceType, definition.Tags, source.GraphSourceKinds)
	evaluation := EvaluationCEL
	detection := DetectionPosture
	switch {
	case strings.TrimSpace(source.GraphQuery) != "":
		evaluation = EvaluationGraph
		detection = DetectionCorrelation
		classification = correlateUnanchoredGraph(classification)
	case strings.TrimSpace(source.Query) != "":
		evaluation = EvaluationSQL
	}
	if classification.Domain == DomainCorrelation {
		detection = DetectionCorrelation
	}
	controls := controlRefs(definition.ControlRefs)
	mitre := mitreRefs(definition.MITREAttack)
	summary := firstNonEmpty(source.Summary, definition.Description)
	remediation := firstNonEmpty(source.Remediation, source.RemediationIntent, definition.Runbook)
	detail := Detail{
		Entry: Entry{
			ID:              strings.TrimSpace(definition.ID),
			Name:            strings.TrimSpace(definition.Name),
			Summary:         summary,
			Severity:        normalizeSeverity(definition.Severity),
			Origin:          OriginBuiltinPolicy,
			Domain:          classification.Domain,
			Posture:         classification.Posture,
			Provider:        classification.Provider,
			Category:        strings.TrimSpace(source.Category),
			ResourceType:    strings.TrimSpace(source.ResourceType),
			Evaluation:      evaluation,
			Detection:       detection,
			Enabled:         source.Enabled,
			Maturity:        strings.TrimSpace(definition.Maturity),
			Tags:            tags,
			Frameworks:      frameworkNames(controls),
			MITRETechniques: mitreTechniques(mitre),
		},
		Description:       strings.TrimSpace(definition.Description),
		AttackDescription: attackDescription(summary, source.RiskStatement, mitre),
		Remediation:       remediation,
		RemediationSteps:  append([]string(nil), source.RemediationSteps...),
		Runbook:           strings.TrimSpace(definition.Runbook),
		FalsePositives:    append([]string(nil), definition.FalsePositives...),
		References:        append([]string(nil), definition.References...),
		ControlRefs:       controls,
		MITREAttack:       mitre,
		Conditions:        append([]string(nil), source.Conditions...),
		Query:             strings.TrimSpace(source.Query),
		GraphQuery:        strings.TrimSpace(source.GraphQuery),
		GraphSourceKinds:  append([]string(nil), source.GraphSourceKinds...),
		FingerprintFields: append([]string(nil), definition.FingerprintFields...),
		Lifecycle:         lifecycleLabel(string(definition.Lifecycle.Kind), string(definition.Lifecycle.Anchor), definition.Lifecycle.TTL),
		SourcePath:        strings.TrimSpace(source.RelPath),
		Testable:          len(source.Conditions) != 0,
	}
	if document, err := findingdsl.FormatPolicyRuleYAML(policyDocument(source, tags)); err == nil {
		detail.Document = string(document)
	}
	return detail
}

func detectionDetail(detection findings.PublicDetection) Detail {
	classification := ClassifyDetection(detection.SourceID, detection.PackID, detection.EvaluationMode, detection.Tags)
	evaluation := EvaluationEvent
	detectionMode := DetectionEvent
	if strings.EqualFold(detection.EvaluationMode, "graph") {
		evaluation = EvaluationGraph
		detectionMode = DetectionCorrelation
	}
	if classification.Domain == DomainCorrelation {
		detectionMode = DetectionCorrelation
	}
	controls := make([]ControlRef, 0, len(detection.ControlRefs))
	for _, ref := range detection.ControlRefs {
		controls = append(controls, ControlRef{Framework: strings.TrimSpace(ref.FrameworkName), Control: strings.TrimSpace(ref.ControlID)})
	}
	mitre := make([]MITRERef, 0, len(detection.MITREAttack))
	for _, ref := range detection.MITREAttack {
		mitre = append(mitre, MITRERef{Tactic: ref.Tactic, Technique: ref.Technique})
	}
	summary := strings.TrimSpace(detection.Description)
	return Detail{
		Entry: Entry{
			ID:              strings.TrimSpace(detection.ID),
			Name:            strings.TrimSpace(detection.Name),
			Summary:         summary,
			Severity:        normalizeSeverity(detection.Severity),
			Origin:          OriginBuiltinDetection,
			Domain:          classification.Domain,
			Posture:         classification.Posture,
			Provider:        classification.Provider,
			Category:        strings.TrimSpace(detection.PackID),
			Evaluation:      evaluation,
			Detection:       detectionMode,
			Enabled:         !strings.EqualFold(detection.Status, "retired") && !strings.EqualFold(detection.Maturity, findings.RuleMaturityRetired),
			Maturity:        strings.TrimSpace(detection.Maturity),
			Tags:            withoutLineageTags(detection.Tags),
			Frameworks:      frameworkNames(controls),
			MITRETechniques: mitreTechniques(mitre),
		},
		Description:       summary,
		AttackDescription: attackDescription(summary, detection.RiskStatement, mitre),
		Remediation:       firstNonEmpty(detection.RemediationIntent, detection.Runbook),
		Runbook:           strings.TrimSpace(detection.Runbook),
		FalsePositives:    append([]string(nil), detection.FalsePositives...),
		References:        append([]string(nil), detection.References...),
		ControlRefs:       controls,
		MITREAttack:       mitre,
		FingerprintFields: append([]string(nil), detection.FingerprintFields...),
		Lifecycle:         lifecycleLabel(string(detection.Lifecycle.Kind), string(detection.Lifecycle.Anchor), time.Duration(detection.Lifecycle.TTLSeconds)*time.Second),
	}
}

func correlationDetail(pattern findings.FindingCorrelationPattern, severityByID map[string]string) Detail {
	severity := "medium"
	for _, ruleID := range pattern.RuleIDs {
		if candidate := severityByID[ruleID]; severityRank(candidate) > severityRank(severity) {
			severity = candidate
		}
	}
	window := ""
	if pattern.Window > 0 {
		window = pattern.Window.String()
	}
	summary := fmt.Sprintf("Raises priority when findings from %s share the same %s", strings.Join(pattern.RuleIDs, " and "), strings.Join(pattern.Dimensions, " or "))
	if window != "" {
		summary += " within " + window
	}
	summary += "."
	reasons := make([]string, 0, len(pattern.Reasons))
	for _, reason := range pattern.Reasons {
		reasons = append(reasons, strings.ReplaceAll(reason, "_", " "))
	}
	attack := summary
	if len(reasons) != 0 {
		attack += " Together these signals indicate " + strings.Join(reasons, ", ") + ", which is more likely to be exploitable than either finding alone."
	}
	return Detail{
		Entry: Entry{
			ID:         strings.TrimSpace(pattern.ID),
			Name:       strings.TrimSpace(pattern.Name),
			Summary:    summary,
			Severity:   severity,
			Origin:     OriginCorrelation,
			Domain:     DomainCorrelation,
			Posture:    PostureCorrelation,
			Provider:   "cerebro",
			Evaluation: EvaluationCorrelation,
			Detection:  DetectionCorrelation,
			Enabled:    true,
			Maturity:   findings.RuleMaturityGA,
			Tags:       append([]string{"correlation"}, pattern.Reasons...),
		},
		Description:           summary,
		AttackDescription:     attack,
		Remediation:           "Remediate the contributing findings (" + strings.Join(pattern.RuleIDs, ", ") + "); resolving any one of them breaks the correlated risk.",
		CorrelatedRuleIDs:     append([]string(nil), pattern.RuleIDs...),
		CorrelationDimensions: append([]string(nil), pattern.Dimensions...),
		CorrelationWindow:     window,
	}
}

func policyDocument(source findings.PolicyRuleSource, tags []string) findingdsl.PolicyFindingRule {
	definition := source.Definition
	rule := findingdsl.PolicyFindingRule{
		APIVersion: findingdsl.APIVersion,
		Kind:       findingdsl.KindPolicyFindingRule,
		Metadata: findingdsl.PolicyRuleMetadata{
			ID:          definition.ID,
			Name:        definition.Name,
			Description: firstNonEmpty(source.Summary, definition.Description),
			Tags:        tags,
			References:  definition.References,
		},
		Spec: findingdsl.PolicyFindingRuleSpec{
			Severity:    strings.ToLower(strings.TrimSpace(definition.Severity)),
			Category:    source.Category,
			Resource:    source.Resource,
			Match:       findingdsl.PolicyRuleMatch{Conditions: source.Conditions, Query: source.Query},
			Remediation: findingdsl.PolicyRuleRemediation{Summary: source.Remediation, Steps: source.RemediationSteps},
			Frameworks:  policyFrameworks(definition.ControlRefs),
			MITREAttack: policyMITRE(definition.MITREAttack),
			Input:       findingdsl.PolicyRuleInput{SourceKinds: source.GraphSourceKinds},
			Graph:       findingdsl.PolicyRuleGraphFinding{Query: source.GraphQuery, RowLimit: source.GraphRowLimit, Params: source.GraphParams, RequiredColumns: source.GraphColumns},
		},
	}
	if source.ResourceType != source.Resource {
		rule.Spec.ResourceType = source.ResourceType
	}
	if len(source.Conditions) != 0 {
		rule.Spec.Effect = "forbid"
		rule.Spec.Match.ConditionFormat = "cel"
	}
	if !source.Enabled {
		disabled := false
		rule.Spec.Enabled = &disabled
	}
	return rule
}

// generatedTags are appended by the policy generator and are not authored.
func authoredTags(tags []string, category string, evidenceMode string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		switch {
		case trimmed == "", trimmed == "policy", trimmed == "generated", isLineageTag(trimmed):
			continue
		case strings.HasPrefix(trimmed, "evidence:"), strings.HasPrefix(trimmed, "assessment:"):
			continue
		case trimmed == strings.TrimSpace(evidenceMode), trimmed == strings.TrimSpace(category):
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// lineageTags record which third-party catalog a rule was ported from. They
// carry no detection meaning, so the catalog does not surface them.
var lineageTags = map[string]struct{}{"wiz": {}}

func isLineageTag(tag string) bool {
	_, ok := lineageTags[strings.ToLower(strings.TrimSpace(tag))]
	return ok
}

func withoutLineageTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if !isLineageTag(tag) {
			out = append(out, tag)
		}
	}
	return out
}

func controlRefs(refs []ports.FindingControlRef) []ControlRef {
	out := make([]ControlRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ControlRef{Framework: strings.TrimSpace(ref.FrameworkName), Control: strings.TrimSpace(ref.ControlID)})
	}
	return out
}

func policyFrameworks(refs []ports.FindingControlRef) []findingdsl.PolicyFramework {
	order := []string{}
	controls := map[string][]string{}
	for _, ref := range refs {
		name := strings.TrimSpace(ref.FrameworkName)
		if name == "" {
			continue
		}
		if _, ok := controls[name]; !ok {
			order = append(order, name)
		}
		controls[name] = append(controls[name], strings.TrimSpace(ref.ControlID))
	}
	out := make([]findingdsl.PolicyFramework, 0, len(order))
	for _, name := range order {
		out = append(out, findingdsl.PolicyFramework{Name: name, Controls: controls[name]})
	}
	return out
}

func policyMITRE(refs []findings.MITREAttackRef) []findingdsl.PolicyMITREAttack {
	out := make([]findingdsl.PolicyMITREAttack, 0, len(refs))
	for _, ref := range refs {
		out = append(out, findingdsl.PolicyMITREAttack{Tactic: ref.Tactic, Technique: ref.Technique})
	}
	return out
}

func mitreRefs(refs []findings.MITREAttackRef) []MITRERef {
	out := make([]MITRERef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, MITRERef{Tactic: strings.TrimSpace(ref.Tactic), Technique: strings.TrimSpace(ref.Technique)})
	}
	return out
}

func frameworkNames(refs []ControlRef) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, ref := range refs {
		if ref.Framework == "" {
			continue
		}
		if _, ok := seen[ref.Framework]; ok {
			continue
		}
		seen[ref.Framework] = struct{}{}
		out = append(out, ref.Framework)
	}
	sort.Strings(out)
	return out
}

func mitreTechniques(refs []MITRERef) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, ref := range refs {
		if ref.Technique == "" {
			continue
		}
		if _, ok := seen[ref.Technique]; ok {
			continue
		}
		seen[ref.Technique] = struct{}{}
		out = append(out, ref.Technique)
	}
	return out
}

// attackDescription explains how an attacker benefits from the condition.
func attackDescription(summary string, risk string, mitre []MITRERef) string {
	parts := []string{}
	if summary = strings.TrimSpace(summary); summary != "" {
		parts = append(parts, ensureSentence(summary))
	}
	if len(mitre) != 0 {
		tactics := []string{}
		seen := map[string]struct{}{}
		for _, ref := range mitre {
			label := strings.TrimSpace(ref.Tactic)
			if ref.Technique != "" {
				label = strings.TrimSpace(label + " (" + ref.Technique + ")")
			}
			if _, ok := seen[label]; ok || label == "" {
				continue
			}
			seen[label] = struct{}{}
			tactics = append(tactics, label)
		}
		if len(tactics) != 0 {
			parts = append(parts, "An attacker can use this for "+strings.Join(tactics, ", ")+".")
		}
	}
	if risk = strings.TrimSpace(risk); risk != "" {
		parts = append(parts, ensureSentence(risk))
	}
	return strings.Join(parts, " ")
}

func ensureSentence(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasSuffix(value, ".") || strings.HasSuffix(value, "!") || strings.HasSuffix(value, "?") {
		return value
	}
	return value + "."
}

func lifecycleLabel(kind string, anchor string, ttl time.Duration) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return ""
	}
	label := kind
	if anchor = strings.TrimSpace(anchor); anchor != "" && anchor != "none" {
		label += " (" + anchor + ")"
	}
	if ttl > 0 {
		label += ", expires after " + ttl.String()
	}
	return label
}

func normalizeSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "critical", "high", "medium", "low", "info":
		return value
	case "informational":
		return "info"
	case "":
		return "medium"
	default:
		return value
	}
}

func severityRank(value string) int {
	switch normalizeSeverity(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
