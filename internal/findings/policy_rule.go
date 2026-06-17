package findings

import (
	"context"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	policyRuleSourceID        = "policy"
	policyRuleOutputKind      = "policy.finding"
	policyRuleEvidenceKind    = "policy.evidence"
	policyRuleResultEventKind = "policy.result"
)

type policyRuleConfig struct {
	Definition        RuleDefinition
	Conditions        []string
	Query             string
	Resource          string
	ResourceType      string
	Category          string
	EvidenceMode      string
	EvidenceType      string
	AssessmentMethods []string
	AuditorGuidance   string
	RiskStatement     string
	RemediationIntent string
	ExceptionGuidance []string
	ControlFamilies   []string
	Enabled           bool
}

type policyCatalogRule struct {
	config policyRuleConfig
}

func newPolicyCatalogRules() []Rule {
	rules := make([]Rule, 0, len(generatedPolicyRuleCatalog))
	for _, config := range generatedPolicyRuleCatalog {
		rules = append(rules, newPolicyCatalogRule(config))
	}
	return rules
}

func newPolicyCatalogRule(config policyRuleConfig) Rule {
	definition := cloneRuleDefinition(config.Definition)
	if definition.SourceID == "" {
		definition.SourceID = policyRuleSourceID
	}
	if definition.OutputKind == "" {
		definition.OutputKind = policyRuleOutputKind
	}
	if len(definition.EventKinds) == 0 {
		definition.EventKinds = []string{policyRuleEvidenceKind, policyRuleResultEventKind}
	}
	if definition.Lifecycle.Kind == "" {
		definition.Lifecycle = Lifecycle{Kind: LifecycleAuditEvidence, Anchor: AnchorNone}
	}
	config.Definition = definition
	config.Conditions = cloneStringSlice(config.Conditions)
	config.AssessmentMethods = cloneStringSlice(config.AssessmentMethods)
	config.ExceptionGuidance = cloneStringSlice(config.ExceptionGuidance)
	config.ControlFamilies = cloneStringSlice(config.ControlFamilies)
	return &policyCatalogRule{config: config}
}

func (r *policyCatalogRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.config.Definition)
}

func (r *policyCatalogRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return r.config.Definition.RuleSpec()
}

func (r *policyCatalogRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	if !r.config.Enabled {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), policyRuleSourceID) {
		return false
	}
	return runtimeMayEmitEventKind(runtime, r.config.Definition.EventKinds)
}

func (r *policyCatalogRule) Evaluate(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if r == nil {
		return nil, nil
	}
	if !r.config.Enabled {
		return nil, nil
	}
	definition := r.config.Definition
	if err := definition.Validate(); err != nil {
		return nil, err
	}
	if runtime == nil || event == nil {
		return nil, nil
	}
	if !identityKindAllowed(event.GetKind(), definition.EventKinds) {
		return nil, nil
	}
	attributes := event.GetAttributes()
	if !policyRuleEventMatchesDefinition(definition.ID, attributes) || !policyRuleEventFailed(attributes) {
		return nil, nil
	}
	finding := r.buildFinding(runtime, event, attributes)
	if finding == nil {
		return nil, nil
	}
	return []*ports.FindingRecord{finding}, nil
}

func (r *policyCatalogRule) buildFinding(runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, attributes map[string]string) *ports.FindingRecord {
	definition := r.config.Definition
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	resourceURN := firstNonEmpty(attributes["resource_urn"], firstCSVValue(attributes["resource_urns"]))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["asset_id"], attributes["subject_id"], attributes["entity_id"])
	fingerprintResource := firstNonEmpty(resourceURN, resourceID, strings.TrimSpace(event.GetId()))
	fingerprint := hashFindingFingerprint(definition.ID, tenantID, runtimeID, fingerprintResource)
	findingAttributes := map[string]string{
		"policy_id":               definition.ID,
		"policy_name":             definition.Name,
		"policy_category":         r.config.Category,
		"policy_evidence":         r.config.EvidenceMode,
		"policy_evidence_type":    r.config.EvidenceType,
		"policy_evidence_summary": policyEvidenceSummary(r.config),
		"policy_resource":         r.config.Resource,
		"policy_resource_type":    r.config.ResourceType,
		"policy_audit_impact":     r.config.RiskStatement,
		"policy_auditor_guidance": r.config.AuditorGuidance,
		"policy_next_step":        policyNextStep(r.config),
		"policy_risk_statement":   r.config.RiskStatement,
		"policy_remediation":      r.config.RemediationIntent,
		"policy_status":           firstNonEmpty(attributes["policy_status"], attributes["compliance_status"], attributes["result"], attributes["status"], attributes["outcome"]),
	}
	for key, value := range attributes {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	if len(r.config.Conditions) != 0 {
		findingAttributes["policy_condition_count"] = strconv.Itoa(len(r.config.Conditions))
	}
	if strings.TrimSpace(r.config.Query) != "" {
		findingAttributes["policy_query_present"] = "true"
	}
	addPolicyAttributeList(findingAttributes, "policy_assessment_methods", r.config.AssessmentMethods)
	addPolicyAttributeList(findingAttributes, "policy_control_families", r.config.ControlFamilies)
	addPolicyAttributeList(findingAttributes, "policy_exception_guidance", r.config.ExceptionGuidance)
	trimEmptyAttributes(findingAttributes)
	resourceURNs := nonEmptyStringSlice(resourceURN)
	eventIDs := nonEmptyStringSlice(event.GetId())
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          tenantID,
		RuntimeID:         runtimeID,
		RuleID:            definition.ID,
		Title:             firstNonEmpty(attributes["title"], policyFindingTitle(definition.Name)),
		Severity:          normalizeFindingSeverity(firstNonEmpty(attributes["severity"], definition.Severity)),
		Status:            findingStatusOpen,
		Summary:           firstNonEmpty(attributes["summary"], policyFindingSummary(definition, r.config, attributes)),
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: []string{definition.ID},
		PolicyID:          definition.ID,
		PolicyName:        definition.Name,
		CheckID:           definition.ID,
		CheckName:         definition.Name,
		ControlRefs:       cloneFindingControlRefs(definition.ControlRefs),
		Attributes:        findingAttributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}
}

func policyFindingTitle(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "Policy evidence failed"
	}
	return "Policy failed: " + trimmed
}

func policyFindingSummary(definition RuleDefinition, config policyRuleConfig, attributes map[string]string) string {
	subject := firstNonEmpty(attributes["resource_label"], attributes["resource_name"], attributes["resource_id"], config.ResourceType, config.Resource, "the assessed subject")
	risk := firstNonEmpty(config.RiskStatement, definition.Description)
	parts := []string{
		"Policy evidence failed for " + subject + ": " + definition.Name + ".",
	}
	if risk != "" {
		parts = append(parts, "Audit impact: "+risk)
	}
	if families := compactPolicyControlFamilies(config.ControlFamilies, 3); families != "" {
		parts = append(parts, "Mapped control families: "+families)
	}
	if guidance := strings.TrimSpace(config.AuditorGuidance); guidance != "" {
		parts = append(parts, "Auditor review: "+guidance)
	}
	return joinPolicySentences(parts)
}

func policyEvidenceSummary(config policyRuleConfig) string {
	mode := strings.TrimSpace(config.EvidenceMode)
	evidenceType := strings.TrimSpace(config.EvidenceType)
	if evidenceType == "" {
		evidenceType = "control evidence"
	}
	evidenceType = humanPolicyEvidenceType(evidenceType)
	switch mode {
	case "query":
		return "Failed query-result evidence for " + evidenceType + ". Review each returned row as an exception candidate."
	case "manual":
		return "Failed manual-attestation evidence for " + evidenceType + ". Confirm owner, approval, and supporting evidence."
	default:
		return "Failed resource-state evidence for " + evidenceType + ". Review the normalized subject state and evaluated policy conditions."
	}
}

func humanPolicyEvidenceType(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	if value == "" {
		return "control evidence"
	}
	return value
}

func policyNextStep(config policyRuleConfig) string {
	if remediation := strings.TrimSpace(config.RemediationIntent); remediation != "" {
		return remediation
	}
	if guidance := strings.TrimSpace(config.AuditorGuidance); guidance != "" {
		return guidance
	}
	return "Review the failed evidence, document remediation or exception status, and rerun evidence collection."
}

func compactPolicyControlFamilies(values []string, limit int) string {
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		if item := strings.TrimSpace(value); item != "" {
			trimmed = append(trimmed, item)
		}
	}
	if len(trimmed) == 0 {
		return ""
	}
	if limit <= 0 || len(trimmed) <= limit {
		return strings.Join(trimmed, "; ") + "."
	}
	return strings.Join(trimmed[:limit], "; ") + "; +" + strconv.Itoa(len(trimmed)-limit) + " more."
}

func joinPolicySentences(parts []string) string {
	sentences := make([]string, 0, len(parts))
	for _, part := range parts {
		if sentence := policySentence(part); sentence != "" {
			sentences = append(sentences, sentence)
		}
	}
	return strings.Join(sentences, " ")
}

func policySentence(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	switch trimmed[len(trimmed)-1] {
	case '.', '!', '?':
		return trimmed
	default:
		return trimmed + "."
	}
}

func policyRuleEventMatchesDefinition(ruleID string, attributes map[string]string) bool {
	want := strings.TrimSpace(ruleID)
	if want == "" {
		return false
	}
	for _, key := range []string{"policy_id", "check_id", "rule_id"} {
		if strings.EqualFold(strings.TrimSpace(attributes[key]), want) {
			return true
		}
	}
	return false
}

func policyRuleEventFailed(attributes map[string]string) bool {
	status := strings.ToLower(firstNonEmpty(
		attributes["policy_status"],
		attributes["compliance_status"],
		attributes["result"],
		attributes["status"],
		attributes["outcome"],
		attributes["finding_status"],
	))
	switch strings.TrimSpace(status) {
	case "fail", "failed", "failing", "failure", "noncompliant", "non_compliant", "not_compliant", "violation", "violated", "open", "error":
		return true
	}
	compliant := strings.ToLower(strings.TrimSpace(attributes["compliant"]))
	return compliant == "false" || compliant == "no"
}

func firstCSVValue(value string) string {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func addPolicyAttributeList(attributes map[string]string, key string, values []string) {
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		if item := strings.TrimSpace(value); item != "" {
			trimmed = append(trimmed, item)
		}
	}
	if len(trimmed) != 0 {
		attributes[key] = strings.Join(trimmed, ",")
	}
}

func nonEmptyStringSlice(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
