package findings

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// LifecycleKind enumerates the supported finding lifecycle classifications.
type LifecycleKind string

const (
	LifecycleDurableState  LifecycleKind = "durable_state"
	LifecycleAuditEvidence LifecycleKind = "audit_evidence"
	LifecycleTTLEvidence   LifecycleKind = "ttl_evidence"
	LifecycleRetired       LifecycleKind = "retired"
)

// LifecycleAnchor identifies what a finding is anchored to.
type LifecycleAnchor string

const (
	AnchorGraphAnchored LifecycleAnchor = "graph_anchored"
	AnchorSourceState   LifecycleAnchor = "source_state"
	AnchorNone          LifecycleAnchor = "none"
)

// Lifecycle captures the lifecycle semantics declared by a rule definition.
type Lifecycle struct {
	Kind   LifecycleKind
	TTL    time.Duration
	Anchor LifecycleAnchor
}

func validateLifecycle(ruleID string, lifecycle Lifecycle) error {
	id := strings.TrimSpace(ruleID)
	kind := LifecycleKind(strings.TrimSpace(string(lifecycle.Kind)))
	if kind == "" {
		if id == "" {
			return errors.New("rule lifecycle kind is required")
		}
		return fmt.Errorf("rule %q lifecycle kind is required", id)
	}
	switch kind {
	case LifecycleTTLEvidence:
		if lifecycle.TTL <= 0 {
			return fmt.Errorf("rule %q lifecycle ttl_evidence requires TTL > 0", id)
		}
	case LifecycleRetired:
		anchor := LifecycleAnchor(strings.TrimSpace(string(lifecycle.Anchor)))
		if anchor != AnchorNone {
			return fmt.Errorf("rule %q lifecycle retired requires anchor=none", id)
		}
	case LifecycleDurableState:
		anchor := LifecycleAnchor(strings.TrimSpace(string(lifecycle.Anchor)))
		if anchor == AnchorNone {
			return fmt.Errorf("rule %q lifecycle durable_state forbids anchor=none", id)
		}
	case LifecycleAuditEvidence:
		// audit_evidence places no additional anchor or TTL constraints.
	default:
		return fmt.Errorf("rule %q lifecycle kind %q is not recognized", id, string(kind))
	}
	return nil
}

type MetadataRule interface {
	RuleMetadata() RuleDefinition
}

type PublicDetectionCatalog struct {
	Version    string            `json:"version"`
	Detections []PublicDetection `json:"detections"`
}

type PublicDetection struct {
	ID             string   `json:"id"`
	PackID         string   `json:"pack_id"`
	PackName       string   `json:"pack_name"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	SourceID       string   `json:"source_id"`
	EvaluationMode string   `json:"evaluation_mode"`
	EventKinds     []string `json:"event_kinds,omitempty"`
	OutputKind     string   `json:"output_kind"`
	Severity       string   `json:"severity"`
	Status         string   `json:"status"`
	Maturity       string   `json:"maturity"`
	Tags           []string `json:"tags,omitempty"`
	References     []string `json:"references,omitempty"`
	FalsePositives []string `json:"false_positives,omitempty"`
	Runbook        string   `json:"runbook"`
	PublicDetectionAuditDepth
	RequiredAttributes       []string                  `json:"required_attributes,omitempty"`
	RequiredAttributesByKind map[string][]string       `json:"required_attributes_by_kind,omitempty"`
	FingerprintFields        []string                  `json:"fingerprint_fields,omitempty"`
	ControlRefs              []ports.FindingControlRef `json:"control_refs,omitempty"`
	SourceCoverageRefs       []SourceCoverageRef       `json:"source_coverage_refs,omitempty"`
	MITREAttack              []MITREAttackRef          `json:"mitre_attack,omitempty"`
	MITREDefend              []MITREDefendRef          `json:"mitre_defend,omitempty"`
}

type PublicDetectionAuditDepth struct {
	EvidenceType      string   `json:"evidence_type,omitempty"`
	AssessmentMethods []string `json:"assessment_methods,omitempty"`
	AuditorGuidance   string   `json:"auditor_guidance,omitempty"`
	RiskStatement     string   `json:"risk_statement,omitempty"`
	RemediationIntent string   `json:"remediation_intent,omitempty"`
}

const (
	RuleMaturityTest         = "test"
	RuleMaturityCandidate    = "candidate"
	RuleMaturityExperimental = "experimental"
	RuleMaturityGA           = "ga"
	RuleMaturityProduction   = "production"
	RuleMaturityRetired      = "retired"
)

var builtinRuleMetadataCache struct {
	once      sync.Once
	metadata  []RuleDefinition
	sourceIDs map[string]string
}

func (r *eventRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.config.definition)
}

func (r *cloudSignalRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.config.definition)
}

func (r *identitySignalRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.config.definition)
}

func (r *cloudPublicExposurePrivilegedPrincipalRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *deprovisionedOktaActiveGitHubRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *deprovisionedOktaActiveCloudAccessRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *githubActiveWithoutOktaLinkRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *identityPrivilegedNoMFAAccessRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *grcInactiveIdentityActiveAccessRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *grcPrivilegedAccountMissingPersonRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *grcOverdueVulnerabilityLiveOnAssetsRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *grcFailingControlOpenOperationalFindingsRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *sentinelOneEndpointActiveInfectionGraphRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *sentinelOneInfectedPrivilegedOwnerRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *sentinelOneAgentStaleGraphRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *vulnViewExternalAssetConcentratedSignalRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func BuiltinRuleMetadata() []RuleDefinition {
	builtinRuleMetadataCache.once.Do(loadBuiltinRuleMetadataCache)
	return cloneRuleDefinitions(builtinRuleMetadataCache.metadata)
}

// BuiltinRuleSourceIDs returns a rule-id-to-source-id index for built-in metadata.
func BuiltinRuleSourceIDs() map[string]string {
	builtinRuleMetadataCache.once.Do(loadBuiltinRuleMetadataCache)
	sourceIDs := make(map[string]string, len(builtinRuleMetadataCache.sourceIDs))
	for id, sourceID := range builtinRuleMetadataCache.sourceIDs {
		sourceIDs[id] = sourceID
	}
	return sourceIDs
}

func loadBuiltinRuleMetadataCache() {
	metadata := []RuleDefinition{}
	sourceIDs := map[string]string{}
	for _, pack := range builtinRulePacks() {
		for _, rule := range pack.Rules {
			definition, ok := ruleMetadata(rule)
			if !ok || definition.IsZero() {
				continue
			}
			metadata = append(metadata, applyBuiltinRuleAuditDepth(definition))
		}
	}
	sort.Slice(metadata, func(i int, j int) bool {
		return metadata[i].ID < metadata[j].ID
	})
	for _, definition := range metadata {
		if id := strings.TrimSpace(definition.ID); id != "" {
			sourceIDs[id] = strings.TrimSpace(definition.SourceID)
		}
	}
	builtinRuleMetadataCache.metadata = metadata
	builtinRuleMetadataCache.sourceIDs = sourceIDs
}

func BuiltinPublicDetectionCatalog() PublicDetectionCatalog {
	catalog := PublicDetectionCatalog{
		Version:    "2026-05-21",
		Detections: []PublicDetection{},
	}
	for _, pack := range builtinRulePacks() {
		for _, rule := range pack.Rules {
			metadata, ok := ruleMetadata(rule)
			if !ok || metadata.IsZero() {
				continue
			}
			mode := "event"
			if _, ok := asGraphRule(rule); ok {
				mode = "graph"
			}
			catalog.Detections = append(catalog.Detections, publicDetectionFromRule(pack, applyBuiltinRuleAuditDepth(metadata), mode))
		}
	}
	sort.Slice(catalog.Detections, func(i int, j int) bool {
		left := catalog.Detections[i]
		right := catalog.Detections[j]
		if left.PackID != right.PackID {
			return left.PackID < right.PackID
		}
		return left.ID < right.ID
	})
	return catalog
}

func ValidateRuleMetadataCompleteness(metadatas []RuleDefinition) []error {
	var errs []error
	seen := map[string]struct{}{}
	for _, metadata := range metadatas {
		id := strings.TrimSpace(metadata.ID)
		if id == "" {
			errs = append(errs, fmt.Errorf("rule id is required"))
			continue
		}
		if _, ok := seen[id]; ok {
			errs = append(errs, fmt.Errorf("rule %q duplicate metadata id", id))
		}
		seen[id] = struct{}{}
		requiredStrings := map[string]string{
			"name":        metadata.Name,
			"description": metadata.Description,
			"source_id":   metadata.SourceID,
			"output_kind": metadata.OutputKind,
			"severity":    metadata.Severity,
			"status":      metadata.Status,
			"maturity":    metadata.Maturity,
			"runbook":     metadata.Runbook,
		}
		for field, value := range requiredStrings {
			if strings.TrimSpace(value) == "" {
				errs = append(errs, fmt.Errorf("rule %q %s is required", id, field))
			}
		}
		if maturity := strings.TrimSpace(metadata.Maturity); maturity != "" && !validRuleMaturity(maturity) {
			errs = append(errs, fmt.Errorf("rule %q maturity %q is not supported", id, maturity))
		}
		requiredSlices := map[string][]string{
			"tags":               metadata.Tags,
			"false_positives":    metadata.FalsePositives,
			"fingerprint_fields": metadata.FingerprintFields,
		}
		if !policyRuleMetadata(metadata) {
			requiredSlices["references"] = metadata.References
		}
		for field, values := range requiredSlices {
			if retiredRuleMetadata(metadata) && (field == "fingerprint_fields") {
				continue
			}
			if len(uniqueSortedStrings(values)) == 0 {
				errs = append(errs, fmt.Errorf("rule %q %s is required", id, field))
			}
		}
		if !retiredRuleMetadata(metadata) && len(cloneFindingControlRefs(metadata.ControlRefs)) == 0 {
			errs = append(errs, fmt.Errorf("rule %q control_refs is required", id))
		}
	}
	return errs
}

func validRuleMaturity(maturity string) bool {
	switch strings.TrimSpace(maturity) {
	case RuleMaturityTest, RuleMaturityCandidate, RuleMaturityExperimental, RuleMaturityGA, RuleMaturityProduction, RuleMaturityRetired:
		return true
	default:
		return false
	}
}

func ruleMetadata(rule Rule) (RuleDefinition, bool) {
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return RuleDefinition{}, false
	}
	return metadataRule.RuleMetadata(), true
}

func publicDetectionFromRule(pack RulePack, metadata RuleDefinition, mode string) PublicDetection {
	return PublicDetection{
		ID:             strings.TrimSpace(metadata.ID),
		PackID:         strings.TrimSpace(pack.ID),
		PackName:       strings.TrimSpace(pack.Name),
		Name:           strings.TrimSpace(metadata.Name),
		Description:    strings.TrimSpace(metadata.Description),
		SourceID:       strings.TrimSpace(metadata.SourceID),
		EvaluationMode: mode,
		EventKinds:     uniqueSortedStrings(metadata.EventKinds),
		OutputKind:     strings.TrimSpace(metadata.OutputKind),
		Severity:       strings.TrimSpace(metadata.Severity),
		Status:         strings.TrimSpace(metadata.Status),
		Maturity:       strings.TrimSpace(metadata.Maturity),
		Tags:           uniqueSortedStrings(metadata.Tags),
		References:     uniqueSortedStrings(metadata.References),
		FalsePositives: uniqueSortedStrings(metadata.FalsePositives),
		Runbook:        strings.TrimSpace(metadata.Runbook),
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType:      strings.TrimSpace(metadata.EvidenceType),
			AssessmentMethods: uniqueSortedStrings(metadata.AssessmentMethods),
			AuditorGuidance:   strings.TrimSpace(metadata.AuditorGuidance),
			RiskStatement:     strings.TrimSpace(metadata.RiskStatement),
			RemediationIntent: strings.TrimSpace(metadata.RemediationIntent),
		},
		RequiredAttributes:       uniqueSortedStrings(metadata.RequiredAttributes),
		RequiredAttributesByKind: normalizedStringSliceMap(metadata.RequiredAttributesByKind),
		FingerprintFields:        uniqueTrimmedStringsPreserveOrder(metadata.FingerprintFields),
		ControlRefs:              cloneFindingControlRefs(metadata.ControlRefs),
		MITREAttack:              cloneMITREAttackRefs(metadata.MITREAttack),
		MITREDefend:              cloneMITREDefendRefs(metadata.MITREDefend),
	}
}

func cloneRuleDefinition(definition RuleDefinition) RuleDefinition {
	return RuleDefinition{
		ID:                       strings.TrimSpace(definition.ID),
		Name:                     strings.TrimSpace(definition.Name),
		Description:              strings.TrimSpace(definition.Description),
		SourceID:                 strings.TrimSpace(definition.SourceID),
		EventKinds:               cloneStringSlice(definition.EventKinds),
		OutputKind:               strings.TrimSpace(definition.OutputKind),
		Severity:                 strings.TrimSpace(definition.Severity),
		Status:                   strings.TrimSpace(definition.Status),
		Maturity:                 strings.TrimSpace(definition.Maturity),
		Tags:                     cloneStringSlice(definition.Tags),
		References:               cloneStringSlice(definition.References),
		FalsePositives:           cloneStringSlice(definition.FalsePositives),
		Runbook:                  strings.TrimSpace(definition.Runbook),
		EvidenceType:             strings.TrimSpace(definition.EvidenceType),
		AssessmentMethods:        cloneStringSlice(definition.AssessmentMethods),
		AuditorGuidance:          strings.TrimSpace(definition.AuditorGuidance),
		RiskStatement:            strings.TrimSpace(definition.RiskStatement),
		RemediationIntent:        strings.TrimSpace(definition.RemediationIntent),
		RequiredAttributes:       cloneStringSlice(definition.RequiredAttributes),
		RequiredAttributesByKind: cloneStringSliceMap(definition.RequiredAttributesByKind),
		FingerprintFields:        cloneStringSlice(definition.FingerprintFields),
		ControlRefs:              cloneFindingControlRefs(definition.ControlRefs),
		MITREAttack:              cloneMITREAttackRefs(definition.MITREAttack),
		MITREDefend:              cloneMITREDefendRefs(definition.MITREDefend),
		Lifecycle:                definition.Lifecycle,
	}
}

func cloneMITREAttackRefs(refs []MITREAttackRef) []MITREAttackRef {
	if len(refs) == 0 {
		return nil
	}
	cloned := make([]MITREAttackRef, 0, len(refs))
	for _, ref := range refs {
		tactic := strings.TrimSpace(ref.Tactic)
		technique := strings.TrimSpace(ref.Technique)
		if tactic == "" && technique == "" {
			continue
		}
		cloned = append(cloned, MITREAttackRef{Tactic: tactic, Technique: technique})
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

func cloneMITREDefendRefs(refs []MITREDefendRef) []MITREDefendRef {
	if len(refs) == 0 {
		return nil
	}
	cloned := make([]MITREDefendRef, 0, len(refs))
	for _, ref := range refs {
		tactic := strings.TrimSpace(ref.Tactic)
		technique := strings.TrimSpace(ref.Technique)
		artifact := strings.TrimSpace(ref.Artifact)
		if tactic == "" && technique == "" && artifact == "" {
			continue
		}
		cloned = append(cloned, MITREDefendRef{Tactic: tactic, Technique: technique, Artifact: artifact})
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

func cloneStringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string][]string, len(values))
	for key, slice := range values {
		cloned[key] = cloneStringSlice(slice)
	}
	return cloned
}

func normalizedStringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string][]string, len(values))
	for key, slice := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		entries := uniqueSortedStrings(slice)
		if len(entries) != 0 {
			normalized[key] = entries
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func keyedAttributesAttribute(values map[string][]string) string {
	normalized := normalizedStringSliceMap(values)
	if len(normalized) == 0 {
		return ""
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strings.Join(normalized[key], ","))
	}
	return strings.Join(parts, ";")
}

func cloneRuleDefinitions(definitions []RuleDefinition) []RuleDefinition {
	if len(definitions) == 0 {
		return nil
	}
	cloned := make([]RuleDefinition, 0, len(definitions))
	for _, definition := range definitions {
		cloned = append(cloned, cloneRuleDefinition(definition))
	}
	return cloned
}

func retiredRuleMetadata(metadata RuleDefinition) bool {
	if strings.EqualFold(strings.TrimSpace(metadata.Maturity), "retired") || strings.EqualFold(strings.TrimSpace(metadata.Status), "retired") {
		return true
	}
	for _, tag := range metadata.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "retired") {
			return true
		}
	}
	return false
}

func policyRuleMetadata(metadata RuleDefinition) bool {
	if !strings.EqualFold(strings.TrimSpace(metadata.SourceID), policyRuleSourceID) {
		return false
	}
	for _, tag := range metadata.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "policy") {
			return true
		}
	}
	return false
}
