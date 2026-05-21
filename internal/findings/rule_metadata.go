package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

type MetadataRule interface {
	RuleMetadata() RuleDefinition
}

type PublicDetectionCatalog struct {
	Version    string            `json:"version"`
	Detections []PublicDetection `json:"detections"`
}

type PublicDetection struct {
	ID                 string                    `json:"id"`
	PackID             string                    `json:"pack_id"`
	PackName           string                    `json:"pack_name"`
	Name               string                    `json:"name"`
	Description        string                    `json:"description"`
	SourceID           string                    `json:"source_id"`
	EvaluationMode     string                    `json:"evaluation_mode"`
	EventKinds         []string                  `json:"event_kinds,omitempty"`
	OutputKind         string                    `json:"output_kind"`
	Severity           string                    `json:"severity"`
	Status             string                    `json:"status"`
	Maturity           string                    `json:"maturity"`
	Tags               []string                  `json:"tags,omitempty"`
	References         []string                  `json:"references,omitempty"`
	FalsePositives     []string                  `json:"false_positives,omitempty"`
	Runbook            string                    `json:"runbook"`
	RequiredAttributes []string                  `json:"required_attributes,omitempty"`
	FingerprintFields  []string                  `json:"fingerprint_fields,omitempty"`
	ControlRefs        []ports.FindingControlRef `json:"control_refs,omitempty"`
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

func (r *githubActiveWithoutOktaLinkRule) RuleMetadata() RuleDefinition {
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
	metadatas := []RuleDefinition{}
	for _, pack := range builtinRulePacks() {
		for _, rule := range pack.Rules {
			metadata, ok := ruleMetadata(rule)
			if !ok || metadata.IsZero() {
				continue
			}
			metadatas = append(metadatas, metadata)
		}
	}
	sort.Slice(metadatas, func(i int, j int) bool {
		return metadatas[i].ID < metadatas[j].ID
	})
	return metadatas
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
			catalog.Detections = append(catalog.Detections, publicDetectionFromRule(pack, metadata, mode))
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
		requiredSlices := map[string][]string{
			"tags":               metadata.Tags,
			"references":         metadata.References,
			"false_positives":    metadata.FalsePositives,
			"fingerprint_fields": metadata.FingerprintFields,
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

func ruleMetadata(rule Rule) (RuleDefinition, bool) {
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return RuleDefinition{}, false
	}
	return metadataRule.RuleMetadata(), true
}

func publicDetectionFromRule(pack RulePack, metadata RuleDefinition, mode string) PublicDetection {
	return PublicDetection{
		ID:                 strings.TrimSpace(metadata.ID),
		PackID:             strings.TrimSpace(pack.ID),
		PackName:           strings.TrimSpace(pack.Name),
		Name:               strings.TrimSpace(metadata.Name),
		Description:        strings.TrimSpace(metadata.Description),
		SourceID:           strings.TrimSpace(metadata.SourceID),
		EvaluationMode:     mode,
		EventKinds:         uniqueSortedStrings(metadata.EventKinds),
		OutputKind:         strings.TrimSpace(metadata.OutputKind),
		Severity:           strings.TrimSpace(metadata.Severity),
		Status:             strings.TrimSpace(metadata.Status),
		Maturity:           strings.TrimSpace(metadata.Maturity),
		Tags:               uniqueSortedStrings(metadata.Tags),
		References:         uniqueSortedStrings(metadata.References),
		FalsePositives:     uniqueSortedStrings(metadata.FalsePositives),
		Runbook:            strings.TrimSpace(metadata.Runbook),
		RequiredAttributes: uniqueSortedStrings(metadata.RequiredAttributes),
		FingerprintFields:  uniqueSortedStrings(metadata.FingerprintFields),
		ControlRefs:        cloneFindingControlRefs(metadata.ControlRefs),
	}
}

func cloneRuleDefinition(definition RuleDefinition) RuleDefinition {
	return RuleDefinition{
		ID:                 strings.TrimSpace(definition.ID),
		Name:               strings.TrimSpace(definition.Name),
		Description:        strings.TrimSpace(definition.Description),
		SourceID:           strings.TrimSpace(definition.SourceID),
		EventKinds:         cloneStringSlice(definition.EventKinds),
		OutputKind:         strings.TrimSpace(definition.OutputKind),
		Severity:           strings.TrimSpace(definition.Severity),
		Status:             strings.TrimSpace(definition.Status),
		Maturity:           strings.TrimSpace(definition.Maturity),
		Tags:               cloneStringSlice(definition.Tags),
		References:         cloneStringSlice(definition.References),
		FalsePositives:     cloneStringSlice(definition.FalsePositives),
		Runbook:            strings.TrimSpace(definition.Runbook),
		RequiredAttributes: cloneStringSlice(definition.RequiredAttributes),
		FingerprintFields:  cloneStringSlice(definition.FingerprintFields),
		ControlRefs:        cloneFindingControlRefs(definition.ControlRefs),
	}
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
