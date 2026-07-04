package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/findingdsl"
)

func checkPolicyDepthContracts(root string, rules []findingdsl.PolicyFindingRule, controlCatalog *compliance.CatalogIndex) ([]issue, error) {
	if !policyRulesDeclareEvidenceRequirementRefs(rules) {
		return nil, nil
	}
	if controlCatalog == nil {
		return []issue{{path: "policies", message: "control catalog is required when policies declare spec.evidence.requirementRefs"}}, nil
	}
	requirements, issues, err := loadPolicyDepthRequirementResolution(root, controlCatalog)
	if err != nil || len(issues) != 0 {
		return issues, err
	}
	requirementIndex := buildPolicyDepthRequirementRefIndex(requirements)
	for _, rule := range rules {
		issues = append(issues, validatePolicyDepthRequirementRefs(rule, requirementIndex)...)
	}
	return issues, nil
}

func loadPolicyDepthRequirementResolution(root string, controlCatalog *compliance.CatalogIndex) (compliance.ControlEvidenceRequirementResolution, []issue, error) {
	path := filepath.Join(root, filepath.FromSlash(compliance.DefaultControlEvidenceRequirementsPath))
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return compliance.ControlEvidenceRequirementResolution{}, []issue{{path: compliance.DefaultControlEvidenceRequirementsPath, message: "control evidence requirements catalog is required when policies declare spec.evidence.requirementRefs"}}, nil
		}
		return compliance.ControlEvidenceRequirementResolution{}, nil, fmt.Errorf("read %s: %w", slashRel(root, path), err)
	}
	catalog, err := compliance.LoadControlEvidenceRequirementCatalog(content)
	if err != nil {
		return compliance.ControlEvidenceRequirementResolution{}, []issue{{path: compliance.DefaultControlEvidenceRequirementsPath, message: "invalid YAML: " + err.Error()}}, nil
	}
	resolution, validationIssues := compliance.ResolveControlEvidenceRequirements(controlCatalog, catalog)
	issues := make([]issue, 0, len(validationIssues))
	for _, validationIssue := range validationIssues {
		issues = append(issues, issue{path: compliance.DefaultControlEvidenceRequirementsPath, message: validationIssue.Error()})
	}
	return resolution, issues, nil
}

func buildPolicyDepthRequirementRefIndex(resolution compliance.ControlEvidenceRequirementResolution) map[string]map[string]struct{} {
	index := map[string]map[string]struct{}{}
	for _, requirement := range resolution.Requirements {
		controlKey := compliance.ControlKey(compliance.ControlRef{
			FrameworkID:   requirement.FrameworkID,
			FrameworkName: requirement.FrameworkName,
			ControlID:     requirement.ControlID,
		})
		ref := policyDepthRequirementRef(requirement.ProfileID, requirement.SourceRequirement.SourceID, requirement.SourceRequirement.EntityType)
		if controlKey == "" || ref == "" {
			continue
		}
		if index[controlKey] == nil {
			index[controlKey] = map[string]struct{}{}
		}
		index[controlKey][ref] = struct{}{}
	}
	return index
}

func validatePolicyDepthRequirementRefs(rule findingdsl.PolicyFindingRule, requirementIndex map[string]map[string]struct{}) []issue {
	refs := trimPolicyDepthRequirementRefs(rule.Spec.Evidence.RequirementRefs)
	if len(refs) == 0 {
		return nil
	}
	controlKeys := policyDepthControlKeys(rule)
	if len(controlKeys) == 0 {
		return []issue{{path: rule.RelPath, message: "spec.frameworks controls are required when spec.evidence.requirementRefs is set"}}
	}
	var issues []issue
	for _, ref := range refs {
		found := false
		for _, controlKey := range controlKeys {
			if _, ok := requirementIndex[controlKey][ref]; ok {
				found = true
				break
			}
		}
		if !found {
			issues = append(issues, issue{path: rule.RelPath, message: fmt.Sprintf("spec.evidence.requirementRefs %q does not match any resolved requirement for the policy controls", ref)})
		}
	}
	return issues
}

func policyRulesDeclareEvidenceRequirementRefs(rules []findingdsl.PolicyFindingRule) bool {
	for _, rule := range rules {
		if len(trimPolicyDepthRequirementRefs(rule.Spec.Evidence.RequirementRefs)) != 0 {
			return true
		}
	}
	return false
}

func policyDepthControlKeys(rule findingdsl.PolicyFindingRule) []string {
	keys := []string{}
	for _, framework := range rule.Spec.Frameworks {
		for _, controlID := range framework.Controls {
			key := compliance.ControlKey(compliance.ControlRef{FrameworkName: framework.Name, ControlID: controlID})
			if key != "" {
				keys = appendUniqueCatalogString(keys, key)
			}
		}
	}
	return keys
}

func trimPolicyDepthRequirementRefs(values []string) []string {
	refs := []string{}
	for _, value := range values {
		parts := strings.Split(strings.TrimSpace(value), "/")
		if len(parts) != 3 {
			continue
		}
		ref := policyDepthRequirementRef(parts[0], parts[1], parts[2])
		if ref != "" {
			refs = appendUniqueCatalogString(refs, ref)
		}
	}
	return refs
}

func policyDepthRequirementRef(profileID string, sourceID string, entityType string) string {
	profileID = strings.TrimSpace(profileID)
	sourceID = strings.TrimSpace(sourceID)
	entityType = strings.TrimSpace(entityType)
	if profileID == "" || sourceID == "" || entityType == "" {
		return ""
	}
	return profileID + "/" + sourceID + "/" + entityType
}

func appendUniqueCatalogString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
