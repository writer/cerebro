package connectorvalidation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

type Grade string

const (
	GradeGeneratedFromDocs  Grade = "generated_from_docs"
	GradeSchemaValidated    Grade = "schema_validated"
	GradeFixtureValidated   Grade = "fixture_validated"
	GradeLiveValidated      Grade = "live_validated"
	GradeProductionObserved Grade = "production_observed"
)

type Evidence struct {
	Type           string `json:"type,omitempty" yaml:"type,omitempty"`
	Ref            string `json:"ref,omitempty" yaml:"ref,omitempty"`
	Test           string `json:"test,omitempty" yaml:"test,omitempty"`
	ResourceFamily string `json:"resource_family,omitempty" yaml:"resource_family,omitempty"`
}

type ResourceFamilyValidation struct {
	ID           string     `json:"id" yaml:"id"`
	Grade        Grade      `json:"grade" yaml:"grade"`
	EvidenceRefs []string   `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	Evidence     []Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

type ConnectorValidation struct {
	SourceID         string                     `json:"source_id,omitempty" yaml:"source_id,omitempty"`
	Grade            Grade                      `json:"grade" yaml:"grade"`
	Evidence         []Evidence                 `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	LastValidatedAt  string                     `json:"last_validated_at,omitempty" yaml:"last_validated_at,omitempty"`
	ResourceFamilies []ResourceFamilyValidation `json:"resource_families,omitempty" yaml:"resource_families,omitempty"`
}

type Registry struct {
	Entries []ConnectorValidation `json:"entries" yaml:"entries"`
}

func NormalizeEntryValidation(sourceID string, validation ConnectorValidation, classifierOutput string) ConnectorValidation {
	validation.SourceID = strings.TrimSpace(firstNonEmpty(validation.SourceID, sourceID))
	validation.Grade = NormalizeGrade(validation.Grade)
	if validation.Grade == "" {
		validation.Grade = GradeGeneratedFromDocs
	}
	validation.LastValidatedAt = strings.TrimSpace(validation.LastValidatedAt)
	validation.Evidence = normalizeEvidence(validation.Evidence)
	if validation.Grade == GradeGeneratedFromDocs && len(validation.Evidence) == 0 && strings.TrimSpace(classifierOutput) != "" {
		validation.Evidence = []Evidence{{
			Type: "classifier_output",
			Ref:  strings.TrimSpace(classifierOutput),
		}}
	}
	for i := range validation.ResourceFamilies {
		family := &validation.ResourceFamilies[i]
		family.ID = strings.TrimSpace(family.ID)
		family.Grade = NormalizeGrade(family.Grade)
		if family.Grade == "" {
			family.Grade = validation.Grade
		}
		family.EvidenceRefs = normalizeStrings(family.EvidenceRefs)
		family.Evidence = normalizeEvidence(family.Evidence)
	}
	sort.SliceStable(validation.ResourceFamilies, func(i, j int) bool {
		return validation.ResourceFamilies[i].ID < validation.ResourceFamilies[j].ID
	})
	return validation
}

func ValidateClaim(definition connectordefinitions.Definition, validation ConnectorValidation) []error {
	validation = NormalizeEntryValidation(definition.SourceID, validation, "")
	var errs []error
	if validation.SourceID == "" {
		errs = append(errs, fmt.Errorf("validation source_id is required"))
	}
	if !ValidGrade(validation.Grade) {
		errs = append(errs, fmt.Errorf("validation grade %q is not supported", validation.Grade))
	}
	if GradeRank(validation.Grade) >= GradeRank(GradeFixtureValidated) && !hasEvidenceType(validation.Evidence, "fixture", "live", "production_observation") {
		errs = append(errs, fmt.Errorf("%s claims %s without fixture, live, or production evidence", validation.SourceID, validation.Grade))
	}
	families := map[string]struct{}{}
	for _, family := range definition.ResourceFamilies {
		families[strings.TrimSpace(family.ID)] = struct{}{}
	}
	for _, family := range validation.ResourceFamilies {
		if family.ID == "" {
			errs = append(errs, fmt.Errorf("%s validation resource family id is required", validation.SourceID))
			continue
		}
		if _, ok := families[family.ID]; !ok {
			errs = append(errs, fmt.Errorf("%s validation references unknown resource family %q", validation.SourceID, family.ID))
		}
		if GradeRank(family.Grade) >= GradeRank(GradeFixtureValidated) && len(family.EvidenceRefs) == 0 && !hasEvidenceType(family.Evidence, "fixture", "live", "production_observation") {
			errs = append(errs, fmt.Errorf("%s family %s claims %s without evidence", validation.SourceID, family.ID, family.Grade))
		}
	}
	return errs
}

func NormalizeGrade(grade Grade) Grade {
	value := strings.ToLower(strings.TrimSpace(string(grade)))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	switch Grade(value) {
	case GradeGeneratedFromDocs, GradeSchemaValidated, GradeFixtureValidated, GradeLiveValidated, GradeProductionObserved:
		return Grade(value)
	default:
		return ""
	}
}

func ValidGrade(grade Grade) bool {
	return NormalizeGrade(grade) == grade && grade != ""
}

func GradeRank(grade Grade) int {
	switch NormalizeGrade(grade) {
	case GradeGeneratedFromDocs:
		return 0
	case GradeSchemaValidated:
		return 1
	case GradeFixtureValidated:
		return 2
	case GradeLiveValidated:
		return 3
	case GradeProductionObserved:
		return 4
	default:
		return -1
	}
}

func GradeAtLeast(grade Grade, minimum Grade) bool {
	return GradeRank(grade) >= GradeRank(minimum)
}

func FamilyGrade(validation ConnectorValidation, familyID string) Grade {
	familyID = strings.TrimSpace(familyID)
	for _, family := range validation.ResourceFamilies {
		if family.ID == familyID {
			return NormalizeGrade(family.Grade)
		}
	}
	return NormalizeGrade(validation.Grade)
}

func normalizeEvidence(values []Evidence) []Evidence {
	out := make([]Evidence, 0, len(values))
	for _, evidence := range values {
		evidence.Type = strings.ToLower(strings.TrimSpace(evidence.Type))
		evidence.Ref = strings.TrimSpace(evidence.Ref)
		evidence.Test = strings.TrimSpace(evidence.Test)
		evidence.ResourceFamily = strings.TrimSpace(evidence.ResourceFamily)
		if evidence.Type == "" && evidence.Ref == "" && evidence.Test == "" && evidence.ResourceFamily == "" {
			continue
		}
		out = append(out, evidence)
	}
	return out
}

func normalizeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasEvidenceType(values []Evidence, types ...string) bool {
	wanted := map[string]struct{}{}
	for _, typ := range types {
		wanted[strings.TrimSpace(typ)] = struct{}{}
	}
	for _, evidence := range values {
		if _, ok := wanted[strings.TrimSpace(evidence.Type)]; ok {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
