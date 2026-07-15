package compliance

import (
	_ "embed"
	"fmt"
)

//go:embed control_families.yaml
var builtinControlCatalogYAML []byte

//go:embed control_profiles.yaml
var builtinControlProfilesYAML []byte

//go:embed control_coverage_index.yaml
var builtinControlCoverageIndexYAML []byte

//go:embed finding_profile_index.json.gz
var builtinFindingProfileIndexJSONGZ []byte

//go:embed finding_profile_exclusions.yaml
var builtinFindingProfileExclusionsYAML []byte

//go:embed control_archetypes.yaml
var builtinControlArchetypesYAML []byte

//go:embed control_evidence_requirements.yaml
var builtinControlEvidenceRequirementsYAML []byte

func LoadBuiltinControlCatalog() (ControlCatalog, error) {
	return LoadControlCatalog(builtinControlCatalogYAML)
}

func LoadBuiltinControlProfileSet() (ControlProfileSet, error) {
	return LoadControlProfileSet(builtinControlProfilesYAML)
}

func LoadBuiltinControlCoverageIndex() (ControlCoverageIndex, error) {
	return LoadControlCoverageIndex(builtinControlCoverageIndexYAML)
}

func LoadBuiltinFindingProfileIndex() (FindingProfileIndex, error) {
	index, err := LoadCompressedFindingProfileIndex(builtinFindingProfileIndexJSONGZ)
	if err != nil {
		return FindingProfileIndex{}, err
	}
	coverage, err := LoadBuiltinControlCoverageIndex()
	if err != nil {
		return FindingProfileIndex{}, fmt.Errorf("load built-in control coverage for finding profile index: %w", err)
	}
	digest, err := findingProfileIndexSourceDigest(coverage, BuiltinRuleControlMappings())
	if err != nil {
		return FindingProfileIndex{}, err
	}
	if index.SourceDigest != digest {
		return FindingProfileIndex{}, fmt.Errorf("built-in finding profile index source digest mismatch: got %q, want %q", index.SourceDigest, digest)
	}
	return index, nil
}

func LoadBuiltinFindingProfileExclusionLedger() (FindingProfileExclusionLedger, error) {
	return LoadFindingProfileExclusionLedger(builtinFindingProfileExclusionsYAML)
}

func LoadBuiltinControlArchetypeSet() (ControlArchetypeSet, error) {
	return LoadControlArchetypeSet(builtinControlArchetypesYAML)
}

func LoadBuiltinControlEvidenceRequirementCatalog() (ControlEvidenceRequirementCatalog, error) {
	return LoadControlEvidenceRequirementCatalog(builtinControlEvidenceRequirementsYAML)
}
