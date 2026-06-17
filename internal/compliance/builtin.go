package compliance

import _ "embed"

//go:embed control_families.yaml
var builtinControlCatalogYAML []byte

//go:embed control_profiles.yaml
var builtinControlProfilesYAML []byte

//go:embed control_coverage_index.yaml
var builtinControlCoverageIndexYAML []byte

//go:embed control_archetypes.yaml
var builtinControlArchetypesYAML []byte

func LoadBuiltinControlCatalog() (ControlCatalog, error) {
	return LoadControlCatalog(builtinControlCatalogYAML)
}

func LoadBuiltinControlProfileSet() (ControlProfileSet, error) {
	return LoadControlProfileSet(builtinControlProfilesYAML)
}

func LoadBuiltinControlCoverageIndex() (ControlCoverageIndex, error) {
	return LoadControlCoverageIndex(builtinControlCoverageIndexYAML)
}

func LoadBuiltinControlArchetypeSet() (ControlArchetypeSet, error) {
	return LoadControlArchetypeSet(builtinControlArchetypesYAML)
}
