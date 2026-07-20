package grcfindings

import "strings"

// FindingProfileExportFields is the stable CSV projection of one finding's
// compliance profile associations.
type FindingProfileExportFields struct {
	IDs                    []string
	Names                  []string
	CoverageVersions       []string
	CoverageRevisions      []string
	MappingBases           []string
	MatchedProfileControls []string
	MatchedFindingControls []string
	MappingPaths           []string
}

// ProfileExportFields renders profile link explanations without moving profile
// semantics into the HTTP export adapter.
func (item FindingItem) ProfileExportFields() FindingProfileExportFields {
	fields := FindingProfileExportFields{}
	for _, profile := range item.Profiles {
		fields.IDs = append(fields.IDs, profile.ID)
		fields.Names = append(fields.Names, profile.Name)
		fields.CoverageVersions = append(fields.CoverageVersions, profile.CoverageIndexVersion)
		fields.CoverageRevisions = append(fields.CoverageRevisions, profile.CoverageIndexRevision)
		fields.MappingBases = append(fields.MappingBases, profile.MappingBasis)
		for _, control := range profile.MatchedControls {
			fields.MatchedProfileControls = append(fields.MatchedProfileControls, profile.ID+":"+profileExportControl(control))
		}
		for _, control := range profile.MatchedFindingControls {
			fields.MatchedFindingControls = append(fields.MatchedFindingControls, profile.ID+":"+profileExportControl(control))
		}
		for _, path := range profile.MappingPaths {
			value := profile.ID + ":matched " + profileExportControl(path.Source) + " -> " + profileExportControl(path.Target)
			if path.Relationship != "" {
				value += "; declared " + profileExportControl(path.DeclaredSource) + " " + path.Relationship + " " + profileExportControl(path.DeclaredTarget)
			}
			if path.CoverageCredit != "" {
				value += "; credit " + path.CoverageCredit
			}
			fields.MappingPaths = append(fields.MappingPaths, value)
		}
	}
	return fields
}

func profileExportControl(control ControlRef) string {
	return strings.TrimSpace(control.FrameworkName + " " + control.ControlID)
}
