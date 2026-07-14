package grcfindings

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

type findingProfileMatch struct {
	profileID             string
	profileName           string
	mappingBasis          string
	controls              []ControlRef
	directControls        []ControlRef
	catalogMappedControls []ControlRef
	mappingPaths          []ProfileMappingPath
}

type findingProfileIndex struct {
	version         string
	contentRevision string
	byRuleID        map[string][]findingProfileMatch
	byControlID     map[string][]findingProfileMatch
	profiles        map[string]ProfileRef
}

// ProfilePredicate is the persisted finding selector for one immutable
// compliance profile. Rule IDs and control references are alternatives: a
// finding belongs to the profile when either selector matches.
type ProfilePredicate = ports.FindingProfilePredicate

var builtinFindingProfileIndex = sync.OnceValues(func() (findingProfileIndex, error) {
	index, err := compliance.LoadBuiltinFindingProfileIndex()
	if err != nil {
		return findingProfileIndex{}, fmt.Errorf("load built-in finding profile index: %w", err)
	}
	result := buildFindingProfileIndex(index)
	profiles, err := compliance.LoadBuiltinControlProfileSet()
	if err != nil {
		return findingProfileIndex{}, fmt.Errorf("load built-in control profiles: %w", err)
	}
	if err := result.applyProfiles(profiles); err != nil {
		return findingProfileIndex{}, fmt.Errorf("join built-in finding profile metadata: %w", err)
	}
	if err := result.validate(); err != nil {
		return findingProfileIndex{}, fmt.Errorf("validate built-in finding profile index: %w", err)
	}
	return result, nil
})

// ValidateBuiltinFindingProfileIndex loads and validates the immutable index
// used to annotate GRC findings. Production startup calls this so a damaged or
// incompatible embedded index stops the process instead of removing every
// compliance association from otherwise successful responses.
func ValidateBuiltinFindingProfileIndex() error {
	_, err := builtinFindingProfileIndex()
	return err
}

func (index *findingProfileIndex) applyProfiles(set compliance.ControlProfileSet) error {
	if strings.TrimSpace(set.Version) == "" || strings.TrimSpace(set.Version) != index.version {
		return fmt.Errorf("control profile version %q does not match serving index version %q", strings.TrimSpace(set.Version), index.version)
	}
	if len(index.byRuleID) == 0 && len(index.byControlID) == 0 {
		return fmt.Errorf("serving index contains no finding associations")
	}
	matchedProfiles := make(map[string]struct{}, len(index.profiles))
	for id := range index.profiles {
		matchedProfiles[id] = struct{}{}
	}
	configured := make(map[string]struct{}, len(set.Profiles))
	for _, selection := range set.Profiles {
		id := strings.TrimSpace(selection.ID)
		name := strings.TrimSpace(selection.Name)
		if id == "" || name == "" {
			return fmt.Errorf("profile id and name are required")
		}
		configured[id] = struct{}{}
		if _, ok := matchedProfiles[id]; !ok {
			return fmt.Errorf("configured profile %q has no serving index associations", id)
		}
		if matched, ok := index.profiles[id]; ok && matched.Name != name {
			return fmt.Errorf("profile %q name %q does not match serving index name %q", id, name, matched.Name)
		}
		index.profiles[id] = ProfileRef{ID: id, Name: name, CoverageIndexVersion: index.version, CoverageIndexRevision: index.contentRevision}
	}
	for id := range index.profiles {
		if _, ok := configured[id]; !ok {
			return fmt.Errorf("serving index references unknown profile %q", id)
		}
	}
	return nil
}

// BuiltinFindingProfile returns metadata for a known built-in profile. The
// boolean is false for an unknown profile ID.
func BuiltinFindingProfile(profileID string) (ProfileRef, bool, error) {
	index, err := builtinFindingProfileIndex()
	if err != nil {
		return ProfileRef{}, false, err
	}
	profile, ok := index.profiles[strings.TrimSpace(profileID)]
	return profile, ok, nil
}

// BuiltinFindingProfilePredicate returns the exact persisted finding selector
// for a built-in profile. Callers apply it before ordering and pagination, then
// retain profilesForFinding as a defensive serving-index verification step.
func BuiltinFindingProfilePredicate(profileID string) (ProfilePredicate, bool, error) {
	index, err := builtinFindingProfileIndex()
	if err != nil {
		return ProfilePredicate{}, false, err
	}
	profileID = strings.TrimSpace(profileID)
	if _, ok := index.profiles[profileID]; !ok {
		return ProfilePredicate{}, false, nil
	}
	predicate := ProfilePredicate{}
	for ruleID, matches := range index.byRuleID {
		if profileMatchesID(matches, profileID) {
			predicate.RuleIDs = append(predicate.RuleIDs, ruleID)
		}
	}
	for controlKey, matches := range index.byControlID {
		if !profileMatchesID(matches, profileID) {
			continue
		}
		frameworkName, controlID, ok := strings.Cut(controlKey, "\x00")
		if !ok || strings.TrimSpace(frameworkName) == "" || strings.TrimSpace(controlID) == "" {
			return ProfilePredicate{}, false, fmt.Errorf("profile %q has invalid control selector %q", profileID, controlKey)
		}
		predicate.ControlRefs = append(predicate.ControlRefs, ports.FindingControlRef{
			FrameworkName: frameworkName,
			ControlID:     controlID,
		})
	}
	sort.Strings(predicate.RuleIDs)
	sort.Slice(predicate.ControlRefs, func(i, j int) bool {
		left := predicate.ControlRefs[i].FrameworkName + "\x00" + predicate.ControlRefs[i].ControlID
		right := predicate.ControlRefs[j].FrameworkName + "\x00" + predicate.ControlRefs[j].ControlID
		return left < right
	})
	return predicate, true, nil
}

func profileMatchesID(matches []findingProfileMatch, profileID string) bool {
	for _, match := range matches {
		if match.profileID == profileID {
			return true
		}
	}
	return false
}

func builtinFindingProfiles(ruleID string, refs []ports.FindingControlRef) []ProfileRef {
	index, err := builtinFindingProfileIndex()
	if err != nil {
		// NewWithError validates the immutable index before any production route
		// is registered. Keep this helper total for package-level callers; the
		// bootstrap boundary is the fail-closed contract.
		return nil
	}
	controls := make([]ControlRef, 0, len(refs))
	for _, ref := range refs {
		controls = append(controls, ControlRef{
			FrameworkName: ref.FrameworkName,
			ControlID:     ref.ControlID,
		})
	}
	return index.profilesForFinding(ruleID, controls)
}

func buildFindingProfileIndex(index compliance.FindingProfileIndex) findingProfileIndex {
	result := findingProfileIndex{
		version:         strings.TrimSpace(index.Version),
		contentRevision: strings.TrimSpace(index.ContentRevision),
		byRuleID:        map[string][]findingProfileMatch{},
		byControlID:     map[string][]findingProfileMatch{},
		profiles:        map[string]ProfileRef{},
	}
	for ruleID, matches := range index.MatchesByRuleID {
		for _, match := range matches {
			converted := findingProfileMatchFromCompliance(match)
			result.addProfile(converted)
			result.byRuleID[strings.TrimSpace(ruleID)] = appendProfileMatch(result.byRuleID[strings.TrimSpace(ruleID)], converted)
		}
	}
	for controlKey, matches := range index.MatchesByControl {
		for _, match := range matches {
			converted := findingProfileMatchFromCompliance(match)
			result.addProfile(converted)
			result.byControlID[controlKey] = appendProfileMatch(result.byControlID[controlKey], converted)
		}
	}
	return result
}

func (index *findingProfileIndex) addProfile(match findingProfileMatch) {
	if match.profileID == "" {
		return
	}
	index.profiles[match.profileID] = ProfileRef{
		ID:                    match.profileID,
		Name:                  match.profileName,
		CoverageIndexVersion:  index.version,
		CoverageIndexRevision: index.contentRevision,
	}
}

func findingProfileMatchFromCompliance(match compliance.FindingProfileMatch) findingProfileMatch {
	paths := make([]ProfileMappingPath, 0, len(match.MappingPaths))
	for _, path := range match.MappingPaths {
		coverageCredit := "reviewed_catalog_mapping"
		if strings.TrimSpace(path.Source.Relationship) == "" {
			coverageCredit = "legacy_catalog_mapping"
		}
		paths = append(paths, ProfileMappingPath{
			Source:             controlRefFromCompliance(path.Source),
			Target:             controlRefFromCompliance(path.Target),
			MatchDirection:     "finding_control_to_profile_control",
			DeclaredSource:     controlRefFromCompliance(path.Target),
			DeclaredTarget:     controlRefFromCompliance(path.Source),
			CoverageCredit:     coverageCredit,
			Relationship:       strings.TrimSpace(path.Source.Relationship),
			MatchingRationale:  strings.TrimSpace(path.Source.MatchingRationale),
			MappingDescription: strings.TrimSpace(path.Source.MappingDescription),
			MappingAuthority:   strings.TrimSpace(path.Source.MappingAuthority),
			MappingSource:      strings.TrimSpace(path.Source.MappingSource),
			ReviewStatus:       strings.TrimSpace(path.Source.ReviewStatus),
			ReviewedAt:         strings.TrimSpace(path.Source.ReviewedAt),
			MappingVersion:     strings.TrimSpace(path.Source.MappingVersion),
		})
	}
	return findingProfileMatch{
		profileID:             strings.TrimSpace(match.ProfileID),
		profileName:           strings.TrimSpace(match.ProfileName),
		mappingBasis:          strings.TrimSpace(match.MappingBasis),
		controls:              complianceControlRefsForGRC(match.MatchedControls),
		directControls:        complianceControlRefsForGRC(match.DirectControls),
		catalogMappedControls: complianceControlRefsForGRC(match.CatalogMappedControls),
		mappingPaths:          paths,
	}
}

func (index findingProfileIndex) profilesForFinding(ruleID string, refs []ControlRef) []ProfileRef {
	matches := map[string]ProfileRef{}
	add := func(match findingProfileMatch, findingControl *ControlRef) {
		profile := matches[match.profileID]
		profile.ID = match.profileID
		profile.Name = match.profileName
		profile.CoverageIndexVersion = index.version
		profile.CoverageIndexRevision = index.contentRevision
		profile.MatchedControls = appendUniqueControlRefs(profile.MatchedControls, match.controls...)
		profile.DirectControls = appendUniqueControlRefs(profile.DirectControls, match.directControls...)
		profile.CatalogMappedControls = appendUniqueControlRefs(profile.CatalogMappedControls, match.catalogMappedControls...)
		profile.MappingPaths = appendUniqueProfileMappingPaths(profile.MappingPaths, match.mappingPaths...)
		for _, control := range match.directControls {
			profile.MatchedFindingControls = appendUniqueControlRefs(profile.MatchedFindingControls, control)
		}
		for _, path := range match.mappingPaths {
			profile.MatchedFindingControls = appendUniqueControlRefs(profile.MatchedFindingControls, path.Source)
		}
		if findingControl != nil {
			profile.MatchedFindingControls = appendUniqueControlRefs(profile.MatchedFindingControls, *findingControl)
		}
		profile.MappingBasis = findingProfileMappingBasis(profile.DirectControls, profile.CatalogMappedControls, match.mappingBasis)
		matches[match.profileID] = profile
	}
	for _, match := range index.byRuleID[strings.TrimSpace(ruleID)] {
		add(match, nil)
	}
	for _, ref := range refs {
		key := compliance.ControlKey(compliance.ControlRef{
			FrameworkName: ref.FrameworkName,
			ControlID:     ref.ControlID,
		})
		for _, match := range index.byControlID[key] {
			matched := ref
			add(match, &matched)
		}
	}
	profiles := make([]ProfileRef, 0, len(matches))
	for _, profile := range matches {
		sort.Slice(profile.MatchedControls, func(i, j int) bool {
			return controlRefKey(profile.MatchedControls[i]) < controlRefKey(profile.MatchedControls[j])
		})
		sort.Slice(profile.DirectControls, func(i, j int) bool {
			return controlRefKey(profile.DirectControls[i]) < controlRefKey(profile.DirectControls[j])
		})
		sort.Slice(profile.CatalogMappedControls, func(i, j int) bool {
			return controlRefKey(profile.CatalogMappedControls[i]) < controlRefKey(profile.CatalogMappedControls[j])
		})
		sort.Slice(profile.MatchedFindingControls, func(i, j int) bool {
			return controlRefKey(profile.MatchedFindingControls[i]) < controlRefKey(profile.MatchedFindingControls[j])
		})
		sort.Slice(profile.MappingPaths, func(i, j int) bool {
			left := controlRefKey(profile.MappingPaths[i].Source) + "->" + controlRefKey(profile.MappingPaths[i].Target)
			right := controlRefKey(profile.MappingPaths[j].Source) + "->" + controlRefKey(profile.MappingPaths[j].Target)
			return left < right
		})
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles
}

func appendProfileMatch(matches []findingProfileMatch, candidate findingProfileMatch) []findingProfileMatch {
	for i := range matches {
		if matches[i].profileID != candidate.profileID {
			continue
		}
		matches[i].controls = appendUniqueControlRefs(matches[i].controls, candidate.controls...)
		matches[i].directControls = appendUniqueControlRefs(matches[i].directControls, candidate.directControls...)
		matches[i].catalogMappedControls = appendUniqueControlRefs(matches[i].catalogMappedControls, candidate.catalogMappedControls...)
		matches[i].mappingPaths = appendUniqueProfileMappingPaths(matches[i].mappingPaths, candidate.mappingPaths...)
		matches[i].mappingBasis = findingProfileMappingBasis(matches[i].directControls, matches[i].catalogMappedControls, candidate.mappingBasis)
		return matches
	}
	return append(matches, candidate)
}

func (index findingProfileIndex) validate() error {
	if index.version == "" {
		return fmt.Errorf("coverage index version is required")
	}
	if index.contentRevision == "" {
		return fmt.Errorf("coverage index content revision is required")
	}
	if len(index.profiles) == 0 {
		return fmt.Errorf("at least one profile is required")
	}
	for id, profile := range index.profiles {
		if strings.TrimSpace(profile.Name) == "" {
			return fmt.Errorf("profile %q name is required", id)
		}
	}
	return nil
}

func findingProfileMappingBasis(direct, catalog []ControlRef, fallback string) string {
	switch {
	case len(direct) != 0 && len(catalog) != 0:
		return compliance.FindingProfileMappingDirectAndCatalog
	case len(catalog) != 0:
		return compliance.FindingProfileMappingCatalog
	case len(direct) != 0:
		return compliance.FindingProfileMappingDirect
	default:
		return strings.TrimSpace(fallback)
	}
}

func appendUniqueProfileMappingPaths(paths []ProfileMappingPath, candidates ...ProfileMappingPath) []ProfileMappingPath {
	seen := make(map[string]struct{}, len(paths)+len(candidates))
	for _, path := range paths {
		seen[controlRefKey(path.Source)+"->"+controlRefKey(path.Target)] = struct{}{}
	}
	for _, candidate := range candidates {
		key := controlRefKey(candidate.Source) + "->" + controlRefKey(candidate.Target)
		if key == "\x00->\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		paths = append(paths, candidate)
	}
	return paths
}

func complianceControlRefsForGRC(refs []compliance.ControlRef) []ControlRef {
	result := make([]ControlRef, 0, len(refs))
	for _, ref := range refs {
		ref = compliance.NormalizeControlRef(ref)
		if ref.FrameworkName == "" || ref.ControlID == "" {
			continue
		}
		result = appendUniqueControlRefs(result, ControlRef{
			FrameworkName: ref.FrameworkName,
			ControlID:     ref.ControlID,
		})
	}
	return result
}

func controlRefFromCompliance(ref compliance.ControlRef) ControlRef {
	ref = compliance.NormalizeControlRef(ref)
	return ControlRef{FrameworkName: ref.FrameworkName, ControlID: ref.ControlID}
}

func appendUniqueControlRefs(refs []ControlRef, candidates ...ControlRef) []ControlRef {
	seen := make(map[string]struct{}, len(refs)+len(candidates))
	for _, ref := range refs {
		seen[controlRefKey(ref)] = struct{}{}
	}
	for _, ref := range candidates {
		ref.FrameworkName = strings.TrimSpace(ref.FrameworkName)
		ref.ControlID = strings.TrimSpace(ref.ControlID)
		if ref.FrameworkName == "" || ref.ControlID == "" {
			continue
		}
		key := controlRefKey(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func controlRefKey(ref ControlRef) string {
	return compliance.ControlKey(compliance.ControlRef{
		FrameworkName: ref.FrameworkName,
		ControlID:     ref.ControlID,
	})
}
