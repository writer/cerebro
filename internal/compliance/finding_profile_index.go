package compliance

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const DefaultFindingProfileIndexPath = "internal/compliance/finding_profile_index.json.gz"

const maxDecodedFindingProfileIndexBytes = 32 << 20

const (
	FindingProfileMappingDirect           = "direct"
	FindingProfileMappingCatalog          = "catalog_mapping"
	FindingProfileMappingDirectAndCatalog = "direct_and_catalog_mapping"
)

// FindingProfileIndex is the compact serving projection used to associate
// finding rules and control references with named compliance profiles. The
// full control coverage index remains the audit and explanation artifact.
type FindingProfileIndex struct {
	Version          string                           `json:"version"`
	MatchesByRuleID  map[string][]FindingProfileMatch `json:"matches_by_rule_id"`
	MatchesByControl map[string][]FindingProfileMatch `json:"matches_by_control"`
}

type FindingProfileMatch struct {
	ProfileID             string                      `json:"profile_id"`
	ProfileName           string                      `json:"profile_name,omitempty"`
	MappingBasis          string                      `json:"mapping_basis"`
	MatchedControls       []ControlRef                `json:"matched_controls,omitempty"`
	DirectControls        []ControlRef                `json:"direct_controls,omitempty"`
	CatalogMappedControls []ControlRef                `json:"catalog_mapped_controls,omitempty"`
	MappingPaths          []FindingProfileMappingPath `json:"mapping_paths,omitempty"`
}

type FindingProfileMappingPath struct {
	Source ControlRef `json:"source"`
	Target ControlRef `json:"target"`
}

type findingProfileIndexWire struct {
	Version          string                    `json:"version"`
	Profiles         map[string]string         `json:"profiles"`
	Controls         map[string]ControlRef     `json:"controls"`
	Matches          []findingProfileMatchWire `json:"matches"`
	MatchesByRuleID  map[string][]int          `json:"matches_by_rule_id"`
	MatchesByControl map[string][]int          `json:"matches_by_control"`
}

type findingProfileMatchWire struct {
	ProfileID                string                          `json:"profile_id"`
	MappingBasis             string                          `json:"mapping_basis"`
	MatchedControlKeys       []string                        `json:"matched_control_keys,omitempty"`
	DirectControlKeys        []string                        `json:"direct_control_keys,omitempty"`
	CatalogMappedControlKeys []string                        `json:"catalog_mapped_control_keys,omitempty"`
	MappingPaths             []findingProfileMappingPathWire `json:"mapping_paths,omitempty"`
}

type findingProfileMappingPathWire struct {
	Source           ControlRef `json:"source"`
	TargetControlKey string     `json:"target_control_key"`
}

func (index FindingProfileIndex) MarshalJSON() ([]byte, error) {
	wire := findingProfileIndexWire{
		Version:          strings.TrimSpace(index.Version),
		Profiles:         map[string]string{},
		Controls:         map[string]ControlRef{},
		MatchesByRuleID:  map[string][]int{},
		MatchesByControl: map[string][]int{},
	}
	appendMatches := func(matches []FindingProfileMatch) []int {
		indexes := make([]int, 0, len(matches))
		for _, match := range matches {
			wire.Profiles[match.ProfileID] = match.ProfileName
			encoded := findingProfileMatchWire{
				ProfileID:                match.ProfileID,
				MappingBasis:             match.MappingBasis,
				MatchedControlKeys:       findingProfileControlKeys(wire.Controls, match.MatchedControls),
				DirectControlKeys:        findingProfileControlKeys(wire.Controls, match.DirectControls),
				CatalogMappedControlKeys: findingProfileControlKeys(wire.Controls, match.CatalogMappedControls),
			}
			for _, path := range match.MappingPaths {
				targetKey := findingProfileStoreControl(wire.Controls, path.Target)
				encoded.MappingPaths = append(encoded.MappingPaths, findingProfileMappingPathWire{
					Source:           path.Source,
					TargetControlKey: targetKey,
				})
			}
			indexes = append(indexes, len(wire.Matches))
			wire.Matches = append(wire.Matches, encoded)
		}
		return indexes
	}
	for _, key := range sortedFindingProfileMapKeys(index.MatchesByRuleID) {
		wire.MatchesByRuleID[key] = appendMatches(index.MatchesByRuleID[key])
	}
	for _, key := range sortedFindingProfileMapKeys(index.MatchesByControl) {
		wire.MatchesByControl[key] = appendMatches(index.MatchesByControl[key])
	}
	return json.Marshal(wire)
}

func (index *FindingProfileIndex) UnmarshalJSON(content []byte) error {
	var wire findingProfileIndexWire
	if err := json.Unmarshal(content, &wire); err != nil {
		return err
	}
	decodeMatch := func(matchIndex int) (FindingProfileMatch, error) {
		if matchIndex < 0 || matchIndex >= len(wire.Matches) {
			return FindingProfileMatch{}, fmt.Errorf("finding profile match index %d is out of range", matchIndex)
		}
		encoded := wire.Matches[matchIndex]
		match := FindingProfileMatch{
			ProfileID:    encoded.ProfileID,
			ProfileName:  wire.Profiles[encoded.ProfileID],
			MappingBasis: encoded.MappingBasis,
		}
		var err error
		if match.MatchedControls, err = findingProfileControlsForKeys(wire.Controls, encoded.MatchedControlKeys); err != nil {
			return FindingProfileMatch{}, err
		}
		if match.DirectControls, err = findingProfileControlsForKeys(wire.Controls, encoded.DirectControlKeys); err != nil {
			return FindingProfileMatch{}, err
		}
		if match.CatalogMappedControls, err = findingProfileControlsForKeys(wire.Controls, encoded.CatalogMappedControlKeys); err != nil {
			return FindingProfileMatch{}, err
		}
		for _, path := range encoded.MappingPaths {
			target, ok := wire.Controls[path.TargetControlKey]
			if !ok {
				return FindingProfileMatch{}, fmt.Errorf("finding profile mapping target %q is not declared", path.TargetControlKey)
			}
			match.MappingPaths = append(match.MappingPaths, FindingProfileMappingPath{Source: path.Source, Target: target})
		}
		return match, nil
	}
	result := FindingProfileIndex{
		Version:          wire.Version,
		MatchesByRuleID:  map[string][]FindingProfileMatch{},
		MatchesByControl: map[string][]FindingProfileMatch{},
	}
	decodeIndexes := func(indexes []int) ([]FindingProfileMatch, error) {
		matches := make([]FindingProfileMatch, 0, len(indexes))
		for _, matchIndex := range indexes {
			match, err := decodeMatch(matchIndex)
			if err != nil {
				return nil, err
			}
			matches = append(matches, match)
		}
		return matches, nil
	}
	for key, indexes := range wire.MatchesByRuleID {
		matches, err := decodeIndexes(indexes)
		if err != nil {
			return err
		}
		result.MatchesByRuleID[key] = matches
	}
	for key, indexes := range wire.MatchesByControl {
		matches, err := decodeIndexes(indexes)
		if err != nil {
			return err
		}
		result.MatchesByControl[key] = matches
	}
	*index = result
	return nil
}

func findingProfileControlKeys(controls map[string]ControlRef, refs []ControlRef) []string {
	keys := make([]string, 0, len(refs))
	for _, ref := range refs {
		if key := findingProfileStoreControl(controls, ref); key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func findingProfileStoreControl(controls map[string]ControlRef, ref ControlRef) string {
	ref = NormalizeControlRef(ref)
	key := ControlKey(ref)
	if key == "\x00" {
		return ""
	}
	controls[key] = ref
	return key
}

func findingProfileControlsForKeys(controls map[string]ControlRef, keys []string) ([]ControlRef, error) {
	refs := make([]ControlRef, 0, len(keys))
	for _, key := range keys {
		ref, ok := controls[key]
		if !ok {
			return nil, fmt.Errorf("finding profile control %q is not declared", key)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func sortedFindingProfileMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func LoadFindingProfileIndex(content []byte) (FindingProfileIndex, error) {
	var index FindingProfileIndex
	if err := json.Unmarshal(content, &index); err != nil {
		return FindingProfileIndex{}, err
	}
	if strings.TrimSpace(index.Version) == "" {
		return FindingProfileIndex{}, fmt.Errorf("finding profile index version is required")
	}
	if index.MatchesByRuleID == nil {
		index.MatchesByRuleID = map[string][]FindingProfileMatch{}
	}
	if index.MatchesByControl == nil {
		index.MatchesByControl = map[string][]FindingProfileMatch{}
	}
	return index, nil
}

func LoadCompressedFindingProfileIndex(content []byte) (FindingProfileIndex, error) {
	reader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return FindingProfileIndex{}, fmt.Errorf("open compressed finding profile index: %w", err)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, maxDecodedFindingProfileIndexBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		return FindingProfileIndex{}, fmt.Errorf("read compressed finding profile index: %w", readErr)
	}
	if closeErr != nil {
		return FindingProfileIndex{}, fmt.Errorf("close compressed finding profile index: %w", closeErr)
	}
	if len(decoded) > maxDecodedFindingProfileIndexBytes {
		return FindingProfileIndex{}, fmt.Errorf("compressed finding profile index exceeds %d decoded bytes", maxDecodedFindingProfileIndexBytes)
	}
	return LoadFindingProfileIndex(decoded)
}

func BuildFindingProfileIndex(coverage ControlCoverageIndex, rules []RuleControlMapping) (FindingProfileIndex, error) {
	result := FindingProfileIndex{
		Version:          strings.TrimSpace(coverage.Version),
		MatchesByRuleID:  map[string][]FindingProfileMatch{},
		MatchesByControl: map[string][]FindingProfileMatch{},
	}
	if result.Version == "" {
		return FindingProfileIndex{}, fmt.Errorf("control coverage index version is required")
	}
	rulesByID := make(map[string][]ControlRef, len(rules))
	for _, rule := range rules {
		ruleID := strings.TrimSpace(rule.RuleID)
		if ruleID == "" {
			continue
		}
		rulesByID[ruleID] = uniqueFindingProfileControlRefs(rule.ControlRefs)
	}
	for _, profile := range coverage.Profiles {
		profileID := strings.TrimSpace(profile.ID)
		if profileID == "" {
			continue
		}
		controlsByKey := make(map[string]ControlCoverageControl, len(profile.Controls))
		for _, control := range profile.Controls {
			target := coverageControlRef(control)
			if controlKey := ControlKey(target); controlKey != "\x00" {
				controlsByKey[controlKey] = control
				result.MatchesByControl[controlKey] = mergeFindingProfileMatch(result.MatchesByControl[controlKey], FindingProfileMatch{
					ProfileID:       profileID,
					ProfileName:     strings.TrimSpace(profile.Name),
					MappingBasis:    FindingProfileMappingDirect,
					MatchedControls: []ControlRef{target},
					DirectControls:  []ControlRef{target},
				})
			}
			for _, source := range control.MappedControlRefs {
				if !ControlMappingCreditsCoverage(source) {
					continue
				}
				source = NormalizeControlRef(source)
				if sourceKey := ControlKey(source); sourceKey != "\x00" {
					result.MatchesByControl[sourceKey] = mergeFindingProfileMatch(result.MatchesByControl[sourceKey], FindingProfileMatch{
						ProfileID:             profileID,
						ProfileName:           strings.TrimSpace(profile.Name),
						MappingBasis:          FindingProfileMappingCatalog,
						MatchedControls:       []ControlRef{target},
						CatalogMappedControls: []ControlRef{target},
						MappingPaths:          []FindingProfileMappingPath{{Source: source, Target: target}},
					})
				}
			}
		}
		for _, rule := range profile.Rules {
			ruleID := strings.TrimSpace(rule.RuleID)
			if ruleID == "" {
				continue
			}
			sourceRefs, ok := rulesByID[ruleID]
			if !ok {
				return FindingProfileIndex{}, fmt.Errorf("profile %s references rule %s without control metadata", profileID, ruleID)
			}
			match, err := buildFindingProfileRuleMatch(profileID, profile.Name, rule, sourceRefs, controlsByKey)
			if err != nil {
				return FindingProfileIndex{}, err
			}
			result.MatchesByRuleID[ruleID] = mergeFindingProfileMatch(result.MatchesByRuleID[ruleID], match)
		}
	}
	sortFindingProfileIndex(&result)
	return result, nil
}

func ResolveFindingProfileMatches(index FindingProfileIndex, ruleID string, refs []ControlRef) []FindingProfileMatch {
	matches := []FindingProfileMatch{}
	for _, match := range index.MatchesByRuleID[strings.TrimSpace(ruleID)] {
		matches = mergeFindingProfileMatch(matches, match)
	}
	for _, ref := range refs {
		for _, match := range index.MatchesByControl[ControlKey(ref)] {
			matches = mergeFindingProfileMatch(matches, match)
		}
	}
	for idx := range matches {
		matches[idx].MappingBasis = findingProfileMappingBasis(len(matches[idx].DirectControls) != 0, len(matches[idx].CatalogMappedControls) != 0)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ProfileID < matches[j].ProfileID })
	return matches
}

func buildFindingProfileRuleMatch(profileID, profileName string, rule ControlCoverageRule, sourceRefs []ControlRef, controlsByKey map[string]ControlCoverageControl) (FindingProfileMatch, error) {
	directSet := map[string]struct{}{}
	for _, ref := range sourceRefs {
		directSet[ControlKey(ref)] = struct{}{}
	}
	match := FindingProfileMatch{ProfileID: profileID, ProfileName: strings.TrimSpace(profileName)}
	for _, rawTarget := range rule.Controls {
		target := NormalizeControlRef(rawTarget)
		match.MatchedControls = appendUniqueFindingProfileControlRef(match.MatchedControls, target)
		if _, direct := directSet[ControlKey(target)]; direct {
			match.DirectControls = appendUniqueFindingProfileControlRef(match.DirectControls, target)
			continue
		}
		control, ok := controlsByKey[ControlKey(target)]
		if !ok {
			return FindingProfileMatch{}, fmt.Errorf("profile %s rule %s references missing selected control %s %s", profileID, rule.RuleID, target.FrameworkName, target.ControlID)
		}
		mapped := false
		for _, rawSource := range control.MappedControlRefs {
			if !ControlMappingCreditsCoverage(rawSource) {
				continue
			}
			source := NormalizeControlRef(rawSource)
			if _, ok := directSet[ControlKey(source)]; !ok {
				continue
			}
			mapped = true
			match.MappingPaths = appendUniqueFindingProfileMappingPath(match.MappingPaths, FindingProfileMappingPath{Source: source, Target: target})
		}
		if !mapped {
			return FindingProfileMatch{}, fmt.Errorf("profile %s rule %s has no direct or catalog-mapped basis for %s %s", profileID, rule.RuleID, target.FrameworkName, target.ControlID)
		}
		match.CatalogMappedControls = appendUniqueFindingProfileControlRef(match.CatalogMappedControls, target)
	}
	match.MappingBasis = findingProfileMappingBasis(len(match.DirectControls) != 0, len(match.CatalogMappedControls) != 0)
	return match, nil
}

func mergeFindingProfileMatch(matches []FindingProfileMatch, candidate FindingProfileMatch) []FindingProfileMatch {
	for idx := range matches {
		if matches[idx].ProfileID != candidate.ProfileID {
			continue
		}
		matches[idx].ProfileName = candidate.ProfileName
		matches[idx].MatchedControls = appendUniqueFindingProfileControlRef(matches[idx].MatchedControls, candidate.MatchedControls...)
		matches[idx].DirectControls = appendUniqueFindingProfileControlRef(matches[idx].DirectControls, candidate.DirectControls...)
		matches[idx].CatalogMappedControls = appendUniqueFindingProfileControlRef(matches[idx].CatalogMappedControls, candidate.CatalogMappedControls...)
		for _, path := range candidate.MappingPaths {
			matches[idx].MappingPaths = appendUniqueFindingProfileMappingPath(matches[idx].MappingPaths, path)
		}
		matches[idx].MappingBasis = findingProfileMappingBasis(len(matches[idx].DirectControls) != 0, len(matches[idx].CatalogMappedControls) != 0)
		return matches
	}
	return append(matches, candidate)
}

func findingProfileMappingBasis(direct, mapped bool) string {
	switch {
	case direct && mapped:
		return FindingProfileMappingDirectAndCatalog
	case mapped:
		return FindingProfileMappingCatalog
	default:
		return FindingProfileMappingDirect
	}
}

func coverageControlRef(control ControlCoverageControl) ControlRef {
	return NormalizeControlRef(ControlRef{
		FrameworkID:   control.FrameworkID,
		FrameworkName: control.FrameworkName,
		ControlID:     control.ControlID,
	})
}

func uniqueFindingProfileControlRefs(refs []ControlRef) []ControlRef {
	var result []ControlRef
	return appendUniqueFindingProfileControlRef(result, refs...)
}

func appendUniqueFindingProfileControlRef(refs []ControlRef, candidates ...ControlRef) []ControlRef {
	seen := make(map[string]struct{}, len(refs)+len(candidates))
	for _, ref := range refs {
		seen[ControlKey(ref)] = struct{}{}
	}
	for _, candidate := range candidates {
		candidate = NormalizeControlRef(candidate)
		key := ControlKey(candidate)
		if key == "\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, candidate)
	}
	return refs
}

func appendUniqueFindingProfileMappingPath(paths []FindingProfileMappingPath, candidate FindingProfileMappingPath) []FindingProfileMappingPath {
	key := ControlKey(candidate.Source) + "->" + ControlKey(candidate.Target)
	for _, path := range paths {
		if ControlKey(path.Source)+"->"+ControlKey(path.Target) == key {
			return paths
		}
	}
	return append(paths, candidate)
}

func sortFindingProfileIndex(index *FindingProfileIndex) {
	for _, matches := range []map[string][]FindingProfileMatch{index.MatchesByRuleID, index.MatchesByControl} {
		for key := range matches {
			for idx := range matches[key] {
				sort.Slice(matches[key][idx].MatchedControls, func(i, j int) bool {
					return ControlKey(matches[key][idx].MatchedControls[i]) < ControlKey(matches[key][idx].MatchedControls[j])
				})
				sort.Slice(matches[key][idx].DirectControls, func(i, j int) bool {
					return ControlKey(matches[key][idx].DirectControls[i]) < ControlKey(matches[key][idx].DirectControls[j])
				})
				sort.Slice(matches[key][idx].CatalogMappedControls, func(i, j int) bool {
					return ControlKey(matches[key][idx].CatalogMappedControls[i]) < ControlKey(matches[key][idx].CatalogMappedControls[j])
				})
				sort.Slice(matches[key][idx].MappingPaths, func(i, j int) bool {
					left := ControlKey(matches[key][idx].MappingPaths[i].Source) + "->" + ControlKey(matches[key][idx].MappingPaths[i].Target)
					right := ControlKey(matches[key][idx].MappingPaths[j].Source) + "->" + ControlKey(matches[key][idx].MappingPaths[j].Target)
					return left < right
				})
			}
			sort.Slice(matches[key], func(i, j int) bool { return matches[key][i].ProfileID < matches[key][j].ProfileID })
		}
	}
}
