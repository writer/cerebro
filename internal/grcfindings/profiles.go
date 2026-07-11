package grcfindings

import (
	"sort"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

type findingProfileMatch struct {
	profileID   string
	profileName string
	controls    []ControlRef
}

type findingProfileIndex struct {
	byRuleID    map[string][]findingProfileMatch
	byControlID map[string][]findingProfileMatch
}

var builtinFindingProfileIndex = sync.OnceValues(func() (findingProfileIndex, error) {
	index, err := compliance.LoadBuiltinControlCoverageIndex()
	if err != nil {
		return findingProfileIndex{}, err
	}
	return buildFindingProfileIndex(index), nil
})

func builtinFindingProfiles(ruleID string, refs []ports.FindingControlRef) []ProfileRef {
	index, err := builtinFindingProfileIndex()
	if err != nil {
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

func buildFindingProfileIndex(index compliance.ControlCoverageIndex) findingProfileIndex {
	result := findingProfileIndex{
		byRuleID:    map[string][]findingProfileMatch{},
		byControlID: map[string][]findingProfileMatch{},
	}
	for _, profile := range index.Profiles {
		profileID := strings.TrimSpace(profile.ID)
		if profileID == "" {
			continue
		}
		for _, rule := range profile.Rules {
			ruleID := strings.TrimSpace(rule.RuleID)
			if ruleID == "" {
				continue
			}
			result.byRuleID[ruleID] = appendProfileMatch(result.byRuleID[ruleID], findingProfileMatch{
				profileID:   profileID,
				profileName: strings.TrimSpace(profile.Name),
				controls:    complianceControlRefsForGRC(rule.Controls),
			})
		}
		for _, control := range profile.Controls {
			selected := ControlRef{
				FrameworkName: strings.TrimSpace(control.FrameworkName),
				ControlID:     strings.TrimSpace(control.ControlID),
			}
			match := findingProfileMatch{
				profileID:   profileID,
				profileName: strings.TrimSpace(profile.Name),
				controls:    []ControlRef{selected},
			}
			refs := append([]compliance.ControlRef{{
				FrameworkName: selected.FrameworkName,
				ControlID:     selected.ControlID,
			}}, control.MappedControlRefs...)
			for _, ref := range refs {
				key := compliance.ControlKey(ref)
				if key == "\x00" {
					continue
				}
				result.byControlID[key] = appendProfileMatch(result.byControlID[key], match)
			}
		}
	}
	return result
}

func (index findingProfileIndex) profilesForFinding(ruleID string, refs []ControlRef) []ProfileRef {
	matches := map[string]ProfileRef{}
	add := func(match findingProfileMatch) {
		profile := matches[match.profileID]
		profile.ID = match.profileID
		profile.Name = match.profileName
		profile.MatchedControls = appendUniqueControlRefs(profile.MatchedControls, match.controls...)
		matches[match.profileID] = profile
	}
	for _, match := range index.byRuleID[strings.TrimSpace(ruleID)] {
		add(match)
	}
	for _, ref := range refs {
		key := compliance.ControlKey(compliance.ControlRef{
			FrameworkName: ref.FrameworkName,
			ControlID:     ref.ControlID,
		})
		for _, match := range index.byControlID[key] {
			add(match)
		}
	}
	profiles := make([]ProfileRef, 0, len(matches))
	for _, profile := range matches {
		sort.Slice(profile.MatchedControls, func(i, j int) bool {
			return controlRefKey(profile.MatchedControls[i]) < controlRefKey(profile.MatchedControls[j])
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
		return matches
	}
	return append(matches, candidate)
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
