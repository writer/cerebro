package connectorpreview

import (
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

// ScopeOption is the API-facing resource-family selector derived from source
// coverage contracts or declarative connector definitions.
type ScopeOption struct {
	ID                     string                         `json:"id"`
	Label                  string                         `json:"label"`
	Type                   string                         `json:"type"`
	Families               []string                       `json:"families,omitempty"`
	Support                string                         `json:"support,omitempty"`
	HighValue              bool                           `json:"high_value,omitempty"`
	KnownUnsupportedFields []string                       `json:"known_unsupported_fields,omitempty"`
	Notes                  []string                       `json:"notes,omitempty"`
	EvidenceTypes          []string                       `json:"evidence_types,omitempty"`
	ControlDomains         []string                       `json:"control_domains,omitempty"`
	ControlRefs            []sourcecdk.CoverageControlRef `json:"control_refs,omitempty"`
}

func ScopeOptionsFromDefinition(definition connectordefinitions.Definition) []ScopeOption {
	options := make([]ScopeOption, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		for _, dimension := range family.Coverage {
			if len(dimension.Families) == 0 || dimension.Support == sourcecdk.CoverageSupportUnsupported || dimension.Support == sourcecdk.CoverageSupportPlanned {
				continue
			}
			label := strings.TrimSpace(dimension.Title)
			if label == "" {
				label = firstNonEmpty(family.Label, fieldLabel(family.ID))
			}
			options = append(options, ScopeOption{
				ID:                     dimension.ID,
				Label:                  label,
				Type:                   dimension.Type,
				Families:               append([]string{}, dimension.Families...),
				Support:                dimension.Support,
				HighValue:              dimension.HighValue,
				KnownUnsupportedFields: append([]string{}, dimension.KnownUnsupportedFields...),
				Notes:                  append([]string{}, dimension.Notes...),
				EvidenceTypes:          append([]string{}, dimension.EvidenceTypes...),
				ControlDomains:         append([]string{}, dimension.ControlDomains...),
				ControlRefs:            controlRefsFromDefinition(dimension.ControlRefs),
			})
		}
	}
	sortScopeOptions(options)
	return options
}

func ScopeOptionsFromCoverage(contract sourcecdk.CoverageContract) []ScopeOption {
	options := make([]ScopeOption, 0, len(contract.Dimensions))
	for _, dimension := range contract.Dimensions {
		if len(dimension.Families) == 0 || dimension.Support == sourcecdk.CoverageSupportUnsupported || dimension.Support == sourcecdk.CoverageSupportPlanned {
			continue
		}
		options = append(options, ScopeOption{
			ID:                     dimension.ID,
			Label:                  dimension.Title,
			Type:                   dimension.Type,
			Families:               append([]string{}, dimension.Families...),
			Support:                dimension.Support,
			HighValue:              dimension.HighValue,
			KnownUnsupportedFields: append([]string{}, dimension.KnownUnsupportedFields...),
			Notes:                  append([]string{}, dimension.Notes...),
			EvidenceTypes:          append([]string{}, dimension.EvidenceTypes...),
			ControlDomains:         append([]string{}, dimension.ControlDomains...),
			ControlRefs:            append([]sourcecdk.CoverageControlRef{}, dimension.ControlRefs...),
		})
	}
	sortScopeOptions(options)
	return options
}

func ScopeOptionsFromKinds(kinds []string) []ScopeOption {
	options := make([]ScopeOption, 0, len(kinds))
	for _, kind := range kinds {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			continue
		}
		options = append(options, ScopeOption{
			ID:       kind,
			Label:    fieldLabel(strings.ReplaceAll(kind, ".", "_")),
			Type:     "emitted_kind",
			Families: []string{kind},
			Support:  sourcecdk.CoverageSupportSupported,
		})
	}
	sort.Slice(options, func(i, j int) bool { return strings.ToLower(options[i].Label) < strings.ToLower(options[j].Label) })
	return options
}

func controlRefsFromDefinition(refs []connectordefinitions.CoverageControlRefSpec) []sourcecdk.CoverageControlRef {
	out := make([]sourcecdk.CoverageControlRef, len(refs))
	for i, ref := range refs {
		out[i] = sourcecdk.CoverageControlRef{FrameworkID: ref.FrameworkID, FrameworkName: ref.FrameworkName, ControlID: ref.ControlID}
	}
	return out
}

func sortScopeOptions(options []ScopeOption) {
	sort.Slice(options, func(i, j int) bool {
		if options[i].HighValue != options[j].HighValue {
			return options[i].HighValue
		}
		return strings.ToLower(options[i].Label) < strings.ToLower(options[j].Label)
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fieldLabel(key string) string {
	words := strings.Fields(strings.ReplaceAll(strings.TrimSpace(key), "_", " "))
	for i, word := range words {
		switch strings.ToLower(word) {
		case "id", "iam", "sso", "api", "arn", "url", "wif", "gcp", "aws":
			words[i] = strings.ToUpper(word)
		default:
			if word != "" {
				words[i] = strings.ToUpper(word[:1]) + word[1:]
			}
		}
	}
	return strings.Join(words, " ")
}
