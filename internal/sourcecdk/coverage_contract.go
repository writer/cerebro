package sourcecdk

import (
	"fmt"
	"sort"
	"strings"
)

const (
	CoverageSupportSupported   = "supported"
	CoverageSupportPartial     = "partial"
	CoverageSupportUnsupported = "unsupported"
	CoverageSupportPlanned     = "planned"
)

// CoverageContract describes the source-backed coverage a connector can claim.
type CoverageContract struct {
	SourceID        string              `json:"source_id" yaml:"source_id"`
	OwnerDomain     string              `json:"owner_domain,omitempty" yaml:"owner_domain"`
	AuthorityDomain string              `json:"authority_domain,omitempty" yaml:"authority_domain"`
	Dimensions      []CoverageDimension `json:"dimensions,omitempty" yaml:"dimensions"`
}

// CoverageDimension is one machine-readable coverage claim or explicit gap.
type CoverageDimension struct {
	ID                     string   `json:"id" yaml:"id"`
	Type                   string   `json:"type" yaml:"type"`
	Title                  string   `json:"title" yaml:"title"`
	Families               []string `json:"families,omitempty" yaml:"families"`
	Support                string   `json:"support" yaml:"support"`
	HighValue              bool     `json:"high_value,omitempty" yaml:"high_value"`
	KnownUnsupportedFields []string `json:"known_unsupported_fields,omitempty" yaml:"known_unsupported_fields"`
	Notes                  []string `json:"notes,omitempty" yaml:"notes"`
}

func NormalizeCoverageContract(sourceID string, contract CoverageContract) (CoverageContract, error) {
	normalized := CoverageContract{
		SourceID:        strings.TrimSpace(contract.SourceID),
		OwnerDomain:     strings.TrimSpace(contract.OwnerDomain),
		AuthorityDomain: strings.TrimSpace(contract.AuthorityDomain),
	}
	sourceID = strings.TrimSpace(sourceID)
	if normalized.SourceID == "" {
		normalized.SourceID = sourceID
	}
	if normalized.SourceID == "" {
		return CoverageContract{}, fmt.Errorf("coverage_contract source_id is required")
	}
	if sourceID != "" && normalized.SourceID != sourceID {
		return CoverageContract{}, fmt.Errorf("coverage_contract source_id %q does not match catalog %q", normalized.SourceID, sourceID)
	}
	seen := map[string]struct{}{}
	for _, dimension := range contract.Dimensions {
		next, err := normalizeCoverageDimension(dimension)
		if err != nil {
			return CoverageContract{}, err
		}
		if _, ok := seen[next.ID]; ok {
			return CoverageContract{}, fmt.Errorf("duplicate coverage_contract dimension %q", next.ID)
		}
		seen[next.ID] = struct{}{}
		normalized.Dimensions = append(normalized.Dimensions, next)
	}
	sort.Slice(normalized.Dimensions, func(i int, j int) bool {
		if normalized.Dimensions[i].Type != normalized.Dimensions[j].Type {
			return normalized.Dimensions[i].Type < normalized.Dimensions[j].Type
		}
		return normalized.Dimensions[i].ID < normalized.Dimensions[j].ID
	})
	return normalized, nil
}

func normalizeCoverageDimension(dimension CoverageDimension) (CoverageDimension, error) {
	normalized := CoverageDimension{
		ID:                     strings.TrimSpace(dimension.ID),
		Type:                   strings.TrimSpace(dimension.Type),
		Title:                  strings.TrimSpace(dimension.Title),
		Families:               uniqueTrimmedStrings(dimension.Families),
		Support:                strings.ToLower(strings.TrimSpace(dimension.Support)),
		HighValue:              dimension.HighValue,
		KnownUnsupportedFields: uniqueTrimmedStrings(dimension.KnownUnsupportedFields),
		Notes:                  uniqueTrimmedStrings(dimension.Notes),
	}
	if normalized.ID == "" {
		return CoverageDimension{}, fmt.Errorf("coverage_contract dimension id is required")
	}
	if !validIdentifierPart(normalized.ID) {
		return CoverageDimension{}, fmt.Errorf("coverage_contract dimension id %q must use lowercase identifier syntax", normalized.ID)
	}
	switch normalized.Type {
	case "app_entitlement", "audit_event", "entity_family", "incremental_sync", "lifecycle_state", "relationship", "remediation_state":
	default:
		return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q has invalid type %q", normalized.ID, dimension.Type)
	}
	if normalized.Title == "" {
		return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q title is required", normalized.ID)
	}
	switch normalized.Support {
	case CoverageSupportSupported, CoverageSupportPartial, CoverageSupportUnsupported, CoverageSupportPlanned:
	default:
		return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q has invalid support %q", normalized.ID, dimension.Support)
	}
	for _, family := range normalized.Families {
		if !validIdentifierPart(family) {
			return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q family %q must use lowercase identifier syntax", normalized.ID, family)
		}
	}
	return normalized, nil
}

func cloneCoverageContract(contract CoverageContract) CoverageContract {
	cloned := CoverageContract{
		SourceID:        contract.SourceID,
		OwnerDomain:     contract.OwnerDomain,
		AuthorityDomain: contract.AuthorityDomain,
		Dimensions:      make([]CoverageDimension, len(contract.Dimensions)),
	}
	for i, dimension := range contract.Dimensions {
		cloned.Dimensions[i] = CoverageDimension{
			ID:                     dimension.ID,
			Type:                   dimension.Type,
			Title:                  dimension.Title,
			Families:               append([]string(nil), dimension.Families...),
			Support:                dimension.Support,
			HighValue:              dimension.HighValue,
			KnownUnsupportedFields: append([]string(nil), dimension.KnownUnsupportedFields...),
			Notes:                  append([]string(nil), dimension.Notes...),
		}
	}
	return cloned
}
