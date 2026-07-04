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
	ID                     string               `json:"id" yaml:"id"`
	Type                   string               `json:"type" yaml:"type"`
	Title                  string               `json:"title" yaml:"title"`
	Families               []string             `json:"families,omitempty" yaml:"families"`
	RuntimeFamilies        []string             `json:"runtime_families,omitempty" yaml:"runtime_families"`
	Support                string               `json:"support" yaml:"support"`
	HighValue              bool                 `json:"high_value,omitempty" yaml:"high_value"`
	KnownUnsupportedFields []string             `json:"known_unsupported_fields,omitempty" yaml:"known_unsupported_fields"`
	Notes                  []string             `json:"notes,omitempty" yaml:"notes"`
	EvidenceTypes          []string             `json:"evidence_types,omitempty" yaml:"evidence_types"`
	ControlDomains         []string             `json:"control_domains,omitempty" yaml:"control_domains"`
	ControlRefs            []CoverageControlRef `json:"control_refs,omitempty" yaml:"control_refs"`
}

// CoverageControlRef connects a source coverage dimension to an auditor-facing
// control identity without coupling source catalogs to the compliance package.
type CoverageControlRef struct {
	FrameworkID   string `json:"framework_id,omitempty" yaml:"framework_id,omitempty"`
	FrameworkName string `json:"framework_name,omitempty" yaml:"framework_name,omitempty"`
	ControlID     string `json:"control_id" yaml:"control_id"`
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
		RuntimeFamilies:        uniqueTrimmedStrings(dimension.RuntimeFamilies),
		Support:                strings.ToLower(strings.TrimSpace(dimension.Support)),
		HighValue:              dimension.HighValue,
		KnownUnsupportedFields: uniqueTrimmedStrings(dimension.KnownUnsupportedFields),
		Notes:                  uniqueTrimmedStrings(dimension.Notes),
		EvidenceTypes:          uniqueTrimmedStrings(dimension.EvidenceTypes),
		ControlDomains:         uniqueTrimmedStrings(dimension.ControlDomains),
		ControlRefs:            normalizeCoverageControlRefs(dimension.ControlRefs),
	}
	if len(normalized.EvidenceTypes) == 0 {
		normalized.EvidenceTypes = defaultCoverageEvidenceTypes(normalized.Type)
	}
	if len(normalized.ControlDomains) == 0 {
		normalized.ControlDomains = defaultCoverageControlDomains(normalized.Type)
	}
	if normalized.ID == "" {
		return CoverageDimension{}, fmt.Errorf("coverage_contract dimension id is required")
	}
	if !validIdentifierPart(normalized.ID) {
		return CoverageDimension{}, fmt.Errorf("coverage_contract dimension id %q must use lowercase identifier syntax", normalized.ID)
	}
	switch normalized.Type {
	case "alert_state", "app_entitlement", "audit_event", "deployment_state", "entity_family", "incremental_sync", "lifecycle_state", "relationship", "remediation_state":
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
	for _, family := range normalized.RuntimeFamilies {
		if !validIdentifierPart(family) {
			return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q runtime_family %q must use lowercase identifier syntax", normalized.ID, family)
		}
	}
	for _, evidenceType := range normalized.EvidenceTypes {
		if !validIdentifierPart(evidenceType) {
			return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q evidence type %q must use lowercase identifier syntax", normalized.ID, evidenceType)
		}
	}
	for _, domain := range normalized.ControlDomains {
		if !validIdentifierPart(domain) {
			return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q control domain %q must use lowercase identifier syntax", normalized.ID, domain)
		}
	}
	for _, ref := range normalized.ControlRefs {
		if ref.ControlID == "" || (ref.FrameworkID == "" && ref.FrameworkName == "") {
			return CoverageDimension{}, fmt.Errorf("coverage_contract dimension %q control_refs require framework_name or framework_id and control_id", normalized.ID)
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
			RuntimeFamilies:        append([]string(nil), dimension.RuntimeFamilies...),
			Support:                dimension.Support,
			HighValue:              dimension.HighValue,
			KnownUnsupportedFields: append([]string(nil), dimension.KnownUnsupportedFields...),
			Notes:                  append([]string(nil), dimension.Notes...),
			EvidenceTypes:          append([]string(nil), dimension.EvidenceTypes...),
			ControlDomains:         append([]string(nil), dimension.ControlDomains...),
			ControlRefs:            cloneCoverageControlRefs(dimension.ControlRefs),
		}
	}
	return cloned
}

func defaultCoverageEvidenceTypes(dimensionType string) []string {
	switch strings.TrimSpace(dimensionType) {
	case "alert_state":
		return []string{"security_monitoring"}
	case "app_entitlement":
		return []string{"identity_configuration"}
	case "audit_event":
		return []string{"logging_configuration"}
	case "deployment_state":
		return []string{"change_management"}
	case "entity_family":
		return []string{"source_snapshot"}
	case "incremental_sync":
		return []string{"source_sync_status"}
	case "lifecycle_state":
		return []string{"configuration_state"}
	case "relationship":
		return []string{"relationship_evidence"}
	case "remediation_state":
		return []string{"remediation_state"}
	default:
		return nil
	}
}

func defaultCoverageControlDomains(dimensionType string) []string {
	switch strings.TrimSpace(dimensionType) {
	case "alert_state":
		return []string{"logging_monitoring", "security_operations"}
	case "app_entitlement":
		return []string{"identity_access"}
	case "audit_event":
		return []string{"logging_monitoring"}
	case "deployment_state":
		return []string{"secure_delivery"}
	case "entity_family":
		return []string{"asset_inventory"}
	case "incremental_sync":
		return []string{"source_operations"}
	case "lifecycle_state":
		return []string{"security_operations"}
	case "relationship":
		return []string{"asset_inventory"}
	case "remediation_state":
		return []string{"remediation"}
	default:
		return nil
	}
}

func normalizeCoverageControlRefs(refs []CoverageControlRef) []CoverageControlRef {
	if len(refs) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]CoverageControlRef, 0, len(refs))
	for _, ref := range refs {
		next := CoverageControlRef{
			FrameworkID:   strings.TrimSpace(ref.FrameworkID),
			FrameworkName: strings.TrimSpace(ref.FrameworkName),
			ControlID:     strings.TrimSpace(ref.ControlID),
		}
		if next.ControlID == "" || (next.FrameworkID == "" && next.FrameworkName == "") {
			normalized = append(normalized, next)
			continue
		}
		key := next.FrameworkID + "\x00" + next.FrameworkName + "\x00" + next.ControlID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, next)
	}
	sort.Slice(normalized, func(i int, j int) bool {
		if normalized[i].FrameworkName != normalized[j].FrameworkName {
			return normalized[i].FrameworkName < normalized[j].FrameworkName
		}
		if normalized[i].FrameworkID != normalized[j].FrameworkID {
			return normalized[i].FrameworkID < normalized[j].FrameworkID
		}
		return normalized[i].ControlID < normalized[j].ControlID
	})
	return normalized
}

func cloneCoverageControlRefs(refs []CoverageControlRef) []CoverageControlRef {
	if len(refs) == 0 {
		return nil
	}
	cloned := make([]CoverageControlRef, len(refs))
	copy(cloned, refs)
	return cloned
}
