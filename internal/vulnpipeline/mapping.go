package vulnpipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

// Mapping target fields. Every generic mapping and every inference report is
// expressed in these names.
const (
	FieldSourceRecordID   = "source_record_id"
	FieldTitle            = "title"
	FieldDescription      = "description"
	FieldVulnerabilityIDs = "vulnerability_ids"
	FieldCWEs             = "cwes"
	FieldSeverity         = "severity"
	FieldCVSSScore        = "cvss_score"
	FieldCVSSVector       = "cvss_vector"
	FieldStatus           = "status"
	FieldClass            = "class"
	FieldAssetType        = "asset_type"
	FieldAssetIdentifier  = "asset_identifier"
	FieldAssetName        = "asset_name"
	FieldImageDigest      = "image_digest"
	FieldPackageEcosystem = "package_ecosystem"
	FieldPackageName      = "package_name"
	FieldPackageVersion   = "package_version"
	FieldFixedVersion     = "fixed_version"
	FieldPackageURL       = "package_url"
	FieldLocation         = "location"
	FieldReferences       = "references"
	FieldScanner          = "scanner"
	FieldFirstSeenAt      = "first_seen_at"
	FieldLastSeenAt       = "last_seen_at"
	FieldObservedAt       = "observed_at"
)

const maxMappingBytes = 64 * 1024

var (
	// ErrInvalidMapping reports a mapping that cannot be applied.
	ErrInvalidMapping = errors.New("invalid vulnerability mapping")

	listFields = map[string]bool{FieldVulnerabilityIDs: true, FieldCWEs: true, FieldReferences: true}
)

// MappingFields returns every target field a mapping may populate.
func MappingFields() []string {
	return []string{
		FieldSourceRecordID, FieldTitle, FieldDescription, FieldVulnerabilityIDs, FieldCWEs,
		FieldSeverity, FieldCVSSScore, FieldCVSSVector, FieldStatus, FieldClass,
		FieldAssetType, FieldAssetIdentifier, FieldAssetName, FieldImageDigest,
		FieldPackageEcosystem, FieldPackageName, FieldPackageVersion, FieldFixedVersion, FieldPackageURL,
		FieldLocation, FieldReferences, FieldScanner, FieldFirstSeenAt, FieldLastSeenAt, FieldObservedAt,
	}
}

func knownField(name string) bool {
	for _, field := range MappingFields() {
		if field == name {
			return true
		}
	}
	return false
}

// FieldRule lists candidate source paths for one target field. Scalar fields
// take the first non-empty value; list fields collect every value.
type FieldRule struct {
	Paths []string `json:"paths"`
}

// Mapping is the declarative, versioned translation from one source's native
// record shape into a normalized observation. Mappings are data, so learned
// mappings can be reviewed, edited, and replayed without code changes.
type Mapping struct {
	RecordsPath    string               `json:"records_path,omitempty"`
	Fields         map[string]FieldRule `json:"fields"`
	SeverityScale  string               `json:"severity_scale,omitempty"`
	SeverityValues map[string]string    `json:"severity_values,omitempty"`
	StatusValues   map[string]string    `json:"status_values,omitempty"`
	Defaults       map[string]string    `json:"defaults,omitempty"`
}

// ParseMapping decodes and validates a mapping document.
func ParseMapping(raw string) (*Mapping, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: mapping is empty", ErrInvalidMapping)
	}
	if len(raw) > maxMappingBytes {
		return nil, fmt.Errorf("%w: mapping exceeds %d bytes", ErrInvalidMapping, maxMappingBytes)
	}
	var mapping Mapping
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&mapping); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMapping, err)
	}
	if err := mapping.Validate(); err != nil {
		return nil, err
	}
	return &mapping, nil
}

// Validate checks paths, target names, and value maps.
func (m *Mapping) Validate() error {
	if m == nil {
		return fmt.Errorf("%w: mapping is required", ErrInvalidMapping)
	}
	if _, err := parsePath(m.RecordsPath); err != nil {
		return fmt.Errorf("%w: records_path: %w", ErrInvalidMapping, err)
	}
	if len(m.Fields) == 0 {
		return fmt.Errorf("%w: at least one field is required", ErrInvalidMapping)
	}
	for name, rule := range m.Fields {
		if !knownField(name) {
			return fmt.Errorf("%w: unknown field %q", ErrInvalidMapping, name)
		}
		if len(rule.Paths) == 0 || len(rule.Paths) > 8 {
			return fmt.Errorf("%w: field %q needs between 1 and 8 paths", ErrInvalidMapping, name)
		}
		for _, path := range rule.Paths {
			if strings.TrimSpace(path) == "" {
				return fmt.Errorf("%w: field %q has an empty path", ErrInvalidMapping, name)
			}
			if _, err := parsePath(path); err != nil {
				return fmt.Errorf("%w: field %q: %w", ErrInvalidMapping, name, err)
			}
		}
	}
	if _, hasTitle := m.Fields[FieldTitle]; !hasTitle {
		if _, hasIDs := m.Fields[FieldVulnerabilityIDs]; !hasIDs {
			return fmt.Errorf("%w: map title or vulnerability_ids", ErrInvalidMapping)
		}
	}
	switch m.SeverityScale {
	case "", SeverityScaleCVSS, SeverityScaleZeroFour, SeverityScaleOneFive, SeverityScaleLabelOnly:
	default:
		return fmt.Errorf("%w: unknown severity_scale %q", ErrInvalidMapping, m.SeverityScale)
	}
	for raw, severity := range m.SeverityValues {
		if strings.TrimSpace(raw) == "" || !validSeverity(severity) {
			return fmt.Errorf("%w: severity_values entry %q -> %q is invalid", ErrInvalidMapping, raw, severity)
		}
	}
	for raw, status := range m.StatusValues {
		if strings.TrimSpace(raw) == "" || !validStatus(status) {
			return fmt.Errorf("%w: status_values entry %q -> %q is invalid", ErrInvalidMapping, raw, status)
		}
	}
	for name := range m.Defaults {
		if !knownField(name) || listFields[name] {
			return fmt.Errorf("%w: defaults entry %q is not a scalar field", ErrInvalidMapping, name)
		}
	}
	if class, ok := m.Defaults[FieldClass]; ok && !validClass(class) {
		return fmt.Errorf("%w: default class %q is invalid", ErrInvalidMapping, class)
	}
	return nil
}

// JSON renders the mapping with stable key order.
func (m *Mapping) JSON() string {
	if m == nil {
		return ""
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(payload)
}

// records selects the record list a mapping applies to.
func (m *Mapping) records(document any) []any {
	segments, err := parsePath(m.RecordsPath)
	if err != nil {
		return nil
	}
	values := resolvePath(document, segments)
	out := []any{}
	for _, value := range values {
		if list, ok := value.([]any); ok {
			out = append(out, list...)
			continue
		}
		out = append(out, value)
	}
	return out
}

// apply translates every record in a decoded document into a draft
// observation. Drafts are finalized and validated by the pipeline.
func (m *Mapping) apply(document any) []Draft {
	records := m.records(document)
	drafts := make([]Draft, 0, len(records))
	for _, record := range records {
		if _, ok := record.(map[string]any); !ok {
			drafts = append(drafts, Draft{Raw: record, Problem: "record is not a JSON object"})
			continue
		}
		drafts = append(drafts, m.applyRecord(record))
	}
	return drafts
}

func (m *Mapping) applyRecord(record any) Draft {
	values := map[string][]string{}
	for name, rule := range m.Fields {
		for _, path := range rule.Paths {
			found := resolveStrings(record, path)
			if len(found) == 0 {
				continue
			}
			if listFields[name] {
				values[name] = append(values[name], found...)
				continue
			}
			values[name] = []string{strings.TrimSpace(found[0])}
			break
		}
	}
	for name, fallback := range m.Defaults {
		if len(values[name]) == 0 && strings.TrimSpace(fallback) != "" {
			values[name] = []string{fallback}
		}
	}
	draft := draftFromValues(values)
	draft.Raw = record
	draft.SeverityScale = m.SeverityScale
	draft.SeverityValues = m.SeverityValues
	draft.StatusValues = m.StatusValues
	return draft
}

// Draft is a partially normalized observation plus the source record it came
// from. Builtin format adapters and generic mappings both produce drafts.
type Draft struct {
	Observation    ports.VulnerabilityObservation
	RawSeverity    string
	RawStatus      string
	RawFirstSeen   string
	RawLastSeen    string
	RawObservedAt  string
	SeverityScale  string
	SeverityValues map[string]string
	StatusValues   map[string]string
	Raw            any
	Problem        string
}

func first(values map[string][]string, name string) string {
	if list := values[name]; len(list) > 0 {
		return strings.TrimSpace(list[0])
	}
	return ""
}

func draftFromValues(values map[string][]string) Draft {
	obs := ports.VulnerabilityObservation{
		SourceRecordID: first(values, FieldSourceRecordID),
		VulnerabilityDetails: ports.VulnerabilityDetails{
			Title:            first(values, FieldTitle),
			Description:      first(values, FieldDescription),
			Class:            strings.ToLower(first(values, FieldClass)),
			VulnerabilityIDs: values[FieldVulnerabilityIDs],
			CWEs:             values[FieldCWEs],
			CVSSVector:       first(values, FieldCVSSVector),
		},
		VulnerabilityAsset: ports.VulnerabilityAsset{
			AssetType:       first(values, FieldAssetType),
			AssetIdentifier: first(values, FieldAssetIdentifier),
			AssetName:       first(values, FieldAssetName),
			ImageDigest:     first(values, FieldImageDigest),
		},
		VulnerabilityPackage: ports.VulnerabilityPackage{
			PackageEcosystem: first(values, FieldPackageEcosystem),
			PackageName:      first(values, FieldPackageName),
			PackageVersion:   first(values, FieldPackageVersion),
			FixedVersion:     first(values, FieldFixedVersion),
			PackageURL:       first(values, FieldPackageURL),
		},
		Location:   first(values, FieldLocation),
		References: values[FieldReferences],
		Scanner:    first(values, FieldScanner),
	}
	if score, err := strconv.ParseFloat(first(values, FieldCVSSScore), 64); err == nil && score >= 0 && score <= 10 {
		obs.CVSSScore = &score
	}
	return Draft{
		Observation:   obs,
		RawSeverity:   first(values, FieldSeverity),
		RawStatus:     first(values, FieldStatus),
		RawFirstSeen:  first(values, FieldFirstSeenAt),
		RawLastSeen:   first(values, FieldLastSeenAt),
		RawObservedAt: first(values, FieldObservedAt),
	}
}
