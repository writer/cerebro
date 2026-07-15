package assurancereliability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
)

var ErrInvalidReliabilityInput = errors.New("invalid assurance reliability input")

const ConcentrationReportVersion = "assurance-concentration/v1"

type FailureDomainKind string

const (
	FailureDomainProvider   FailureDomainKind = "provider"
	FailureDomainSource     FailureDomainKind = "source"
	FailureDomainCredential FailureDomainKind = "credential"
	FailureDomainCollector  FailureDomainKind = "collector"
	FailureDomainReviewer   FailureDomainKind = "reviewer"
	FailureDomainArtifact   FailureDomainKind = "artifact"
)

type FailureDomainRef struct {
	Kind FailureDomainKind `json:"kind"`
	ID   string            `json:"id"`
}

type AssuranceUnit struct {
	TenantID       string                                 `json:"tenant_id"`
	ObligationID   string                                 `json:"obligation_id"`
	Decision       complianceassessment.QualifiedDecision `json:"decision"`
	CoverageUnits  uint64                                 `json:"coverage_units"`
	SourceIDs      []string                               `json:"source_ids"`
	ProviderIDs    []string                               `json:"provider_ids"`
	Control        compliance.ControlRef                  `json:"control_ref"`
	OwnerID        string                                 `json:"owner_id"`
	FailureDomains []FailureDomainRef                     `json:"failure_domains"`
}

type ConcentrationDimension string

const (
	ConcentrationSource        ConcentrationDimension = "source"
	ConcentrationProvider      ConcentrationDimension = "provider"
	ConcentrationControl       ConcentrationDimension = "control"
	ConcentrationOwner         ConcentrationDimension = "owner"
	ConcentrationFailureDomain ConcentrationDimension = "failure_domain"
)

type ConcentrationEntry struct {
	Dimension          ConcentrationDimension `json:"dimension"`
	Key                string                 `json:"key"`
	QualifiedUnits     uint64                 `json:"qualified_units"`
	DependencyShareBPS uint64                 `json:"dependency_share_bps"`
}

type CorrelatedFailureExposure struct {
	FailureDomain        FailureDomainRef `json:"failure_domain"`
	QualifiedUnitsAtRisk uint64           `json:"qualified_units_at_risk"`
	ShareBPS             uint64           `json:"share_bps"`
}

type CoverageReliability struct {
	ApplicableUnits            uint64 `json:"applicable_units"`
	NominalQualifiedUnits      uint64 `json:"nominal_qualified_units"`
	EffectiveIndependentUnits  uint64 `json:"effective_independent_units"`
	NominalCoverageBPS         uint64 `json:"nominal_coverage_bps"`
	EffectiveCoverageBPS       uint64 `json:"effective_coverage_bps"`
	LargestCorrelatedLossUnits uint64 `json:"largest_correlated_loss_units"`
	LargestCorrelatedLossBPS   uint64 `json:"largest_correlated_loss_bps"`
}

type ConcentrationReport struct {
	Version             string                      `json:"version"`
	TenantID            string                      `json:"tenant_id"`
	Coverage            CoverageReliability         `json:"coverage"`
	Concentrations      []ConcentrationEntry        `json:"concentrations"`
	CorrelatedExposures []CorrelatedFailureExposure `json:"correlated_exposures"`
	ReportDigest        string                      `json:"report_digest"`
}

// AnalyzeConcentration reports nominal qualified coverage and the coverage
// that survives the largest single correlated failure domain. Only decisions
// that pass the qualified-decision production gate contribute qualified units.
func AnalyzeConcentration(tenantID string, units []AssuranceUnit) (ConcentrationReport, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || len(units) == 0 {
		return ConcentrationReport{}, fmt.Errorf("%w: tenant and assurance units are required", ErrInvalidReliabilityInput)
	}
	units = append([]AssuranceUnit(nil), units...)
	sort.Slice(units, func(i, j int) bool {
		return strings.TrimSpace(units[i].ObligationID) < strings.TrimSpace(units[j].ObligationID)
	})
	report := ConcentrationReport{Version: ConcentrationReportVersion, TenantID: tenantID}
	concentrations := map[ConcentrationDimension]map[string]uint64{}
	failureLoss := map[string]uint64{}
	failureRefs := map[string]FailureDomainRef{}
	seen := map[string]struct{}{}
	for index := range units {
		unit := normalizeAssuranceUnit(units[index])
		if err := validateAssuranceUnit(tenantID, unit); err != nil {
			return ConcentrationReport{}, fmt.Errorf("%w: units[%d]: %w", ErrInvalidReliabilityInput, index, err)
		}
		if _, ok := seen[unit.ObligationID]; ok {
			return ConcentrationReport{}, fmt.Errorf("%w: duplicate obligation %q", ErrInvalidReliabilityInput, unit.ObligationID)
		}
		seen[unit.ObligationID] = struct{}{}
		var err error
		report.Coverage.ApplicableUnits, err = checkedAdd(report.Coverage.ApplicableUnits, unit.CoverageUnits)
		if err != nil {
			return ConcentrationReport{}, err
		}
		if unit.Decision.AuthorizeProductionUse() != nil {
			continue
		}
		report.Coverage.NominalQualifiedUnits, err = checkedAdd(report.Coverage.NominalQualifiedUnits, unit.CoverageUnits)
		if err != nil {
			return ConcentrationReport{}, err
		}
		controlKey := compliance.ControlKey(unit.Control)
		for _, key := range unit.SourceIDs {
			if err := addConcentration(concentrations, ConcentrationSource, key, unit.CoverageUnits); err != nil {
				return ConcentrationReport{}, err
			}
		}
		for _, key := range unit.ProviderIDs {
			if err := addConcentration(concentrations, ConcentrationProvider, key, unit.CoverageUnits); err != nil {
				return ConcentrationReport{}, err
			}
		}
		if err := addConcentration(concentrations, ConcentrationControl, controlKey, unit.CoverageUnits); err != nil {
			return ConcentrationReport{}, err
		}
		if err := addConcentration(concentrations, ConcentrationOwner, unit.OwnerID, unit.CoverageUnits); err != nil {
			return ConcentrationReport{}, err
		}
		for _, domain := range unit.FailureDomains {
			key := failureDomainKey(domain)
			if err := addConcentration(concentrations, ConcentrationFailureDomain, key, unit.CoverageUnits); err != nil {
				return ConcentrationReport{}, err
			}
			failureLoss[key], err = checkedAdd(failureLoss[key], unit.CoverageUnits)
			if err != nil {
				return ConcentrationReport{}, err
			}
			failureRefs[key] = domain
		}
	}

	report.Coverage.NominalCoverageBPS = basisPoints(report.Coverage.NominalQualifiedUnits, report.Coverage.ApplicableUnits)
	for key, loss := range failureLoss {
		if loss > report.Coverage.LargestCorrelatedLossUnits {
			report.Coverage.LargestCorrelatedLossUnits = loss
		}
		report.CorrelatedExposures = append(report.CorrelatedExposures, CorrelatedFailureExposure{
			FailureDomain: failureRefs[key], QualifiedUnitsAtRisk: loss, ShareBPS: basisPoints(loss, report.Coverage.NominalQualifiedUnits),
		})
	}
	if report.Coverage.NominalQualifiedUnits >= report.Coverage.LargestCorrelatedLossUnits {
		report.Coverage.EffectiveIndependentUnits = report.Coverage.NominalQualifiedUnits - report.Coverage.LargestCorrelatedLossUnits
	}
	report.Coverage.EffectiveCoverageBPS = basisPoints(report.Coverage.EffectiveIndependentUnits, report.Coverage.ApplicableUnits)
	report.Coverage.LargestCorrelatedLossBPS = basisPoints(report.Coverage.LargestCorrelatedLossUnits, report.Coverage.NominalQualifiedUnits)
	report.Concentrations = flattenConcentrations(concentrations, report.Coverage.NominalQualifiedUnits)
	sort.Slice(report.CorrelatedExposures, func(i, j int) bool {
		left, right := report.CorrelatedExposures[i], report.CorrelatedExposures[j]
		if left.QualifiedUnitsAtRisk != right.QualifiedUnitsAtRisk {
			return left.QualifiedUnitsAtRisk > right.QualifiedUnitsAtRisk
		}
		return failureDomainKey(left.FailureDomain) < failureDomainKey(right.FailureDomain)
	})
	digest, err := deterministicDigest(report)
	if err != nil {
		return ConcentrationReport{}, err
	}
	report.ReportDigest = digest
	return report, nil
}

func normalizeAssuranceUnit(unit AssuranceUnit) AssuranceUnit {
	unit.TenantID = strings.TrimSpace(unit.TenantID)
	unit.ObligationID = strings.TrimSpace(unit.ObligationID)
	unit.OwnerID = strings.TrimSpace(unit.OwnerID)
	unit.Control = compliance.NormalizeControlRef(unit.Control)
	unit.SourceIDs = normalizedStrings(unit.SourceIDs)
	unit.ProviderIDs = normalizedStrings(unit.ProviderIDs)
	unit.FailureDomains = append([]FailureDomainRef(nil), unit.FailureDomains...)
	for index := range unit.FailureDomains {
		unit.FailureDomains[index].Kind = FailureDomainKind(strings.TrimSpace(string(unit.FailureDomains[index].Kind)))
		unit.FailureDomains[index].ID = strings.TrimSpace(unit.FailureDomains[index].ID)
	}
	sort.Slice(unit.FailureDomains, func(i, j int) bool {
		return failureDomainKey(unit.FailureDomains[i]) < failureDomainKey(unit.FailureDomains[j])
	})
	unit.FailureDomains = deduplicateFailureDomains(unit.FailureDomains)
	return unit
}

func validateAssuranceUnit(tenantID string, unit AssuranceUnit) error {
	if unit.TenantID != tenantID {
		return errors.New("tenant does not match report tenant")
	}
	if unit.ObligationID == "" || unit.CoverageUnits == 0 || unit.OwnerID == "" || strings.TrimSpace(unit.Control.ControlID) == "" {
		return errors.New("obligation, coverage units, control, and owner are required")
	}
	if unit.Decision.AuthorizeProductionUse() == nil && (len(unit.SourceIDs) == 0 || len(unit.ProviderIDs) == 0 || len(unit.FailureDomains) == 0) {
		return errors.New("qualified assurance requires source, provider, and failure-domain dependencies")
	}
	for _, domain := range unit.FailureDomains {
		if !knownFailureDomainKind(domain.Kind) || domain.ID == "" {
			return errors.New("failure-domain kind and id are required")
		}
	}
	return nil
}

func addConcentration(values map[ConcentrationDimension]map[string]uint64, dimension ConcentrationDimension, key string, units uint64) error {
	if values[dimension] == nil {
		values[dimension] = map[string]uint64{}
	}
	value, err := checkedAdd(values[dimension][key], units)
	if err != nil {
		return err
	}
	values[dimension][key] = value
	return nil
}

func flattenConcentrations(values map[ConcentrationDimension]map[string]uint64, total uint64) []ConcentrationEntry {
	var result []ConcentrationEntry
	for dimension, entries := range values {
		for key, units := range entries {
			result = append(result, ConcentrationEntry{Dimension: dimension, Key: key, QualifiedUnits: units, DependencyShareBPS: basisPoints(units, total)})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Dimension != result[j].Dimension {
			return result[i].Dimension < result[j].Dimension
		}
		if result[i].QualifiedUnits != result[j].QualifiedUnits {
			return result[i].QualifiedUnits > result[j].QualifiedUnits
		}
		return result[i].Key < result[j].Key
	})
	return result
}

func failureDomainKey(value FailureDomainRef) string { return string(value.Kind) + "/" + value.ID }

func knownFailureDomainKind(value FailureDomainKind) bool {
	switch value {
	case FailureDomainProvider, FailureDomainSource, FailureDomainCredential, FailureDomainCollector, FailureDomainReviewer, FailureDomainArtifact:
		return true
	default:
		return false
	}
}

func deduplicateFailureDomains(values []FailureDomainRef) []FailureDomainRef {
	result := make([]FailureDomainRef, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && failureDomainKey(result[len(result)-1]) == failureDomainKey(value) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func normalizedStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func checkedAdd(left, right uint64) (uint64, error) {
	result, carry := bits.Add64(left, right, 0)
	if carry != 0 {
		return 0, fmt.Errorf("%w: assurance units overflow", ErrInvalidReliabilityInput)
	}
	return result, nil
}

func basisPoints(part, total uint64) uint64 {
	if part == 0 || total == 0 {
		return 0
	}
	high, low := bits.Mul64(part, 10_000)
	quotient, _ := bits.Div64(high, low, total)
	return quotient
}

func deterministicDigest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
