package sourcecdk

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var (
	catalogEventContracts    sync.Map
	catalogCoverageContracts sync.Map
)

type catalogFile struct {
	ID             string                 `yaml:"id"`
	Name           string                 `yaml:"name"`
	Description    string                 `yaml:"description"`
	EmittedKinds   []string               `yaml:"emitted_kinds"`
	KindLifecycle  []catalogKindLifecycle `yaml:"kind_lifecycle"`
	Families       []CatalogFamily        `yaml:"families"`
	EventContracts []EventContract        `yaml:"event_contracts"`
	Coverage       CoverageContract       `yaml:"coverage_contract"`
}

type catalogKindLifecycle struct {
	Kind        string `yaml:"kind"`
	Status      string `yaml:"status"`
	Replacement string `yaml:"replacement"`
}

type SourceCatalog struct {
	Spec             *cerebrov1.SourceSpec
	Families         []CatalogFamily
	EventContracts   []EventContract
	CoverageContract *CoverageContract
}

// CatalogFamily declares optional per-family source catalog capabilities.
type CatalogFamily struct {
	ID             string          `yaml:"id"`
	Incremental    string          `yaml:"incremental"`
	FreshnessProbe *FreshnessProbe `yaml:"freshness_probe,omitempty"`
}

// FreshnessProbe declares whether a family supports a cheap change signal and
// how authoritative that signal is for short-circuiting reads.
type FreshnessProbe struct {
	Supported              bool   `yaml:"supported"`
	CanaryKind             string `yaml:"canary_kind"`
	Confidence             string `yaml:"confidence"`
	ReconciliationInterval string `yaml:"reconciliation_interval"`
	MaxSkipDuration        string `yaml:"max_skip_duration"`
	MaxConsecutiveSkips    int    `yaml:"max_consecutive_skips"`
}

// LoadCatalog parses a source catalog.yaml file into a source spec.
func LoadCatalog(data []byte) (*cerebrov1.SourceSpec, error) {
	catalog, err := LoadSourceCatalog(data)
	if err != nil {
		return nil, err
	}
	return catalog.Spec, nil
}

// LoadSourceCatalog parses a source catalog.yaml file, including optional event contracts.
func LoadSourceCatalog(data []byte) (*SourceCatalog, error) {
	var catalog catalogFile
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshal catalog: %w", err)
	}
	catalog.ID = strings.TrimSpace(catalog.ID)
	catalog.Name = strings.TrimSpace(catalog.Name)
	catalog.Description = strings.TrimSpace(catalog.Description)
	if catalog.ID == "" {
		return nil, fmt.Errorf("catalog id is required")
	}
	if catalog.Name == "" {
		return nil, fmt.Errorf("catalog name is required")
	}
	emittedKinds, err := normalizeCatalogKinds(catalog.EmittedKinds)
	if err != nil {
		return nil, err
	}
	if err := validateCatalogLifecycle(catalog.KindLifecycle); err != nil {
		return nil, err
	}
	families, err := normalizeCatalogFamilies(catalog.Families)
	if err != nil {
		return nil, err
	}
	eventContracts, err := ValidateEventContracts(catalog.EventContracts)
	if err != nil {
		return nil, err
	}
	coverageContract, err := NormalizeCoverageContract(catalog.ID, catalog.Coverage)
	if err != nil {
		return nil, err
	}
	registerCatalogEventContracts(catalog.ID, eventContracts)
	registerCatalogCoverageContract(catalog.ID, coverageContract)
	var coverage *CoverageContract
	if len(coverageContract.Dimensions) > 0 {
		cloned := cloneCoverageContract(coverageContract)
		coverage = &cloned
	}
	return &SourceCatalog{Spec: &cerebrov1.SourceSpec{
		Id:           catalog.ID,
		Name:         catalog.Name,
		Description:  catalog.Description,
		EmittedKinds: emittedKinds,
	}, Families: families, EventContracts: eventContracts, CoverageContract: coverage}, nil
}

func registerCatalogEventContracts(sourceID string, contracts []EventContract) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return
	}
	if len(contracts) == 0 {
		catalogEventContracts.Delete(sourceID)
		return
	}
	catalogEventContracts.Store(sourceID, cloneEventContracts(contracts))
}

func catalogEventContractsForSource(sourceID string) []EventContract {
	value, ok := catalogEventContracts.Load(strings.TrimSpace(sourceID))
	if !ok {
		return nil
	}
	contracts, ok := value.([]EventContract)
	if !ok {
		return nil
	}
	return cloneEventContracts(contracts)
}

func registerCatalogCoverageContract(sourceID string, contract CoverageContract) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return
	}
	if len(contract.Dimensions) == 0 {
		catalogCoverageContracts.Delete(sourceID)
		return
	}
	catalogCoverageContracts.Store(sourceID, cloneCoverageContract(contract))
}

func catalogCoverageContractForSource(sourceID string) *CoverageContract {
	value, ok := catalogCoverageContracts.Load(strings.TrimSpace(sourceID))
	if !ok {
		return nil
	}
	contract, ok := value.(CoverageContract)
	if !ok {
		return nil
	}
	cloned := cloneCoverageContract(contract)
	return &cloned
}

func normalizeCatalogKinds(values []string) ([]string, error) {
	kinds := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		kind := strings.TrimSpace(value)
		if kind == "" {
			return nil, fmt.Errorf("emitted kind is required")
		}
		if !validEventKind(kind) {
			return nil, fmt.Errorf("emitted kind %q must use dot-separated lowercase identifiers", kind)
		}
		if _, ok := seen[kind]; ok {
			return nil, fmt.Errorf("duplicate emitted kind %q", kind)
		}
		seen[kind] = struct{}{}
		kinds = append(kinds, kind)
	}
	return kinds, nil
}

func validateCatalogLifecycle(entries []catalogKindLifecycle) error {
	seen := map[string]struct{}{}
	for _, entry := range entries {
		kind := strings.TrimSpace(entry.Kind)
		status := strings.ToLower(strings.TrimSpace(entry.Status))
		if kind == "" {
			return fmt.Errorf("kind_lifecycle kind is required")
		}
		if !validEventKind(kind) {
			return fmt.Errorf("kind_lifecycle kind %q must use dot-separated lowercase identifiers", kind)
		}
		if _, ok := seen[kind]; ok {
			return fmt.Errorf("duplicate kind_lifecycle kind %q", kind)
		}
		seen[kind] = struct{}{}
		switch status {
		case "active", "planned", "deprecated", "retired":
		default:
			return fmt.Errorf("kind_lifecycle kind %q has invalid status %q", kind, entry.Status)
		}
		replacement := strings.TrimSpace(entry.Replacement)
		if replacement != "" && !validEventKind(replacement) {
			return fmt.Errorf("kind_lifecycle kind %q has invalid replacement %q", kind, replacement)
		}
	}
	return nil
}

func normalizeCatalogFamilies(families []CatalogFamily) ([]CatalogFamily, error) {
	if len(families) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	normalized := make([]CatalogFamily, 0, len(families))
	for _, family := range families {
		family.ID = strings.TrimSpace(family.ID)
		family.Incremental = strings.TrimSpace(family.Incremental)
		if family.ID == "" {
			return nil, fmt.Errorf("families id is required")
		}
		if _, ok := seen[family.ID]; ok {
			return nil, fmt.Errorf("duplicate family %q", family.ID)
		}
		seen[family.ID] = struct{}{}
		probe, err := normalizeFreshnessProbe(family.ID, family.FreshnessProbe)
		if err != nil {
			return nil, err
		}
		family.FreshnessProbe = probe
		normalized = append(normalized, family)
	}
	return normalized, nil
}

func normalizeFreshnessProbe(family string, probe *FreshnessProbe) (*FreshnessProbe, error) {
	if probe == nil {
		return nil, nil
	}
	normalized := *probe
	normalized.CanaryKind = strings.TrimSpace(normalized.CanaryKind)
	normalized.Confidence = strings.ToLower(strings.TrimSpace(normalized.Confidence))
	normalized.ReconciliationInterval = strings.TrimSpace(normalized.ReconciliationInterval)
	normalized.MaxSkipDuration = strings.TrimSpace(normalized.MaxSkipDuration)
	if normalized.Supported && normalized.CanaryKind == "" {
		return nil, fmt.Errorf("family %q freshness_probe canary_kind is required when supported", family)
	}
	switch normalized.Confidence {
	case "":
		if normalized.Supported {
			normalized.Confidence = CanaryConfidenceHeuristic
		}
	case CanaryConfidenceAuthoritative, CanaryConfidenceHeuristic:
	default:
		return nil, fmt.Errorf("family %q freshness_probe confidence must be one of authoritative or heuristic", family)
	}
	if normalized.MaxConsecutiveSkips < 0 {
		return nil, fmt.Errorf("family %q freshness_probe max_consecutive_skips must be non-negative", family)
	}
	if err := validateFreshnessProbeDuration(family, "reconciliation_interval", normalized.ReconciliationInterval); err != nil {
		return nil, err
	}
	if err := validateFreshnessProbeDuration(family, "max_skip_duration", normalized.MaxSkipDuration); err != nil {
		return nil, err
	}
	return &normalized, nil
}

func validateFreshnessProbeDuration(family string, field string, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("family %q freshness_probe %s must be a Go duration: %w", family, field, err)
	}
	if duration <= 0 {
		return fmt.Errorf("family %q freshness_probe %s must be greater than zero", family, field)
	}
	return nil
}
