package sourcecdk

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var (
	catalogEventContracts     sync.Map
	catalogCoverageContracts  sync.Map
	catalogLifecycleContracts sync.Map
	catalogProviderAPIs       sync.Map
	catalogCertifications     sync.Map
)

type catalogFile struct {
	ID                  string                     `yaml:"id"`
	Name                string                     `yaml:"name"`
	Description         string                     `yaml:"description"`
	EmittedKinds        []string                   `yaml:"emitted_kinds"`
	KindLifecycle       []KindLifecycle            `yaml:"kind_lifecycle"`
	RuntimeFamilies     []string                   `yaml:"runtime_families"`
	Families            []CatalogFamily            `yaml:"families"`
	ProviderAPI         CatalogProviderAPI         `yaml:"provider_api"`
	ProviderAPIDisproof CatalogProviderAPIDisproof `yaml:"provider_api_disproof"`
	Certification       CatalogCertification       `yaml:"certification"`
	EventContracts      []EventContract            `yaml:"event_contracts"`
	Coverage            CoverageContract           `yaml:"coverage_contract"`
}

type SourceCatalog struct {
	Spec              *cerebrov1.SourceSpec
	RuntimeFamilies   []string
	Families          []CatalogFamily
	ProviderAPI       *CatalogProviderAPI
	EventContracts    []EventContract
	CoverageContract  *CoverageContract
	LifecycleContract *LifecycleContract
	Certification     *CatalogCertification
}

// CatalogFamily declares optional per-family source catalog capabilities.
type CatalogFamily struct {
	ID             string          `yaml:"id"`
	Incremental    string          `yaml:"incremental"`
	FreshnessProbe *FreshnessProbe `yaml:"freshness_probe,omitempty"`
}

// CatalogProviderAPI records the provider-owned API proof declared by a source
// catalog.
type CatalogProviderAPI struct {
	Status        string                     `yaml:"status"`
	Basis         string                     `yaml:"basis"`
	VerifiedAt    string                     `yaml:"verified_at"`
	Transport     string                     `yaml:"transport"`
	Auth          string                     `yaml:"auth"`
	AuthMechanics string                     `yaml:"auth_mechanics"`
	BaseURL       string                     `yaml:"base_url"`
	Endpoint      string                     `yaml:"endpoint"`
	SpecURL       string                     `yaml:"spec_url"`
	SpecKind      string                     `yaml:"spec_kind"`
	References    []string                   `yaml:"references"`
	AuthEvidence  []string                   `yaml:"auth_evidence"`
	ScopeEvidence []string                   `yaml:"scope_evidence"`
	Families      []CatalogProviderAPIFamily `yaml:"families"`
	Disproof      CatalogProviderAPIDisproof `yaml:"-"`
}

// CatalogProviderAPIDisproof records a reviewed provider API invalidation from
// a source catalog when a provider surface cannot cover the runtime families.
type CatalogProviderAPIDisproof struct {
	Status           string   `yaml:"status"`
	Reason           string   `yaml:"reason"`
	CheckedAt        string   `yaml:"checked_at"`
	References       []string `yaml:"references"`
	AffectedFamilies []string `yaml:"affected_families"`
	MissingPaths     []string `yaml:"missing_paths"`
	Notes            []string `yaml:"notes"`
}

// CatalogProviderAPIFamily maps one runtime family to a documented provider API
// path or operation.
type CatalogProviderAPIFamily struct {
	ID        string `yaml:"id"`
	Method    string `yaml:"method"`
	Path      string `yaml:"path"`
	Operation string `yaml:"operation"`
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
	lifecycleContract, err := normalizeLifecycleContract(catalog.ID, emittedKinds, catalog.KindLifecycle)
	if err != nil {
		return nil, err
	}
	families, err := normalizeCatalogFamilies(catalog.Families)
	if err != nil {
		return nil, err
	}
	runtimeFamilies := normalizeCatalogRuntimeFamilies(catalog.RuntimeFamilies, families)
	providerAPI := normalizeCatalogProviderAPI(catalog.ProviderAPI)
	providerAPIDisproof := normalizeCatalogProviderAPIDisproof(catalog.ProviderAPIDisproof)
	certification, err := normalizeCatalogCertification(catalog.Certification)
	if err != nil {
		return nil, err
	}
	if providerAPI == nil && providerAPIDisproof != nil {
		providerAPI = &CatalogProviderAPI{}
	}
	if providerAPI != nil && providerAPIDisproof != nil {
		providerAPI.Disproof = *providerAPIDisproof
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
	registerCatalogLifecycleContract(catalog.ID, lifecycleContract)
	registerCatalogProviderAPI(catalog.ID, providerAPI, runtimeFamilies)
	registerCatalogCertification(catalog.ID, certification)
	var coverage *CoverageContract
	if len(coverageContract.Dimensions) > 0 {
		cloned := cloneCoverageContract(coverageContract)
		coverage = &cloned
	}
	var lifecycle *LifecycleContract
	if len(lifecycleContract.Kinds) > 0 {
		cloned := cloneLifecycleContract(lifecycleContract)
		lifecycle = &cloned
	}
	var api *CatalogProviderAPI
	if providerAPI != nil {
		cloned := cloneCatalogProviderAPI(*providerAPI)
		api = &cloned
	}
	return &SourceCatalog{Spec: &cerebrov1.SourceSpec{
		Id:           catalog.ID,
		Name:         catalog.Name,
		Description:  catalog.Description,
		EmittedKinds: emittedKinds,
	}, RuntimeFamilies: runtimeFamilies, Families: families, ProviderAPI: api, EventContracts: eventContracts, CoverageContract: coverage, LifecycleContract: lifecycle, Certification: cloneCatalogCertificationPtr(certification)}, nil
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

func registerCatalogLifecycleContract(sourceID string, contract LifecycleContract) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return
	}
	if len(contract.Kinds) == 0 {
		catalogLifecycleContracts.Delete(sourceID)
		return
	}
	catalogLifecycleContracts.Store(sourceID, cloneLifecycleContract(contract))
}

func catalogLifecycleContractForSource(sourceID string) *LifecycleContract {
	value, ok := catalogLifecycleContracts.Load(strings.TrimSpace(sourceID))
	if !ok {
		return nil
	}
	contract, ok := value.(LifecycleContract)
	if !ok {
		return nil
	}
	cloned := cloneLifecycleContract(contract)
	return &cloned
}

type catalogProviderAPIRegistration struct {
	API             CatalogProviderAPI
	RuntimeFamilies []string
}

func registerCatalogProviderAPI(sourceID string, api *CatalogProviderAPI, runtimeFamilies []string) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return
	}
	if api == nil {
		catalogProviderAPIs.Delete(sourceID)
		return
	}
	catalogProviderAPIs.Store(sourceID, catalogProviderAPIRegistration{
		API:             cloneCatalogProviderAPI(*api),
		RuntimeFamilies: append([]string(nil), runtimeFamilies...),
	})
}

// CatalogProviderAPIForSource returns embedded source-catalog provider API proof.
func CatalogProviderAPIForSource(sourceID string) (CatalogProviderAPI, []string, bool) {
	value, ok := catalogProviderAPIs.Load(strings.TrimSpace(sourceID))
	if !ok {
		return CatalogProviderAPI{}, nil, false
	}
	registration, ok := value.(catalogProviderAPIRegistration)
	if !ok {
		return CatalogProviderAPI{}, nil, false
	}
	return cloneCatalogProviderAPI(registration.API), append([]string(nil), registration.RuntimeFamilies...), true
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

func normalizeCatalogRuntimeFamilies(runtimeFamilies []string, families []CatalogFamily) []string {
	values := runtimeFamilies
	if len(values) == 0 {
		values = make([]string, 0, len(families))
		for _, family := range families {
			values = append(values, family.ID)
		}
	}
	return normalizeCatalogStringList(values)
}

func normalizeCatalogProviderAPI(api CatalogProviderAPI) *CatalogProviderAPI {
	api.Status = strings.TrimSpace(api.Status)
	api.Basis = strings.TrimSpace(api.Basis)
	api.VerifiedAt = strings.TrimSpace(api.VerifiedAt)
	api.Transport = strings.TrimSpace(api.Transport)
	api.Auth = strings.TrimSpace(api.Auth)
	api.AuthMechanics = strings.TrimSpace(api.AuthMechanics)
	api.BaseURL = strings.TrimSpace(api.BaseURL)
	api.Endpoint = strings.TrimSpace(api.Endpoint)
	api.SpecURL = strings.TrimSpace(api.SpecURL)
	api.SpecKind = strings.TrimSpace(api.SpecKind)
	api.References = normalizeCatalogStringList(api.References)
	api.AuthEvidence = normalizeCatalogStringList(api.AuthEvidence)
	api.ScopeEvidence = normalizeCatalogStringList(api.ScopeEvidence)
	families := make([]CatalogProviderAPIFamily, 0, len(api.Families))
	seen := map[string]struct{}{}
	for _, family := range api.Families {
		family.ID = strings.TrimSpace(family.ID)
		family.Method = strings.ToUpper(strings.TrimSpace(family.Method))
		family.Path = strings.TrimSpace(family.Path)
		family.Operation = strings.TrimSpace(family.Operation)
		if family.ID == "" {
			continue
		}
		key := family.ID + "\x00" + family.Method + "\x00" + family.Path + "\x00" + family.Operation
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		families = append(families, family)
	}
	sort.SliceStable(families, func(i int, j int) bool {
		if families[i].ID != families[j].ID {
			return families[i].ID < families[j].ID
		}
		if families[i].Method != families[j].Method {
			return families[i].Method < families[j].Method
		}
		if families[i].Path != families[j].Path {
			return families[i].Path < families[j].Path
		}
		return families[i].Operation < families[j].Operation
	})
	api.Families = families
	if catalogProviderAPIEmpty(api) {
		return nil
	}
	return &api
}

func catalogProviderAPIEmpty(api CatalogProviderAPI) bool {
	return api.Status == "" &&
		api.Basis == "" &&
		api.VerifiedAt == "" &&
		api.Transport == "" &&
		api.Auth == "" &&
		api.AuthMechanics == "" &&
		api.BaseURL == "" &&
		api.Endpoint == "" &&
		api.SpecURL == "" &&
		api.SpecKind == "" &&
		len(api.References) == 0 &&
		len(api.AuthEvidence) == 0 &&
		len(api.ScopeEvidence) == 0 &&
		len(api.Families) == 0 &&
		catalogProviderAPIDisproofEmpty(api.Disproof)
}

func normalizeCatalogProviderAPIDisproof(disproof CatalogProviderAPIDisproof) *CatalogProviderAPIDisproof {
	disproof.Status = strings.TrimSpace(disproof.Status)
	disproof.Reason = strings.TrimSpace(disproof.Reason)
	disproof.CheckedAt = strings.TrimSpace(disproof.CheckedAt)
	disproof.References = normalizeCatalogStringList(disproof.References)
	disproof.AffectedFamilies = normalizeCatalogStringList(disproof.AffectedFamilies)
	disproof.MissingPaths = normalizeCatalogStringList(disproof.MissingPaths)
	disproof.Notes = normalizeCatalogStringList(disproof.Notes)
	if catalogProviderAPIDisproofEmpty(disproof) {
		return nil
	}
	return &disproof
}

func catalogProviderAPIDisproofEmpty(disproof CatalogProviderAPIDisproof) bool {
	return disproof.Status == "" &&
		disproof.Reason == "" &&
		disproof.CheckedAt == "" &&
		len(disproof.References) == 0 &&
		len(disproof.AffectedFamilies) == 0 &&
		len(disproof.MissingPaths) == 0 &&
		len(disproof.Notes) == 0
}

func normalizeCatalogStringList(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(seen))
	for value := range seen {
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func cloneCatalogProviderAPI(api CatalogProviderAPI) CatalogProviderAPI {
	api.References = append([]string(nil), api.References...)
	api.AuthEvidence = append([]string(nil), api.AuthEvidence...)
	api.ScopeEvidence = append([]string(nil), api.ScopeEvidence...)
	api.Families = append([]CatalogProviderAPIFamily(nil), api.Families...)
	api.Disproof.References = append([]string(nil), api.Disproof.References...)
	api.Disproof.AffectedFamilies = append([]string(nil), api.Disproof.AffectedFamilies...)
	api.Disproof.MissingPaths = append([]string(nil), api.Disproof.MissingPaths...)
	api.Disproof.Notes = append([]string(nil), api.Disproof.Notes...)
	return api
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
