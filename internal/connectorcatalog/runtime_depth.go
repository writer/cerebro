package connectorcatalog

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuntimeDepthInventory maps source IDs to repository evidence for a concrete
// Source CDK package. Catalog-only connector definitions will not have an entry.
type RuntimeDepthInventory map[string]RuntimeDepth

// RuntimeDepth captures the repository-level implementation signals expected
// from reference sources such as GitHub: source package, catalog, fixtures,
// deploy manifest, and projector coverage.
type RuntimeDepth struct {
	SourceID                string                  `json:"source_id"`
	PackagePath             string                  `json:"package_path,omitempty"`
	Score                   int                     `json:"score"`
	Missing                 []string                `json:"missing,omitempty"`
	HasSourcePackage        bool                    `json:"has_source_package,omitempty"`
	HasSourceCatalog        bool                    `json:"has_source_catalog,omitempty"`
	HasSourceImplementation bool                    `json:"has_source_implementation,omitempty"`
	HasSourceTests          bool                    `json:"has_source_tests,omitempty"`
	HasReadFixtures         bool                    `json:"has_read_fixtures,omitempty"`
	HasDiscoverFixtures     bool                    `json:"has_discover_fixtures,omitempty"`
	HasFixturePair          bool                    `json:"has_fixture_pair,omitempty"`
	HasDeployManifest       bool                    `json:"has_deploy_manifest,omitempty"`
	HasProjectorTests       bool                    `json:"has_projector_tests,omitempty"`
	HasEventContracts       bool                    `json:"has_event_contracts,omitempty"`
	HasCoverageContract     bool                    `json:"has_coverage_contract,omitempty"`
	ProviderAPI             RuntimeProviderAPIDepth `json:"provider_api,omitempty"`
	RuntimeFamilies         []string                `json:"runtime_families,omitempty"`
	ReadFixtureFamilies     []string                `json:"read_fixture_families,omitempty"`
	DiscoverFixtureFamilies []string                `json:"discover_fixture_families,omitempty"`
	MissingReadFixtures     []string                `json:"missing_read_fixtures,omitempty"`
	MissingDiscoverFixtures []string                `json:"missing_discover_fixtures,omitempty"`
	RequiredProjectorKinds  []string                `json:"required_projector_kinds,omitempty"`
	ProjectedKinds          []string                `json:"projected_kinds,omitempty"`
	MissingProjectorKinds   []string                `json:"missing_projector_kinds,omitempty"`
}

type RuntimeProviderAPIDepth struct {
	HasContract           bool     `json:"has_contract,omitempty"`
	HasMapping            bool     `json:"has_mapping,omitempty"`
	HasRuntimeTransport   bool     `json:"has_runtime_transport,omitempty"`
	Status                string   `json:"status,omitempty"`
	Transport             string   `json:"transport,omitempty"`
	Auth                  string   `json:"auth,omitempty"`
	BaseURL               string   `json:"base_url,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	References            []string `json:"references,omitempty"`
	MappedFamilies        []string `json:"mapped_families,omitempty"`
	MissingFamilyMappings []string `json:"missing_family_mappings,omitempty"`
}

type runtimeCatalogFields struct {
	ID              string   `yaml:"id"`
	EmittedKinds    []string `yaml:"emitted_kinds"`
	RuntimeFamilies []string `yaml:"runtime_families"`
	Families        []struct {
		ID string `yaml:"id"`
	} `yaml:"families"`
	EventContracts []struct {
		Kind string `yaml:"kind"`
	} `yaml:"event_contracts"`
	CoverageContract *struct{}                `yaml:"coverage_contract"`
	ProviderAPI      runtimeProviderAPIFields `yaml:"provider_api"`
}

type runtimeProviderAPIFields struct {
	Status     string   `yaml:"status"`
	Transport  string   `yaml:"transport"`
	Auth       string   `yaml:"auth"`
	BaseURL    string   `yaml:"base_url"`
	Endpoint   string   `yaml:"endpoint"`
	References []string `yaml:"references"`
	Families   []struct {
		ID        string `yaml:"id"`
		Method    string `yaml:"method"`
		Path      string `yaml:"path"`
		Operation string `yaml:"operation"`
	} `yaml:"families"`
}

// DiscoverRuntimeDepth scans repository source packages and sourceprojection
// tests for reference-runtime evidence. Missing sources/ is treated as an empty
// inventory so callers can use the review tool on partial checkouts.
func DiscoverRuntimeDepth(root string) (RuntimeDepthInventory, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" || root == "." {
		root = "."
	}
	repoRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open repository root: %w", err)
	}
	defer func() {
		_ = repoRoot.Close()
	}()
	inventory := RuntimeDepthInventory{}
	projectorTests, err := discoverProjectorTestKinds(repoRoot)
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(repoRoot.FS(), "sources")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inventory, nil
		}
		return nil, fmt.Errorf("read sources directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceDir := filepath.Join(root, "sources", entry.Name())
		depth, err := inspectRuntimeDepth(root, repoRoot, sourceDir, projectorTests)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(depth.SourceID) == "" {
			continue
		}
		inventory[depth.SourceID] = depth
	}
	return inventory, nil
}

func inspectRuntimeDepth(root string, repoRoot *os.Root, sourceDir string, projectorTests map[string]map[string]struct{}) (RuntimeDepth, error) {
	sourceID := filepath.Base(sourceDir)
	depth := RuntimeDepth{
		SourceID:         sourceID,
		PackagePath:      slashRel(root, sourceDir),
		HasSourcePackage: true,
	}
	if hasRegularFile(filepath.Join(sourceDir, "catalog.yaml")) {
		depth.HasSourceCatalog = true
		catalog, err := readRuntimeCatalogFields(repoRoot, filepath.ToSlash(filepath.Join(depth.PackagePath, "catalog.yaml")))
		if err != nil {
			return RuntimeDepth{}, err
		}
		if strings.TrimSpace(catalog.ID) != "" {
			depth.SourceID = strings.TrimSpace(catalog.ID)
		}
		depth.RuntimeFamilies = runtimeFamiliesFromCatalog(catalog)
		depth.RequiredProjectorKinds = projectorKindsFromCatalog(catalog)
		depth.HasEventContracts = len(catalog.EventContracts) > 0
		depth.HasCoverageContract = catalog.CoverageContract != nil
		depth.ProviderAPI.Status = strings.TrimSpace(catalog.ProviderAPI.Status)
		depth.ProviderAPI.Transport = strings.TrimSpace(catalog.ProviderAPI.Transport)
		depth.ProviderAPI.Auth = strings.TrimSpace(catalog.ProviderAPI.Auth)
		depth.ProviderAPI.BaseURL = strings.TrimSpace(catalog.ProviderAPI.BaseURL)
		depth.ProviderAPI.Endpoint = strings.TrimSpace(catalog.ProviderAPI.Endpoint)
		depth.ProviderAPI.References = normalizedList(catalog.ProviderAPI.References)
		depth.ProviderAPI.HasContract = hasProviderAPIContract(catalog.ProviderAPI)
		depth.ProviderAPI.MappedFamilies = providerAPIFamilies(catalog.ProviderAPI)
		depth.ProviderAPI.MissingFamilyMappings = missingValues(depth.RuntimeFamilies, depth.ProviderAPI.MappedFamilies)
		depth.ProviderAPI.HasMapping = depth.ProviderAPI.HasContract && len(depth.ProviderAPI.MissingFamilyMappings) == 0
	}
	depth.HasSourceImplementation = hasRegularFile(filepath.Join(sourceDir, "source.go"))
	sourceGoPath := filepath.ToSlash(filepath.Join(depth.PackagePath, "source.go"))
	depth.ProviderAPI.HasRuntimeTransport = depth.ProviderAPI.HasContract && runtimeTransportMatchesProviderAPI(repoRoot, sourceGoPath, depth.ProviderAPI.Transport)
	depth.HasSourceTests = hasSourceTests(sourceDir)
	depth.HasDeployManifest = hasRegularFile(filepath.Join(sourceDir, "deploy.yaml"))
	depth.ReadFixtureFamilies, depth.DiscoverFixtureFamilies = fixtureFamilies(sourceDir)
	depth.HasReadFixtures = len(depth.ReadFixtureFamilies) > 0
	depth.HasDiscoverFixtures = len(depth.DiscoverFixtureFamilies) > 0
	depth.MissingReadFixtures = missingValues(depth.RuntimeFamilies, depth.ReadFixtureFamilies)
	depth.MissingDiscoverFixtures = missingValues(depth.RuntimeFamilies, depth.DiscoverFixtureFamilies)
	depth.HasFixturePair = hasRequiredFixturePair(depth.RuntimeFamilies, depth.ReadFixtureFamilies, depth.DiscoverFixtureFamilies)
	depth.ProjectedKinds = sortedKeys(projectorTests[depth.SourceID])
	depth.MissingProjectorKinds = missingValues(depth.RequiredProjectorKinds, depth.ProjectedKinds)
	if len(depth.RequiredProjectorKinds) > 0 {
		depth.HasProjectorTests = len(depth.MissingProjectorKinds) == 0
	} else {
		depth.HasProjectorTests = len(depth.ProjectedKinds) > 0
	}
	depth.Score, depth.Missing = runtimeDepthScore(depth)
	sort.Strings(depth.RuntimeFamilies)
	sort.Strings(depth.ReadFixtureFamilies)
	sort.Strings(depth.DiscoverFixtureFamilies)
	sort.Strings(depth.MissingReadFixtures)
	sort.Strings(depth.MissingDiscoverFixtures)
	sort.Strings(depth.RequiredProjectorKinds)
	sort.Strings(depth.ProjectedKinds)
	sort.Strings(depth.MissingProjectorKinds)
	sort.Strings(depth.ProviderAPI.References)
	sort.Strings(depth.ProviderAPI.MappedFamilies)
	sort.Strings(depth.ProviderAPI.MissingFamilyMappings)
	sort.Strings(depth.Missing)
	return depth, nil
}

func readRuntimeCatalogFields(repoRoot *os.Root, path string) (runtimeCatalogFields, error) {
	payload, err := repoRoot.ReadFile(path)
	if err != nil {
		return runtimeCatalogFields{}, fmt.Errorf("read %s: %w", path, err)
	}
	var catalog runtimeCatalogFields
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		return runtimeCatalogFields{}, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return catalog, nil
}

func runtimeDepthScore(depth RuntimeDepth) (int, []string) {
	score := 0
	var missing []string
	if depth.HasSourcePackage {
		score += 10
	} else {
		missing = append(missing, "runtime:source_package")
	}
	if depth.HasSourceCatalog {
		score += 10
	} else {
		missing = append(missing, "runtime:catalog")
	}
	if depth.ProviderAPI.HasContract && depth.ProviderAPI.HasMapping && depth.ProviderAPI.HasRuntimeTransport {
		score += 15
	} else {
		missing = append(missing, "runtime:provider_api_contract")
		if !depth.ProviderAPI.HasContract {
			missing = append(missing, "runtime:provider_api_reference")
		}
		for _, family := range depth.ProviderAPI.MissingFamilyMappings {
			missing = append(missing, "runtime:provider_api_family:"+family)
		}
		if depth.ProviderAPI.HasContract && !depth.ProviderAPI.HasRuntimeTransport {
			missing = append(missing, "runtime:provider_api_transport_mismatch")
		}
	}
	if depth.HasEventContracts && depth.HasCoverageContract {
		score += 10
	} else {
		missing = append(missing, "runtime:catalog_contracts")
	}
	if depth.HasSourceImplementation {
		score += 15
	} else {
		missing = append(missing, "runtime:source_go")
	}
	if depth.HasSourceTests {
		score += 10
	} else {
		missing = append(missing, "runtime:source_tests")
	}
	if depth.HasFixturePair {
		score += 15
	} else {
		missing = append(missing, "runtime:fixture_pair")
		for _, family := range depth.MissingReadFixtures {
			missing = append(missing, "runtime:read_fixture:"+family)
		}
		for _, family := range depth.MissingDiscoverFixtures {
			missing = append(missing, "runtime:discover_fixture:"+family)
		}
	}
	if depth.HasDeployManifest {
		score += 5
	} else {
		missing = append(missing, "runtime:deploy_manifest")
	}
	if depth.HasProjectorTests {
		score += 10
	} else {
		missing = append(missing, "runtime:projector_tests")
		for _, kind := range depth.MissingProjectorKinds {
			missing = append(missing, "runtime:projector_kind:"+kind)
		}
	}
	return score, missing
}

func hasRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func hasSourceTests(sourceDir string) bool {
	matches, err := filepath.Glob(filepath.Join(sourceDir, "*_test.go"))
	return err == nil && len(matches) > 0
}

func fixtureFamilies(sourceDir string) ([]string, []string) {
	testdata := filepath.Join(sourceDir, "testdata")
	entries, err := os.ReadDir(testdata)
	if err != nil {
		return nil, nil
	}
	read := map[string]struct{}{}
	discover := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		switch {
		case name == "read":
			read["default"] = struct{}{}
		case strings.HasPrefix(name, "read_"):
			read[strings.TrimPrefix(name, "read_")] = struct{}{}
		case name == "discover":
			discover["default"] = struct{}{}
		case strings.HasPrefix(name, "discover_"):
			discover[strings.TrimPrefix(name, "discover_")] = struct{}{}
		}
	}
	return sortedKeys(read), sortedKeys(discover)
}

func hasRequiredFixturePair(required []string, read []string, discover []string) bool {
	if len(required) == 0 {
		return hasFixturePair(read, discover)
	}
	return len(missingValues(required, read)) == 0 && len(missingValues(required, discover)) == 0
}

func hasFixturePair(read []string, discover []string) bool {
	if len(read) == 0 || len(discover) == 0 {
		return false
	}
	discovered := map[string]struct{}{}
	for _, family := range discover {
		discovered[family] = struct{}{}
	}
	for _, family := range read {
		if _, ok := discovered[family]; ok {
			return true
		}
	}
	return false
}

func discoverProjectorTestKinds(repoRoot *os.Root) (map[string]map[string]struct{}, error) {
	sources := map[string]map[string]struct{}{}
	const dir = "internal/sourceprojection"
	err := fs.WalkDir(repoRoot.FS(), dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		payload, err := repoRoot.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		for sourceID, kinds := range sourceKindsFromProjectorTest(string(payload)) {
			if sources[sourceID] == nil {
				sources[sourceID] = map[string]struct{}{}
			}
			for _, kind := range kinds {
				sources[sourceID][kind] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return sources, nil
		}
		return nil, err
	}
	return sources, nil
}

func sourceIDsFromProjectorTest(content string) []string {
	sourceKinds := sourceKindsFromProjectorTest(content)
	sourceIDs := make([]string, 0, len(sourceKinds))
	for sourceID := range sourceKinds {
		sourceIDs = append(sourceIDs, sourceID)
	}
	sort.Strings(sourceIDs)
	return sourceIDs
}

func sourceKindsFromProjectorTest(content string) map[string][]string {
	file, err := parser.ParseFile(token.NewFileSet(), "sourceprojection_test.go", content, 0)
	if err != nil {
		return nil
	}
	eventSources := map[string]struct{}{}
	kindSources := map[string]map[string]struct{}{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.KeyValueExpr:
			key, ok := n.Key.(*ast.Ident)
			if !ok {
				return true
			}
			value, ok := stringLiteralValue(n.Value)
			if !ok {
				return true
			}
			switch strings.ToLower(key.Name) {
			case "sourceid":
				if sourceIDLooksStable(value) {
					eventSources[value] = struct{}{}
				}
			case "kind":
				if sourceID, ok := sourceIDFromEventKindLiteral(value); ok {
					if kindSources[sourceID] == nil {
						kindSources[sourceID] = map[string]struct{}{}
					}
					kindSources[sourceID][value] = struct{}{}
				}
			}
		}
		return true
	})
	covered := map[string][]string{}
	for sourceID := range kindSources {
		if _, ok := eventSources[sourceID]; ok {
			covered[sourceID] = sortedKeys(kindSources[sourceID])
		}
	}
	return covered
}

func stringLiteralValue(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func sourceIDFromEventKindLiteral(value string) (string, bool) {
	if strings.Contains(value, "/") || strings.Contains(value, "@") || strings.Contains(value, "://") {
		return "", false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", false
	}
	for _, part := range parts {
		if !sourceIDLooksStable(part) {
			return "", false
		}
	}
	return parts[0], true
}

func sourceIDLooksStable(value string) bool {
	if len(value) < 2 {
		return false
	}
	if value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizedList(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	return sortedKeys(seen)
}

func runtimeFamiliesFromCatalog(catalog runtimeCatalogFields) []string {
	families := normalizedList(catalog.RuntimeFamilies)
	if len(families) > 0 {
		return families
	}
	seen := map[string]struct{}{}
	for _, family := range catalog.Families {
		if id := strings.TrimSpace(family.ID); id != "" {
			seen[id] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func hasProviderAPIContract(api runtimeProviderAPIFields) bool {
	if strings.TrimSpace(api.Status) != "verified" {
		return false
	}
	if strings.TrimSpace(api.Transport) == "" || strings.TrimSpace(api.Auth) == "" {
		return false
	}
	if strings.TrimSpace(api.BaseURL) == "" && strings.TrimSpace(api.Endpoint) == "" {
		return false
	}
	return len(normalizedList(api.References)) > 0
}

func providerAPIFamilies(api runtimeProviderAPIFields) []string {
	seen := map[string]struct{}{}
	for _, family := range api.Families {
		id := strings.TrimSpace(family.ID)
		if id == "" {
			continue
		}
		switch strings.TrimSpace(api.Transport) {
		case "graphql":
			if strings.TrimSpace(family.Operation) == "" {
				continue
			}
		default:
			if strings.TrimSpace(family.Method) == "" || strings.TrimSpace(family.Path) == "" {
				continue
			}
		}
		seen[id] = struct{}{}
	}
	return sortedKeys(seen)
}

func runtimeTransportMatchesProviderAPI(repoRoot *os.Root, sourceGoPath string, transport string) bool {
	transport = strings.TrimSpace(transport)
	if transport == "" {
		return true
	}
	if repoRoot == nil {
		return false
	}
	payload, err := repoRoot.ReadFile(sourceGoPath)
	if err != nil {
		return false
	}
	source := string(payload)
	switch transport {
	case "graphql":
		return !strings.Contains(source, "sources/internal/jsonapi")
	case "json_api":
		return strings.Contains(source, "sources/internal/jsonapi")
	case "rest":
		return strings.Contains(source, "sources/internal/jsonapi") ||
			strings.Contains(source, "github.com/google/go-github") ||
			strings.Contains(source, "sources/internal/githubapi") ||
			strings.Contains(source, "net/http")
	default:
		return true
	}
}

func projectorKindsFromCatalog(catalog runtimeCatalogFields) []string {
	kinds := normalizedList(catalog.EmittedKinds)
	if len(kinds) > 0 {
		return kinds
	}
	seen := map[string]struct{}{}
	for _, contract := range catalog.EventContracts {
		if kind := strings.TrimSpace(contract.Kind); kind != "" {
			seen[kind] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func missingValues(required []string, present []string) []string {
	if len(required) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, value := range present {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	missing := map[string]struct{}{}
	for _, value := range required {
		if value = strings.TrimSpace(value); value == "" {
			continue
		}
		if _, ok := seen[value]; !ok {
			missing[value] = struct{}{}
		}
	}
	return sortedKeys(missing)
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func slashRel(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
