package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const genericCoverageNote = "Generated Source Runtime SDK mapping requires provider field review before certification."

type report struct {
	Summary summary        `json:"summary"`
	Sources []sourceReport `json:"sources"`
}

type summary struct {
	TotalSources                    int `json:"total_sources"`
	RuntimeSources                  int `json:"runtime_sources"`
	HighFidelitySources             int `json:"high_fidelity_sources"`
	NeedsRealFixtures               int `json:"needs_real_fixtures"`
	NeedsEveryFamilyTests           int `json:"needs_every_family_tests"`
	NeedsDeployFamilyCoverage       int `json:"needs_deploy_family_coverage"`
	NeedsCoverageSpecificity        int `json:"needs_coverage_specificity"`
	NeedsIncrementalCheckpointTests int `json:"needs_incremental_checkpoint_tests"`
}

type sourceReport struct {
	SourceID                  string   `json:"source_id"`
	Level                     string   `json:"level"`
	Score                     int      `json:"score"`
	PossibleScore             int      `json:"possible_score"`
	RuntimeFamilies           int      `json:"runtime_families"`
	ReadFixtures              int      `json:"read_fixtures"`
	DiscoverFixtures          int      `json:"discover_fixtures"`
	SyntheticReadFixtures     int      `json:"synthetic_read_fixtures"`
	ProviderLikeReadFixtures  int      `json:"provider_like_read_fixtures"`
	DeployRuntimes            int      `json:"deploy_runtimes"`
	DeployRuntimeFamilies     int      `json:"deploy_runtime_families"`
	IncrementalFamilies       int      `json:"incremental_families"`
	FreshnessProbeFamilies    int      `json:"freshness_probe_families"`
	CoverageDimensions        int      `json:"coverage_dimensions"`
	GenericCoverageDimensions int      `json:"generic_coverage_dimensions"`
	CoverageWithControlRefs   int      `json:"coverage_with_control_refs"`
	CoverageWithKnownGaps     int      `json:"coverage_with_known_gaps"`
	UsesJSONAPI               bool     `json:"uses_json_api"`
	HasHTTPTest               bool     `json:"has_http_test"`
	HasGenericRecordTest      bool     `json:"has_generic_record_test"`
	HasEveryFamilyTest        bool     `json:"has_every_family_test"`
	HasCheckpointTest         bool     `json:"has_checkpoint_test"`
	HasProviderUnavailable    bool     `json:"has_provider_unavailable"`
	IsGeneratedScaffold       bool     `json:"is_generated_scaffold"`
	Missing                   []string `json:"missing"`
	Advisory                  []string `json:"advisory"`
	BlockingCandidate         []string `json:"blocking_candidate"`
	EvidenceFiles             []string `json:"evidence_files"`
}

type sourceCatalog struct {
	ID               string `yaml:"id"`
	RuntimeFamilies  []string
	LegacyFamilies   []catalogFamily
	CoverageContract struct {
		Dimensions []coverageDimension `yaml:"dimensions"`
	} `yaml:"coverage_contract"`
}

type catalogFamily struct {
	ID             string `yaml:"id"`
	Incremental    string `yaml:"incremental"`
	FreshnessProbe *struct {
		Supported bool `yaml:"supported"`
	} `yaml:"freshness_probe"`
}

type coverageDimension struct {
	ID                     string       `yaml:"id"`
	Support                string       `yaml:"support"`
	Notes                  []string     `yaml:"notes"`
	ControlRefs            []controlRef `yaml:"control_refs"`
	KnownUnsupportedFields []string     `yaml:"known_unsupported_fields"`
}

type controlRef struct {
	FrameworkName string `yaml:"framework_name"`
	FrameworkID   string `yaml:"framework_id"`
	ControlID     string `yaml:"control_id"`
}

type deployManifest struct {
	Runtimes []struct {
		LocalID string            `yaml:"localId"`
		Config  map[string]string `yaml:"config"`
	} `yaml:"runtimes"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	jsonOut := flag.String("json-out", "", "write JSON report to this path")
	markdownOut := flag.String("markdown-out", "", "write Markdown report to this path")
	maxItems := flag.Int("max-items", 40, "maximum sources to render in Markdown")
	failUnder := flag.Int("fail-under", -1, "exit non-zero when any runtime source score is below this value")
	flag.Parse()

	result, err := buildReport(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sourcefidelity: %v\n", err)
		os.Exit(1)
	}
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, result); err != nil {
			fmt.Fprintf(os.Stderr, "sourcefidelity: %v\n", err)
			os.Exit(1)
		}
	}
	markdown := renderMarkdown(result, *maxItems)
	if *markdownOut != "" {
		if err := writeFile(*markdownOut, []byte(markdown)); err != nil {
			fmt.Fprintf(os.Stderr, "sourcefidelity: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("sourcefidelity: sources=%d runtime_sources=%d high_fidelity=%d needs_real_fixtures=%d needs_every_family_tests=%d needs_deploy_family_coverage=%d\n",
		result.Summary.TotalSources,
		result.Summary.RuntimeSources,
		result.Summary.HighFidelitySources,
		result.Summary.NeedsRealFixtures,
		result.Summary.NeedsEveryFamilyTests,
		result.Summary.NeedsDeployFamilyCoverage,
	)
	if *markdownOut == "" && *jsonOut == "" {
		fmt.Print(markdown)
	}
	if *failUnder >= 0 {
		for _, source := range result.Sources {
			if source.RuntimeFamilies > 0 && source.Score < *failUnder {
				os.Exit(1)
			}
		}
	}
}

func buildReport(root string) (report, error) {
	sourcesRoot := filepath.Join(root, "sources")
	entries, err := os.ReadDir(sourcesRoot)
	if err != nil {
		return report{}, fmt.Errorf("read sources root: %w", err)
	}
	result := report{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceRoot := filepath.Join(sourcesRoot, entry.Name())
		catalogPath := filepath.Join(sourceRoot, "catalog.yaml")
		if _, err := os.Stat(catalogPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return report{}, fmt.Errorf("stat %s: %w", catalogPath, err)
		}
		source, err := analyzeSource(sourceRoot)
		if err != nil {
			return report{}, err
		}
		result.Sources = append(result.Sources, source)
		accumulateSummary(&result.Summary, source)
	}
	sort.Slice(result.Sources, func(i, j int) bool {
		if result.Sources[i].Score != result.Sources[j].Score {
			return result.Sources[i].Score < result.Sources[j].Score
		}
		return result.Sources[i].SourceID < result.Sources[j].SourceID
	})
	return result, nil
}

func analyzeSource(sourceRoot string) (sourceReport, error) {
	catalog, err := readSourceCatalog(filepath.Join(sourceRoot, "catalog.yaml"))
	if err != nil {
		return sourceReport{}, err
	}
	source := sourceReport{SourceID: firstNonEmpty(catalog.ID, filepath.Base(sourceRoot))}
	source.RuntimeFamilies = runtimeFamilyCount(catalog)
	source.IncrementalFamilies, source.FreshnessProbeFamilies = incrementalSignals(catalog.LegacyFamilies)
	source.CoverageDimensions = len(catalog.CoverageContract.Dimensions)
	for _, dimension := range catalog.CoverageContract.Dimensions {
		if hasGenericCoverageNote(dimension.Notes) {
			source.GenericCoverageDimensions++
		}
		if len(dimension.ControlRefs) > 0 {
			source.CoverageWithControlRefs++
		}
		if len(dimension.KnownUnsupportedFields) > 0 {
			source.CoverageWithKnownGaps++
		}
	}
	source.ReadFixtures, source.DiscoverFixtures, source.SyntheticReadFixtures, source.ProviderLikeReadFixtures = fixtureSignals(sourceRoot)
	source.DeployRuntimes, source.DeployRuntimeFamilies = deploySignals(filepath.Join(sourceRoot, "deploy.yaml"))
	source.UsesJSONAPI = fileContains(filepath.Join(sourceRoot, "source.go"), "sources/internal/jsonapi")
	testPath := filepath.Join(sourceRoot, "source_test.go")
	source.HasHTTPTest = fileContains(testPath, "httptest.NewServer")
	source.HasGenericRecordTest = hasGenericRecordTest(testPath)
	source.HasEveryFamilyTest = hasEveryFamilyTest(testPath, runtimeFamilyNames(catalog))
	source.HasCheckpointTest = hasCheckpointEvidence(testPath, filepath.Join(sourceRoot, "source.go"))
	source.HasProviderUnavailable = fileContains(testPath, "ProviderUnavailable") || fileContains(filepath.Join(sourceRoot, "source.go"), "ProviderUnavailable")
	source.IsGeneratedScaffold = generatedScaffold(sourceRoot)
	source.EvidenceFiles = evidenceFiles(sourceRoot)
	scoreSource(&source)
	source.Level = fidelityLevel(source.Score)
	normalizeSourceReportSlices(&source)
	return source, nil
}

func readSourceCatalog(path string) (sourceCatalog, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return sourceCatalog{}, fmt.Errorf("read %s: %w", path, err)
	}
	var raw struct {
		ID               string          `yaml:"id"`
		RuntimeFamilies  []string        `yaml:"runtime_families"`
		LegacyFamilies   []catalogFamily `yaml:"families"`
		CoverageContract struct {
			Dimensions []coverageDimension `yaml:"dimensions"`
		} `yaml:"coverage_contract"`
	}
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return sourceCatalog{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return sourceCatalog{
		ID:              raw.ID,
		RuntimeFamilies: raw.RuntimeFamilies,
		LegacyFamilies:  raw.LegacyFamilies,
		CoverageContract: struct {
			Dimensions []coverageDimension `yaml:"dimensions"`
		}(raw.CoverageContract),
	}, nil
}

func runtimeFamilyCount(catalog sourceCatalog) int {
	if len(catalog.RuntimeFamilies) > 0 {
		return len(catalog.RuntimeFamilies)
	}
	return len(catalog.LegacyFamilies)
}

func runtimeFamilyNames(catalog sourceCatalog) []string {
	if len(catalog.RuntimeFamilies) > 0 {
		return catalog.RuntimeFamilies
	}
	names := make([]string, 0, len(catalog.LegacyFamilies))
	for _, family := range catalog.LegacyFamilies {
		if strings.TrimSpace(family.ID) != "" {
			names = append(names, family.ID)
		}
	}
	return names
}

func incrementalSignals(families []catalogFamily) (int, int) {
	incremental := 0
	freshnessProbe := 0
	for _, family := range families {
		if strings.TrimSpace(family.Incremental) != "" {
			incremental++
		}
		if family.FreshnessProbe != nil && family.FreshnessProbe.Supported {
			freshnessProbe++
		}
	}
	return incremental, freshnessProbe
}

func fixtureSignals(sourceRoot string) (readFixtures int, discoverFixtures int, synthetic int, providerLike int) {
	testdata := filepath.Join(sourceRoot, "testdata")
	readMatches, _ := filepath.Glob(filepath.Join(testdata, "read_*.json"))
	discoverMatches, _ := filepath.Glob(filepath.Join(testdata, "discover_*.json"))
	for _, path := range readMatches {
		readFixtures++
		payload, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if syntheticFixture(payload) {
			synthetic++
		} else {
			providerLike++
		}
	}
	return readFixtures, len(discoverMatches), synthetic, providerLike
}

func syntheticFixture(payload []byte) bool {
	text := string(payload)
	if strings.Contains(text, `"api_path"`) || strings.Contains(text, `"Record One"`) {
		return true
	}
	var events []struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(payload, &events); err == nil && len(events) > 0 {
		if id, ok := events[0].Payload["id"].(string); ok && strings.HasPrefix(id, "source-") {
			return true
		}
		if name, ok := events[0].Payload["name"].(string); ok && strings.HasSuffix(name, " Fixture") {
			return true
		}
	}
	return false
}

func hasGenericRecordTest(path string) bool {
	payload, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(payload), "\n") {
		if !strings.Contains(line, "Record One") {
			continue
		}
		if strings.Contains(line, "strings.Contains") {
			continue
		}
		return true
	}
	return false
}

func hasEveryFamilyTest(path string, familyNames []string) bool {
	payload, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(payload)
	for _, marker := range []string{
		"TestNewFixtureReplaysGeneratedFamilies",
		"TestNewFixtureReplaysEveryRuntimeFamily",
		"TestSourceCheckAndReadFamilies",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	if len(familyNames) == 0 {
		return false
	}
	if !strings.Contains(text, "t.Run(") && !strings.Contains(text, "RunFixtureSuite") && !strings.Contains(text, "FamilyConfigs") {
		return false
	}
	for _, family := range familyNames {
		if !strings.Contains(text, family) && !strings.Contains(text, camelFamilyConst(family)) {
			return false
		}
	}
	return true
}

func hasCheckpointEvidence(testPath string, sourcePath string) bool {
	if fileContainsAny(testPath, []string{
		"ReadWithCheckpoint",
		"WithCheckpoint",
		"IncrementalCheckpointForCursor",
		"Checkpoint:",
		".Checkpoint",
		"GetCheckpoint",
		"CursorOpaque",
		"NextCursor",
	}) {
		return true
	}
	return fileContainsAny(sourcePath, []string{
		"ReadWithCheckpoint",
		"WithCheckpoint",
		"IncrementalCheckpointForCursor",
		"CheckpointStart",
		"SourceCheckpoint",
		"CursorOpaque",
	})
}

func camelFamilyConst(family string) string {
	parts := strings.FieldsFunc(family, func(r rune) bool {
		return r == '_' || r == '-'
	})
	var b strings.Builder
	b.WriteString("family")
	for _, part := range parts {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			b.WriteString(part[1:])
		}
	}
	return b.String()
}

func deploySignals(path string) (int, int) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	var manifest deployManifest
	if err := yaml.Unmarshal(payload, &manifest); err != nil {
		return 0, 0
	}
	families := map[string]struct{}{}
	for _, runtime := range manifest.Runtimes {
		if family := strings.TrimSpace(runtime.Config["family"]); family != "" {
			families[family] = struct{}{}
		}
	}
	return len(manifest.Runtimes), len(families)
}

func scoreSource(source *sourceReport) {
	add := func(points int, ok bool, finding string) {
		source.PossibleScore += points
		if ok {
			source.Score += points
			return
		}
		if finding != "" {
			source.Missing = append(source.Missing, finding)
		}
	}
	runtimeFamilies := source.RuntimeFamilies
	if runtimeFamilies == 0 {
		runtimeFamilies = 1
	}
	add(10, source.ReadFixtures >= runtimeFamilies && source.DiscoverFixtures >= runtimeFamilies, "fixture pairs do not cover every runtime family")
	add(20, source.ReadFixtures > 0 && source.ProviderLikeReadFixtures >= source.ReadFixtures-source.ReadFixtures/5, "read fixtures are still mostly generated or generic")
	add(15, source.HasEveryFamilyTest, "source tests do not replay every runtime family")
	add(15, source.DeployRuntimeFamilies >= runtimeFamilies || source.RuntimeFamilies <= 1, "deploy manifest does not configure every runtime family")
	add(15, source.CoverageDimensions > 0 && source.GenericCoverageDimensions == 0 && source.CoverageWithControlRefs > 0, "coverage contract lacks provider-specific control mapping")
	add(10, source.HasHTTPTest && !source.HasGenericRecordTest, "HTTP test still uses a generic fixture response")
	if source.IncrementalFamilies > 0 || source.FreshnessProbeFamilies > 0 {
		add(10, source.HasCheckpointTest, "incremental or freshness families lack checkpoint tests")
	}
	add(5, source.HasProviderUnavailable || source.RuntimeFamilies <= 1, "provider-unavailable behavior is not covered")
	source.Advisory = append(source.Advisory, source.Missing...)
	if source.RuntimeFamilies > 1 && !source.HasEveryFamilyTest {
		source.BlockingCandidate = append(source.BlockingCandidate, "source tests must replay every runtime family before promotion")
	}
	if source.RuntimeFamilies > 1 && source.DeployRuntimeFamilies < source.RuntimeFamilies {
		source.BlockingCandidate = append(source.BlockingCandidate, "deploy manifest must configure each runtime family before promotion")
	}
	if source.ReadFixtures > 0 && source.SyntheticReadFixtures == source.ReadFixtures {
		source.BlockingCandidate = append(source.BlockingCandidate, "provider-shaped fixtures are required before reference status")
	}
}

func normalizeSourceReportSlices(source *sourceReport) {
	if source.Missing == nil {
		source.Missing = []string{}
	}
	if source.Advisory == nil {
		source.Advisory = []string{}
	}
	if source.BlockingCandidate == nil {
		source.BlockingCandidate = []string{}
	}
	if source.EvidenceFiles == nil {
		source.EvidenceFiles = []string{}
	}
}

func accumulateSummary(summary *summary, source sourceReport) {
	summary.TotalSources++
	if source.RuntimeFamilies > 0 {
		summary.RuntimeSources++
	}
	if source.Score >= 80 {
		summary.HighFidelitySources++
	}
	if source.ReadFixtures > 0 && source.SyntheticReadFixtures > 0 {
		summary.NeedsRealFixtures++
	}
	if source.RuntimeFamilies > 1 && !source.HasEveryFamilyTest {
		summary.NeedsEveryFamilyTests++
	}
	if source.RuntimeFamilies > 1 && source.DeployRuntimeFamilies < source.RuntimeFamilies {
		summary.NeedsDeployFamilyCoverage++
	}
	if source.GenericCoverageDimensions > 0 || source.CoverageWithControlRefs == 0 {
		summary.NeedsCoverageSpecificity++
	}
	if (source.IncrementalFamilies > 0 || source.FreshnessProbeFamilies > 0) && !source.HasCheckpointTest {
		summary.NeedsIncrementalCheckpointTests++
	}
}

func renderMarkdown(result report, maxItems int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Source Fidelity Report\n\n")
	fmt.Fprintf(&b, "- Sources: %d\n", result.Summary.TotalSources)
	fmt.Fprintf(&b, "- Runtime sources: %d\n", result.Summary.RuntimeSources)
	fmt.Fprintf(&b, "- High-fidelity sources: %d\n", result.Summary.HighFidelitySources)
	fmt.Fprintf(&b, "- Need real fixtures: %d\n", result.Summary.NeedsRealFixtures)
	fmt.Fprintf(&b, "- Need every-family tests: %d\n", result.Summary.NeedsEveryFamilyTests)
	fmt.Fprintf(&b, "- Need deploy family coverage: %d\n", result.Summary.NeedsDeployFamilyCoverage)
	fmt.Fprintf(&b, "- Need coverage specificity: %d\n\n", result.Summary.NeedsCoverageSpecificity)
	fmt.Fprintf(&b, "## Lowest Scores\n\n")
	fmt.Fprintf(&b, "| Source | Score | Runtime families | Real fixtures | Deploy families | Findings |\n")
	fmt.Fprintf(&b, "| --- | ---: | ---: | ---: | ---: | --- |\n")
	limit := maxItems
	if limit <= 0 || limit > len(result.Sources) {
		limit = len(result.Sources)
	}
	for _, source := range result.Sources[:limit] {
		fmt.Fprintf(&b, "| %s | %d/%d | %d | %d/%d | %d/%d | %s |\n",
			source.SourceID,
			source.Score,
			source.PossibleScore,
			source.RuntimeFamilies,
			source.ProviderLikeReadFixtures,
			source.ReadFixtures,
			source.DeployRuntimeFamilies,
			source.RuntimeFamilies,
			markdownCell(strings.Join(source.Missing, "; ")),
		)
	}
	return b.String()
}

func fidelityLevel(score int) string {
	switch {
	case score >= 90:
		return "reference"
	case score >= 75:
		return "runtime_ready"
	case score >= 55:
		return "shallow_runtime"
	default:
		return "catalog_or_scaffold"
	}
}

func generatedScaffold(sourceRoot string) bool {
	if fileContains(filepath.Join(sourceRoot, "SOURCE_RUNTIME.md"), "Generated Source Runtime SDK scaffold") ||
		fileContains(filepath.Join(sourceRoot, "PR_BODY.md"), "Generated runtime contract") {
		return true
	}
	return hasGenericRecordTest(filepath.Join(sourceRoot, "source_test.go")) && fileContains(filepath.Join(sourceRoot, "source.go"), "jsonapi.New")
}

func evidenceFiles(sourceRoot string) []string {
	candidates := []string{"catalog.yaml", "deploy.yaml", "source.go", "source_test.go", "fixture.go", "source_health_receipt.json"}
	files := []string{}
	for _, candidate := range candidates {
		path := filepath.Join(sourceRoot, candidate)
		if fileExists(path) {
			files = append(files, filepath.ToSlash(path))
		}
	}
	if readFixtures, _ := filepath.Glob(filepath.Join(sourceRoot, "testdata", "read_*.json")); len(readFixtures) > 0 {
		files = append(files, filepath.ToSlash(readFixtures[0]))
	}
	if discoverFixtures, _ := filepath.Glob(filepath.Join(sourceRoot, "testdata", "discover_*.json")); len(discoverFixtures) > 0 {
		files = append(files, filepath.ToSlash(discoverFixtures[0]))
	}
	return files
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func hasGenericCoverageNote(notes []string) bool {
	for _, note := range notes {
		if strings.TrimSpace(note) == genericCoverageNote {
			return true
		}
	}
	return false
}

func fileContains(path string, needle string) bool {
	payload, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(payload), needle)
}

func fileContainsAny(path string, needles []string) bool {
	payload, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(payload)
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

func writeJSON(path string, result report) error {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	payload = append(payload, '\n')
	return writeFile(path, payload)
}

func writeFile(path string, payload []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
