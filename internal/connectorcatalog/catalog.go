package connectorcatalog

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen"
	"gopkg.in/yaml.v3"
)

const (
	StatusCatalogReady        = "catalog_ready"
	StatusGenerateable        = "generateable"
	StatusNeedsAuthExtension  = "needs_auth_extension"
	StatusNeedsBespokeRuntime = "needs_bespoke_runtime"
)

const builtinCatalogDir = "catalog"

//go:embed catalog/*
var builtinCatalogFS embed.FS

var (
	builtinOnce            sync.Once
	builtinAnalysis        Analysis
	builtinErr             error
	builtinRuntimeOnce     sync.Once
	builtinRuntimeAnalysis Analysis
	builtinRuntimeErr      error
)

// Options controls optional proof-gate checks.
type Options struct {
	DryRunSourcegen bool
}

// EntryFile is the catalog file shape. Files may contain one entry, an entries
// array, or a bare array of entries.
type EntryFile struct {
	Entries []RawEntry `json:"entries" yaml:"entries"`
}

// RawEntry wraps a source-of-truth connector definition with the expected
// classifier verdict committed to the catalog.
type RawEntry struct {
	ClassifierOutput string                          `json:"classifier_output" yaml:"classifier_output"`
	Definition       connectordefinitions.Definition `json:"definition" yaml:"definition"`
}

// Entry is one normalized and classified catalog record.
type Entry struct {
	Path              string
	Definition        connectordefinitions.Definition
	Report            connectordefinitions.SupportReport
	ClassifierOutput  string
	Status            string
	Generateable      bool
	SourcegenDryRun   bool
	SourcegenError    string
	VerificationPath  string
	ResourceFamilyIDs []string
}

// Issue is one proof-gate failure.
type Issue struct {
	Path    string
	Message string
}

// Summary aggregates catalog readiness for CI and API consumers.
type Summary struct {
	Total               int            `json:"total"`
	CatalogReady        int            `json:"catalog_ready"`
	Generateable        int            `json:"generateable"`
	NeedsAuthExtension  int            `json:"needs_auth_extension"`
	NeedsBespokeRuntime int            `json:"needs_bespoke_runtime"`
	ByClassifierOutput  map[string]int `json:"by_classifier_output,omitempty"`
	ByAuthModel         map[string]int `json:"by_auth_model,omitempty"`
}

// Analysis contains normalized entries, summary counts, and non-fatal proof
// gate issues. A non-empty Issues list means the catalog must not be claimed.
type Analysis struct {
	Entries []Entry `json:"-"`
	Summary Summary `json:"summary"`
	Issues  []Issue `json:"issues,omitempty"`
}

// Builtin returns the embedded connector-definition catalog analysis.
func Builtin() (Analysis, error) {
	builtinOnce.Do(func() {
		builtinAnalysis, builtinErr = AnalyzeFS(builtinCatalogFS, builtinCatalogDir, Options{DryRunSourcegen: true})
		if builtinErr == nil && len(builtinAnalysis.Issues) != 0 {
			builtinErr = fmt.Errorf("connector definition catalog has %d issue(s)", len(builtinAnalysis.Issues))
		}
	})
	return builtinAnalysis, builtinErr
}

// BuiltinRuntime returns embedded catalog analysis for runtime registration
// paths that need definitions but must not execute sourcegen dry-runs at init.
func BuiltinRuntime() (Analysis, error) {
	builtinRuntimeOnce.Do(func() {
		builtinRuntimeAnalysis, builtinRuntimeErr = AnalyzeFS(builtinCatalogFS, builtinCatalogDir, Options{})
		if builtinRuntimeErr == nil && len(builtinRuntimeAnalysis.Issues) != 0 {
			builtinRuntimeErr = fmt.Errorf("connector definition catalog has %d issue(s)", len(builtinRuntimeAnalysis.Issues))
		}
	})
	return builtinRuntimeAnalysis, builtinRuntimeErr
}

// BuiltinEntry returns one embedded connector-definition catalog entry by source ID.
func BuiltinEntry(sourceID string) (Entry, bool, error) {
	normalized, err := normalizeSourceID(sourceID)
	if err != nil {
		return Entry{}, false, err
	}
	analysis, err := Builtin()
	if err != nil {
		return Entry{}, false, err
	}
	for _, entry := range analysis.Entries {
		if entry.Definition.SourceID == normalized {
			return entry, true, nil
		}
	}
	return Entry{}, false, nil
}

// AnalyzeDir reads a filesystem directory containing catalog files.
func AnalyzeDir(dir string, options Options) (Analysis, error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "" {
		dir = "."
	}
	return AnalyzeFS(os.DirFS(dir), ".", options)
}

// AnalyzeFS reads and checks catalog entries from fsys rooted at dir.
func AnalyzeFS(fsys fs.FS, dir string, options Options) (Analysis, error) {
	dir = strings.Trim(strings.TrimSpace(filepath.ToSlash(dir)), "/")
	if dir == "" || dir == "." {
		dir = "."
	}
	var raw []loadedEntry
	err := fs.WalkDir(fsys, dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			raw = append(raw, loadedEntry{path: path, issues: []Issue{{Path: path, Message: "symlinked catalog files are not allowed"}}})
			return nil
		}
		payload, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		raw = appendDecodedEntries(raw, path, payload)
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Analysis{}, nil
		}
		return Analysis{}, err
	}
	return analyzeEntries(raw, options), nil
}

type loadedEntry struct {
	path   string
	entry  RawEntry
	issues []Issue
}

func appendDecodedEntries(raw []loadedEntry, path string, payload []byte) []loadedEntry {
	entries, issues := decodeEntries(path, payload)
	for _, entry := range entries {
		raw = append(raw, loadedEntry{path: path, entry: entry})
	}
	for _, issue := range issues {
		raw = append(raw, loadedEntry{path: path, issues: []Issue{issue}})
	}
	return raw
}

func analyzeEntries(raw []loadedEntry, options Options) Analysis {
	analysis := Analysis{
		Entries: make([]Entry, 0, len(raw)),
		Summary: Summary{
			ByClassifierOutput: map[string]int{},
			ByAuthModel:        map[string]int{},
		},
	}
	seenSourceIDs := map[string]string{}
	for index, loaded := range raw {
		analysis.Issues = append(analysis.Issues, loaded.issues...)
		if len(loaded.issues) != 0 {
			continue
		}
		path := loaded.path
		if path == "" {
			path = fmt.Sprintf("entry[%d]", index)
		}
		declared := normalizeClassifierOutput(loaded.entry.ClassifierOutput)
		if declared == "" {
			analysis.Issues = append(analysis.Issues, Issue{Path: path, Message: "classifier_output is required"})
		}
		analysis.Issues = append(analysis.Issues, proofGateIssues(path, loaded.entry.Definition)...)
		definition, err := connectordefinitions.Normalize(loaded.entry.Definition)
		if err != nil {
			analysis.Issues = append(analysis.Issues, Issue{Path: path, Message: "normalize definition: " + err.Error()})
			continue
		}
		if existing := seenSourceIDs[definition.SourceID]; definition.SourceID != "" && existing != "" {
			analysis.Issues = append(analysis.Issues, Issue{Path: path, Message: fmt.Sprintf("duplicate source_id %q also used by %s", definition.SourceID, existing)})
		}
		if definition.SourceID != "" {
			seenSourceIDs[definition.SourceID] = path
		}
		report, err := connectordefinitions.Classify(definition, connectordefinitions.DefaultGrammar())
		if err != nil {
			analysis.Issues = append(analysis.Issues, Issue{Path: path, Message: "classify definition: " + err.Error()})
			continue
		}
		entry := Entry{
			Path:              path,
			Definition:        definition,
			Report:            report,
			ClassifierOutput:  declared,
			Status:            statusForReport(report),
			VerificationPath:  verificationPath(definition),
			ResourceFamilyIDs: resourceFamilyIDs(definition),
		}
		if declared != "" {
			analysis.Summary.ByClassifierOutput[declared]++
			if declared != report.Verdict {
				analysis.Issues = append(analysis.Issues, Issue{Path: path, Message: fmt.Sprintf("classifier_output %q does not match classifier verdict %q", declared, report.Verdict)})
			}
		}
		if overlap := intersect(report.SupportedFeatures, report.MissingFeatures); len(overlap) != 0 {
			analysis.Issues = append(analysis.Issues, Issue{Path: path, Message: "classifier report has contradictory supported and missing features: " + strings.Join(overlap, ", ")})
		}
		if options.DryRunSourcegen && report.Verdict == connectordefinitions.SupportVerdictSupported {
			entry.SourcegenDryRun = true
			if _, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{Definition: definition, OutputDir: ".", DryRun: true}); err != nil {
				entry.SourcegenError = err.Error()
				if needsAuthExtension(err, report) {
					entry.Status = StatusNeedsAuthExtension
				} else {
					entry.Status = StatusNeedsBespokeRuntime
				}
			} else {
				entry.Generateable = true
				entry.Status = StatusGenerateable
			}
		}
		analysis.Summary.record(entry)
		analysis.Entries = append(analysis.Entries, entry)
	}
	sort.SliceStable(analysis.Entries, func(i int, j int) bool {
		return analysis.Entries[i].Definition.SourceID < analysis.Entries[j].Definition.SourceID
	})
	sort.SliceStable(analysis.Issues, func(i int, j int) bool {
		if analysis.Issues[i].Path != analysis.Issues[j].Path {
			return analysis.Issues[i].Path < analysis.Issues[j].Path
		}
		return analysis.Issues[i].Message < analysis.Issues[j].Message
	})
	if len(analysis.Summary.ByClassifierOutput) == 0 {
		analysis.Summary.ByClassifierOutput = nil
	}
	if len(analysis.Summary.ByAuthModel) == 0 {
		analysis.Summary.ByAuthModel = nil
	}
	return analysis
}

func (s *Summary) record(entry Entry) {
	s.Total++
	s.ByAuthModel[entry.Definition.Auth.Model]++
	switch entry.Status {
	case StatusGenerateable:
		s.Generateable++
	case StatusNeedsAuthExtension:
		s.NeedsAuthExtension++
	case StatusNeedsBespokeRuntime:
		s.NeedsBespokeRuntime++
	default:
		s.CatalogReady++
	}
}

func decodeEntries(path string, payload []byte) ([]RawEntry, []Issue) {
	ext := strings.ToLower(filepath.Ext(path))
	decode := func(target any) error {
		if ext == ".json" {
			return json.Unmarshal(payload, target)
		}
		return unmarshalYAMLWithJSONTags(payload, target)
	}
	var file EntryFile
	if err := decode(&file); err == nil && len(file.Entries) != 0 {
		return file.Entries, nil
	}
	var entries []RawEntry
	if err := decode(&entries); err == nil && len(entries) != 0 {
		return entries, nil
	}
	var entry RawEntry
	if err := decode(&entry); err != nil {
		return nil, []Issue{{Path: path, Message: "decode catalog entries: " + err.Error()}}
	}
	if entry.Definition.SourceID == "" && entry.ClassifierOutput == "" {
		return nil, []Issue{{Path: path, Message: "catalog file must contain an entry or entries array"}}
	}
	return []RawEntry{entry}, nil
}

func unmarshalYAMLWithJSONTags(payload []byte, target any) error {
	var raw any
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return err
	}
	encoded, err := json.Marshal(yamlToJSON(raw))
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}

func yamlToJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = yamlToJSON(value)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[fmt.Sprint(key)] = yamlToJSON(value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, value := range typed {
			out[index] = yamlToJSON(value)
		}
		return out
	default:
		return value
	}
}

func normalizeClassifierOutput(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	switch value {
	case connectordefinitions.SupportVerdictSupported,
		connectordefinitions.SupportVerdictExtensionRequired,
		connectordefinitions.SupportVerdictBespokeRequired:
		return value
	default:
		return ""
	}
}

func normalizeSourceID(sourceID string) (string, error) {
	definition, err := connectordefinitions.Normalize(connectordefinitions.Definition{SourceID: sourceID})
	if err != nil {
		return "", err
	}
	return definition.SourceID, nil
}

func statusForReport(report connectordefinitions.SupportReport) string {
	switch report.Verdict {
	case connectordefinitions.SupportVerdictSupported:
		return StatusCatalogReady
	case connectordefinitions.SupportVerdictExtensionRequired:
		return StatusNeedsAuthExtension
	default:
		return StatusNeedsBespokeRuntime
	}
}

func proofGateIssues(path string, definition connectordefinitions.Definition) []Issue {
	var issues []Issue
	if definition.Transport == nil || definition.Transport.Verification == nil || strings.TrimSpace(definition.Transport.Verification.Path) == "" {
		issues = append(issues, Issue{Path: path, Message: "verification endpoint is required"})
	}
	highValueFamilies := 0
	for _, family := range definition.ResourceFamilies {
		if len(family.Coverage) == 0 {
			issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("resource family %q must declare coverage dimensions", family.ID)})
			continue
		}
		familyHighValue := false
		for _, dimension := range family.Coverage {
			dimensionID := proofGateDimensionID(family.ID, dimension)
			if dimension.HighValue {
				familyHighValue = true
			}
			if !dimension.HighValue {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(dimension.Support)) {
			case "supported", "partial":
				if len(dimension.EvidenceTypes) == 0 {
					issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("resource family %q high-value coverage dimension %q must declare evidence types", family.ID, dimensionID)})
				}
				if len(dimension.ControlDomains) == 0 {
					issues = append(issues, Issue{Path: path, Message: fmt.Sprintf("resource family %q high-value coverage dimension %q must declare control domains", family.ID, dimensionID)})
				}
			}
		}
		if familyHighValue {
			highValueFamilies++
		}
	}
	if len(definition.ResourceFamilies) < 2 || highValueFamilies > 12 {
		issues = append(issues, Issue{Path: path, Message: "definition must include at least 2 resource families and at most 12 high-value resource families"})
	}
	if highValueFamilies == 0 {
		issues = append(issues, Issue{Path: path, Message: "at least one high-value coverage dimension is required"})
	}
	return issues
}

func proofGateDimensionID(familyID string, dimension connectordefinitions.CoverageDimensionSpec) string {
	if id := strings.TrimSpace(dimension.ID); id != "" {
		return id
	}
	dimensionType := strings.TrimSpace(dimension.Type)
	if familyID == "" || dimensionType == "" {
		return ""
	}
	return strings.Trim(familyID+"_"+dimensionType, "_")
}

func verificationPath(definition connectordefinitions.Definition) string {
	if definition.Transport == nil || definition.Transport.Verification == nil {
		return ""
	}
	return strings.TrimSpace(definition.Transport.Verification.Path)
}

func resourceFamilyIDs(definition connectordefinitions.Definition) []string {
	ids := make([]string, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		if strings.TrimSpace(family.ID) != "" {
			ids = append(ids, family.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func needsAuthExtension(err error, report connectordefinitions.SupportReport) bool {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "auth model") {
		return true
	}
	for _, missing := range report.MissingFeatures {
		if strings.HasPrefix(missing, "auth.") {
			return true
		}
	}
	return false
}

func intersect(left []string, right []string) []string {
	seen := map[string]struct{}{}
	for _, value := range left {
		seen[value] = struct{}{}
	}
	var overlap []string
	for _, value := range right {
		if _, ok := seen[value]; ok {
			overlap = append(overlap, value)
		}
	}
	sort.Strings(overlap)
	return overlap
}
