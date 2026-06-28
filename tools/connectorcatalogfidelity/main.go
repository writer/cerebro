package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"gopkg.in/yaml.v3"
)

type options struct {
	root       string
	catalogDir string
	write      bool
	check      bool
	jsonOut    string
}

type report struct {
	TotalEntries   int                  `json:"total_entries"`
	ChangedEntries int                  `json:"changed_entries"`
	ChangedFiles   int                  `json:"changed_files"`
	ChangeCount    int                  `json:"change_count"`
	Files          []fileReport         `json:"files,omitempty"`
	Changes        []fidelityChangeItem `json:"changes,omitempty"`
}

type fileReport struct {
	Path           string `json:"path"`
	Entries        int    `json:"entries"`
	ChangedEntries int    `json:"changed_entries"`
	ChangeCount    int    `json:"change_count"`
}

type fidelityChangeItem struct {
	FilePath string `json:"file_path"`
	connectorcatalog.DefinitionFidelityChange
}

type processedFile struct {
	report  fileReport
	entries []connectorcatalog.RawEntry
	changes []connectorcatalog.DefinitionFidelityChange
	split   bool
}

type catalogFile struct {
	Entries []catalogEntry `json:"entries"`
}

type catalogEntry struct {
	ClassifierOutput string         `json:"classifier_output"`
	Definition       map[string]any `json:"definition"`
}

var computedDefinitionKeys = []string{
	"validation",
	"promotion",
	"current_version",
	"runtime",
	"stage",
	"maturity",
	"created_at",
	"updated_at",
}

func main() {
	var opts options
	flag.StringVar(&opts.root, "root", ".", "repository root")
	flag.StringVar(&opts.catalogDir, "catalog", "internal/connectorcatalog/catalog", "connector catalog directory")
	flag.BoolVar(&opts.write, "write", false, "write deterministic fidelity updates to catalog files")
	flag.BoolVar(&opts.check, "check", false, "fail when catalog fidelity updates are not committed")
	flag.StringVar(&opts.jsonOut, "json-out", "", "write JSON change report to this path")
	flag.Parse()

	result, err := run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connector-catalog-fidelity: %v\n", err)
		os.Exit(1)
	}
	if opts.jsonOut != "" {
		if err := writeJSON(opts.jsonOut, result); err != nil {
			fmt.Fprintf(os.Stderr, "connector-catalog-fidelity: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("connector-catalog-fidelity: entries=%d changed_entries=%d changed_files=%d changes=%d\n",
		result.TotalEntries,
		result.ChangedEntries,
		result.ChangedFiles,
		result.ChangeCount,
	)
	if opts.check && result.ChangedEntries > 0 {
		fmt.Fprintf(os.Stderr, "connector-catalog-fidelity: %d definition(s) need deterministic fidelity updates; run `make connector-catalog-fidelity-generate`\n", result.ChangedEntries)
		os.Exit(1)
	}
}

func run(opts options) (report, error) {
	root := filepath.Clean(strings.TrimSpace(opts.root))
	if root == "" {
		root = "."
	}
	catalogDir := strings.TrimSpace(opts.catalogDir)
	if catalogDir == "" {
		catalogDir = "internal/connectorcatalog/catalog"
	}
	if !filepath.IsAbs(catalogDir) {
		catalogDir = filepath.Join(root, catalogDir)
	}
	catalogDir = filepath.Clean(catalogDir)

	var result report
	err := filepath.WalkDir(catalogDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		processed, err := processFile(root, path)
		if err != nil {
			return err
		}
		result.TotalEntries += processed.report.Entries
		if len(processed.entries) == 0 {
			return nil
		}
		result.ChangedEntries += processed.report.ChangedEntries
		result.ChangedFiles++
		result.ChangeCount += processed.report.ChangeCount
		result.Files = append(result.Files, processed.report)
		for _, change := range processed.changes {
			result.Changes = append(result.Changes, fidelityChangeItem{FilePath: processed.report.Path, DefinitionFidelityChange: change})
		}
		if opts.write {
			if processed.split {
				if err := writeSplitCatalogFiles(catalogDir, path, processed.entries); err != nil {
					return err
				}
				return nil
			}
			if err := writeCatalogFile(path, processed.entries); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return report{}, err
	}
	sort.SliceStable(result.Files, func(i int, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	sort.SliceStable(result.Changes, func(i int, j int) bool {
		if result.Changes[i].FilePath != result.Changes[j].FilePath {
			return result.Changes[i].FilePath < result.Changes[j].FilePath
		}
		if result.Changes[i].SourceID != result.Changes[j].SourceID {
			return result.Changes[i].SourceID < result.Changes[j].SourceID
		}
		if result.Changes[i].FamilyID != result.Changes[j].FamilyID {
			return result.Changes[i].FamilyID < result.Changes[j].FamilyID
		}
		return result.Changes[i].DefinitionFidelityChange.Path < result.Changes[j].DefinitionFidelityChange.Path
	})
	return result, nil
}

func processFile(root string, path string) (processedFile, error) {
	rel := slashRel(root, path)
	payload, err := os.ReadFile(path) //nolint:gosec // repository-local catalog maintenance tool.
	if err != nil {
		return processedFile{}, fmt.Errorf("read %s: %w", rel, err)
	}
	entries, err := decodeCatalogEntries(path, payload)
	if err != nil {
		return processedFile{}, fmt.Errorf("%s: %w", rel, err)
	}
	result := fileReport{Path: rel, Entries: len(entries)}
	changedEntries := make([]connectorcatalog.RawEntry, len(entries))
	copy(changedEntries, entries)
	var allChanges []connectorcatalog.DefinitionFidelityChange
	for i, entry := range entries {
		hardened, changes := connectorcatalog.HardenDefinitionFidelity(entry.Definition)
		if len(changes) == 0 || definitionsEqual(entry.Definition, hardened) {
			continue
		}
		if _, err := connectordefinitions.Normalize(hardened); err != nil {
			return processedFile{}, fmt.Errorf("%s source %q normalize after hardening: %w", rel, entry.Definition.SourceID, err)
		}
		changedEntries[i].Definition = hardened
		result.ChangedEntries++
		result.ChangeCount += len(changes)
		allChanges = append(allChanges, changes...)
	}
	split := len(entries) > 1
	if split {
		for _, entry := range changedEntries {
			change := connectorcatalog.DefinitionFidelityChange{
				SourceID: strings.TrimSpace(entry.Definition.SourceID),
				Path:     "catalog_file.layout",
				Detail:   "split multi-entry catalog file into one source file",
			}
			allChanges = append(allChanges, change)
		}
		if result.ChangedEntries < len(entries) {
			result.ChangedEntries = len(entries)
		}
		result.ChangeCount += len(entries)
	}
	if result.ChangedEntries == 0 {
		return processedFile{report: result}, nil
	}
	return processedFile{report: result, entries: changedEntries, changes: allChanges, split: split}, nil
}

func decodeCatalogEntries(path string, payload []byte) ([]connectorcatalog.RawEntry, error) {
	ext := strings.ToLower(filepath.Ext(path))
	decode := func(target any) error {
		if ext == ".json" {
			return json.Unmarshal(payload, target)
		}
		return unmarshalYAMLWithJSONTags(payload, target)
	}
	var file connectorcatalog.EntryFile
	if err := decode(&file); err == nil && len(file.Entries) != 0 {
		return file.Entries, nil
	}
	var entries []connectorcatalog.RawEntry
	if err := decode(&entries); err == nil && len(entries) != 0 {
		return entries, nil
	}
	var entry connectorcatalog.RawEntry
	if err := decode(&entry); err != nil {
		return nil, err
	}
	if entry.Definition.SourceID == "" && entry.ClassifierOutput == "" {
		return nil, errors.New("catalog file must contain an entry or entries array")
	}
	return []connectorcatalog.RawEntry{entry}, nil
}

func writeCatalogFile(path string, entries []connectorcatalog.RawEntry) error {
	payload, err := renderCatalogEntries(entries)
	if err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0o644
	}
	if err := os.WriteFile(path, payload, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeSplitCatalogFiles(catalogDir string, sourcePath string, entries []connectorcatalog.RawEntry) error {
	if len(entries) <= 1 {
		return writeCatalogFile(sourcePath, entries)
	}
	rewroteSource := false
	for _, entry := range entries {
		target := splitTargetPath(catalogDir, sourcePath, entry.Definition.SourceID)
		if target != sourcePath {
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("split target %s already exists", target)
			} else if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("stat split target %s: %w", target, err)
			}
		} else {
			rewroteSource = true
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return fmt.Errorf("create split target dir %s: %w", filepath.Dir(target), err)
		}
		payload, err := renderCatalogEntries([]connectorcatalog.RawEntry{entry})
		if err != nil {
			return fmt.Errorf("render split target %s: %w", target, err)
		}
		if err := os.WriteFile(target, payload, 0o644); err != nil {
			return fmt.Errorf("write split target %s: %w", target, err)
		}
		if err := os.Chmod(target, 0o644); err != nil {
			return fmt.Errorf("set split target %s permissions: %w", target, err)
		}
	}
	if rewroteSource {
		return nil
	}
	if err := os.Remove(sourcePath); err != nil {
		return fmt.Errorf("remove split source %s: %w", sourcePath, err)
	}
	return nil
}

func splitTargetPath(catalogDir string, sourcePath string, sourceID string) string {
	fileName := catalogSourceFileName(sourceID)
	sourceDir := filepath.Dir(sourcePath)
	if filepath.Clean(sourceDir) == filepath.Clean(catalogDir) {
		base := strings.TrimSuffix(filepath.Base(sourcePath), filepath.Ext(sourcePath))
		sourceDir = filepath.Join(sourceDir, base)
	}
	return filepath.Join(sourceDir, fileName)
}

func catalogSourceFileName(sourceID string) string {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		sourceID = "source"
	}
	sourceID = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(sourceID)
	return sourceID + ".yaml"
}

func renderCatalogEntries(entries []connectorcatalog.RawEntry) ([]byte, error) {
	file := catalogFile{Entries: make([]catalogEntry, 0, len(entries))}
	for _, entry := range entries {
		definitionMap, err := minimalDefinitionMap(entry.Definition)
		if err != nil {
			return nil, err
		}
		file.Entries = append(file.Entries, catalogEntry{
			ClassifierOutput: strings.TrimSpace(entry.ClassifierOutput),
			Definition:       definitionMap,
		})
	}
	return marshalYAMLWithJSONTags(file)
}

func minimalDefinitionMap(definition connectordefinitions.Definition) (map[string]any, error) {
	encoded, err := json.Marshal(definition)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		return nil, err
	}
	for _, key := range computedDefinitionKeys {
		delete(generic, key)
	}
	if emptyMap(generic["ingest"]) {
		delete(generic, "ingest")
	}
	return generic, nil
}

func emptyMap(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		return len(typed) == 0
	case map[any]any:
		return len(typed) == 0
	default:
		return false
	}
}

func marshalYAMLWithJSONTags(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := yaml.Unmarshal(encoded, &generic); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(generic); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
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
		for i, value := range typed {
			out[i] = yamlToJSON(value)
		}
		return out
	default:
		return value
	}
}

func definitionsEqual(left connectordefinitions.Definition, right connectordefinitions.Definition) bool {
	leftPayload, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rightPayload, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftPayload, rightPayload)
}

func writeJSON(path string, result report) error {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report JSON: %w", err)
	}
	payload = append(payload, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func slashRel(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
