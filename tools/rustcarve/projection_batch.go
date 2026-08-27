package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"gopkg.in/yaml.v3"
)

const (
	projectionBatchPlanV1 = "cerebro.rustcarve.projection-batch-plan/v1"
	projectionExclusionV1 = "cerebro.rustcarve.path-exclusions/v1"
)

var authoritativeProjectionTemplates = map[string]struct{}{
	"alert": {}, "asset": {}, "audit_event": {}, "cloud_resource": {},
	"deployment": {}, "endpoint_device": {}, "evidence_cas_reference": {},
	"finding": {}, "group_membership": {}, "identity_app_assignment": {},
	"identity_application": {}, "identity_credential": {}, "identity_group": {},
	"identity_group_membership": {}, "identity_user": {}, "policy": {},
	"repository": {}, "secret": {}, "vulnerability": {},
}

type projectionPathExclusions struct {
	SchemaVersion string   `json:"schema_version"`
	Owner         string   `json:"owner"`
	Revision      string   `json:"revision"`
	Paths         []string `json:"paths"`
}

type projectionBatchPlan struct {
	SchemaVersion          string                    `json:"schema_version"`
	ToolRevision           string                    `json:"tool_revision"`
	RepositoryRevision     string                    `json:"repository_revision,omitempty"`
	InputDigestSHA256      string                    `json:"input_digest_sha256"`
	PlanDigestSHA256       string                    `json:"plan_digest_sha256"`
	EligibleSources        int                       `json:"eligible_sources"`
	EligibleFamilies       int                       `json:"eligible_families"`
	CandidateSources       int                       `json:"candidate_sources"`
	CandidateProductionLOC int                       `json:"candidate_production_lines"`
	CandidateTestLOC       int                       `json:"candidate_test_lines"`
	OwnershipExclusions    projectionOwnershipRecord `json:"ownership_exclusions"`
	Batches                []projectionBatch         `json:"batches"`
	DeletionCandidates     []projectionFileCandidate `json:"deletion_candidates"`
}

type projectionOwnershipRecord struct {
	Owner          string   `json:"owner,omitempty"`
	Revision       string   `json:"revision,omitempty"`
	ManifestPath   string   `json:"manifest_path,omitempty"`
	ManifestDigest string   `json:"manifest_digest_sha256,omitempty"`
	Paths          []string `json:"paths,omitempty"`
}

type projectionBatch struct {
	SourceID            string   `json:"source_id"`
	FamilyIDs           []string `json:"family_ids"`
	EventKinds          []string `json:"event_kinds"`
	ImplementationFiles []string `json:"implementation_files,omitempty"`
	TestFiles           []string `json:"test_files,omitempty"`
	ExcludedPaths       []string `json:"excluded_paths,omitempty"`
	Blockers            []string `json:"blockers,omitempty"`
	ProductionLines     int      `json:"production_lines"`
	TestLines           int      `json:"test_lines"`
}

type projectionFileCandidate struct {
	Path         string   `json:"path"`
	Class        string   `json:"class"`
	DigestSHA256 string   `json:"digest_sha256"`
	Lines        int      `json:"lines"`
	SourceIDs    []string `json:"source_ids"`
}

type projectionProofManifest struct {
	ID              string                      `yaml:"id"`
	RuntimeFamilies []string                    `yaml:"runtime_families"`
	ProviderAPI     *projectionProviderAPIProof `yaml:"provider_api"`
}

type projectionProviderAPIProof struct {
	Status     string                  `yaml:"status"`
	Basis      string                  `yaml:"basis"`
	SpecURL    string                  `yaml:"spec_url"`
	References []string                `yaml:"references"`
	Families   []projectionFamilyProof `yaml:"families"`
}

type projectionFamilyProof struct {
	ID     string `yaml:"id"`
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

type projectionRegistryEntry struct {
	Kind     string
	Function string
}

func discoverProjectionBatchArtifacts(root, exclusionPath string) (map[string][]byte, error) {
	plan, err := discoverProjectionBatchPlan(root, exclusionPath)
	if err != nil {
		return nil, err
	}
	payload, err := marshalJSON(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal projection batch plan: %w", err)
	}
	return map[string][]byte{"projection-batch-plan.json": payload}, nil
}

func discoverProjectionBatchPlan(root, exclusionPath string) (projectionBatchPlan, error) {
	root, err := secureRepositoryRoot(root)
	if err != nil {
		return projectionBatchPlan{}, err
	}
	exclusions, exclusionRecord, err := loadProjectionExclusions(root, exclusionPath)
	if err != nil {
		return projectionBatchPlan{}, err
	}

	analysis, err := connectorcatalog.AnalyzeDir(filepath.Join(root, "internal/connectorcatalog/catalog"), connectorcatalog.Options{})
	if err != nil {
		return projectionBatchPlan{}, fmt.Errorf("load connector catalog: %w", err)
	}
	if len(analysis.Issues) != 0 {
		return projectionBatchPlan{}, fmt.Errorf("connector catalog contains %d issue(s)", len(analysis.Issues))
	}
	proofs, proofPaths, err := loadProjectionProofs(root)
	if err != nil {
		return projectionBatchPlan{}, err
	}
	registryEntries, functionFiles, sourceProjectionInputs, err := inspectProjectionRegistry(root)
	if err != nil {
		return projectionBatchPlan{}, err
	}

	entriesByKind := make(map[string][]projectionRegistryEntry)
	fileSourceIDs := make(map[string]map[string]struct{})
	for _, entry := range registryEntries {
		entriesByKind[entry.Kind] = append(entriesByKind[entry.Kind], entry)
		if path := functionFiles[entry.Function]; path != "" {
			sourceID := eventSourceID(entry.Kind)
			if sourceID != "" {
				if fileSourceIDs[path] == nil {
					fileSourceIDs[path] = make(map[string]struct{})
				}
				fileSourceIDs[path][sourceID] = struct{}{}
			}
		}
	}

	definitionPaths := make([]string, 0, len(analysis.Entries))
	batches := make([]projectionBatch, 0)
	eligibleFamilies := 0
	for _, entry := range analysis.Entries {
		definitionPaths = append(definitionPaths, filepath.ToSlash(filepath.Join("internal/connectorcatalog/catalog", entry.Path)))
		proof := proofs[entry.Definition.SourceID]
		familyIDs, eventKinds, ready := projectionReadyFamilies(entry.Definition, proof)
		if !ready {
			continue
		}
		eligibleFamilies += len(familyIDs)
		batch := projectionBatch{SourceID: entry.Definition.SourceID, FamilyIDs: familyIDs, EventKinds: eventKinds}
		implementationSet := make(map[string]struct{})
		for _, kind := range eventKinds {
			for _, registryEntry := range entriesByKind[kind] {
				if path := functionFiles[registryEntry.Function]; path != "" {
					implementationSet[path] = struct{}{}
				}
			}
		}
		if len(implementationSet) == 0 {
			batch.Blockers = append(batch.Blockers, "no_static_go_projection_path")
		}
		for path := range implementationSet {
			testPath := strings.TrimSuffix(path, ".go") + "_test.go"
			if _, excluded := exclusions[path]; excluded {
				batch.ExcludedPaths = append(batch.ExcludedPaths, path)
				if _, testExcluded := exclusions[testPath]; testExcluded {
					batch.ExcludedPaths = append(batch.ExcludedPaths, testPath)
				}
				continue
			}
			if len(fileSourceIDs[path]) != 1 {
				batch.Blockers = append(batch.Blockers, "shared_go_projection_file:"+path)
				continue
			}
			batch.ImplementationFiles = append(batch.ImplementationFiles, path)
			if fileExists(filepath.Join(root, filepath.FromSlash(testPath))) {
				if _, excluded := exclusions[testPath]; excluded {
					batch.ExcludedPaths = append(batch.ExcludedPaths, testPath)
				} else {
					batch.TestFiles = append(batch.TestFiles, testPath)
				}
			}
		}
		sort.Strings(batch.ImplementationFiles)
		sort.Strings(batch.TestFiles)
		sort.Strings(batch.ExcludedPaths)
		sort.Strings(batch.Blockers)
		batches = append(batches, batch)
	}
	sort.Slice(batches, func(i, j int) bool { return batches[i].SourceID < batches[j].SourceID })

	candidates, err := buildProjectionCandidates(root, batches)
	if err != nil {
		return projectionBatchPlan{}, err
	}
	candidateSources := 0
	productionLines := 0
	testLines := 0
	lineByPath := make(map[string]int, len(candidates))
	for _, candidate := range candidates {
		lineByPath[candidate.Path] = candidate.Lines
		if candidate.Class == "production" {
			productionLines += candidate.Lines
		} else {
			testLines += candidate.Lines
		}
	}
	for i := range batches {
		for _, path := range batches[i].ImplementationFiles {
			batches[i].ProductionLines += lineByPath[path]
		}
		for _, path := range batches[i].TestFiles {
			batches[i].TestLines += lineByPath[path]
		}
		if len(batches[i].ImplementationFiles) != 0 || len(batches[i].TestFiles) != 0 {
			candidateSources++
		}
	}

	inputPaths := append(definitionPaths, proofPaths...)
	inputPaths = append(inputPaths, sourceProjectionInputs...)
	if exclusionRecord.ManifestPath != "" {
		inputPaths = append(inputPaths, exclusionRecord.ManifestPath)
	}
	inputDigest, err := digestProjectionInputs(root, inputPaths)
	if err != nil {
		return projectionBatchPlan{}, err
	}
	plan := projectionBatchPlan{
		SchemaVersion:          projectionBatchPlanV1,
		ToolRevision:           rustcarveToolRevision,
		RepositoryRevision:     gitRevision(root),
		InputDigestSHA256:      inputDigest,
		EligibleSources:        len(batches),
		EligibleFamilies:       eligibleFamilies,
		CandidateSources:       candidateSources,
		CandidateProductionLOC: productionLines,
		CandidateTestLOC:       testLines,
		OwnershipExclusions:    exclusionRecord,
		Batches:                batches,
		DeletionCandidates:     candidates,
	}
	plan.PlanDigestSHA256, err = digestProjectionPlan(plan)
	if err != nil {
		return projectionBatchPlan{}, err
	}
	return plan, nil
}

func secureRepositoryRoot(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve root symlinks: %w", err)
	}
	for _, required := range []string{"go.mod", "Cargo.toml", "internal/connectorcatalog/catalog", "internal/sourceprojection"} {
		if _, err := os.Stat(filepath.Join(root, required)); err != nil {
			return "", fmt.Errorf("repository root missing %s: %w", required, err)
		}
	}
	return root, nil
}

func loadProjectionExclusions(root, relative string) (map[string]struct{}, projectionOwnershipRecord, error) {
	set := make(map[string]struct{})
	if strings.TrimSpace(relative) == "" {
		return set, projectionOwnershipRecord{}, nil
	}
	relative, err := cleanRepositoryRelativePath(relative)
	if err != nil {
		return nil, projectionOwnershipRecord{}, fmt.Errorf("exclusion manifest: %w", err)
	}
	payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative))) // #nosec G304 -- validated repository-relative operator input.
	if err != nil {
		return nil, projectionOwnershipRecord{}, fmt.Errorf("read exclusion manifest: %w", err)
	}
	var manifest projectionPathExclusions
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, projectionOwnershipRecord{}, fmt.Errorf("decode exclusion manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, projectionOwnershipRecord{}, errors.New("decode exclusion manifest: trailing JSON value")
	}
	if manifest.SchemaVersion != projectionExclusionV1 || strings.TrimSpace(manifest.Owner) == "" || strings.TrimSpace(manifest.Revision) == "" {
		return nil, projectionOwnershipRecord{}, errors.New("exclusion manifest requires the current schema, owner, and revision")
	}
	for _, path := range manifest.Paths {
		path, err = cleanRepositoryRelativePath(path)
		if err != nil {
			return nil, projectionOwnershipRecord{}, fmt.Errorf("excluded path: %w", err)
		}
		if _, exists := set[path]; exists {
			return nil, projectionOwnershipRecord{}, fmt.Errorf("duplicate excluded path %s", path)
		}
		set[path] = struct{}{}
	}
	paths := sortedSet(set)
	return set, projectionOwnershipRecord{
		Owner: manifest.Owner, Revision: manifest.Revision, ManifestPath: relative,
		ManifestDigest: sha256Hex(payload), Paths: paths,
	}, nil
}

func loadProjectionProofs(root string) (map[string]projectionProofManifest, []string, error) {
	directories, err := os.ReadDir(filepath.Join(root, "sources"))
	if err != nil {
		return nil, nil, fmt.Errorf("read source manifests: %w", err)
	}
	proofs := make(map[string]projectionProofManifest)
	paths := make([]string, 0)
	for _, directory := range directories {
		if !directory.IsDir() || directory.Type()&fs.ModeSymlink != 0 {
			continue
		}
		relative := filepath.ToSlash(filepath.Join("sources", directory.Name(), "catalog.yaml"))
		path := filepath.Join(root, filepath.FromSlash(relative))
		payload, err := os.ReadFile(path) // #nosec G304 -- bounded repository catalog path.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", relative, err)
		}
		var proof projectionProofManifest
		if err := yaml.Unmarshal(payload, &proof); err != nil {
			return nil, nil, fmt.Errorf("decode %s: %w", relative, err)
		}
		proof.ID = strings.TrimSpace(proof.ID)
		if proof.ID == "" {
			return nil, nil, fmt.Errorf("%s has no source id", relative)
		}
		if _, exists := proofs[proof.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate source proof %s", proof.ID)
		}
		proofs[proof.ID] = proof
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	return proofs, paths, nil
}

func projectionReadyFamilies(definition connectordefinitions.Definition, proof projectionProofManifest) ([]string, []string, bool) {
	verified := verifiedProjectionProofs(proof)
	familyIDs := make([]string, 0, len(definition.ResourceFamilies))
	eventKinds := make([]string, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		template := ""
		if family.Projection != nil {
			template = strings.TrimSpace(family.Projection.Template)
		}
		if _, supported := authoritativeProjectionTemplates[template]; !supported {
			return nil, nil, false
		}
		method := strings.TrimSpace(family.Method)
		if method == "" {
			method = "GET"
		}
		baseURL := ""
		if family.Config != nil {
			baseURL = family.Config.BaseURL
		}
		locator, ok := canonicalFamilyLocator(baseURL, family.Path)
		if !ok {
			return nil, nil, false
		}
		key := family.ID + "\x00" + method + "\x00" + locator
		if _, ok := verified[key]; !ok {
			return nil, nil, false
		}
		familyIDs = append(familyIDs, family.ID)
		kind := strings.TrimSpace(family.Event.Kind)
		if kind == "" {
			kind = strings.TrimSpace(family.EventKind)
		}
		if kind == "" || !strings.Contains(kind, ".") {
			kind = definition.SourceID + "." + family.ID
		}
		eventKinds = append(eventKinds, kind)
	}
	sort.Strings(familyIDs)
	sort.Strings(eventKinds)
	return familyIDs, eventKinds, len(familyIDs) != 0
}

func verifiedProjectionProofs(proof projectionProofManifest) map[string]struct{} {
	verified := make(map[string]struct{})
	api := proof.ProviderAPI
	if api == nil || strings.TrimSpace(api.Status) != "verified" || strings.TrimSpace(api.Basis) != "declared" || (strings.TrimSpace(api.SpecURL) == "" && len(api.References) == 0) {
		return verified
	}
	runtime := make(map[string]struct{}, len(proof.RuntimeFamilies))
	for _, family := range proof.RuntimeFamilies {
		runtime[family] = struct{}{}
	}
	for _, family := range api.Families {
		if _, ok := runtime[family.ID]; !ok || strings.TrimSpace(family.Path) == "" {
			continue
		}
		method := strings.TrimSpace(family.Method)
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "POST" {
			continue
		}
		path, ok := canonicalContractLocator(family.Path)
		if ok {
			verified[family.ID+"\x00"+method+"\x00"+path] = struct{}{}
		}
	}
	return verified
}

func canonicalFamilyLocator(baseURL, path string) (string, bool) {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	if strings.HasPrefix(baseURL, "https://") && !strings.Contains(baseURL, "${") {
		return canonicalContractLocator(baseURL + path)
	}
	return canonicalPathTemplate(path)
}

func canonicalContractLocator(locator string) (string, bool) {
	if strings.HasPrefix(locator, "/") {
		return canonicalPathTemplate(locator)
	}
	remainder, ok := strings.CutPrefix(locator, "https://")
	if !ok {
		return "", false
	}
	host, path, ok := strings.Cut(remainder, "/")
	if !ok || host == "" || strings.ContainsAny(host, "@?#\\") {
		return "", false
	}
	canonical, ok := canonicalPathTemplate("/" + path)
	if !ok {
		return "", false
	}
	return "https://" + host + canonical, true
}

func canonicalPathTemplate(path string) (string, bool) {
	pathPart, query, hasQuery := strings.Cut(path, "?")
	if !strings.HasPrefix(pathPart, "/") {
		return "", false
	}
	segments := strings.Split(pathPart, "/")
	for i, segment := range segments {
		if isPathParameter(segment) {
			segments[i] = "{}"
		} else if strings.ContainsAny(segment, "{}") {
			return "", false
		}
	}
	canonical := strings.Join(segments, "/")
	if hasQuery {
		if strings.ContainsAny(query, "{}") {
			return "", false
		}
		canonical += "?" + query
	}
	return canonical, true
}

func isPathParameter(segment string) bool {
	parameter := ""
	if strings.HasPrefix(segment, "${config.") && strings.HasSuffix(segment, "}") {
		parameter = strings.TrimSuffix(strings.TrimPrefix(segment, "${config."), "}")
	} else if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
		parameter = strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
	}
	if parameter == "" {
		return false
	}
	for _, character := range parameter {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func inspectProjectionRegistry(root string) ([]projectionRegistryEntry, map[string]string, []string, error) {
	directory := filepath.Join(root, "internal/sourceprojection")
	entries := make([]projectionRegistryEntry, 0)
	functionFiles := make(map[string]string)
	inputs := make([]string, 0)
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		inputs = append(inputs, relative)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
		if !strings.HasSuffix(path, "_test.go") {
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if ok && function.Recv == nil {
					if existing := functionFiles[function.Name.Name]; existing != "" && existing != relative {
						return fmt.Errorf("duplicate source projection function %s", function.Name.Name)
					}
					functionFiles[function.Name.Name] = relative
				}
			}
		}
		if relative == "internal/sourceprojection/registry_builtins.go" {
			ast.Inspect(parsed, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				for _, element := range literal.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := goStringLiteral(pair.Key)
					identifier, valueOK := pair.Value.(*ast.Ident)
					if ok && valueOK {
						entries = append(entries, projectionRegistryEntry{Kind: key, Function: identifier.Name})
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("inspect source projection registry: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind == entries[j].Kind {
			return entries[i].Function < entries[j].Function
		}
		return entries[i].Kind < entries[j].Kind
	})
	sort.Strings(inputs)
	return entries, functionFiles, inputs, nil
}

func goStringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func buildProjectionCandidates(root string, batches []projectionBatch) ([]projectionFileCandidate, error) {
	type candidateState struct {
		class     string
		sourceIDs map[string]struct{}
	}
	states := make(map[string]*candidateState)
	for _, batch := range batches {
		for _, path := range batch.ImplementationFiles {
			if states[path] == nil {
				states[path] = &candidateState{class: "production", sourceIDs: make(map[string]struct{})}
			}
			states[path].sourceIDs[batch.SourceID] = struct{}{}
		}
		for _, path := range batch.TestFiles {
			if states[path] == nil {
				states[path] = &candidateState{class: "test", sourceIDs: make(map[string]struct{})}
			}
			states[path].sourceIDs[batch.SourceID] = struct{}{}
		}
	}
	paths := make([]string, 0, len(states))
	for path := range states {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	candidates := make([]projectionFileCandidate, 0, len(paths))
	for _, path := range paths {
		payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path))) // #nosec G304 -- discovered repository path.
		if err != nil {
			return nil, fmt.Errorf("read deletion candidate %s: %w", path, err)
		}
		candidates = append(candidates, projectionFileCandidate{
			Path: path, Class: states[path].class, DigestSHA256: sha256Hex(payload),
			Lines: sourceLineCount(payload), SourceIDs: sortedSet(states[path].sourceIDs),
		})
	}
	return candidates, nil
}

func digestProjectionInputs(root string, paths []string) (string, error) {
	sort.Strings(paths)
	hash := sha256.New()
	previous := ""
	for _, path := range paths {
		if path == previous {
			continue
		}
		previous = path
		payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path))) // #nosec G304 -- discovered repository input path.
		if err != nil {
			return "", fmt.Errorf("read planner input %s: %w", path, err)
		}
		_, _ = hash.Write([]byte(path))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(payload)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestProjectionPlan(plan projectionBatchPlan) (string, error) {
	plan.PlanDigestSHA256 = ""
	payload, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("marshal projection plan digest: %w", err)
	}
	return sha256Hex(payload), nil
}

func gitRevision(root string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "rev-parse", "HEAD") // #nosec G204 -- fixed command and arguments.
	command.Dir = root
	payload, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func cleanRepositoryRelativePath(path string) (string, error) {
	path = filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	if path == "" || path == "." || filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../") {
		return "", fmt.Errorf("path must be repository-relative: %q", path)
	}
	return path, nil
}

func sourceLineCount(payload []byte) int {
	if len(payload) == 0 {
		return 0
	}
	lines := bytes.Count(payload, []byte{'\n'})
	if payload[len(payload)-1] != '\n' {
		lines++
	}
	return lines
}

func eventSourceID(kind string) string {
	sourceID, _, ok := strings.Cut(kind, ".")
	if !ok {
		return ""
	}
	return sourceID
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func sortedSet[T ~string](set map[T]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, string(value))
	}
	sort.Strings(values)
	return values
}
