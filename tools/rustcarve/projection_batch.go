package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectorcatalog"
)

const projectionBatchPlanV1 = "cerebro.rustcarve.projection-batch-plan/v1"

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

func discoverProjectionBatchArtifacts(root, exclusionPath string) (map[string][]byte, error) {
	plan, err := discoverProjectionBatchPlan(root, exclusionPath)
	if err != nil {
		return nil, err
	}
	batchPayload, err := marshalJSON(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal projection batch plan: %w", err)
	}
	plannerRequest, err := buildProjectionPlanRequest(plan)
	if err != nil {
		return nil, err
	}
	plannerPayload, err := marshalJSON(plannerRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal projection planner request: %w", err)
	}
	return map[string][]byte{
		"projection-batch-plan.json":   batchPayload,
		"projection-plan-request.json": plannerPayload,
	}, nil
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
		implPaths, testPaths, excludedPaths, blockers := classifyImplementationFiles(root, implementationSet, exclusions, fileSourceIDs)
		batch.ImplementationFiles = append(batch.ImplementationFiles, implPaths...)
		batch.TestFiles = append(batch.TestFiles, testPaths...)
		batch.ExcludedPaths = append(batch.ExcludedPaths, excludedPaths...)
		batch.Blockers = append(batch.Blockers, blockers...)
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

// classifyImplementationFiles decides, for each discovered Go implementation
// path, whether it becomes an eligible deletion candidate (implementation
// plus its paired test file, if present), stays blocked because more than
// one source shares the same implementation file, or is excluded by the
// ownership manifest (in which case the file and its paired test file, if
// also listed, are recorded as excluded and never reach the candidate
// pipeline regardless of how many sources reference them).
func classifyImplementationFiles(root string, implementationSet map[string]struct{}, exclusions map[string]struct{}, fileSourceIDs map[string]map[string]struct{}) (implementationFiles, testFiles, excludedPaths, blockers []string) {
	for path := range implementationSet {
		testPath := strings.TrimSuffix(path, ".go") + "_test.go"
		if _, excluded := exclusions[path]; excluded {
			excludedPaths = append(excludedPaths, path)
			if _, testExcluded := exclusions[testPath]; testExcluded {
				excludedPaths = append(excludedPaths, testPath)
			}
			continue
		}
		if len(fileSourceIDs[path]) != 1 {
			blockers = append(blockers, "shared_go_projection_file:"+path)
			continue
		}
		implementationFiles = append(implementationFiles, path)
		if fileExists(filepath.Join(root, filepath.FromSlash(testPath))) {
			if _, excluded := exclusions[testPath]; excluded {
				excludedPaths = append(excludedPaths, testPath)
			} else {
				testFiles = append(testFiles, testPath)
			}
		}
	}
	return implementationFiles, testFiles, excludedPaths, blockers
}
