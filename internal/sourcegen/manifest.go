package sourcegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/sourcegen/stampfile"
)

var ErrGeneratedOutputModified = errors.New("generated output contains changes not owned by sourcegen")

const (
	generatorVersion = "sourcegen/v3"
	manifestName     = ".sourcegen-manifest.json"

	ChangePlanReady   = "ready"
	ChangePlanBlocked = "blocked"

	ChangeActionCreate    = "create"
	ChangeActionUpdate    = "update"
	ChangeActionUnchanged = "unchanged"
	ChangeActionDelete    = "delete"
	ChangeActionConflict  = "ownership_conflict"
)

type generationManifest struct {
	GeneratorVersion string            `json:"generator_version"`
	SourceID         string            `json:"source_id"`
	InputDigest      string            `json:"input_digest"`
	ProofDigest      string            `json:"proof_digest"`
	Outputs          map[string]string `json:"outputs"`
}

type generationPlan struct {
	ManifestPath string
	ProofPath    string
	Manifest     generationManifest
	ProofPayload []byte
	StalePaths   []string
	ChangePlan   ChangePlan
}

// ChangePlan reports every filesystem action sourcegen would take before it
// writes or removes any artifact.
type ChangePlan struct {
	Status         string       `json:"status"`
	Changes        []FileChange `json:"changes"`
	RequiredChecks []string     `json:"required_checks"`
}

// FileChange is one content-addressed sourcegen filesystem action.
type FileChange struct {
	Path      string `json:"path"`
	Action    string `json:"action"`
	Ownership string `json:"ownership"`
}

func planGeneration(request normalizedRequest, files []generatedFile) (generationPlan, error) {
	manifestPath := filepath.Join(request.OutputDir, "sources", request.SourceID, manifestName)
	proofPath := filepath.Join(request.OutputDir, "sources", request.SourceID, proofBundleName)
	previous, err := loadGenerationManifest(manifestPath)
	if err != nil {
		return generationPlan{}, err
	}
	digestInput := request
	digestInput.OutputDir = "."
	digestInput.DryRun = false
	digestInput.Force = false
	inputPayload, err := json.Marshal(digestInput)
	if err != nil {
		return generationPlan{}, fmt.Errorf("marshal sourcegen input: %w", err)
	}
	inputDigest, err := stampfile.HashReader(bytes.NewReader(inputPayload))
	if err != nil {
		return generationPlan{}, fmt.Errorf("hash sourcegen input: %w", err)
	}
	next := generationManifest{
		GeneratorVersion: generatorVersion,
		SourceID:         request.SourceID,
		InputDigest:      inputDigest,
		Outputs:          make(map[string]string, len(files)),
	}
	for _, file := range files {
		relativePath, err := manifestRelativePath(request.OutputDir, file.Path)
		if err != nil {
			return generationPlan{}, err
		}
		digest, err := stampfile.HashReader(strings.NewReader(file.Content))
		if err != nil {
			return generationPlan{}, fmt.Errorf("hash generated output %s: %w", relativePath, err)
		}
		next.Outputs[relativePath] = digest
	}
	proofPayload, err := marshalProofBundle(buildProofBundle(request, next))
	if err != nil {
		return generationPlan{}, fmt.Errorf("marshal sourcegen proof bundle: %w", err)
	}
	proofDigest, err := stampfile.HashReader(bytes.NewReader(proofPayload))
	if err != nil {
		return generationPlan{}, fmt.Errorf("hash sourcegen proof bundle: %w", err)
	}
	next.ProofDigest = proofDigest
	plan := generationPlan{ManifestPath: manifestPath, ProofPath: proofPath, Manifest: next, ProofPayload: proofPayload}
	if previous != nil {
		for previousPath := range previous.Outputs {
			if _, retained := next.Outputs[previousPath]; !retained {
				plan.StalePaths = append(plan.StalePaths, filepath.Join(request.OutputDir, filepath.FromSlash(previousPath)))
			}
		}
	}
	sort.Strings(plan.StalePaths)
	plan.ChangePlan, err = buildChangePlan(request, files, plan, previous)
	if err != nil {
		return generationPlan{}, err
	}
	return plan, nil
}

func preflightGeneration(request normalizedRequest, files []generatedFile, plan generationPlan) error {
	previous, err := loadGenerationManifest(plan.ManifestPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		current, err := os.ReadFile(file.Path) // #nosec G304 -- generated path is constrained to OutputDir.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if bytes.Equal(current, []byte(file.Content)) || request.Force {
			continue
		}
		relativePath, err := manifestRelativePath(request.OutputDir, file.Path)
		if err != nil {
			return err
		}
		if previous != nil && digestMatches(current, previous.Outputs[relativePath]) {
			continue
		}
		return fmt.Errorf("%w: %s; preserve the changes in an override file or pass force=true", ErrGeneratedOutputModified, file.Path)
	}
	for _, stalePath := range plan.StalePaths {
		current, err := os.ReadFile(stalePath) // #nosec G304 -- path came from a prior constrained manifest.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		relativePath, err := manifestRelativePath(request.OutputDir, stalePath)
		if err != nil {
			return err
		}
		if !request.Force && (previous == nil || !digestMatches(current, previous.Outputs[relativePath])) {
			return fmt.Errorf("%w: stale output %s", ErrGeneratedOutputModified, stalePath)
		}
	}
	// The proof path is generated beneath the operator-selected OutputDir and cannot escape it.
	// codeql[go/path-injection]
	currentProof, err := os.ReadFile(plan.ProofPath) // #nosec G304 -- proof path is constrained to OutputDir.
	if err == nil && !bytes.Equal(currentProof, plan.ProofPayload) && !request.Force {
		if previous == nil || !digestMatches(currentProof, previous.ProofDigest) {
			return fmt.Errorf("%w: %s; preserve the changes outside the generated proof bundle or pass force=true", ErrGeneratedOutputModified, plan.ProofPath)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func commitGeneration(plan generationPlan) error {
	for _, stalePath := range plan.StalePaths {
		if err := os.Remove(stalePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale generated output %s: %w", stalePath, err)
		}
	}
	if err := writeGeneratedMetadata(plan.ProofPath, plan.ProofPayload, ".sourcegen-proof-*.tmp"); err != nil {
		return err
	}
	payload, err := marshalGenerationManifest(plan.Manifest)
	if err != nil {
		return err
	}
	return writeGeneratedMetadata(plan.ManifestPath, payload, ".sourcegen-manifest-*.tmp")
}

func marshalGenerationManifest(manifest generationManifest) ([]byte, error) {
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func writeGeneratedMetadata(path string, payload []byte, pattern string) error {
	// Metadata paths are generated beneath the operator-selected OutputDir.
	// codeql[go/path-injection]
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// Temporary metadata is created beside its constrained destination.
	// codeql[go/path-injection]
	temporary, err := os.CreateTemp(filepath.Dir(path), pattern)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Both rename paths are temporary or generated metadata paths beneath OutputDir.
	// codeql[go/path-injection]
	return os.Rename(temporaryPath, path)
}

func buildChangePlan(request normalizedRequest, files []generatedFile, plan generationPlan, previous *generationManifest) (ChangePlan, error) {
	changePlan := ChangePlan{
		Status: ChangePlanReady,
		RequiredChecks: []string{
			fmt.Sprintf("go test ./sources/%s ./internal/sourceprojection -count=1", request.SourceID),
			"make catalog-check",
			"make sourcegen-grammar-check",
		},
	}
	for _, file := range files {
		relativePath, err := manifestRelativePath(request.OutputDir, file.Path)
		if err != nil {
			return ChangePlan{}, err
		}
		action, ownership, err := plannedFileAction(file.Path, []byte(file.Content), outputDigest(previous, relativePath), request.Force)
		if err != nil {
			return ChangePlan{}, err
		}
		changePlan.Changes = append(changePlan.Changes, FileChange{Path: relativePath, Action: action, Ownership: ownership})
	}
	for _, stalePath := range plan.StalePaths {
		relativePath, err := manifestRelativePath(request.OutputDir, stalePath)
		if err != nil {
			return ChangePlan{}, err
		}
		// Stale paths came from a manifest path previously constrained to OutputDir.
		// codeql[go/path-injection]
		current, err := os.ReadFile(stalePath) // #nosec G304 -- stale path came from a constrained manifest.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ChangePlan{}, err
		}
		action := ChangeActionDelete
		ownership := "sourcegen"
		if !request.Force && !digestMatches(current, outputDigest(previous, relativePath)) {
			action = ChangeActionConflict
			ownership = "operator_or_unknown"
		}
		changePlan.Changes = append(changePlan.Changes, FileChange{Path: relativePath, Action: action, Ownership: ownership})
	}
	proofRelative, err := manifestRelativePath(request.OutputDir, plan.ProofPath)
	if err != nil {
		return ChangePlan{}, err
	}
	proofDigest := ""
	if previous != nil {
		proofDigest = previous.ProofDigest
	}
	proofAction, proofOwnership, err := plannedFileAction(plan.ProofPath, plan.ProofPayload, proofDigest, request.Force)
	if err != nil {
		return ChangePlan{}, err
	}
	changePlan.Changes = append(changePlan.Changes, FileChange{Path: proofRelative, Action: proofAction, Ownership: proofOwnership})

	manifestPayload, err := marshalGenerationManifest(plan.Manifest)
	if err != nil {
		return ChangePlan{}, err
	}
	manifestRelative, err := manifestRelativePath(request.OutputDir, plan.ManifestPath)
	if err != nil {
		return ChangePlan{}, err
	}
	manifestAction, err := metadataAction(plan.ManifestPath, manifestPayload)
	if err != nil {
		return ChangePlan{}, err
	}
	changePlan.Changes = append(changePlan.Changes, FileChange{Path: manifestRelative, Action: manifestAction, Ownership: "sourcegen"})

	sort.Slice(changePlan.Changes, func(left, right int) bool { return changePlan.Changes[left].Path < changePlan.Changes[right].Path })
	for _, change := range changePlan.Changes {
		if change.Action == ChangeActionConflict {
			changePlan.Status = ChangePlanBlocked
			break
		}
	}
	return changePlan, nil
}

func plannedFileAction(path string, expected []byte, previousDigest string, force bool) (string, string, error) {
	// Generated paths are validated with manifestRelativePath before this call.
	// codeql[go/path-injection]
	current, err := os.ReadFile(path) // #nosec G304 -- generated path is constrained to OutputDir.
	if os.IsNotExist(err) {
		return ChangeActionCreate, "sourcegen", nil
	}
	if err != nil {
		return "", "", err
	}
	if bytes.Equal(current, expected) {
		return ChangeActionUnchanged, "sourcegen", nil
	}
	if force || digestMatches(current, previousDigest) {
		return ChangeActionUpdate, "sourcegen", nil
	}
	return ChangeActionConflict, "operator_or_unknown", nil
}

func metadataAction(path string, expected []byte) (string, error) {
	// Metadata paths are generated beneath the operator-selected OutputDir.
	// codeql[go/path-injection]
	current, err := os.ReadFile(path) // #nosec G304 -- metadata path is constrained to OutputDir.
	if os.IsNotExist(err) {
		return ChangeActionCreate, nil
	}
	if err != nil {
		return "", err
	}
	if bytes.Equal(current, expected) {
		return ChangeActionUnchanged, nil
	}
	return ChangeActionUpdate, nil
}

func outputDigest(manifest *generationManifest, path string) string {
	if manifest == nil {
		return ""
	}
	return manifest.Outputs[path]
}

func loadGenerationManifest(path string) (*generationManifest, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- generated path is constrained to OutputDir.
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest generationManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return nil, fmt.Errorf("decode sourcegen manifest %s: %w", path, err)
	}
	if manifest.SourceID == "" || manifest.GeneratorVersion == "" || manifest.Outputs == nil {
		return nil, fmt.Errorf("sourcegen manifest %s is incomplete", path)
	}
	return &manifest, nil
}

func manifestRelativePath(outputDir string, path string) (string, error) {
	relativePath, err := filepath.Rel(outputDir, path)
	if err != nil {
		return "", err
	}
	if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) || filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("generated path %s escapes output directory %s", path, outputDir)
	}
	return filepath.ToSlash(relativePath), nil
}

func digestMatches(payload []byte, expected string) bool {
	if strings.TrimSpace(expected) == "" {
		return false
	}
	digest, err := stampfile.HashReader(bytes.NewReader(payload))
	return err == nil && digest == expected
}
