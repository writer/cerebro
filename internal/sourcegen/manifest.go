package sourcegen

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/sourcegen/stampfile"
)

var (
	ErrGeneratedOutputModified       = errors.New("generated output contains changes not owned by sourcegen")
	ErrInvalidGenerationManifestPath = errors.New("generation manifest output path is invalid")
)

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
	OutputDir    string
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
	previous, err := loadGenerationManifest(request.OutputDir, manifestPath)
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
	plan := generationPlan{
		OutputDir:    request.OutputDir,
		ManifestPath: manifestPath,
		ProofPath:    proofPath,
		Manifest:     next,
		ProofPayload: proofPayload,
	}
	if previous != nil {
		for previousPath := range previous.Outputs {
			if _, retained := next.Outputs[previousPath]; retained {
				continue
			}
			stalePath, err := manifestOutputPath(request.OutputDir, previousPath)
			if err != nil {
				return generationPlan{}, err
			}
			plan.StalePaths = append(plan.StalePaths, stalePath)
		}
	}
	sort.Strings(plan.StalePaths)
	plan.ChangePlan, err = buildChangePlan(request, files, plan, previous)
	if err != nil {
		return generationPlan{}, err
	}
	return plan, nil
}

func preflightGeneration(root *os.Root, request normalizedRequest, files []generatedFile, plan generationPlan) error {
	previous, err := loadGenerationManifest(plan.OutputDir, plan.ManifestPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		relativePath, err := manifestRelativePath(request.OutputDir, file.Path)
		if err != nil {
			return err
		}
		current, err := root.ReadFile(filepath.FromSlash(relativePath))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if bytes.Equal(current, []byte(file.Content)) || request.Force {
			continue
		}
		if previous != nil && digestMatches(current, previous.Outputs[relativePath]) {
			continue
		}
		return fmt.Errorf("%w: %s; preserve the changes in an override file or pass force=true", ErrGeneratedOutputModified, file.Path)
	}
	for _, stalePath := range plan.StalePaths {
		relativePath, err := manifestRelativePath(request.OutputDir, stalePath)
		if err != nil {
			return err
		}
		current, err := root.ReadFile(filepath.FromSlash(relativePath))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !request.Force && (previous == nil || !digestMatches(current, previous.Outputs[relativePath])) {
			return fmt.Errorf("%w: stale output %s", ErrGeneratedOutputModified, stalePath)
		}
	}
	proofRelative, err := manifestRelativePath(request.OutputDir, plan.ProofPath)
	if err != nil {
		return err
	}
	currentProof, err := root.ReadFile(filepath.FromSlash(proofRelative))
	if err == nil && !bytes.Equal(currentProof, plan.ProofPayload) && !request.Force {
		if previous == nil || !digestMatches(currentProof, previous.ProofDigest) {
			return fmt.Errorf("%w: %s; preserve the changes outside the generated proof bundle or pass force=true", ErrGeneratedOutputModified, plan.ProofPath)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func commitGeneration(root *os.Root, plan generationPlan) error {
	for _, stalePath := range plan.StalePaths {
		relativePath, err := manifestRelativePath(plan.OutputDir, stalePath)
		if err != nil {
			return err
		}
		if err := root.Remove(filepath.FromSlash(relativePath)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale generated output %s: %w", stalePath, err)
		}
	}
	if err := writeGeneratedMetadata(root, plan.OutputDir, plan.ProofPath, plan.ProofPayload, ".sourcegen-proof"); err != nil {
		return err
	}
	payload, err := marshalGenerationManifest(plan.Manifest)
	if err != nil {
		return err
	}
	return writeGeneratedMetadata(root, plan.OutputDir, plan.ManifestPath, payload, ".sourcegen-manifest")
}

func marshalGenerationManifest(manifest generationManifest) ([]byte, error) {
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func writeGeneratedMetadata(root *os.Root, outputDir string, path string, payload []byte, temporaryPrefix string) error {
	relativePath, err := manifestRelativePath(outputDir, path)
	if err != nil {
		return err
	}
	relativePath = filepath.FromSlash(relativePath)
	metadataDir := filepath.Dir(relativePath)
	if err := root.MkdirAll(metadataDir, 0o750); err != nil {
		return err
	}
	temporaryPath := filepath.Join(metadataDir, temporaryPrefix+"-"+rand.Text()+".tmp")
	temporary, err := root.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temporaryPath) }()
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return root.Rename(temporaryPath, relativePath)
}

func buildChangePlan(request normalizedRequest, files []generatedFile, plan generationPlan, previous *generationManifest) (ChangePlan, error) {
	root, err := openExistingGenerationRoot(request.OutputDir)
	if err != nil {
		return ChangePlan{}, err
	}
	if root != nil {
		defer func() { _ = root.Close() }()
	}
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
		action, ownership, err := plannedFileAction(root, relativePath, []byte(file.Content), outputDigest(previous, relativePath), request.Force)
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
		current, err := readGeneratedPath(root, relativePath)
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
	proofAction, proofOwnership, err := plannedFileAction(root, proofRelative, plan.ProofPayload, proofDigest, request.Force)
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
	manifestAction, err := metadataAction(root, manifestRelative, manifestPayload)
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

func plannedFileAction(root *os.Root, relativePath string, expected []byte, previousDigest string, force bool) (string, string, error) {
	current, err := readGeneratedPath(root, relativePath)
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

func metadataAction(root *os.Root, relativePath string, expected []byte) (string, error) {
	current, err := readGeneratedPath(root, relativePath)
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

func readGeneratedPath(root *os.Root, relativePath string) ([]byte, error) {
	if root == nil {
		return nil, os.ErrNotExist
	}
	return root.ReadFile(filepath.FromSlash(relativePath))
}

func outputDigest(manifest *generationManifest, path string) string {
	if manifest == nil {
		return ""
	}
	return manifest.Outputs[path]
}

func loadGenerationManifest(outputDir string, path string) (*generationManifest, error) {
	relativePath, err := manifestRelativePath(outputDir, path)
	if err != nil {
		return nil, err
	}
	root, err := openExistingGenerationRoot(outputDir)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	defer func() { _ = root.Close() }()
	payload, err := root.ReadFile(filepath.FromSlash(relativePath))
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

func openExistingGenerationRoot(outputDir string) (*os.Root, error) {
	root, err := os.OpenRoot(outputDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return root, nil
}

func openOrCreateGenerationRoot(outputDir string) (*os.Root, error) {
	absoluteOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve sourcegen output root: %w", err)
	}
	volumeRoot := filepath.VolumeName(absoluteOutputDir) + string(filepath.Separator)
	filesystemRoot, err := os.OpenRoot(volumeRoot)
	if err != nil {
		return nil, fmt.Errorf("open sourcegen filesystem root: %w", err)
	}
	relativeOutputDir, err := filepath.Rel(volumeRoot, absoluteOutputDir)
	if err != nil {
		_ = filesystemRoot.Close()
		return nil, fmt.Errorf("resolve sourcegen output path: %w", err)
	}
	if relativeOutputDir == "." {
		return filesystemRoot, nil
	}
	if err := filesystemRoot.MkdirAll(relativeOutputDir, 0o750); err != nil {
		_ = filesystemRoot.Close()
		return nil, fmt.Errorf("create sourcegen output root: %w", err)
	}
	root, err := filesystemRoot.OpenRoot(relativeOutputDir)
	_ = filesystemRoot.Close()
	if err != nil {
		return nil, fmt.Errorf("open sourcegen output root: %w", err)
	}
	return root, nil
}

func manifestOutputPath(outputDir string, manifestPath string) (string, error) {
	path := filepath.Join(outputDir, filepath.FromSlash(manifestPath))
	relativePath, err := manifestRelativePath(outputDir, path)
	if err != nil || relativePath != manifestPath || relativePath == "." {
		return "", fmt.Errorf("%w: %q", ErrInvalidGenerationManifestPath, manifestPath)
	}
	return path, nil
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
