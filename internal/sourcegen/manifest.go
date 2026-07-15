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
	generatorVersion = "sourcegen/v2"
	manifestName     = ".sourcegen-manifest.json"
)

type generationManifest struct {
	GeneratorVersion string            `json:"generator_version"`
	SourceID         string            `json:"source_id"`
	InputDigest      string            `json:"input_digest"`
	Outputs          map[string]string `json:"outputs"`
}

type generationPlan struct {
	OutputDir    string
	ManifestPath string
	Manifest     generationManifest
	StalePaths   []string
}

func planGeneration(request normalizedRequest, files []generatedFile) (generationPlan, error) {
	manifestPath := filepath.Join(request.OutputDir, "sources", request.SourceID, manifestName)
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
	plan := generationPlan{OutputDir: request.OutputDir, ManifestPath: manifestPath, Manifest: next}
	if previous == nil {
		return plan, nil
	}
	for previousPath := range previous.Outputs {
		if _, retained := next.Outputs[previousPath]; !retained {
			stalePath, err := manifestOutputPath(request.OutputDir, previousPath)
			if err != nil {
				return generationPlan{}, err
			}
			plan.StalePaths = append(plan.StalePaths, stalePath)
		}
	}
	sort.Strings(plan.StalePaths)
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
	payload, err := json.MarshalIndent(plan.Manifest, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	manifestPath, err := manifestRelativePath(plan.OutputDir, plan.ManifestPath)
	if err != nil {
		return err
	}
	manifestPath = filepath.FromSlash(manifestPath)
	manifestDir := filepath.Dir(manifestPath)
	if err := root.MkdirAll(manifestDir, 0o750); err != nil {
		return err
	}
	temporaryPath := filepath.Join(manifestDir, ".sourcegen-manifest-"+rand.Text()+".tmp")
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
	return root.Rename(temporaryPath, manifestPath)
}

func loadGenerationManifest(outputDir string, path string) (*generationManifest, error) {
	relativePath, err := manifestRelativePath(outputDir, path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(outputDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
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
