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
	ManifestPath string
	Manifest     generationManifest
	StalePaths   []string
}

func planGeneration(request normalizedRequest, files []generatedFile) (generationPlan, error) {
	manifestPath := filepath.Join(request.OutputDir, "sources", request.SourceID, manifestName)
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
	plan := generationPlan{ManifestPath: manifestPath, Manifest: next}
	if previous == nil {
		return plan, nil
	}
	for previousPath := range previous.Outputs {
		if _, retained := next.Outputs[previousPath]; !retained {
			plan.StalePaths = append(plan.StalePaths, filepath.Join(request.OutputDir, filepath.FromSlash(previousPath)))
		}
	}
	sort.Strings(plan.StalePaths)
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
	return nil
}

func commitGeneration(plan generationPlan) error {
	for _, stalePath := range plan.StalePaths {
		if err := os.Remove(stalePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale generated output %s: %w", stalePath, err)
		}
	}
	payload, err := json.MarshalIndent(plan.Manifest, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if err := os.MkdirAll(filepath.Dir(plan.ManifestPath), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(plan.ManifestPath), ".sourcegen-manifest-*.tmp")
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
	return os.Rename(temporaryPath, plan.ManifestPath)
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
