// Package wasmartifacts defines and verifies the reproducible embedded Wasm
// artifact manifest.
package wasmartifacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	ManifestPath  = "tools/archtests/embedded_wasm_artifacts.json"
	SchemaVersion = 1
)

type BuilderIdentity struct {
	ID            string `json:"id"`
	Platform      string `json:"platform"`
	Registry      string `json:"registry"`
	RustToolchain string `json:"rust_toolchain"`
	Target        string `json:"target"`
	Profile       string `json:"profile"`
}

type ModuleSpec struct {
	Name         string
	ArtifactPath string
	SourcePath   string
	ABIVersion   uint32
	MaxSizeBytes int64
}

type ModuleArtifact struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	MaxSizeBytes int64  `json:"max_size_bytes"`
	ABIVersion   uint32 `json:"abi_version"`
}

type Manifest struct {
	SchemaVersion    int              `json:"schema_version"`
	CanonicalBuilder BuilderIdentity  `json:"canonical_builder"`
	Modules          []ModuleArtifact `json:"modules"`
}

var canonicalBuilder = BuilderIdentity{
	ID:            "cerebro-embedded-wasm-v1",
	Platform:      "Linux-x86_64",
	Registry:      "scripts/embedded_wasm.py",
	RustToolchain: "1.93.1",
	Target:        "wasm32-unknown-unknown",
	Profile:       "release",
}

var moduleSpecs = []ModuleSpec{
	{
		Name:         "graphagent-static-validator",
		ArtifactPath: "internal/graphagent/staticvalidator.wasm",
		SourcePath:   "internal/graphagent/staticvalidator/src/lib.rs",
		ABIVersion:   2,
		MaxSizeBytes: 700_000,
	},
	{
		Name:         "sourcecoverage-evaluator",
		ArtifactPath: "internal/sourcecoverage/evaluator.wasm",
		SourcePath:   "internal/sourcecoverage/evaluator/src/lib.rs",
		ABIVersion:   1,
		MaxSizeBytes: 175_000,
	},
	{
		Name:         "panopticon-resource-extractor",
		ArtifactPath: "internal/sourceprojection/panopticonresources.wasm",
		SourcePath:   "internal/sourceprojection/panopticonresources/src/lib.rs",
		ABIVersion:   2,
		MaxSizeBytes: 160_000,
	},
	{
		Name:         "mitre-context-evaluator",
		ArtifactPath: "internal/mitre/evaluator.wasm",
		SourcePath:   "internal/mitre/evaluator/src/lib.rs",
		ABIVersion:   1,
		MaxSizeBytes: 800_000,
	},
}

func CanonicalBuilder() BuilderIdentity {
	return canonicalBuilder
}

func ModuleSpecs() []ModuleSpec {
	return append([]ModuleSpec(nil), moduleSpecs...)
}

func Build(repoRoot string) (Manifest, error) {
	return build(repoRoot, moduleSpecs)
}

func build(repoRoot string, specs []ModuleSpec) (Manifest, error) {
	manifest := Manifest{
		SchemaVersion:    SchemaVersion,
		CanonicalBuilder: canonicalBuilder,
		Modules:          make([]ModuleArtifact, 0, len(specs)),
	}
	for _, spec := range specs {
		body, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(spec.ArtifactPath)))
		if err != nil {
			return Manifest{}, fmt.Errorf("read %s artifact %s: %w", spec.Name, spec.ArtifactPath, err)
		}
		size := int64(len(body))
		if size > spec.MaxSizeBytes {
			overage := size - spec.MaxSizeBytes
			return Manifest{}, fmt.Errorf(
				"%s artifact %s is %d bytes, exceeding its %d-byte budget by %d %s; reduce the artifact or make a reviewed budget change in internal/wasmartifacts/manifest.go",
				spec.Name,
				spec.ArtifactPath,
				size,
				spec.MaxSizeBytes,
				overage,
				byteUnit(overage),
			)
		}
		digest := sha256.Sum256(body)
		manifest.Modules = append(manifest.Modules, ModuleArtifact{
			Name:         spec.Name,
			Path:         spec.ArtifactPath,
			SHA256:       hex.EncodeToString(digest[:]),
			SizeBytes:    size,
			MaxSizeBytes: spec.MaxSizeBytes,
			ABIVersion:   spec.ABIVersion,
		})
	}
	return manifest, nil
}

func Marshal(manifest Manifest) ([]byte, error) {
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode embedded Wasm artifact manifest: %w", err)
	}
	return append(body, '\n'), nil
}

func Load(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open embedded Wasm artifact manifest: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode embedded Wasm artifact manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("decode embedded Wasm artifact manifest: trailing JSON content")
	}
	return manifest, nil
}

func Write(repoRoot string) error {
	manifest, err := Build(repoRoot)
	if err != nil {
		return err
	}
	body, err := Marshal(manifest)
	if err != nil {
		return err
	}
	path := filepath.Join(repoRoot, filepath.FromSlash(ManifestPath))
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlinked manifest %s", ManifestPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect manifest %s: %w", ManifestPath, err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".embedded-wasm-artifacts-*.json")
	if err != nil {
		return fmt.Errorf("create temporary manifest: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return fmt.Errorf("set temporary manifest mode: %w", err)
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return fmt.Errorf("write temporary manifest: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync temporary manifest: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary manifest: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace manifest %s: %w", ManifestPath, err)
	}
	return nil
}

func byteUnit(value int64) string {
	if value == 1 {
		return "byte"
	}
	return "bytes"
}

func Check(repoRoot string) error {
	expected, err := Build(repoRoot)
	if err != nil {
		return err
	}
	path := filepath.Join(repoRoot, filepath.FromSlash(ManifestPath))
	actual, err := Load(path)
	if err != nil {
		return err
	}
	if err := compare(expected, actual); err != nil {
		return fmt.Errorf("%w; regenerate canonical Wasm artifacts, then run make rust-wasm-manifest-generate", err)
	}
	expectedBody, err := Marshal(expected)
	if err != nil {
		return err
	}
	actualBody, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", ManifestPath, err)
	}
	if !bytes.Equal(actualBody, expectedBody) {
		return fmt.Errorf("manifest %s is not in canonical JSON form; run make rust-wasm-manifest-generate", ManifestPath)
	}
	return nil
}

func compare(expected Manifest, actual Manifest) error {
	if actual.SchemaVersion != expected.SchemaVersion {
		return fmt.Errorf("manifest schema_version is %d, expected %d", actual.SchemaVersion, expected.SchemaVersion)
	}
	if actual.CanonicalBuilder != expected.CanonicalBuilder {
		return fmt.Errorf("manifest canonical_builder does not match the pinned builder identity")
	}
	if len(actual.Modules) != len(expected.Modules) {
		return fmt.Errorf("manifest has %d modules, expected %d", len(actual.Modules), len(expected.Modules))
	}
	for index := range expected.Modules {
		want := expected.Modules[index]
		got := actual.Modules[index]
		if got.Name != want.Name || got.Path != want.Path {
			return fmt.Errorf("manifest module %d is %s at %s, expected %s at %s", index, got.Name, got.Path, want.Name, want.Path)
		}
		if got.ABIVersion != want.ABIVersion {
			return fmt.Errorf("%s manifest ABI version is %d, expected %d", want.Name, got.ABIVersion, want.ABIVersion)
		}
		if got.MaxSizeBytes != want.MaxSizeBytes {
			return fmt.Errorf("%s manifest size budget is %d bytes, expected %d", want.Name, got.MaxSizeBytes, want.MaxSizeBytes)
		}
		if got.SizeBytes != want.SizeBytes {
			return fmt.Errorf("%s manifest size is %d bytes, artifact is %d bytes", want.Name, got.SizeBytes, want.SizeBytes)
		}
		if got.SHA256 != want.SHA256 {
			return fmt.Errorf("%s manifest SHA-256 is %s, artifact SHA-256 is %s", want.Name, got.SHA256, want.SHA256)
		}
	}
	return nil
}
