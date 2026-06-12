// Package sourcedeploy declares the deploy contract that lives next to each
// source's catalog and the loader/renderer that turns those manifests into
// infrastructure-ready config blocks.
//
// Scope of this package:
//
//   - In-scope (source-level contract): the secret env vars a source needs and
//     the canonical runtime configurations it ships. These are properties of
//     the source code itself; declaring them here keeps the OSS repo as the
//     single source of truth for what each source requires.
//
//   - Out-of-scope (deployment cadence): orchestrator schedule rates, taskCount,
//     and per-environment backfill instances. Those are operational decisions
//     owned by deployment automation and do not belong in OSS.
//
// The synth tool walks every manifest and renders a single YAML fragment with
// two keys (cerebro:sourceSecretKeys, cerebro:sourceRuntimes) that
// deployment automation can merge into environment-specific config. Schedules
// are authored alongside that deployment step.
package sourcedeploy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrSourceIDMismatch is returned by Discover when a deploy manifest declares
// a sourceId that does not match the source catalog ID it lives next to.
var ErrSourceIDMismatch = errors.New("deploy manifest sourceId does not match source catalog")

// Manifest is the declarative deploy contract that lives next to each
// source's catalog. All fields are optional except SourceID.
type Manifest struct {
	SourceID   string            `yaml:"sourceId"`
	SecretKeys []string          `yaml:"secretKeys,omitempty"`
	Runtimes   []RuntimeManifest `yaml:"runtimes,omitempty"`
}

// RuntimeManifest describes a logical runtime configuration. The fully
// qualified runtime ID is composed at render time as
// `<tenant>-<sourceId>-<localId>`.
type RuntimeManifest struct {
	LocalID string            `yaml:"localId"`
	Config  map[string]string `yaml:"config"`
}

var (
	sourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*[a-z0-9]$`)
	idPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`)
	envVarRegex     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	envRefRegex     = regexp.MustCompile(`^env:[A-Z][A-Z0-9_]*$`)
)

// Load reads a single manifest file from disk.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read deploy manifest %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse decodes a manifest from raw bytes and runs validation.
func Parse(data []byte, label string) (*Manifest, error) {
	var manifest Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode deploy manifest %s: %w", label, err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("validate deploy manifest %s: %w", label, err)
	}
	return &manifest, nil
}

// Discover walks the sources/ directory tree and returns one manifest per
// source that ships a deploy.yaml. Sources without a manifest are skipped
// silently; archtests enforce coverage separately.
func Discover(sourcesRoot string) ([]Manifest, error) {
	entries, err := os.ReadDir(sourcesRoot)
	if err != nil {
		return nil, fmt.Errorf("read sources root %s: %w", sourcesRoot, err)
	}
	manifests := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(sourcesRoot, entry.Name(), "deploy.yaml")
		if _, statErr := os.Stat(path); statErr != nil {
			continue
		}
		manifest, err := Load(path)
		if err != nil {
			return nil, err
		}
		catalogID, err := sourceCatalogID(sourcesRoot, entry.Name())
		if err != nil {
			return nil, err
		}
		if manifest.SourceID != catalogID {
			return nil, fmt.Errorf(
				"%w: %s declares sourceId %q but catalog declares %q",
				ErrSourceIDMismatch, path, manifest.SourceID, catalogID,
			)
		}
		manifests = append(manifests, *manifest)
	}
	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].SourceID < manifests[j].SourceID
	})
	return manifests, nil
}

type sourceCatalog struct {
	ID string `yaml:"id"`
}

func sourceCatalogID(sourcesRoot string, sourceDir string) (string, error) {
	path := filepath.Join(sourcesRoot, sourceDir, "catalog.yaml")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return sourceDir, nil
	}
	if err != nil {
		return "", fmt.Errorf("read source catalog %s: %w", path, err)
	}
	var catalog sourceCatalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return "", fmt.Errorf("decode source catalog %s: %w", path, err)
	}
	if strings.TrimSpace(catalog.ID) == "" {
		return sourceDir, nil
	}
	return strings.TrimSpace(catalog.ID), nil
}

// Validate enforces structural rules the renderer relies on.
func (m *Manifest) Validate() error {
	if !sourceIDPattern.MatchString(m.SourceID) {
		return fmt.Errorf("sourceId %q must be lowercase kebab/snake-case", m.SourceID)
	}
	if err := validateSecretKeys(m.SecretKeys); err != nil {
		return err
	}
	if _, err := validateRuntimes(m.Runtimes, m.SecretKeys); err != nil {
		return err
	}
	return nil
}

func validateRuntimes(list []RuntimeManifest, secretKeys []string) (map[string]struct{}, error) {
	runtimes := map[string]struct{}{}
	declaredSecrets := stringSet(secretKeys)
	for _, runtime := range list {
		if !idPattern.MatchString(runtime.LocalID) {
			return nil, fmt.Errorf("runtime localId %q must be lowercase kebab-case", runtime.LocalID)
		}
		if _, dup := runtimes[runtime.LocalID]; dup {
			return nil, fmt.Errorf("runtime localId %q declared twice", runtime.LocalID)
		}
		runtimes[runtime.LocalID] = struct{}{}
		if len(runtime.Config) == 0 {
			return nil, fmt.Errorf("runtime %q must declare at least one config entry", runtime.LocalID)
		}
		if err := validateRuntimeConfig(runtime, declaredSecrets); err != nil {
			return nil, err
		}
	}
	return runtimes, nil
}

func validateSecretKeys(keys []string) error {
	seen := map[string]struct{}{}
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			return fmt.Errorf("secretKeys entries must be non-empty")
		}
		if !envVarRegex.MatchString(trimmed) {
			return fmt.Errorf("secretKeys entry %q must be SCREAMING_SNAKE_CASE", key)
		}
		if _, dup := seen[trimmed]; dup {
			return fmt.Errorf("secretKeys entry %q declared twice", key)
		}
		seen[trimmed] = struct{}{}
	}
	return nil
}

func validateRuntimeConfig(runtime RuntimeManifest, declaredSecrets map[string]struct{}) error {
	for k, v := range runtime.Config {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("runtime %q config has an empty key", runtime.LocalID)
		}
		trimmedValue := strings.TrimSpace(v)
		if strings.HasPrefix(trimmedValue, "env:") {
			if !envRefRegex.MatchString(trimmedValue) {
				return fmt.Errorf("runtime %q config %q has invalid env reference %q", runtime.LocalID, k, v)
			}
			secretKey := strings.TrimPrefix(trimmedValue, "env:")
			if _, ok := declaredSecrets[secretKey]; !ok {
				return fmt.Errorf("runtime %q config %q references undeclared secretKey %q", runtime.LocalID, k, secretKey)
			}
		}
		if isSensitiveConfigKey(k) {
			if !envRefRegex.MatchString(trimmedValue) {
				return fmt.Errorf(
					"runtime %q config %q is sensitive and must use env:VAR (got %q)",
					runtime.LocalID, k, v,
				)
			}
		}
	}
	return nil
}

// isSensitiveConfigKey fails fast in CI if a developer leaves a literal token
// in a runtime config.
func isSensitiveConfigKey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(key))
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(value)
	switch {
	case strings.Contains(value, "token"),
		strings.Contains(value, "secret"),
		strings.Contains(value, "password"),
		strings.Contains(compact, "apikey"),
		strings.Contains(compact, "privatekey"),
		value == "key",
		compact == "key":
		return true
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[strings.TrimSpace(value)] = struct{}{}
	}
	return out
}
