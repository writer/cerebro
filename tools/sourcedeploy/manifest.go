// Package sourcedeploy declares the deploy contract that lives next to each
// source's catalog and the loader/renderer that turns those manifests into
// infrastructure-ready Pulumi config blocks.
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
//     owned by the private infra repo (WriterInternal/cerebro) and do not
//     belong in OSS.
//
// The synth tool walks every manifest and renders a single YAML fragment with
// two keys (cerebro:sourceSecretKeys, cerebro:sourceRuntimes) that
// WriterInternal merges into its Pulumi.<env>.yaml. Schedules are authored
// alongside that merge step in the private repo.
package sourcedeploy

import (
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
// a sourceId that does not match the directory name it lives under.
var ErrSourceIDMismatch = errors.New("deploy manifest sourceId does not match sources directory")

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
	Family  string            `yaml:"family,omitempty"`
	Config  map[string]string `yaml:"config"`
}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`)
	envRefRegex = regexp.MustCompile(`^env:[A-Z][A-Z0-9_]*$`)
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
	if err := yaml.Unmarshal(data, &manifest); err != nil {
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
		if manifest.SourceID != entry.Name() {
			return nil, fmt.Errorf(
				"%w: %s declares sourceId %q but lives under sources/%s",
				ErrSourceIDMismatch, path, manifest.SourceID, entry.Name(),
			)
		}
		manifests = append(manifests, *manifest)
	}
	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].SourceID < manifests[j].SourceID
	})
	return manifests, nil
}

// Validate enforces structural rules the renderer relies on.
func (m *Manifest) Validate() error {
	if !idPattern.MatchString(m.SourceID) {
		return fmt.Errorf("sourceId %q must be lowercase kebab-case", m.SourceID)
	}
	if err := validateSecretKeys(m.SecretKeys); err != nil {
		return err
	}
	if _, err := validateRuntimes(m.Runtimes); err != nil {
		return err
	}
	return nil
}

func validateRuntimes(list []RuntimeManifest) (map[string]struct{}, error) {
	runtimes := map[string]struct{}{}
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
		if err := validateRuntimeConfig(runtime); err != nil {
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
		if trimmed != strings.ToUpper(trimmed) {
			return fmt.Errorf("secretKeys entry %q must be SCREAMING_SNAKE_CASE", key)
		}
		if _, dup := seen[trimmed]; dup {
			return fmt.Errorf("secretKeys entry %q declared twice", key)
		}
		seen[trimmed] = struct{}{}
	}
	return nil
}

func validateRuntimeConfig(runtime RuntimeManifest) error {
	for k, v := range runtime.Config {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("runtime %q config has an empty key", runtime.LocalID)
		}
		if isSensitiveConfigKey(k) {
			if !envRefRegex.MatchString(strings.TrimSpace(v)) {
				return fmt.Errorf(
					"runtime %q config %q is sensitive and must use env:VAR (got %q)",
					runtime.LocalID, k, v,
				)
			}
		}
	}
	return nil
}

// isSensitiveConfigKey mirrors infra/aws/compute.py:_sensitive_source_config_key
// so the manifest fails fast in CI if a developer leaves a literal token in
// a runtime config.
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
