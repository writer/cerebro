// Package sourcedeploy declares the deploy manifest contract that lives next
// to each source's catalog and the loader/renderer that turns those manifests
// into infrastructure-ready Pulumi config blocks.
//
// Each source under sources/<id>/ may provide a deploy.yaml describing the
// secret keys it expects, the runtimes it ships, and the schedules it would
// like the orchestrator to run. The synth tool walks every manifest, applies
// per-environment overrides, and renders a single YAML fragment matching the
// Pulumi config schema consumed by infra/aws/__main__.py in WriterInternal.
//
// Keeping the manifest source-resident has two benefits: (1) the team that
// adds a new source owns its deployment story instead of pinging SRE, and
// (2) the public OSS code base stays the source of truth — internal infra
// merely renders, never re-invents.
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
	SourceID     string                          `yaml:"sourceId"`
	SecretKeys   []string                        `yaml:"secretKeys,omitempty"`
	Runtimes     []RuntimeManifest               `yaml:"runtimes,omitempty"`
	Schedules    []ScheduleManifest              `yaml:"schedules,omitempty"`
	Environments map[string]EnvironmentOverrides `yaml:"environments,omitempty"`
}

// EnvironmentOverrides layer environment-specific tweaks on top of the base
// manifest. Disabling lists are matched by localId / localName; additional
// runtimes and schedules are appended verbatim and validated identically.
type EnvironmentOverrides struct {
	DisabledRuntimes  []string           `yaml:"disabledRuntimes,omitempty"`
	DisabledSchedules []string           `yaml:"disabledSchedules,omitempty"`
	ExtraRuntimes     []RuntimeManifest  `yaml:"extraRuntimes,omitempty"`
	ExtraSchedules    []ScheduleManifest `yaml:"extraSchedules,omitempty"`
	ExtraSecretKeys   []string           `yaml:"extraSecretKeys,omitempty"`
}

// RuntimeManifest describes a logical runtime configuration. The fully
// qualified runtime ID is composed at render time as
// `<tenant>-<sourceId>-<localId>`.
type RuntimeManifest struct {
	LocalID string            `yaml:"localId"`
	Family  string            `yaml:"family,omitempty"`
	Config  map[string]string `yaml:"config"`
}

// ScheduleManifest describes a recurring orchestrator invocation that
// targets a runtime defined in the same manifest. The fully qualified
// schedule name is `<sourceId>-<localName>`; the rendered command is
// the shared base plus a `runtime_id=` argument so the orchestrator
// runs only that runtime.
type ScheduleManifest struct {
	LocalName          string   `yaml:"localName"`
	RuntimeLocalID     string   `yaml:"runtimeLocalId"`
	ScheduleExpression string   `yaml:"scheduleExpression"`
	TaskCount          int      `yaml:"taskCount,omitempty"`
	Command            []string `yaml:"command,omitempty"`
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
	runtimes, err := validateRuntimes(m.Runtimes)
	if err != nil {
		return err
	}
	if err := validateSchedules(m.Schedules, runtimes); err != nil {
		return err
	}
	for envName, overlay := range m.Environments {
		if strings.TrimSpace(envName) == "" {
			return fmt.Errorf("environments key must be non-empty")
		}
		if err := validateOverlay(envName, overlay, runtimes); err != nil {
			return err
		}
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

func validateSchedules(list []ScheduleManifest, runtimes map[string]struct{}) error {
	scheduleNames := map[string]struct{}{}
	for _, schedule := range list {
		if !idPattern.MatchString(schedule.LocalName) {
			return fmt.Errorf("schedule localName %q must be lowercase kebab-case", schedule.LocalName)
		}
		if _, dup := scheduleNames[schedule.LocalName]; dup {
			return fmt.Errorf("schedule localName %q declared twice", schedule.LocalName)
		}
		scheduleNames[schedule.LocalName] = struct{}{}
		if _, ok := runtimes[schedule.RuntimeLocalID]; !ok {
			return fmt.Errorf(
				"schedule %q references runtime localId %q that is not declared",
				schedule.LocalName, schedule.RuntimeLocalID,
			)
		}
		if strings.TrimSpace(schedule.ScheduleExpression) == "" {
			return fmt.Errorf("schedule %q must set scheduleExpression", schedule.LocalName)
		}
		if schedule.TaskCount < 0 {
			return fmt.Errorf("schedule %q taskCount must be >= 0", schedule.LocalName)
		}
		if err := validateScheduleCommand(schedule); err != nil {
			return err
		}
	}
	return nil
}

func validateOverlay(env string, overlay EnvironmentOverrides, baseRuntimes map[string]struct{}) error {
	for _, id := range overlay.DisabledRuntimes {
		if _, ok := baseRuntimes[id]; !ok {
			return fmt.Errorf("environment %q disables runtime %q which is not declared", env, id)
		}
	}
	combined := make(map[string]struct{}, len(baseRuntimes)+len(overlay.ExtraRuntimes))
	for id := range baseRuntimes {
		combined[id] = struct{}{}
	}
	extraRuntimes, err := validateRuntimes(overlay.ExtraRuntimes)
	if err != nil {
		return fmt.Errorf("environment %q: %w", env, err)
	}
	for id := range extraRuntimes {
		if _, dup := combined[id]; dup {
			return fmt.Errorf("environment %q extra runtime %q collides with base runtime", env, id)
		}
		combined[id] = struct{}{}
	}
	if err := validateSchedules(overlay.ExtraSchedules, combined); err != nil {
		return fmt.Errorf("environment %q: %w", env, err)
	}
	if err := validateSecretKeys(overlay.ExtraSecretKeys); err != nil {
		return fmt.Errorf("environment %q: %w", env, err)
	}
	return nil
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

func validateScheduleCommand(schedule ScheduleManifest) error {
	if len(schedule.Command) == 0 {
		return nil
	}
	for _, part := range schedule.Command {
		if strings.HasPrefix(part, "runtime_id=") {
			return fmt.Errorf(
				"schedule %q must not pre-declare runtime_id; it is composed at render time",
				schedule.LocalName,
			)
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
