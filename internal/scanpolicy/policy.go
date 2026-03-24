package scanpolicy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsimple"
	"gopkg.in/yaml.v3"
)

type Kind string

const (
	KindImage             Kind = "image"
	KindFunction          Kind = "function"
	KindWorkload          Kind = "workload"
	KindRepository        Kind = "repository"
	KindRepositoryHistory Kind = "repository_history"
)

var supportedKinds = []Kind{
	KindImage,
	KindFunction,
	KindWorkload,
	KindRepository,
	KindRepositoryHistory,
}

type Request struct {
	Kind                   Kind              `json:"kind"`
	Team                   string            `json:"team,omitempty"`
	RequestedBy            string            `json:"requested_by,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	Provider               string            `json:"provider,omitempty"`
	Registry               string            `json:"registry,omitempty"`
	DryRun                 bool              `json:"dry_run,omitempty"`
	KeepFilesystem         bool              `json:"keep_filesystem,omitempty"`
	KeepCheckout           bool              `json:"keep_checkout,omitempty"`
	MaxConcurrentSnapshots int               `json:"max_concurrent_snapshots,omitempty"`
}

type Policy struct {
	ID                     string   `yaml:"id"`
	Description            string   `yaml:"description,omitempty"`
	ScanKinds              []Kind   `yaml:"scan_kinds,omitempty"`
	Teams                  []string `yaml:"teams,omitempty"`
	Providers              []string `yaml:"providers,omitempty"`
	Registries             []string `yaml:"registries,omitempty"`
	RequireRequestedBy     bool     `yaml:"require_requested_by,omitempty"`
	RequestedByPatterns    []string `yaml:"requested_by_patterns,omitempty"`
	RequiredMetadata       []string `yaml:"required_metadata,omitempty"`
	AllowDryRun            *bool    `yaml:"allow_dry_run,omitempty"`
	AllowKeepFilesystem    *bool    `yaml:"allow_keep_filesystem,omitempty"`
	AllowKeepCheckout      *bool    `yaml:"allow_keep_checkout,omitempty"`
	MaxConcurrentSnapshots int      `yaml:"max_concurrent_snapshots,omitempty"`
}

type Violation struct {
	PolicyID string `json:"policy_id"`
	Field    string `json:"field"`
	Message  string `json:"message"`
}

type ValidationError struct {
	Violations []Violation `json:"violations"`
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Violations) == 0 {
		return "scan policy validation failed"
	}
	parts := make([]string, 0, len(e.Violations))
	for _, violation := range e.Violations {
		parts = append(parts, fmt.Sprintf("[%s] %s: %s", violation.PolicyID, violation.Field, violation.Message))
	}
	return "scan policy violations: " + strings.Join(parts, "; ")
}

type Evaluator interface {
	Validate(req Request) error
}

type Engine struct {
	policies []compiledPolicy
}

type compiledPolicy struct {
	policy               Policy
	requestedByPatterns  []*regexp.Regexp
	normalizedKinds      []Kind
	normalizedTeams      []string
	normalizedProviders  []string
	normalizedRegistries []string
}

type yamlDocument struct {
	Version  int      `yaml:"version"`
	Policies []Policy `yaml:"policies"`
}

type hclDocument struct {
	Version  int         `hcl:"version,optional"`
	Policies []hclPolicy `hcl:"policy,block"`
}

type hclPolicy struct {
	ID                     string   `hcl:"id"`
	Description            string   `hcl:"description,optional"`
	ScanKinds              []string `hcl:"scan_kinds,optional"`
	Teams                  []string `hcl:"teams,optional"`
	Providers              []string `hcl:"providers,optional"`
	Registries             []string `hcl:"registries,optional"`
	RequireRequestedBy     bool     `hcl:"require_requested_by,optional"`
	RequestedByPatterns    []string `hcl:"requested_by_patterns,optional"`
	RequiredMetadata       []string `hcl:"required_metadata,optional"`
	AllowDryRun            *bool    `hcl:"allow_dry_run,optional"`
	AllowKeepFilesystem    *bool    `hcl:"allow_keep_filesystem,optional"`
	AllowKeepCheckout      *bool    `hcl:"allow_keep_checkout,optional"`
	MaxConcurrentSnapshots int      `hcl:"max_concurrent_snapshots,optional"`
}

func Load(path string) (*Engine, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("scan policy path is required")
	}
	policies, err := loadPolicies(path)
	if err != nil {
		return nil, err
	}
	return NewEngine(policies)
}

func NewEngine(policies []Policy) (*Engine, error) {
	compiled := make([]compiledPolicy, 0, len(policies))
	seen := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		normalized, err := compilePolicy(policy)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized.policy.ID]; ok {
			return nil, fmt.Errorf("duplicate scan policy id %q", normalized.policy.ID)
		}
		seen[normalized.policy.ID] = struct{}{}
		compiled = append(compiled, normalized)
	}
	return &Engine{policies: compiled}, nil
}

func (e *Engine) Validate(req Request) error {
	if e == nil {
		return nil
	}
	req = normalizeRequest(req)
	violations := make([]Violation, 0)
	for _, policy := range e.policies {
		if !policy.matches(req) {
			continue
		}
		violations = append(violations, policy.validate(req)...)
	}
	if len(violations) == 0 {
		return nil
	}
	return &ValidationError{Violations: violations}
}

func TeamFromMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}
	return strings.TrimSpace(metadata["team"])
}

func loadPolicies(path string) ([]Policy, error) {
	rootPath, relPath, absPath, isDir, err := resolvePolicyLoadPath(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open scan policy root %s: %w", rootPath, err)
	}
	defer func() { _ = root.Close() }()

	if !isDir {
		return loadPolicyFile(root, relPath, absPath)
	}

	entries, err := fs.ReadDir(root.FS(), relPath)
	if err != nil {
		return nil, fmt.Errorf("read scan policy directory %s: %w", absPath, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !supportedPolicyExtension(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("scan policy directory %s does not contain any .yaml, .yml, or .hcl policies", path)
	}

	policies := make([]Policy, 0)
	for _, name := range names {
		loaded, err := loadPolicyFile(root, filepath.Join(relPath, name), filepath.Join(absPath, name))
		if err != nil {
			return nil, err
		}
		policies = append(policies, loaded...)
	}
	return policies, nil
}

func resolvePolicyLoadPath(path string) (rootPath, relativePath, absolutePath string, isDir bool, err error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", "", "", false, fmt.Errorf("scan policy path is required")
	}
	candidate, err := filepath.Abs(trimmed)
	if err != nil {
		return "", "", "", false, fmt.Errorf("resolve scan policy path %s: %w", trimmed, err)
	}
	candidate = filepath.Clean(candidate)
	info, err := os.Stat(candidate)
	if err != nil {
		return "", "", "", false, fmt.Errorf("stat scan policy path %s: %w", trimmed, err)
	}
	if info.IsDir() {
		return candidate, ".", candidate, true, nil
	}
	return filepath.Dir(candidate), filepath.Base(candidate), candidate, false, nil
}

func loadPolicyFile(root *os.Root, relativePath, displayPath string) ([]Policy, error) {
	switch strings.ToLower(filepath.Ext(relativePath)) {
	case ".yaml", ".yml":
		return loadYAMLPolicies(root, relativePath, displayPath)
	case ".hcl":
		return loadHCLPolicies(root, relativePath, displayPath)
	default:
		return nil, fmt.Errorf("unsupported scan policy file %s", displayPath)
	}
}

func loadYAMLPolicies(root *os.Root, relativePath, displayPath string) ([]Policy, error) {
	data, err := root.ReadFile(relativePath)
	if err != nil {
		return nil, fmt.Errorf("read scan policy file %s: %w", displayPath, err)
	}
	var doc yamlDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode scan policy yaml %s: %w", displayPath, err)
	}
	if len(doc.Policies) == 0 {
		return nil, fmt.Errorf("scan policy file %s does not define any policies", displayPath)
	}
	return doc.Policies, nil
}

func loadHCLPolicies(root *os.Root, relativePath, displayPath string) ([]Policy, error) {
	data, err := root.ReadFile(relativePath)
	if err != nil {
		return nil, fmt.Errorf("read scan policy file %s: %w", displayPath, err)
	}
	var doc hclDocument
	if err := hclsimple.Decode(displayPath, data, nil, &doc); err != nil {
		return nil, fmt.Errorf("decode scan policy hcl %s: %w", displayPath, err)
	}
	if len(doc.Policies) == 0 {
		return nil, fmt.Errorf("scan policy file %s does not define any policies", displayPath)
	}
	policies := make([]Policy, 0, len(doc.Policies))
	for _, policy := range doc.Policies {
		policies = append(policies, policy.toPolicy())
	}
	return policies, nil
}

func compilePolicy(policy Policy) (compiledPolicy, error) {
	policy.ID = strings.TrimSpace(policy.ID)
	if policy.ID == "" {
		return compiledPolicy{}, fmt.Errorf("scan policy id is required")
	}
	compiled := compiledPolicy{
		policy:               policy,
		normalizedKinds:      normalizeKinds(policy.ScanKinds),
		normalizedTeams:      normalizeStrings(policy.Teams),
		normalizedProviders:  normalizeStrings(policy.Providers),
		normalizedRegistries: normalizeStrings(policy.Registries),
	}
	for _, kind := range compiled.normalizedKinds {
		if !slices.Contains(supportedKinds, kind) {
			return compiledPolicy{}, fmt.Errorf("scan policy %s has unsupported scan kind %q", policy.ID, kind)
		}
	}
	for _, pattern := range policy.RequestedByPatterns {
		re, err := regexp.Compile(strings.TrimSpace(pattern))
		if err != nil {
			return compiledPolicy{}, fmt.Errorf("scan policy %s requested_by pattern %q: %w", policy.ID, pattern, err)
		}
		compiled.requestedByPatterns = append(compiled.requestedByPatterns, re)
	}
	return compiled, nil
}

func (p compiledPolicy) matches(req Request) bool {
	if len(p.normalizedKinds) > 0 && !slices.Contains(p.normalizedKinds, req.Kind) {
		return false
	}
	if len(p.normalizedTeams) > 0 && !slices.Contains(p.normalizedTeams, strings.ToLower(req.Team)) {
		return false
	}
	if len(p.normalizedProviders) > 0 && !slices.Contains(p.normalizedProviders, strings.ToLower(req.Provider)) {
		return false
	}
	if len(p.normalizedRegistries) > 0 && !slices.Contains(p.normalizedRegistries, strings.ToLower(req.Registry)) {
		return false
	}
	return true
}

func (p compiledPolicy) validate(req Request) []Violation {
	violations := make([]Violation, 0)
	if p.policy.RequireRequestedBy && req.RequestedBy == "" {
		violations = append(violations, p.violation("requested_by", "requested_by is required"))
	}
	if req.RequestedBy != "" && len(p.requestedByPatterns) > 0 {
		matched := false
		for _, pattern := range p.requestedByPatterns {
			if pattern.MatchString(req.RequestedBy) {
				matched = true
				break
			}
		}
		if !matched {
			violations = append(violations, p.violation("requested_by", "requested_by does not match the allowed patterns"))
		}
	}
	for _, key := range p.policy.RequiredMetadata {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if strings.TrimSpace(req.Metadata[key]) == "" {
			violations = append(violations, p.violation("metadata."+key, fmt.Sprintf("metadata key %q is required", key)))
		}
	}
	if p.policy.AllowDryRun != nil && !*p.policy.AllowDryRun && req.DryRun {
		violations = append(violations, p.violation("dry_run", "dry_run must be false"))
	}
	if p.policy.AllowKeepFilesystem != nil && !*p.policy.AllowKeepFilesystem && req.KeepFilesystem {
		violations = append(violations, p.violation("keep_filesystem", "keep_filesystem must be false"))
	}
	if p.policy.AllowKeepCheckout != nil && !*p.policy.AllowKeepCheckout && req.KeepCheckout {
		violations = append(violations, p.violation("keep_checkout", "keep_checkout must be false"))
	}
	if p.policy.MaxConcurrentSnapshots > 0 && req.MaxConcurrentSnapshots > p.policy.MaxConcurrentSnapshots {
		violations = append(violations, p.violation("max_concurrent_snapshots", fmt.Sprintf("max_concurrent_snapshots %d exceeds policy limit %d", req.MaxConcurrentSnapshots, p.policy.MaxConcurrentSnapshots)))
	}
	return violations
}

func (p compiledPolicy) violation(field, message string) Violation {
	return Violation{
		PolicyID: p.policy.ID,
		Field:    field,
		Message:  message,
	}
}

func (p hclPolicy) toPolicy() Policy {
	return Policy{
		ID:                     p.ID,
		Description:            p.Description,
		ScanKinds:              normalizeKindsFromStrings(p.ScanKinds),
		Teams:                  p.Teams,
		Providers:              p.Providers,
		Registries:             p.Registries,
		RequireRequestedBy:     p.RequireRequestedBy,
		RequestedByPatterns:    p.RequestedByPatterns,
		RequiredMetadata:       p.RequiredMetadata,
		AllowDryRun:            p.AllowDryRun,
		AllowKeepFilesystem:    p.AllowKeepFilesystem,
		AllowKeepCheckout:      p.AllowKeepCheckout,
		MaxConcurrentSnapshots: p.MaxConcurrentSnapshots,
	}
}

func normalizeRequest(req Request) Request {
	req.Kind = Kind(strings.ToLower(strings.TrimSpace(string(req.Kind))))
	req.Team = strings.TrimSpace(req.Team)
	if req.Team == "" {
		req.Team = TeamFromMetadata(req.Metadata)
	}
	req.Team = strings.ToLower(strings.TrimSpace(req.Team))
	req.RequestedBy = strings.TrimSpace(req.RequestedBy)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.Registry = strings.ToLower(strings.TrimSpace(req.Registry))
	if len(req.Metadata) == 0 {
		req.Metadata = nil
	}
	return req
}

func normalizeKinds(kinds []Kind) []Kind {
	if len(kinds) == 0 {
		return nil
	}
	out := make([]Kind, 0, len(kinds))
	for _, kind := range kinds {
		if trimmed := Kind(strings.ToLower(strings.TrimSpace(string(kind)))); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizeKindsFromStrings(kinds []string) []Kind {
	if len(kinds) == 0 {
		return nil
	}
	out := make([]Kind, 0, len(kinds))
	for _, kind := range kinds {
		if trimmed := strings.ToLower(strings.TrimSpace(kind)); trimmed != "" {
			out = append(out, Kind(trimmed))
		}
	}
	return out
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.ToLower(strings.TrimSpace(value)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func supportedPolicyExtension(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml", ".hcl":
		return true
	default:
		return false
	}
}
