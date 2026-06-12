package sourcedeploy

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RenderOptions controls how manifests are projected onto an environment.
//
// The Environment field is part of the contract even though the current
// renderer is environment-agnostic: future per-source manifests may want to
// gate runtimes on environment without re-introducing schedule logic, and
// keeping the parameter avoids a breaking signature change.
type RenderOptions struct {
	Environment string
	TenantID    string
}

// Fragment is the deployment-config subset this tool owns. Marshalling it as
// YAML produces two stable keys: cerebro:sourceSecretKeys and
// cerebro:sourceRuntimes.
//
// cerebro:orchestratorSchedules is intentionally *not* rendered here: the
// rate, taskCount, and choice of which runtimes to schedule are operational
// decisions owned by deployment automation and authored alongside the generated
// fragment.
type Fragment struct {
	SourceSecretKeys []string          `yaml:"cerebro:sourceSecretKeys,omitempty"`
	SourceRuntimes   []RenderedRuntime `yaml:"cerebro:sourceRuntimes,omitempty"`
}

// RenderedRuntime is the shape deployment automation expects in
// `sourceRuntimes`.
type RenderedRuntime struct {
	ID       string            `yaml:"id"`
	SourceID string            `yaml:"sourceId"`
	TenantID string            `yaml:"tenantId,omitempty"`
	Config   map[string]string `yaml:"config"`
}

// Render projects a list of manifests for a tenant. The result is a
// deterministic, alphabetically sorted Fragment that can be merged into a
// deployment config block.
func Render(manifests []Manifest, opts RenderOptions) (Fragment, error) {
	if strings.TrimSpace(opts.TenantID) == "" {
		return Fragment{}, fmt.Errorf("RenderOptions.TenantID is required")
	}
	if !idPattern.MatchString(opts.TenantID) {
		return Fragment{}, fmt.Errorf("tenantId %q must be lowercase kebab-case", opts.TenantID)
	}
	if strings.TrimSpace(opts.Environment) == "" {
		return Fragment{}, fmt.Errorf("RenderOptions.Environment is required")
	}

	secretKeys := map[string]struct{}{}
	runtimes := make([]RenderedRuntime, 0)

	sortedManifests := append([]Manifest(nil), manifests...)
	sort.Slice(sortedManifests, func(i, j int) bool {
		return sortedManifests[i].SourceID < sortedManifests[j].SourceID
	})

	for _, manifest := range sortedManifests {
		for _, key := range manifest.SecretKeys {
			secretKeys[strings.TrimSpace(key)] = struct{}{}
		}
		for _, runtime := range manifest.Runtimes {
			runtimes = append(runtimes, RenderedRuntime{
				ID:       qualifiedRuntimeID(opts.TenantID, manifest.SourceID, runtime.LocalID),
				SourceID: manifest.SourceID,
				TenantID: opts.TenantID,
				Config:   copyConfig(runtime.Config),
			})
		}
	}

	keys := make([]string, 0, len(secretKeys))
	for key := range secretKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i].ID < runtimes[j].ID })

	return Fragment{SourceSecretKeys: keys, SourceRuntimes: runtimes}, nil
}

// MarshalYAML emits the Fragment as a deterministic YAML document with
// 2-space indentation. Map keys inside `config` are sorted, and config values
// are emitted as quoted strings so deployment consumers can parse them
// consistently.
func (f Fragment) MarshalYAML() ([]byte, error) {
	doc := &yaml.Node{Kind: yaml.MappingNode}
	if len(f.SourceSecretKeys) > 0 {
		doc.Content = append(doc.Content, scalar("cerebro:sourceSecretKeys"), seqOfScalars(f.SourceSecretKeys))
	}
	if len(f.SourceRuntimes) > 0 {
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, runtime := range f.SourceRuntimes {
			node := &yaml.Node{Kind: yaml.MappingNode}
			node.Content = append(node.Content,
				scalar("id"), scalar(runtime.ID),
				scalar("sourceId"), scalar(runtime.SourceID),
				scalar("tenantId"), scalar(runtime.TenantID),
				scalar("config"), sortedQuotedMap(runtime.Config),
			)
			seq.Content = append(seq.Content, node)
		}
		doc.Content = append(doc.Content, scalar("cerebro:sourceRuntimes"), seq)
	}
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func qualifiedRuntimeID(tenant, source, local string) string {
	return fmt.Sprintf("%s-%s-%s", tenant, source, local)
}

func copyConfig(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: value}
}

func seqOfScalars(values []string) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, value := range values {
		seq.Content = append(seq.Content, scalar(value))
	}
	return seq
}

func sortedQuotedMap(in map[string]string) *yaml.Node {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	node := &yaml.Node{Kind: yaml.MappingNode}
	for _, key := range keys {
		valueNode := &yaml.Node{Kind: yaml.ScalarNode, Value: in[key]}
		if shouldQuoteConfigValue(in[key]) {
			valueNode.Style = yaml.DoubleQuotedStyle
		}
		node.Content = append(node.Content, scalar(key), valueNode)
	}
	return node
}

// shouldQuoteConfigValue forces double-quotes on values yaml.v3 would
// otherwise tag as non-strings, such as digits or ISO-8601 timestamps.
func shouldQuoteConfigValue(value string) bool {
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "env:") {
		return false
	}
	if isDigitsOnly(value) {
		return true
	}
	if strings.Contains(value, ":") {
		return true
	}
	if strings.Contains(value, "T") && strings.Contains(value, "-") {
		return true
	}
	return false
}

func isDigitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
