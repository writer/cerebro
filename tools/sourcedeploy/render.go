package sourcedeploy

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RenderOptions controls how manifests are projected onto an environment.
type RenderOptions struct {
	Environment string
	TenantID    string
}

// Fragment is the Pulumi-shaped subset this tool owns. Marshalling it as YAML
// produces keys identical to the ones consumed by infra/aws/__main__.py:
// cerebro:sourceSecretKeys, cerebro:sourceRuntimes, cerebro:orchestratorSchedules.
type Fragment struct {
	SourceSecretKeys      []string           `yaml:"cerebro:sourceSecretKeys,omitempty"`
	SourceRuntimes        []RenderedRuntime  `yaml:"cerebro:sourceRuntimes,omitempty"`
	OrchestratorSchedules []RenderedSchedule `yaml:"cerebro:orchestratorSchedules,omitempty"`
}

// RenderedRuntime is the shape Pulumi expects in `sourceRuntimes`.
type RenderedRuntime struct {
	ID       string            `yaml:"id"`
	SourceID string            `yaml:"sourceId"`
	TenantID string            `yaml:"tenantId,omitempty"`
	Config   map[string]string `yaml:"config"`
}

// RenderedSchedule is the shape Pulumi expects in `orchestratorSchedules`.
type RenderedSchedule struct {
	Name               string   `yaml:"name"`
	ScheduleExpression string   `yaml:"scheduleExpression"`
	TaskCount          int      `yaml:"taskCount,omitempty"`
	Command            []string `yaml:"command"`
}

// Render projects a list of manifests onto an environment, applying overlays
// declared under the manifest's `environments.<env>` block. The result is a
// deterministic, alphabetically sorted Fragment that can be merged into a
// Pulumi.<env>.yaml `config:` block.
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
	schedules := make([]RenderedSchedule, 0)

	sortedManifests := append([]Manifest(nil), manifests...)
	sort.Slice(sortedManifests, func(i, j int) bool {
		return sortedManifests[i].SourceID < sortedManifests[j].SourceID
	})

	for _, manifest := range sortedManifests {
		overlay := manifest.Environments[opts.Environment]
		disabledRuntimes := stringSet(overlay.DisabledRuntimes)
		disabledSchedules := stringSet(overlay.DisabledSchedules)

		for _, key := range manifest.SecretKeys {
			secretKeys[strings.TrimSpace(key)] = struct{}{}
		}
		for _, key := range overlay.ExtraSecretKeys {
			secretKeys[strings.TrimSpace(key)] = struct{}{}
		}

		emit := func(list []RuntimeManifest, disabled map[string]struct{}) {
			for _, runtime := range list {
				if _, dropped := disabled[runtime.LocalID]; dropped {
					continue
				}
				runtimes = append(runtimes, RenderedRuntime{
					ID:       qualifiedRuntimeID(opts.TenantID, manifest.SourceID, runtime.LocalID),
					SourceID: manifest.SourceID,
					TenantID: opts.TenantID,
					Config:   copyConfig(runtime.Config),
				})
			}
		}
		emit(manifest.Runtimes, disabledRuntimes)
		emit(overlay.ExtraRuntimes, nil)

		emitSchedules := func(list []ScheduleManifest, disabled map[string]struct{}) {
			for _, schedule := range list {
				if _, dropped := disabled[schedule.LocalName]; dropped {
					continue
				}
				schedules = append(schedules, RenderedSchedule{
					Name:               qualifiedScheduleName(manifest.SourceID, schedule.LocalName),
					ScheduleExpression: schedule.ScheduleExpression,
					TaskCount:          schedule.TaskCount,
					Command: composeScheduleCommand(
						schedule.Command,
						qualifiedRuntimeID(opts.TenantID, manifest.SourceID, schedule.RuntimeLocalID),
					),
				})
			}
		}
		emitSchedules(manifest.Schedules, disabledSchedules)
		emitSchedules(overlay.ExtraSchedules, nil)
	}

	keys := make([]string, 0, len(secretKeys))
	for key := range secretKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i].ID < runtimes[j].ID })
	sort.Slice(schedules, func(i, j int) bool { return schedules[i].Name < schedules[j].Name })

	return Fragment{
		SourceSecretKeys:      keys,
		SourceRuntimes:        runtimes,
		OrchestratorSchedules: schedules,
	}, nil
}

// MarshalYAML emits the Fragment as a deterministic YAML document with
// 2-space indentation matching the hand-authored Pulumi config files. Map
// keys inside `config` are sorted, and config values are emitted as quoted
// strings because the Pulumi consumer always coerces them via str().
func (f Fragment) MarshalYAML() ([]byte, error) {
	doc := &yaml.Node{Kind: yaml.MappingNode}
	if len(f.SourceSecretKeys) > 0 {
		doc.Content = append(doc.Content, scalar("cerebro:sourceSecretKeys"), seqOfScalars(f.SourceSecretKeys))
	}
	if len(f.OrchestratorSchedules) > 0 {
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, schedule := range f.OrchestratorSchedules {
			node := &yaml.Node{Kind: yaml.MappingNode}
			node.Content = append(node.Content,
				scalar("name"), scalar(schedule.Name),
				scalar("scheduleExpression"), scalar(schedule.ScheduleExpression),
				scalar("taskCount"), intScalar(schedule.TaskCount),
				scalar("command"), seqOfScalars(schedule.Command),
			)
			seq.Content = append(seq.Content, node)
		}
		doc.Content = append(doc.Content, scalar("cerebro:orchestratorSchedules"), seq)
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

func qualifiedScheduleName(source, local string) string {
	return fmt.Sprintf("%s-%s", source, local)
}

// composeScheduleCommand inserts the runtime_id key=value argument immediately
// after the verb tokens (the leading run of arguments without '=') so the
// rendered command matches the existing hand-authored Pulumi schedules:
//
//	[orchestrator, run, runtime_id=..., page_limit=20, ...]
func composeScheduleCommand(base []string, runtimeID string) []string {
	if len(base) == 0 {
		return []string{"orchestrator", "run", fmt.Sprintf("runtime_id=%s", runtimeID)}
	}
	insertAt := 0
	for ; insertAt < len(base); insertAt++ {
		if strings.Contains(base[insertAt], "=") {
			break
		}
	}
	out := make([]string, 0, len(base)+1)
	out = append(out, base[:insertAt]...)
	out = append(out, fmt.Sprintf("runtime_id=%s", runtimeID))
	out = append(out, base[insertAt:]...)
	return out
}

func stringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
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

func intScalar(value int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("%d", value)}
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

// shouldQuoteConfigValue decides whether a runtime config value should be
// emitted as a quoted YAML scalar. We quote any value that yaml.v3 would
// otherwise tag as a non-string (e.g. "200", "2026-01-01T00:00:00Z") so the
// rendered file matches the hand-authored Pulumi config style.
func shouldQuoteConfigValue(value string) bool {
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "env:") {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			continue
		}
	}
	if isDigitsOnly(value) {
		return true
	}
	if strings.Contains(value, ":") || strings.Contains(value, "T") && strings.Contains(value, "-") {
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
