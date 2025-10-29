package pack

import (
	"time"

	"gopkg.in/yaml.v3"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

// Duration wraps time.Duration for YAML decoding support.
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements yaml.v3 unmarshaling for a duration string, e.g. "5m".
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	if raw == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

// Task defines a scheduled action sourced from an artifact pack.
type Task struct {
	Name            string                        `yaml:"name" json:"name"`
	Collector       string                        `yaml:"collector" json:"collector"`
	Interval        Duration                      `yaml:"interval" json:"interval"`
	Tags            map[string]string             `yaml:"tags" json:"tags"`
	Config          map[string]any                `yaml:"config" json:"config"`
	Discovery       []string                      `yaml:"discovery" json:"discovery"`
	Parameters      []types.ArtifactTaskParameter `yaml:"parameters" json:"parameters"`
	ParameterValues map[string]any                `yaml:"parameter_values" json:"parameter_values"`
	Resources       *types.ArtifactTaskResources  `yaml:"resources" json:"resources"`
	Tools           []types.ArtifactTool          `yaml:"tools" json:"tools"`
}

// Pack represents a collection of scheduled tasks and metadata.
type Pack struct {
	Name        string         `yaml:"name" json:"name"`
	Version     string         `yaml:"version" json:"version"`
	Description string         `yaml:"description" json:"description"`
	Selectors   map[string]any `yaml:"selectors" json:"selectors"`
	Tasks       []Task         `yaml:"tasks" json:"tasks"`
}
