package pack

import (
	"time"

	"gopkg.in/yaml.v3"
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
	Name      string            `yaml:"name"`
	Collector string            `yaml:"collector"`
	Interval  Duration          `yaml:"interval"`
	Tags      map[string]string `yaml:"tags"`
}

// Pack represents a collection of scheduled tasks and metadata.
type Pack struct {
	Name        string            `yaml:"name"`
	Version     string            `yaml:"version"`
	Description string            `yaml:"description"`
	Selectors   map[string]string `yaml:"selectors"`
	Tasks       []Task            `yaml:"tasks"`
}
