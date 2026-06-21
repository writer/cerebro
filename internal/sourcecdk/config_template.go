package sourcecdk

import (
	"fmt"
	"strings"
)

// ConfigValue returns a source config value or an empty string.
func ConfigValue(cfg Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
}

// RequiredConfigValue returns a trimmed required config value.
func RequiredConfigValue(sourceID string, cfg Config, key string) (string, error) {
	key = strings.TrimSpace(key)
	value := strings.TrimSpace(ConfigValue(cfg, key))
	if value == "" {
		return "", fmt.Errorf("%w: %s %s is required", ErrInvalidConfig, strings.TrimSpace(sourceID), key)
	}
	return value, nil
}

// RenderConfigTemplate resolves ${config.key}, ${credential.key}, and
// ${connection.key} placeholders from source configuration.
func RenderConfigTemplate(sourceID string, template string, cfg Config, keys []string) (string, error) {
	rendered := strings.TrimSpace(template)
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		for _, prefix := range []string{"config", "credential", "connection"} {
			placeholder := "${" + prefix + "." + key + "}"
			if !strings.Contains(rendered, placeholder) {
				continue
			}
			value, err := RequiredConfigValue(sourceID, cfg, key)
			if err != nil {
				return "", err
			}
			rendered = strings.ReplaceAll(rendered, placeholder, value)
		}
	}
	if strings.Contains(rendered, "${") {
		return "", fmt.Errorf("%w: %s template %q contains unresolved variable", ErrInvalidConfig, strings.TrimSpace(sourceID), template)
	}
	return rendered, nil
}

// ResolveBaseURLConfig returns cfg with its "base_url" value rendered from
// template when "base_url" is unset and template is non-empty. The template is
// expanded with RenderConfigTemplate using keys, and sourceID labels validation
// errors. When "base_url" is already set or template is empty, the configuration
// values are returned unchanged.
func ResolveBaseURLConfig(sourceID string, template string, cfg Config, keys []string) (Config, error) {
	values := cfg.Values()
	if strings.TrimSpace(values["base_url"]) == "" && strings.TrimSpace(template) != "" {
		baseURL, err := RenderConfigTemplate(sourceID, template, cfg, keys)
		if err != nil {
			return Config{}, err
		}
		values["base_url"] = baseURL
	}
	return NewConfig(values), nil
}
