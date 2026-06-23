// APIs.guru registry resolution.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type apisGuruRegistry map[string]struct {
	Preferred string `json:"preferred"`
	Versions  map[string]struct {
		SwaggerURL     string `json:"swaggerUrl"`
		SwaggerYamlURL string `json:"swaggerYamlUrl"`
	} `json:"versions"`
}

func (r apisGuruRegistry) specURL(key string) (string, error) {
	api, ok := r[key]
	if !ok {
		return "", fmt.Errorf("apis_guru key %q not found in registry", key)
	}
	version, ok := api.Versions[api.Preferred]
	if !ok {
		for _, candidate := range api.Versions {
			version = candidate
			break
		}
	}
	// Prefer the JSON rendering: APIs.guru's YAML specs frequently embed Unicode
	// control characters in description/example strings that the YAML parser
	// rejects, whereas the JSON rendering escapes them. parseSpec still sanitizes
	// as a fallback for providers that only publish YAML.
	if url := strings.TrimSpace(version.SwaggerURL); url != "" {
		return url, nil
	}
	if url := strings.TrimSpace(version.SwaggerYamlURL); url != "" {
		return url, nil
	}
	return "", fmt.Errorf("apis_guru key %q has no resolvable spec url", key)
}

func loadAPIsGuru(client *http.Client, cachePath string) (apisGuruRegistry, error) {
	var payload []byte
	var err error
	if strings.TrimSpace(cachePath) != "" {
		payload, err = os.ReadFile(cachePath) //nolint:gosec // operator-provided cache path for a build-time tool.
		if err != nil {
			return nil, fmt.Errorf("read apisguru cache: %w", err)
		}
	} else {
		payload, err = fetch(client, apisGuruListURL)
		if err != nil {
			// A missing registry is only fatal when a target needs it; defer.
			return apisGuruRegistry{}, nil
		}
	}
	registry := apisGuruRegistry{}
	if err := json.Unmarshal(payload, &registry); err != nil {
		return nil, fmt.Errorf("parse apisguru list: %w", err)
	}
	return registry, nil
}
