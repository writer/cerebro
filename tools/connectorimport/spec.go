// OpenAPI spec resolution and intake (file/URL/registry, Swagger 2.0
// conversion, YAML normalization).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

func resolveSpec(client *http.Client, registry apisGuruRegistry, entry manifestTarget) (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	switch {
	case strings.TrimSpace(entry.SpecFile) != "":
		payload, err := os.ReadFile(entry.SpecFile) //nolint:gosec // operator-provided spec path for a build-time tool.
		if err != nil {
			return nil, fmt.Errorf("read spec file: %w", err)
		}
		return parseSpec(loader, payload)
	case strings.TrimSpace(entry.SpecURL) != "":
		return loadSpecFromURL(client, loader, entry.SpecURL)
	case strings.TrimSpace(entry.APIsGuru) != "":
		specURL, err := registry.specURL(entry.APIsGuru)
		if err != nil {
			return nil, err
		}
		return loadSpecFromURL(client, loader, specURL)
	default:
		return nil, fmt.Errorf("target %q has no spec_file, spec_url, or apis_guru source", entry.SourceID)
	}
}

func loadSpecFromURL(client *http.Client, loader *openapi3.Loader, specURL string) (*openapi3.T, error) {
	payload, err := fetch(client, specURL)
	if err != nil {
		return nil, err
	}
	return parseSpec(loader, payload)
}

// parseSpec loads an OpenAPI 3 document, transparently converting Swagger 2.0
// specs (a large share of the APIs.guru corpus) to OpenAPI 3 first. This
// recovers the dominant "spec_parse" intake failure.
func parseSpec(loader *openapi3.Loader, payload []byte) (*openapi3.T, error) {
	payload = sanitizeControlChars(payload)
	if isSwaggerV2(payload) {
		return convertSwaggerV2(loader, payload)
	}
	doc, err := loader.LoadFromData(payload)
	if err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	return doc, nil
}

// sanitizeControlChars removes disallowed control characters (everything below
// U+0020 except tab/newline/carriage-return, plus the C1 control range) that
// some APIs.guru YAML specs embed in description and example strings and that
// the YAML parser rejects ("control characters are not allowed"). It is a no-op
// for clean JSON specs.
func sanitizeControlChars(payload []byte) []byte {
	if utf8.Valid(payload) {
		return []byte(strings.Map(func(r rune) rune {
			if r == '\t' || r == '\n' || r == '\r' || !unicode.IsControl(r) {
				return r
			}
			return -1
		}, string(payload)))
	}
	out := make([]byte, 0, len(payload))
	for _, b := range payload {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			continue
		}
		out = append(out, b)
	}
	return out
}

func isSwaggerV2(payload []byte) bool {
	var probe struct {
		Swagger string `yaml:"swagger" json:"swagger"`
	}
	if err := yaml.Unmarshal(payload, &probe); err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(probe.Swagger), "2")
}

func convertSwaggerV2(loader *openapi3.Loader, payload []byte) (*openapi3.T, error) {
	jsonBytes, err := yamlToJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("normalize swagger 2.0 spec: %w", err)
	}
	var doc2 openapi2.T
	if err := json.Unmarshal(jsonBytes, &doc2); err != nil {
		return nil, fmt.Errorf("parse swagger 2.0 spec: %w", err)
	}
	doc3, err := openapi2conv.ToV3(&doc2)
	if err != nil {
		return nil, fmt.Errorf("convert swagger 2.0 to openapi 3: %w", err)
	}
	_ = loader.ResolveRefsIn(doc3, nil)
	return doc3, nil
}

// yamlToJSON converts a YAML (or already-JSON) payload to JSON so it can be
// unmarshaled into kin-openapi's JSON-tagged openapi2 types.
func yamlToJSON(payload []byte) ([]byte, error) {
	var generic any
	if err := yaml.Unmarshal(payload, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func fetch(client *http.Client, rawURL string) ([]byte, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("refusing non-https spec url %q", rawURL)
	}
	response, err := client.Get(rawURL) //nolint:noctx // build-time codegen tool; per-request timeout set on client.
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", rawURL, response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxSpecBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rawURL, err)
	}
	return payload, nil
}
