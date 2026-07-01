package evidencepackets

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEvidencePacketsResponseOpenAPIDocumentsTopLevelFields(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(payload, &spec); err != nil {
		t.Fatalf("decode openapi.yaml: %v", err)
	}
	response, ok := spec.Components.Schemas["GRCEvidencePacketsResponse"]
	if !ok {
		t.Fatal("GRCEvidencePacketsResponse schema missing from openapi.yaml")
	}
	want := jsonFields(reflect.TypeOf(Response{}))
	var missing []string
	for field := range want {
		if _, ok := response.Properties[field]; !ok {
			missing = append(missing, field)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("GRCEvidencePacketsResponse missing properties for Response fields: %s", strings.Join(missing, ", "))
	}
}

func jsonFields(t reflect.Type) map[string]struct{} {
	fields := map[string]struct{}{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous && field.Type.Kind() == reflect.Struct && field.Tag.Get("json") == "" {
			for name := range jsonFields(field.Type) {
				fields[name] = struct{}{}
			}
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		fields[name] = struct{}{}
	}
	return fields
}
