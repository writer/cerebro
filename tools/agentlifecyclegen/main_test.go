package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerateBindings(t *testing.T) {
	document := schemaDocument{
		Title: "Contract",
		Ref:   "#/$defs/Contract",
		Defs: map[string]*schema{
			"Contract": {
				Type:       "object",
				Required:   []string{"schema_version", "state"},
				Properties: map[string]*schema{"schema_version": {Type: "string", Const: "v1"}, "state": {Ref: "#/$defs/State"}},
			},
			"State": {Type: "string", Enum: []string{"ready", "rolled_back"}},
		},
	}

	goPayload, err := generateGo(document, "agentplatform")
	if err != nil {
		t.Fatalf("generateGo: %v", err)
	}
	typeScriptPayload, err := generateTypeScript(document)
	if err != nil {
		t.Fatalf("generateTypeScript: %v", err)
	}

	assertContains(t, string(goPayload), "StateRolledBack State = \"rolled_back\"")
	assertContains(t, string(goPayload), "SchemaVersion string `json:\"schema_version\"`")
	assertContains(t, string(typeScriptPayload), "schema_version: \"v1\"")
	assertContains(t, string(typeScriptPayload), "state: State")
}

func TestValidateRefsRejectsUnknownDefinition(t *testing.T) {
	err := validateRefs(&schema{Ref: "#/$defs/Missing"}, map[string]*schema{})
	if err == nil || !strings.Contains(err.Error(), "unknown ref") {
		t.Fatalf("validateRefs error = %v, want unknown ref", err)
	}
}

func TestOpenAPIEmbedsCanonicalLifecycleContractSchema(t *testing.T) {
	schemaPayload, err := os.ReadFile("../../schemas/agent-service-lifecycle-contract.schema.json")
	if err != nil {
		t.Fatalf("read lifecycle schema: %v", err)
	}
	var canonical any
	if err := json.Unmarshal(schemaPayload, &canonical); err != nil {
		t.Fatalf("decode lifecycle schema: %v", err)
	}
	openAPIPayload, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				AllOf []any `yaml:"allOf"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(openAPIPayload, &spec); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	embedded := spec.Components.Schemas["AgentServiceLifecycleContract"].AllOf
	if len(embedded) != 1 {
		t.Fatalf("OpenAPI lifecycle component allOf entries = %d, want 1", len(embedded))
	}
	canonical = rewriteSchemaRefs(canonical, "#/$defs/", "#/components/schemas/AgentServiceLifecycleContract/allOf/0/$defs/")
	if !reflect.DeepEqual(normalizeJSONValue(t, embedded[0]), canonical) {
		t.Fatal("OpenAPI lifecycle component differs from schemas/agent-service-lifecycle-contract.schema.json")
	}
}

func rewriteSchemaRefs(value any, from, to string) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = rewriteSchemaRefs(item, from, to)
		}
		return typed
	case []any:
		for index, item := range typed {
			typed[index] = rewriteSchemaRefs(item, from, to)
		}
		return typed
	case string:
		return strings.Replace(typed, from, to, 1)
	default:
		return value
	}
}

func normalizeJSONValue(t *testing.T, value any) any {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal normalized value: %v", err)
	}
	var normalized any
	if err := json.Unmarshal(payload, &normalized); err != nil {
		t.Fatalf("decode normalized value: %v", err)
	}
	return normalized
}

func assertContains(t *testing.T, value string, expected string) {
	t.Helper()
	if !strings.Contains(value, expected) {
		t.Fatalf("generated output missing %q:\n%s", expected, value)
	}
}
