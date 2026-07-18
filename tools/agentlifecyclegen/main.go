// Command agentlifecyclegen generates Go and TypeScript bindings from the
// public AgentServiceLifecycle JSON Schema.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type schemaDocument struct {
	Title                string             `json:"title"`
	Ref                  string             `json:"$ref"`
	Type                 string             `json:"type"`
	Description          string             `json:"description"`
	Properties           map[string]*schema `json:"properties"`
	Required             []string           `json:"required"`
	OneOf                []*schema          `json:"oneOf"`
	AllOf                []*schema          `json:"allOf"`
	AdditionalProperties json.RawMessage    `json:"additionalProperties"`
	Defs                 map[string]*schema `json:"$defs"`
}

type schema struct {
	Type                 string             `json:"type"`
	Description          string             `json:"description"`
	Ref                  string             `json:"$ref"`
	Enum                 []string           `json:"enum"`
	Const                any                `json:"const"`
	Properties           map[string]*schema `json:"properties"`
	Required             []string           `json:"required"`
	Items                *schema            `json:"items"`
	OneOf                []*schema          `json:"oneOf"`
	AllOf                []*schema          `json:"allOf"`
	If                   *schema            `json:"if"`
	Then                 *schema            `json:"then"`
	AdditionalProperties json.RawMessage    `json:"additionalProperties"`
}

func main() {
	var schemaPath string
	var goOutput string
	var goPackage string
	var typeScriptOutput string
	var check bool
	flag.StringVar(&schemaPath, "schema", "schemas/agent-service-lifecycle-contract.schema.json", "canonical JSON Schema path")
	flag.StringVar(&goOutput, "go-out", "internal/agentplatform/agent_service_lifecycle_generated.go", "generated Go output path")
	flag.StringVar(&goPackage, "go-package", "agentplatform", "generated Go package name")
	flag.StringVar(&typeScriptOutput, "ts-out", "sdk/typescript/src/generated/agent-service-lifecycle-contract.ts", "generated TypeScript output path")
	flag.BoolVar(&check, "check", false, "verify generated outputs are current")
	flag.Parse()

	document, err := loadDocument(schemaPath)
	if err != nil {
		fail(err)
	}
	goPayload, err := generateGo(document, goPackage)
	if err != nil {
		fail(err)
	}
	typeScriptPayload, err := generateTypeScript(document)
	if err != nil {
		fail(err)
	}

	outputs := []generatedOutput{
		{path: goOutput, payload: goPayload},
		{path: typeScriptOutput, payload: typeScriptPayload},
	}
	for _, output := range outputs {
		if check {
			if err := checkOutput(output); err != nil {
				fail(err)
			}
			continue
		}
		if err := writeOutput(output); err != nil {
			fail(err)
		}
	}
}

type generatedOutput struct {
	path    string
	payload []byte
}

func loadDocument(path string) (schemaDocument, error) {
	payload, err := os.ReadFile(strings.TrimSpace(path)) // #nosec G304 -- operator-provided repository path.
	if err != nil {
		return schemaDocument{}, fmt.Errorf("read schema: %w", err)
	}
	var document schemaDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&document); err != nil {
		return schemaDocument{}, fmt.Errorf("decode schema: %w", err)
	}
	if strings.TrimSpace(document.Title) == "" {
		return schemaDocument{}, errors.New("schema title is required")
	}
	if len(document.Defs) == 0 {
		return schemaDocument{}, errors.New("schema $defs cannot be empty")
	}
	if document.Ref != "" {
		rootName := refName(document.Ref)
		if _, ok := document.Defs[rootName]; !ok {
			return schemaDocument{}, fmt.Errorf("root ref %q does not name a definition", document.Ref)
		}
	} else if document.Type != "object" || len(document.Properties) == 0 {
		return schemaDocument{}, errors.New("schema must define a root $ref or object properties")
	}
	if err := validateRefs(document.rootSchema(), document.Defs); err != nil {
		return schemaDocument{}, fmt.Errorf("root schema: %w", err)
	}
	for name, definition := range document.Defs {
		if definition == nil {
			return schemaDocument{}, fmt.Errorf("definition %q is null", name)
		}
		if err := validateRefs(definition, document.Defs); err != nil {
			return schemaDocument{}, fmt.Errorf("definition %q: %w", name, err)
		}
	}
	return document, nil
}

func validateRefs(value *schema, definitions map[string]*schema) error {
	if value == nil {
		return nil
	}
	if value.Ref != "" {
		name := refName(value.Ref)
		if _, ok := definitions[name]; !ok {
			return fmt.Errorf("unknown ref %q", value.Ref)
		}
	}
	for name, property := range value.Properties {
		if err := validateRefs(property, definitions); err != nil {
			return fmt.Errorf("property %q: %w", name, err)
		}
	}
	if err := validateRefs(value.Items, definitions); err != nil {
		return err
	}
	for _, candidate := range append(append([]*schema{}, value.OneOf...), value.AllOf...) {
		if err := validateRefs(candidate, definitions); err != nil {
			return err
		}
	}
	if err := validateRefs(value.If, definitions); err != nil {
		return err
	}
	return validateRefs(value.Then, definitions)
}

func generateGo(document schemaDocument, packageName string) ([]byte, error) {
	var output strings.Builder
	fmt.Fprintf(&output, "// Code generated by tools/agentlifecyclegen from the %s JSON Schema. DO NOT EDIT.\n\n", document.Title)
	fmt.Fprintf(&output, "package %s\n", strings.TrimSpace(packageName))
	types := document.types()
	if schemasUseRawJSON(types) {
		output.WriteString("\nimport \"encoding/json\"\n")
	}
	output.WriteString("\n")
	for _, sourceName := range sortedSchemaNames(types) {
		definition := types[sourceName]
		name := typeName(sourceName)
		writeGoComment(&output, name, definition.Description)
		switch {
		case len(definition.Enum) > 0:
			fmt.Fprintf(&output, "type %s string\n\n", name)
			output.WriteString("const (\n")
			for _, value := range definition.Enum {
				fmt.Fprintf(&output, "\t%s%s %s = %q\n", name, exportedName(value), name, value)
			}
			output.WriteString(")\n\n")
		case definition.Type == "object" || len(definition.Properties) > 0:
			fmt.Fprintf(&output, "type %s struct {\n", name)
			required := stringSet(definition.Required)
			for _, propertyName := range sortedSchemaNames(definition.Properties) {
				property := definition.Properties[propertyName]
				jsonTag := propertyName
				if !required[propertyName] {
					jsonTag += ",omitempty"
				}
				fmt.Fprintf(&output, "\t%s %s `json:%q`\n", exportedName(propertyName), goFieldType(property, required[propertyName]), jsonTag)
			}
			output.WriteString("}\n\n")
		default:
			fmt.Fprintf(&output, "type %s %s\n\n", name, goType(definition))
		}
	}
	formatted, err := format.Source([]byte(output.String()))
	if err != nil {
		return nil, fmt.Errorf("format generated Go: %w", err)
	}
	return formatted, nil
}

func generateTypeScript(document schemaDocument) ([]byte, error) {
	var output strings.Builder
	fmt.Fprintf(&output, "// Code generated by tools/agentlifecyclegen from the %s JSON Schema. DO NOT EDIT.\n\n", document.Title)
	for _, sourceName := range sortedSchemaNames(document.types()) {
		definition := document.types()[sourceName]
		name := typeName(sourceName)
		writeTypeScriptComment(&output, definition.Description)
		switch {
		case len(definition.Enum) > 0:
			fmt.Fprintf(&output, "export type %s =\n", name)
			for index, value := range definition.Enum {
				terminator := ""
				if index == len(definition.Enum)-1 {
					terminator = ";"
				}
				fmt.Fprintf(&output, "  | %q%s\n", value, terminator)
			}
			output.WriteString("\n")
		case definition.Type == "object" || len(definition.Properties) > 0:
			fmt.Fprintf(&output, "export type %s = {\n", name)
			required := stringSet(definition.Required)
			for _, propertyName := range sortedSchemaNames(definition.Properties) {
				optional := "?"
				if required[propertyName] {
					optional = ""
				}
				fmt.Fprintf(&output, "  %s%s: %s;\n", propertyName, optional, typeScriptType(definition.Properties[propertyName]))
			}
			output.WriteString("};\n\n")
		default:
			fmt.Fprintf(&output, "export type %s = %s;\n\n", name, typeScriptType(definition))
		}
	}
	return []byte(strings.TrimRight(output.String(), "\n") + "\n"), nil
}

func goType(value *schema) string {
	if value == nil {
		return "any"
	}
	if value.Ref != "" {
		return typeName(refName(value.Ref))
	}
	if len(value.OneOf) > 0 {
		return goUnionType(value.OneOf)
	}
	if value.Const != nil {
		switch value.Const.(type) {
		case bool:
			return "bool"
		case float64:
			return "float64"
		default:
			return "string"
		}
	}
	if len(value.Enum) > 0 {
		return "string"
	}
	switch value.Type {
	case "string":
		return "string"
	case "integer":
		return "int64"
	case "number":
		return "float64"
	case "boolean":
		return "bool"
	case "array":
		return "[]" + goType(value.Items)
	case "object":
		return goAdditionalPropertiesType(value.AdditionalProperties)
	default:
		return "any"
	}
}

func typeScriptType(value *schema) string {
	if value == nil {
		return "unknown"
	}
	if value.Ref != "" {
		return typeName(refName(value.Ref))
	}
	if len(value.OneOf) > 0 {
		parts := make([]string, 0, len(value.OneOf))
		for _, candidate := range value.OneOf {
			parts = append(parts, typeScriptType(candidate))
		}
		return strings.Join(parts, " | ")
	}
	if value.Const != nil {
		payload, err := json.Marshal(value.Const)
		if err != nil {
			return "unknown"
		}
		return string(payload)
	}
	if len(value.Enum) > 0 {
		values := make([]string, 0, len(value.Enum))
		for _, enumValue := range value.Enum {
			values = append(values, fmt.Sprintf("%q", enumValue))
		}
		return strings.Join(values, " | ")
	}
	switch value.Type {
	case "string":
		return "string"
	case "integer", "number":
		return "number"
	case "boolean":
		return "boolean"
	case "array":
		return typeScriptType(value.Items) + "[]"
	case "object":
		return typeScriptAdditionalPropertiesType(value.AdditionalProperties)
	case "null":
		return "null"
	default:
		return "unknown"
	}
}

func (document schemaDocument) rootSchema() *schema {
	return &schema{
		Type:                 document.Type,
		Description:          document.Description,
		Ref:                  document.Ref,
		Properties:           document.Properties,
		Required:             document.Required,
		OneOf:                document.OneOf,
		AllOf:                document.AllOf,
		AdditionalProperties: document.AdditionalProperties,
	}
}

func (document schemaDocument) types() map[string]*schema {
	result := make(map[string]*schema, len(document.Defs)+1)
	for name, definition := range document.Defs {
		result[name] = definition
	}
	if document.Ref == "" {
		result[typeName(document.Title)] = document.rootSchema()
	}
	return result
}

func goFieldType(value *schema, required bool) string {
	base := goType(value)
	if required || strings.HasPrefix(base, "[]") || strings.HasPrefix(base, "map[") || strings.HasPrefix(base, "*") || base == "any" || base == "json.RawMessage" {
		return base
	}
	return "*" + base
}

func goUnionType(values []*schema) string {
	nonNull := make([]*schema, 0, len(values))
	hasNull := false
	for _, candidate := range values {
		if candidate != nil && candidate.Type == "null" {
			hasNull = true
			continue
		}
		nonNull = append(nonNull, candidate)
	}
	if len(nonNull) == 1 {
		base := goType(nonNull[0])
		if hasNull && !strings.HasPrefix(base, "*") {
			return "*" + base
		}
		return base
	}
	return "json.RawMessage"
}

func goAdditionalPropertiesType(raw json.RawMessage) string {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return "map[string]any"
	}
	var value schema
	if err := json.Unmarshal(raw, &value); err == nil && (value.Type != "" || value.Ref != "" || len(value.OneOf) > 0) {
		return "map[string]" + goType(&value)
	}
	return "map[string]any"
}

func typeScriptAdditionalPropertiesType(raw json.RawMessage) string {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return "Record<string, unknown>"
	}
	var value schema
	if err := json.Unmarshal(raw, &value); err == nil && (value.Type != "" || value.Ref != "" || len(value.OneOf) > 0) {
		return "Record<string, " + typeScriptType(&value) + ">"
	}
	return "Record<string, unknown>"
}

func schemasUseRawJSON(types map[string]*schema) bool {
	for _, value := range types {
		if schemaUsesRawJSON(value) {
			return true
		}
	}
	return false
}

func schemaUsesRawJSON(value *schema) bool {
	if value == nil {
		return false
	}
	if len(value.OneOf) > 1 {
		nonNull := 0
		for _, candidate := range value.OneOf {
			if candidate != nil && candidate.Type != "null" {
				nonNull++
			}
		}
		if nonNull > 1 {
			return true
		}
	}
	for _, property := range value.Properties {
		if schemaUsesRawJSON(property) {
			return true
		}
	}
	return schemaUsesRawJSON(value.Items)
}

func exportedName(value string) string {
	parts := strings.FieldsFunc(value, func(character rune) bool {
		return !(unicode.IsLetter(character) || unicode.IsDigit(character))
	})
	var output strings.Builder
	for _, part := range parts {
		upper := strings.ToUpper(part)
		switch upper {
		case "API", "HTTP", "HTTPS", "ID", "JSON", "RPC", "SDK", "URL":
			output.WriteString(upper)
		case "IDS":
			output.WriteString("IDs")
		default:
			runes := []rune(strings.ToLower(part))
			if len(runes) == 0 {
				continue
			}
			runes[0] = unicode.ToUpper(runes[0])
			output.WriteString(string(runes))
		}
	}
	if output.Len() == 0 {
		return "Value"
	}
	return output.String()
}

func refName(ref string) string {
	parts := strings.Split(strings.TrimSpace(ref), "/")
	return parts[len(parts)-1]
}

func typeName(value string) string {
	runes := []rune(value)
	if strings.ContainsAny(value, "_- .") || (len(runes) > 0 && unicode.IsLower(runes[0])) {
		return exportedName(value)
	}
	return value
}

func sortedSchemaNames[T any](values map[string]T) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func writeGoComment(output *strings.Builder, name string, description string) {
	description = strings.TrimSpace(strings.ReplaceAll(description, "\n", " "))
	if description == "" {
		description = name + " is part of the AgentServiceLifecycle contract."
	}
	fmt.Fprintf(output, "// %s %s\n", name, description)
}

func writeTypeScriptComment(output *strings.Builder, description string) {
	description = strings.TrimSpace(strings.ReplaceAll(description, "\n", " "))
	if description != "" {
		fmt.Fprintf(output, "/** %s */\n", description)
	}
}

func checkOutput(output generatedOutput) error {
	existing, err := os.ReadFile(strings.TrimSpace(output.path)) // #nosec G304 -- operator-provided repository path.
	if err != nil {
		return fmt.Errorf("read generated output %s: %w", output.path, err)
	}
	if !bytes.Equal(existing, output.payload) {
		return fmt.Errorf("generated output %s is stale; run make agent-service-lifecycle-generate", output.path)
	}
	return nil
}

func writeOutput(output generatedOutput) error {
	path := strings.TrimSpace(output.path)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create output directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, output.payload, 0o600); err != nil {
		return fmt.Errorf("write generated output %s: %w", path, err)
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agentlifecyclegen:", err)
	os.Exit(1)
}
