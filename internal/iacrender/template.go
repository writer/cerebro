package iacrender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

func RenderTemplate(name, src string, data any) (string, error) {
	tmpl, err := template.New(name).Funcs(FuncMap()).Parse(src)
	if err != nil {
		return "", fmt.Errorf("parse template %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template %s: %w", name, err)
	}
	return strings.TrimLeft(buf.String(), "\n"), nil
}

func FuncMap() template.FuncMap {
	return template.FuncMap{
		"jsonString": JSONString,
		"yamlString": JSONString,
		"hclString":  HCLString,
	}
}

func JSONString(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal template JSON value: %w", err)
	}
	return string(encoded), nil
}

func HCLString(value any) string {
	text := AsString(value)
	text = strings.ReplaceAll(text, "${", "$${")
	text = strings.ReplaceAll(text, "%{", "%%{")
	encoded, _ := json.Marshal(text)
	return string(encoded)
}

func AsString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
