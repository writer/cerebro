package iacrender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

func RenderTemplate(name, src string, data any) string {
	tmpl := template.Must(template.New(name).Funcs(FuncMap()).Parse(src))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		panic(err)
	}
	return strings.TrimLeft(buf.String(), "\n")
}

func FuncMap() template.FuncMap {
	return template.FuncMap{
		"jsonString": JSONString,
		"yamlString": JSONString,
		"hclString":  HCLString,
	}
}

func JSONString(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func HCLString(value any) string {
	text := AsString(value)
	text = strings.ReplaceAll(text, "${", "$${")
	text = strings.ReplaceAll(text, "%{", "%%{")
	return JSONString(text)
}

func AsString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
