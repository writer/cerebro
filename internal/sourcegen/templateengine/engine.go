// Package templateengine provides a shared template rendering engine for
// Cerebro code generators. It wraps Go's text/template with conventions for
// loading embedded templates, applying Go formatting, and rendering to files.
//
// Generators that use this engine store their templates as .tmpl files in an
// embedded filesystem, keeping generation logic separate from output format.
// This replaces the pattern of building Go source via fmt.Fprintf chains.
package templateengine

import (
	"bytes"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// TemplateData is the constraint for data passed to template rendering methods.
// Any struct that holds template context satisfies this interface.
type TemplateData interface{}

// Engine loads and renders templates from an embedded filesystem.
type Engine struct {
	templates *template.Template
	funcMap   template.FuncMap
}

// New creates a template engine from an embedded filesystem rooted at dir.
// All .tmpl files in the directory are loaded as named templates (using the
// filename without the .tmpl extension as the template name).
func New(fsys fs.FS, dir string, extraFuncs template.FuncMap) (*Engine, error) {
	funcMap := defaultFuncMap()
	for key, fn := range extraFuncs {
		funcMap[key] = fn
	}
	t := template.New("").Funcs(funcMap)
	err := fs.WalkDir(fsys, dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmpl") {
			return nil
		}
		payload, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read template %s: %w", path, err)
		}
		name := strings.TrimSuffix(entry.Name(), ".tmpl")
		if _, err := t.New(name).Parse(string(payload)); err != nil {
			return fmt.Errorf("parse template %s: %w", path, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Engine{templates: t, funcMap: funcMap}, nil
}

// RenderResult holds the output of a template render.
type RenderResult struct {
	Name    string
	Content []byte
}

// Render executes a named template with the given data.
func (e *Engine) Render(name string, data TemplateData) (RenderResult, error) {
	var buf bytes.Buffer
	if err := e.templates.ExecuteTemplate(&buf, name, data); err != nil {
		return RenderResult{}, fmt.Errorf("render %s: %w", name, err)
	}
	return RenderResult{Name: name, Content: buf.Bytes()}, nil
}

// RenderGo executes a named template and formats the result as Go source.
func (e *Engine) RenderGo(name string, data TemplateData) (RenderResult, error) {
	result, err := e.Render(name, data)
	if err != nil {
		return result, err
	}
	formatted, err := format.Source(result.Content)
	if err != nil {
		return result, fmt.Errorf("gofmt %s: %w\n---\n%s", name, err, string(result.Content))
	}
	result.Content = formatted
	return result, nil
}

// RenderToFile renders a template and writes it to a file path.
func (e *Engine) RenderToFile(name string, data TemplateData, outPath string, goFormat bool) error {
	var result RenderResult
	var err error
	if goFormat {
		result, err = e.RenderGo(name, data)
	} else {
		result, err = e.Render(name, data)
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(outPath, result.Content, 0o600)
}

// RenderString renders a template to a string.
func (e *Engine) RenderString(name string, data TemplateData) (string, error) {
	result, err := e.Render(name, data)
	if err != nil {
		return "", err
	}
	return string(result.Content), nil
}

func defaultFuncMap() template.FuncMap {
	return template.FuncMap{
		"quote":     func(s string) string { return fmt.Sprintf("%q", s) },
		"join":      strings.Join,
		"lower":     strings.ToLower,
		"upper":     strings.ToUpper,
		"title":     strings.Title, //nolint:staticcheck // acceptable for codegen templates
		"trimSpace": strings.TrimSpace,
		"contains":  strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"replace":   strings.ReplaceAll,
		"goSlice": func(items []string) string {
			if len(items) == 0 {
				return "nil"
			}
			parts := make([]string, len(items))
			for i, item := range items {
				parts[i] = fmt.Sprintf("%q", item)
			}
			return "[]string{" + strings.Join(parts, ", ") + "}"
		},
		"indent": func(n int, s string) string {
			prefix := strings.Repeat("\t", n)
			lines := strings.Split(s, "\n")
			for i, line := range lines {
				if strings.TrimSpace(line) != "" {
					lines[i] = prefix + line
				}
			}
			return strings.Join(lines, "\n")
		},
	}
}
