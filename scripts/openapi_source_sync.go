//go:build ignore

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

func main() {
	var (
		openAPIPath string
		sourceDir   string
		write       bool
		split       bool
	)
	flag.StringVar(&openAPIPath, "openapi", "api/openapi.yaml", "Path to merged OpenAPI spec")
	flag.StringVar(&sourceDir, "source-dir", "api/source", "Path to OpenAPI source directory")
	flag.BoolVar(&write, "write", false, "Write merged output to the OpenAPI spec")
	flag.BoolVar(&split, "split", false, "Split the merged OpenAPI spec into source files before merging")
	flag.Parse()

	if split {
		if err := splitOpenAPI(openAPIPath, sourceDir); err != nil {
			fatalf("split openapi: %v", err)
		}
		if !write {
			fmt.Printf("Split %s into %s\n", openAPIPath, sourceDir)
			return
		}
	}

	doc, err := mergeOpenAPI(sourceDir)
	if err != nil {
		fatalf("merge openapi: %v", err)
	}

	out, err := encodeYAML(doc)
	if err != nil {
		fatalf("encode merged openapi: %v", err)
	}

	if write {
		if err := os.WriteFile(openAPIPath, out, 0o600); err != nil {
			fatalf("write merged openapi: %v", err)
		}
		fmt.Printf("Wrote merged OpenAPI spec to %s from %s\n", openAPIPath, sourceDir)
		return
	}

	current, err := os.ReadFile(filepath.Clean(openAPIPath))
	if err != nil {
		fatalf("read merged openapi: %v", err)
	}
	if !bytes.Equal(current, out) {
		fmt.Fprintf(os.Stderr, "%s is out of date with %s; run `go run ./scripts/openapi_source_sync.go --write`\n", openAPIPath, sourceDir)
		os.Exit(1)
	}

	fmt.Printf("OpenAPI source sync check passed (%s)\n", sourceDir)
}

func splitOpenAPI(openAPIPath, sourceDir string) error {
	doc, err := loadYAMLDocument(openAPIPath)
	if err != nil {
		return err
	}

	root := documentRoot(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return errors.New("openapi root must be a mapping")
	}

	pathsNode := findMappingValue(root, "paths")
	if pathsNode == nil || pathsNode.Kind != yaml.MappingNode {
		return errors.New("openapi paths must be a mapping")
	}
	componentsNode := findMappingValue(root, "components")
	if componentsNode == nil || componentsNode.Kind != yaml.MappingNode {
		return errors.New("openapi components must be a mapping")
	}

	rootDoc := cloneNode(doc)
	rootDocMap := documentRoot(rootDoc)
	rootPaths := findMappingValue(rootDocMap, "paths")
	rootComponents := findMappingValue(rootDocMap, "components")
	if rootPaths == nil || rootComponents == nil {
		return errors.New("split clone missing paths/components nodes")
	}
	clearMappingNode(rootPaths)
	clearMappingNode(rootComponents)

	pathsDir := filepath.Join(sourceDir, "paths")
	componentsDir := filepath.Join(sourceDir, "components")
	if err := resetYAMLDir(pathsDir); err != nil {
		return fmt.Errorf("reset paths dir: %w", err)
	}
	if err := resetYAMLDir(componentsDir); err != nil {
		return fmt.Errorf("reset components dir: %w", err)
	}
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return fmt.Errorf("mkdir source dir: %w", err)
	}

	if err := writeYAMLDocument(filepath.Join(sourceDir, "root.yaml"), rootDoc); err != nil {
		return fmt.Errorf("write root source: %w", err)
	}

	pathGroups := make(map[string]*yaml.Node)
	var pathGroupNames []string
	for i := 0; i < len(pathsNode.Content); i += 2 {
		key := pathsNode.Content[i]
		value := pathsNode.Content[i+1]
		groupName := pathGroupName(key.Value)
		groupDoc, ok := pathGroups[groupName]
		if !ok {
			groupDoc = newMappingDocument()
			pathGroups[groupName] = groupDoc
			pathGroupNames = append(pathGroupNames, groupName)
		}
		appendMappingEntry(documentRoot(groupDoc), key, value)
	}
	sort.Strings(pathGroupNames)
	for _, groupName := range pathGroupNames {
		if err := writeYAMLDocument(filepath.Join(pathsDir, groupName+".yaml"), pathGroups[groupName]); err != nil {
			return fmt.Errorf("write path group %s: %w", groupName, err)
		}
	}

	componentFiles := make(map[string]*yaml.Node)
	var componentFileNames []string
	for i := 0; i < len(componentsNode.Content); i += 2 {
		key := componentsNode.Content[i]
		value := componentsNode.Content[i+1]
		fileName := componentFileName(key.Value)
		componentDoc, ok := componentFiles[fileName]
		if !ok {
			componentDoc = newMappingDocument()
			componentFiles[fileName] = componentDoc
			componentFileNames = append(componentFileNames, fileName)
		}
		appendMappingEntry(documentRoot(componentDoc), key, value)
	}
	sort.Strings(componentFileNames)
	for _, fileName := range componentFileNames {
		if err := writeYAMLDocument(filepath.Join(componentsDir, fileName+".yaml"), componentFiles[fileName]); err != nil {
			return fmt.Errorf("write component group %s: %w", fileName, err)
		}
	}

	return nil
}

func mergeOpenAPI(sourceDir string) (*yaml.Node, error) {
	rootPath := filepath.Join(sourceDir, "root.yaml")
	doc, err := loadYAMLDocument(rootPath)
	if err != nil {
		return nil, err
	}

	root := documentRoot(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, errors.New("openapi source root must be a mapping")
	}

	pathsNode := findMappingValue(root, "paths")
	if pathsNode == nil {
		return nil, errors.New("openapi source root missing paths key")
	}
	clearMappingNode(pathsNode)

	pathFiles, err := yamlFiles(filepath.Join(sourceDir, "paths"))
	if err != nil {
		return nil, fmt.Errorf("list path source files: %w", err)
	}
	for _, pathFile := range pathFiles {
		fileDoc, err := loadYAMLDocument(pathFile)
		if err != nil {
			return nil, fmt.Errorf("load path source %s: %w", pathFile, err)
		}
		if err := mergeFlatMapping(pathsNode, documentRoot(fileDoc), "path", pathFile); err != nil {
			return nil, err
		}
	}

	componentsNode := findMappingValue(root, "components")
	if componentsNode == nil {
		return nil, errors.New("openapi source root missing components key")
	}
	clearMappingNode(componentsNode)

	componentFiles, err := yamlFiles(filepath.Join(sourceDir, "components"))
	if err != nil {
		return nil, fmt.Errorf("list component source files: %w", err)
	}
	for _, componentFile := range componentFiles {
		fileDoc, err := loadYAMLDocument(componentFile)
		if err != nil {
			return nil, fmt.Errorf("load component source %s: %w", componentFile, err)
		}
		if err := mergeComponentMapping(componentsNode, documentRoot(fileDoc), componentFile); err != nil {
			return nil, err
		}
	}

	return doc, nil
}

func mergeFlatMapping(dst, src *yaml.Node, scope, filePath string) error {
	if dst == nil || src == nil {
		return errors.New("cannot merge nil mapping nodes")
	}
	if dst.Kind != yaml.MappingNode || src.Kind != yaml.MappingNode {
		return fmt.Errorf("%s merge requires mapping nodes", scope)
	}
	for i := 0; i < len(src.Content); i += 2 {
		key := src.Content[i]
		if findMappingValue(dst, key.Value) != nil {
			return fmt.Errorf("duplicate %s %q in %s", scope, key.Value, filePath)
		}
		appendMappingEntry(dst, key, src.Content[i+1])
	}
	return nil
}

func mergeComponentMapping(dst, src *yaml.Node, filePath string) error {
	if dst == nil || src == nil {
		return errors.New("cannot merge nil component mapping nodes")
	}
	if dst.Kind != yaml.MappingNode || src.Kind != yaml.MappingNode {
		return errors.New("component source must be a mapping")
	}
	for i := 0; i < len(src.Content); i += 2 {
		key := src.Content[i]
		value := src.Content[i+1]
		existing := findMappingValue(dst, key.Value)
		if existing == nil {
			appendMappingEntry(dst, key, value)
			continue
		}
		if existing.Kind != yaml.MappingNode || value.Kind != yaml.MappingNode {
			return fmt.Errorf("component section %q in %s must be a mapping", key.Value, filePath)
		}
		if err := mergeFlatMapping(existing, value, "component "+key.Value+" entry", filePath); err != nil {
			return err
		}
	}
	return nil
}

func yamlFiles(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

func loadYAMLDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, errors.New("invalid yaml document")
	}
	return &doc, nil
}

func writeYAMLDocument(path string, doc *yaml.Node) error {
	out, err := encodeYAML(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func encodeYAML(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func newMappingDocument() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}},
	}
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc == nil || len(doc.Content) == 0 {
		return nil
	}
	return doc.Content[0]
}

func findMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func appendMappingEntry(dst, key, value *yaml.Node) {
	dst.Content = append(dst.Content, cloneNode(key), cloneNode(value))
}

func clearMappingNode(node *yaml.Node) {
	node.Kind = yaml.MappingNode
	node.Tag = "!!map"
	node.Value = ""
	node.Content = nil
}

func cloneNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		return cloneNode(node.Alias)
	}
	cloned := *node
	cloned.Alias = nil
	if len(node.Content) > 0 {
		cloned.Content = make([]*yaml.Node, len(node.Content))
		for i, child := range node.Content {
			cloned.Content[i] = cloneNode(child)
		}
	}
	return &cloned
}

func resetYAMLDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			return err
		}
	}
	return nil
}

func pathGroupName(path string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(path), "/")
	segments := strings.Split(trimmed, "/")
	if len(segments) >= 3 && segments[0] == "api" && segments[1] == "v1" {
		switch segments[2] {
		case "status", "tables", "query", "assets", "admin", "scheduler", "notifications":
			return "platform"
		case "policies", "policy":
			return "policies"
		case "findings", "signals", "audit":
			return "findings"
		case "compliance", "trust-center":
			return "compliance"
		case "identity":
			return "identity"
		case "agents":
			return "agents"
		case "webhooks":
			return "webhooks"
		case "sync":
			return "sync"
		case "attack-paths", "graph", "entities", "impact-analysis", "security":
			return "graph"
		case "incidents":
			return "incidents"
		case "forensics":
			return "forensics"
		case "lineage":
			return "lineage"
		}
		return sanitizeName(segments[2])
	}
	return "misc"
}

func componentFileName(name string) string {
	switch name {
	case "securitySchemes":
		return "security_schemes"
	case "parameters":
		return "parameters"
	case "schemas":
		return "schemas"
	default:
		return sanitizeName(name)
	}
}

func sanitizeName(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return "misc"
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range input {
		switch {
		case unicode.IsUpper(r):
			if b.Len() > 0 && !lastUnderscore {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			lastUnderscore = false
		case unicode.IsLower(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
			lastUnderscore = false
		default:
			if !lastUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "misc"
	}
	return out
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
