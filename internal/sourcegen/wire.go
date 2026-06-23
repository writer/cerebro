package sourcegen

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// WireRequest configures the sourcegen wire command.
type WireRequest struct {
	SourceID  string
	OutputDir string
	DryRun    bool
}

// WireResult reports the changes made by the wire command.
type WireResult struct {
	SourceID           string   `json:"source_id"`
	RegistryImport     string   `json:"registry_import"`
	RegistryLoader     string   `json:"registry_loader"`
	ProjectionMappings []string `json:"projection_mappings"`
	DocsEntry          string   `json:"docs_entry"`
	FilesModified      []string `json:"files_modified"`
}

// Wire auto-wires a generated source into the source registry, projection
// registry, and docs reference. It reads the source's catalog.yaml to
// determine the source ID and emitted kinds, then inserts the appropriate
// imports, loader entries, and projector mappings.
func Wire(request WireRequest) (*WireResult, error) {
	sourceID := strings.TrimSpace(request.SourceID)
	if sourceID == "" {
		return nil, fmt.Errorf("source_id is required")
	}
	outputDir := strings.TrimSpace(request.OutputDir)
	if outputDir == "" {
		outputDir = "."
	}

	// Read the generated source's catalog.yaml to get emitted kinds.
	catalogPath := filepath.Join(outputDir, "sources", sourceID, "catalog.yaml")
	catalogBytes, err := os.ReadFile(catalogPath) // #nosec G304 -- operator-provided path.
	if err != nil {
		return nil, fmt.Errorf("read catalog.yaml for %s: %w", sourceID, err)
	}
	kinds := parseEmittedKindsFromCatalog(catalogBytes)
	if err != nil {
		return nil, fmt.Errorf("parse catalog kinds for %s: %w", sourceID, err)
	}
	if len(kinds) == 0 {
		return nil, fmt.Errorf("no emitted kinds found in catalog.yaml for %s", sourceID)
	}

	// Generate the import alias (e.g., "hashicorpvaultsource" for "hashicorp_vault").
	importAlias := sourceIDToImportAlias(sourceID)
	importPath := fmt.Sprintf("github.com/writer/cerebro/sources/%s", sourceID)

	// Generate the loader entry.
	loaderEntry := fmt.Sprintf("\t{\n\t\tname: %q,\n\t\tload: func() (sourcecdk.Source, error) {\n\t\t\treturn %s.New()\n\t\t},\n\t},\n", sourceID, importAlias)

	// Generate the projection mappings.
	var projectionMappings []string
	for _, kind := range kinds {
		mapping := fmt.Sprintf("\t%q: %s,", kind, projectionFuncName(sourceID, kind))
		projectionMappings = append(projectionMappings, mapping)
	}

	// Generate the docs entry.
	docsEntry := fmt.Sprintf("| `%s` | %s source | %s |", sourceID, sourceIDToTitle(sourceID), strings.Join(kinds, ", "))

	result := &WireResult{
		SourceID:           sourceID,
		RegistryImport:     fmt.Sprintf(`%s "%s"`, importAlias, importPath),
		RegistryLoader:     loaderEntry,
		ProjectionMappings: projectionMappings,
		DocsEntry:          docsEntry,
	}

	if request.DryRun {
		return result, nil
	}

	// Apply changes to the registry files.
	registryPath := filepath.Join(outputDir, "internal/sourceregistry/registry.go")
	if err := wireSourceRegistry(registryPath, importAlias, importPath, sourceID, loaderEntry); err != nil {
		return nil, fmt.Errorf("wire source registry: %w", err)
	}
	result.FilesModified = append(result.FilesModified, registryPath)

	projectionRegistryPath := filepath.Join(outputDir, "internal/sourceprojection/registry.go")
	if err := wireProjectionRegistry(projectionRegistryPath, sourceID, projectionMappings); err != nil {
		return nil, fmt.Errorf("wire projection registry: %w", err)
	}
	result.FilesModified = append(result.FilesModified, projectionRegistryPath)

	docsPath := filepath.Join(outputDir, "docs/reference/sources.md")
	if err := wireDocsReference(docsPath, docsEntry, sourceID); err != nil {
		return nil, fmt.Errorf("wire docs reference: %w", err)
	}
	result.FilesModified = append(result.FilesModified, docsPath)

	return result, nil
}

func wireSourceRegistry(path, importAlias, importPath, sourceID, loaderEntry string) error {
	content, err := os.ReadFile(path) // #nosec G304 -- known path.
	if err != nil {
		return err
	}
	text := string(content)

	// Add import in the right position (after the last source import, before non-source imports).
	importLine := fmt.Sprintf("\t%s %q\n", importAlias, importPath)
	if !strings.Contains(text, importLine) {
		// Find the last source import line and insert after it.
		lines := strings.Split(text, "\n")
		insertIdx := -1
		for i, line := range lines {
			if strings.Contains(line, `github.com/writer/cerebro/sources/`) {
				insertIdx = i + 1
			}
		}
		if insertIdx >= 0 {
			lines = append(lines[:insertIdx], append([]string{strings.TrimRight(importLine, "\n")}, lines[insertIdx:]...)...)
			text = strings.Join(lines, "\n")
		}
	}

	// Add loader entry in the right position (alphabetical by name).
	if !strings.Contains(text, fmt.Sprintf(`name: %q`, sourceID)) {
		// Find the right position based on source ID alphabetical order.
		lines := strings.Split(text, "\n")
		insertIdx := -1
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "name: \"") {
				existingName := strings.Trim(strings.TrimPrefix(trimmed, "name: "), "\"")
				if existingName > sourceID {
					// Find the start of this entry block (the opening brace).
					for j := i - 1; j >= 0; j-- {
						if strings.TrimSpace(lines[j]) == "{" {
							insertIdx = j
							break
						}
					}
					break
				}
			}
		}
		if insertIdx >= 0 {
			entry := strings.TrimSuffix(loaderEntry, "\n")
			lines = append(lines[:insertIdx], append([]string{entry}, lines[insertIdx:]...)...)
			text = strings.Join(lines, "\n")
		} else {
			// Source ID sorts after all existing entries; append at end of the loaders slice.
			// Find the slice's closing brace by looking for }\n\n followed by a comment or func.
			sliceEnd := strings.Index(text, "\n}\n\n// Builtin")
			if sliceEnd < 0 {
				sliceEnd = strings.Index(text, "\n}\n\nfunc ")
			}
			if sliceEnd < 0 {
				sliceEnd = strings.Index(text, "\n}\n")
			}
			if sliceEnd >= 0 {
				entry := strings.TrimSuffix(loaderEntry, "\n")
				text = text[:sliceEnd+1] + entry + "\n" + text[sliceEnd+1:]
			}
		}
	}

	return os.WriteFile(path, []byte(text), 0o600) // #nosec G703 -- operator-provided CLI path.
}

func wireProjectionRegistry(path, sourceID string, mappings []string) error {
	content, err := os.ReadFile(path) // #nosec G304 -- known path.
	if err != nil {
		return err
	}
	text := string(content)

	// Check if already wired.
	firstKind := sourceID + "."
	if strings.Contains(text, firstKind) {
		// Already wired for this source, skip.
		return nil
	}

	// Insert before the awscollectorgen marker.
	marker := "// awscollectorgen:projector"
	idx := strings.Index(text, marker)
	if idx < 0 {
		return fmt.Errorf("marker %q not found in projection registry", marker)
	}

	// Build the block to insert.
	var block strings.Builder
	fmt.Fprintf(&block, "\t// %s generated projectors (sourcegen promotion)\n", sourceID)
	for _, m := range mappings {
		block.WriteString(m)
		block.WriteString("\n")
	}
	block.WriteString("\n")

	// Find the line start before the marker.
	lineStart := strings.LastIndex(text[:idx], "\n") + 1
	text = text[:lineStart] + block.String() + text[lineStart:]

	return os.WriteFile(path, []byte(text), 0o600) // #nosec G703 -- operator-provided CLI path.
}

func wireDocsReference(path, entry, sourceID string) error {
	content, err := os.ReadFile(path) // #nosec G304 -- known path.
	if err != nil {
		return err
	}
	text := string(content)

	if strings.Contains(text, fmt.Sprintf("| `%s` |", sourceID)) {
		return nil // Already present.
	}

	// Find the right alphabetical position in the table.
	lines := strings.Split(text, "\n")
	insertIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "| `") {
			existingID := strings.Trim(strings.TrimPrefix(strings.Split(line, "|")[1], " `"), "` ")
			if existingID > sourceID {
				insertIdx = i
				break
			}
		}
	}
	if insertIdx >= 0 {
		lines = append(lines[:insertIdx], append([]string{entry}, lines[insertIdx:]...)...)
		text = strings.Join(lines, "\n")
	} else {
		// Source ID sorts after all existing entries; append at end of file.
		text = strings.TrimRight(text, "\n") + "\n" + entry + "\n"
	}

	return os.WriteFile(path, []byte(text), 0o600) // #nosec G703 -- operator-provided CLI path.
}

func sourceIDToImportAlias(sourceID string) string {
	return strings.Join(strings.Split(sourceID, "_"), "") + "source"
}

// projectionFuncName returns the unexported projector function name that the
// generator emits in internal/sourceprojection/<id>.go for a given emitted
// kind. It must stay in sync with familyData.ProjectorName in generator.go,
// which is lowerCamelIdentifier(sourceID + "_" + family + "_projections"). A
// PascalCase name here would reference an undefined function and break the
// projection registry compile.
func projectionFuncName(sourceID, kind string) string {
	family := strings.TrimPrefix(kind, sourceID+".")
	return lowerCamelIdentifier(sourceID + "_" + family + "_projections")
}

func sourceIDToTitle(sourceID string) string {
	parts := strings.Split(sourceID, "_")
	for i, p := range parts {
		if len(p) > 0 {
			r := []rune(p)
			r[0] = []rune(strings.ToUpper(string(r[0])))[0]
			parts[i] = string(r)
		}
	}
	return strings.Join(parts, " ")
}

// parseEmittedKindsFromCatalog reads a catalog.yaml file and extracts the emitted_kinds list.
func parseEmittedKindsFromCatalog(data []byte) []string {
	text := string(data)
	var kinds []string
	lines := strings.Split(text, "\n")
	inKinds := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "emitted_kinds:") {
			inKinds = true
			continue
		}
		if inKinds {
			if strings.HasPrefix(trimmed, "- ") {
				kind := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				kinds = append(kinds, kind)
			} else if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" {
				inKinds = false
			}
		}
	}
	sort.Strings(kinds)
	return kinds
}
