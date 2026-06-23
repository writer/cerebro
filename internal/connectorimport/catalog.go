// Catalog rendering: emits classified outcomes as built-in-catalog YAML
// entries that round-trip with the catalog loader.
package connectorimport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"gopkg.in/yaml.v3"
)

// computed definition keys that the catalog fills in at load time via
// connectordefinitions.Normalize. They are stripped from emitted entries so the
// committed catalog stays minimal and matches existing hand-authored entries.
var computedDefinitionKeys = []string{
	"validation",
	"promotion",
	"current_version",
	"runtime",
	"stage",
	"maturity",
	"created_at",
	"updated_at",
}

// catalogEntry mirrors the connectorcatalog.RawEntry shape for emission.
type catalogEntry struct {
	ClassifierOutput string         `json:"classifier_output"`
	Definition       map[string]any `json:"definition"`
}

type catalogFile struct {
	Entries []catalogEntry `json:"entries"`
}

// RenderCatalogEntries renders the catalog-ready (supported) outcomes as a YAML
// entries document compatible with the built-in catalog loader. Entries are
// sorted by source_id to match catalog review conventions.
func RenderCatalogEntries(header string, outcomes []Outcome) ([]byte, error) {
	ready := make([]Outcome, 0, len(outcomes))
	for _, outcome := range outcomes {
		if outcome.CatalogReady() {
			ready = append(ready, outcome)
		}
	}
	sort.SliceStable(ready, func(i, j int) bool { return ready[i].SourceID < ready[j].SourceID })
	file := catalogFile{Entries: make([]catalogEntry, 0, len(ready))}
	for _, outcome := range ready {
		definitionMap, err := minimalDefinitionMap(outcome.Definition)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", outcome.SourceID, err)
		}
		file.Entries = append(file.Entries, catalogEntry{
			ClassifierOutput: outcome.Verdict,
			Definition:       definitionMap,
		})
	}
	body, err := marshalYAMLWithJSONTags(file)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(header) == "" {
		return body, nil
	}
	return append([]byte(commentHeader(header)), body...), nil
}

// RenderCatalogEntryBlocks renders each supported outcome as a standalone YAML
// list item suitable for appending under an existing catalog file's `entries:`
// key, keyed by source_id for stable append order.
func RenderCatalogEntryBlocks(outcomes []Outcome) (map[string]string, error) {
	blocks := map[string]string{}
	for _, outcome := range outcomes {
		if !outcome.CatalogReady() {
			continue
		}
		definitionMap, err := minimalDefinitionMap(outcome.Definition)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", outcome.SourceID, err)
		}
		body, err := marshalYAMLWithJSONTags(catalogFile{Entries: []catalogEntry{{
			ClassifierOutput: outcome.Verdict,
			Definition:       definitionMap,
		}}})
		if err != nil {
			return nil, err
		}
		blocks[outcome.SourceID] = stripEntriesKey(string(body))
	}
	return blocks, nil
}

func minimalDefinitionMap(definition connectordefinitions.Definition) (map[string]any, error) {
	encoded, err := json.Marshal(definition)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		return nil, err
	}
	for _, key := range computedDefinitionKeys {
		delete(generic, key)
	}
	return generic, nil
}

func commentHeader(header string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
		b.WriteString("# ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// marshalYAMLWithJSONTags emits YAML whose keys are JSON tag names, at the
// 2-space indentation the built-in catalog files use. It is the inverse of the
// catalog loader's YAML->JSON-tag decode path, so emitted entries round-trip.
func marshalYAMLWithJSONTags(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := yaml.Unmarshal(encoded, &generic); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(generic); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// stripEntriesKey removes the leading `entries:` line from a single-entry
// catalog render, leaving an indented list item that can be appended under an
// existing catalog file's `entries:` key.
func stripEntriesKey(body string) string {
	lines := strings.SplitN(body, "\n", 2)
	if len(lines) == 2 && strings.TrimSpace(lines[0]) == "entries:" {
		return lines[1]
	}
	return body
}
