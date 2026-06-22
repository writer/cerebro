package archtests

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var sourceEventContractBacklog []string

func TestSourceEventContractBacklogDoesNotGrow(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "sources"))
	if err != nil {
		t.Fatalf("ReadDir(sources): %v", err)
	}
	backlog := map[string]struct{}{}
	for _, sourceID := range sourceEventContractBacklog {
		backlog[sourceID] = struct{}{}
	}
	var missing []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "internal" {
			continue
		}
		catalogPath := filepath.Join(root, "sources", entry.Name(), "catalog.yaml")
		body, err := os.ReadFile(catalogPath)
		if err != nil {
			t.Fatalf("read %s: %v", catalogPath, err)
		}
		if strings.Contains(string(body), "\nevent_contracts:\n") {
			continue
		}
		missing = append(missing, entry.Name())
	}
	sort.Strings(missing)
	if !reflect.DeepEqual(missing, sourceEventContractBacklog) {
		t.Fatalf("event-contract backlog = %#v, want %#v", missing, sourceEventContractBacklog)
	}
}

func TestContractedSourcesCoverEveryEmittedKind(t *testing.T) {
	root := repoRoot(t)
	backlog := map[string]struct{}{}
	for _, sourceID := range sourceEventContractBacklog {
		backlog[sourceID] = struct{}{}
	}
	contractRe := regexp.MustCompile(`(?m)^  - kind: ([a-z0-9_.]+)$`)
	catalogPaths, err := filepath.Glob(filepath.Join(root, "sources", "*", "catalog.yaml"))
	if err != nil {
		t.Fatalf("glob source catalogs: %v", err)
	}
	for _, catalogPath := range catalogPaths {
		sourceID := filepath.Base(filepath.Dir(catalogPath))
		if _, ok := backlog[sourceID]; ok {
			continue
		}
		body, err := os.ReadFile(catalogPath)
		if err != nil {
			t.Fatalf("read %s: %v", catalogPath, err)
		}
		text := string(body)
		sections := strings.Split(text, "event_contracts:")
		if len(sections) < 2 {
			t.Fatalf("%s has no event_contracts and is not in the backlog", sourceID)
		}
		contractSection := sections[1]
		if parts := strings.Split(contractSection, "\ncoverage_contract:"); len(parts) > 1 {
			contractSection = parts[0]
		}
		contracts := map[string]struct{}{}
		for _, match := range contractRe.FindAllStringSubmatch(contractSection, -1) {
			contracts[match[1]] = struct{}{}
		}
		for _, kind := range yamlStringList(text, "emitted_kinds") {
			if _, ok := contracts[kind]; !ok {
				t.Fatalf("%s emits %s without a matching event_contract", sourceID, kind)
			}
		}
	}
}

func yamlStringList(text string, key string) []string {
	lines := strings.Split(text, "\n")
	var values []string
	inList := false
	prefix := key + ":"
	for _, line := range lines {
		if !inList {
			if strings.TrimSpace(line) == prefix {
				inList = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			break
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") {
			values = append(values, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
		}
	}
	return values
}
