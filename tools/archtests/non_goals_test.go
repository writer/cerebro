package archtests

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var (
	nonGoalsMarkdownLinkRE = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	nonGoalsCodeSpanRE     = regexp.MustCompile("`([^`]+)`")
)

func TestNonGoalsEnforcedInPointersResolve(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "docs", "engineering", "non-goals.md"))
	if err != nil {
		t.Fatalf("read NON_GOALS.md: %v", err)
	}
	var missing []string
	for lineNumber, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- Enforced in:") {
			continue
		}
		for _, ref := range nonGoalsEnforcedInRefs(line) {
			path := nonGoalsPointerPath(root, ref)
			if path == "" {
				continue
			}
			if _, err := os.Stat(path); err != nil {
				missing = append(missing, filepath.ToSlash(ref)+": line "+strconvLine(lineNumber+1))
			}
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Fatalf("docs/engineering/non-goals.md Enforced in pointers must resolve:\n%s", strings.Join(missing, "\n"))
	}
}

func nonGoalsEnforcedInRefs(line string) []string {
	seen := map[string]struct{}{}
	var refs []string
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || !nonGoalsLooksLikeRepoPath(ref) {
			return
		}
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	for _, match := range nonGoalsMarkdownLinkRE.FindAllStringSubmatch(line, -1) {
		add(match[1])
	}
	for _, match := range nonGoalsCodeSpanRE.FindAllStringSubmatch(line, -1) {
		add(match[1])
	}
	return refs
}

func nonGoalsLooksLikeRepoPath(ref string) bool {
	ref = strings.TrimSpace(strings.Split(ref, "#")[0])
	ref = strings.TrimPrefix(ref, "./")
	ref = strings.TrimPrefix(ref, "../")
	if ref == "" || strings.HasPrefix(ref, "/") || strings.Contains(ref, "*") {
		return false
	}
	first := ref
	if slash := strings.Index(first, "/"); slash >= 0 {
		first = first[:slash]
	}
	switch first {
	case "api", "cmd", "docs", "gen", "internal", "policies", "proto", "scripts", "sdk", "sources", "tools":
		return true
	}
	switch ref {
	case "AGENTS.md", "Makefile", "README.md":
		return true
	}
	return false
}

func nonGoalsPointerPath(root string, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ""
	}
	ref = strings.Split(ref, "#")[0]
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") {
		return filepath.Clean(filepath.Join(root, "docs", "engineering", filepath.FromSlash(ref)))
	}
	return filepath.Join(root, filepath.FromSlash(ref))
}

func strconvLine(lineNumber int) string {
	return strconv.Itoa(lineNumber)
}
