package archtests

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeepSecConfigKeepsSecurityCriticalSurfacesInScope(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, ".deepsec", "data", "cerebro", "config.json"))
	if err != nil {
		t.Fatalf("read deepsec project config: %v", err)
	}
	var config struct {
		IgnorePaths []string `json:"ignorePaths"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatalf("decode deepsec project config: %v", err)
	}
	for _, ignored := range config.IgnorePaths {
		normalized := strings.TrimSpace(ignored)
		if normalized == "" {
			continue
		}
		for _, forbidden := range deepsecSecurityCriticalSurfaces() {
			if deepsecIgnorePathTouchesSurface(normalized, forbidden) {
				t.Fatalf("deepsec ignorePaths excludes security-critical surface %q via %q", forbidden, normalized)
			}
		}
		if strings.Contains(normalized, "_test.go") {
			t.Fatalf("deepsec ignorePaths excludes tests via %q", normalized)
		}
	}

	deepsecConfig, err := os.ReadFile(filepath.Join(root, ".deepsec", "deepsec.config.ts"))
	if err != nil {
		t.Fatalf("read deepsec config: %v", err)
	}
	text := string(deepsecConfig)
	for _, required := range []string{
		`".github/workflows/"`,
		`"api/"`,
		`"internal/bootstrap/"`,
		`"internal/connectorcatalog/"`,
		`"internal/deviceauth/"`,
		`"internal/graphagent/"`,
		`"internal/sourcehttp/"`,
		`"internal/sourceruntime/"`,
		`"policies/"`,
		`"sources/"`,
		`"tools/"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("deepsec priorityPaths missing %s", required)
		}
	}
}

func TestDeepSecIgnorePathSurfaceDetectionCatchesGlobBypasses(t *testing.T) {
	for _, tt := range []struct {
		name      string
		ignored   string
		forbidden string
		want      bool
	}{
		{name: "direct internal", ignored: "internal/**", forbidden: "internal/", want: true},
		{name: "glob-prefixed internal", ignored: "**/internal/**", forbidden: "internal/", want: true},
		{name: "blanket recursive wildcard", ignored: "**", forbidden: "api/", want: true},
		{name: "blanket recursive files", ignored: "**/*", forbidden: "internal/", want: true},
		{name: "blanket wildcard segments", ignored: "*/**", forbidden: "tools/", want: true},
		{name: "brace includes api", ignored: "{api,vendor}/**", forbidden: "api/", want: true},
		{name: "brace includes sources", ignored: "{sources,vendor}/**", forbidden: "sources/", want: true},
		{name: "brace excludes internal", ignored: "{api,vendor}/**", forbidden: "internal/"},
		{name: "multiple brace groups includes internal", ignored: "{vendor,code}/{api,internal}/**", forbidden: "internal/", want: true},
		{name: "multiple brace groups excludes docs", ignored: "{vendor,code}/{api,internal}/**", forbidden: "docs/"},
		{name: "nested brace group includes sources", ignored: "{{api,sources},vendor}/**", forbidden: "sources/", want: true},
		{name: "nested brace group excludes internal", ignored: "{{api,sources},vendor}/**", forbidden: "internal/"},
		{name: "character class includes api", ignored: "[ai]pi/**", forbidden: "api/", want: true},
		{name: "character class includes sources", ignored: "[s]ources/**", forbidden: "sources/", want: true},
		{name: "character range includes api", ignored: "[a-c]pi/**", forbidden: "api/", want: true},
		{name: "question mark includes api", ignored: "a?i/**", forbidden: "api/", want: true},
		{name: "prefix wildcard includes api", ignored: "ap*/**", forbidden: "api/", want: true},
		{name: "character class excludes internal", ignored: "[as]pi/**", forbidden: "internal/"},
		{name: "nested api", ignored: "foo/api/**", forbidden: "api/", want: true},
		{name: "root github", ignored: "/.github/workflows/**", forbidden: ".github/", want: true},
		{name: "allowed vendor", ignored: "vendor/**", forbidden: "internal/"},
		{name: "allowed data", ignored: ".deepsec/data/**", forbidden: "docs/"},
		{name: "substring is not segment", ignored: "notinternal/**", forbidden: "internal/"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := deepsecIgnorePathTouchesSurface(tt.ignored, tt.forbidden); got != tt.want {
				t.Fatalf("deepsecIgnorePathTouchesSurface(%q, %q) = %v, want %v", tt.ignored, tt.forbidden, got, tt.want)
			}
		})
	}
}

func deepsecSecurityCriticalSurfaces() []string {
	return []string{
		".github/",
		"api/",
		"docs/",
		"internal/",
		"policies/",
		"sources/",
		"tools/",
	}
}

func deepsecIgnorePathTouchesSurface(ignored string, forbidden string) bool {
	normalized := strings.Trim(strings.ReplaceAll(strings.TrimSpace(ignored), "\\", "/"), "/")
	surface := strings.Trim(strings.TrimSpace(forbidden), "/")
	if normalized == "" || surface == "" {
		return false
	}
	for _, candidate := range deepsecIgnorePathCandidates(normalized) {
		if deepsecIgnorePathCandidateIsBlanket(candidate) {
			return true
		}
		if candidate == surface || strings.HasPrefix(candidate, surface+"/") {
			return true
		}
		if strings.Contains(candidate, "/"+surface+"/") || strings.HasSuffix(candidate, "/"+surface) {
			return true
		}
		if deepsecIgnorePathCandidateGlobMatchesSurface(candidate, surface) {
			return true
		}
	}
	return false
}

func deepsecIgnorePathCandidateIsBlanket(candidate string) bool {
	segments := strings.Split(strings.Trim(candidate, "/"), "/")
	hasSegment := false
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		hasSegment = true
		if segment != "*" && segment != "**" {
			return false
		}
	}
	return hasSegment
}

func deepsecIgnorePathCandidateGlobMatchesSurface(candidate string, surface string) bool {
	for _, segment := range strings.Split(strings.Trim(candidate, "/"), "/") {
		segment = strings.TrimSpace(segment)
		if segment == "" || segment == "*" || segment == "**" || !strings.ContainsAny(segment, "*?[") {
			continue
		}
		matched, err := path.Match(segment, surface)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func deepsecIgnorePathCandidates(pattern string) []string {
	pattern = strings.Trim(pattern, "/")
	candidates := []string{}
	seen := map[string]struct{}{}
	var add func(string)
	add = func(candidate string) {
		candidate = strings.Trim(candidate, "/")
		if _, ok := seen[candidate]; ok {
			return
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
	}
	var expand func(string)
	expand = func(candidate string) {
		candidate = strings.Trim(candidate, "/")
		if start := strings.Index(candidate, "{"); start >= 0 {
			end := deepsecClosingBraceIndex(candidate, start)
			if end < 0 {
				add(candidate)
				return
			}
			add(candidate)
			prefix := candidate[:start]
			suffix := candidate[end+1:]
			for _, option := range deepsecBraceOptions(candidate[start+1 : end]) {
				option = strings.TrimSpace(option)
				if option == "" {
					continue
				}
				expand(prefix + option + suffix)
			}
			return
		}
		if start := strings.Index(candidate, "["); start >= 0 {
			endOffset := strings.Index(candidate[start+1:], "]")
			if endOffset >= 0 {
				end := start + 1 + endOffset
				options := deepsecCharacterClassOptions(candidate[start+1 : end])
				if len(options) != 0 {
					add(candidate)
					prefix := candidate[:start]
					suffix := candidate[end+1:]
					for _, option := range options {
						expand(prefix + option + suffix)
					}
					return
				}
			}
		}
		add(candidate)
	}
	expand(pattern)
	return candidates
}

func deepsecClosingBraceIndex(pattern string, start int) int {
	depth := 0
	for i := start; i < len(pattern); i++ {
		switch pattern[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func deepsecBraceOptions(group string) []string {
	options := []string{}
	depth := 0
	start := 0
	for i := 0; i < len(group); i++ {
		switch group[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				options = append(options, group[start:i])
				start = i + 1
			}
		}
	}
	options = append(options, group[start:])
	return options
}

func deepsecCharacterClassOptions(group string) []string {
	group = strings.TrimSpace(group)
	if group == "" || strings.HasPrefix(group, "!") || strings.HasPrefix(group, "^") {
		return nil
	}
	options := []string{}
	seen := map[byte]struct{}{}
	add := func(value byte) {
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		options = append(options, string(value))
	}
	for i := 0; i < len(group); i++ {
		if i+2 < len(group) && group[i+1] == '-' && group[i] <= group[i+2] && group[i+2]-group[i] <= 64 {
			for value := group[i]; value <= group[i+2]; value++ {
				add(value)
			}
			i += 2
			continue
		}
		add(group[i])
	}
	return options
}
