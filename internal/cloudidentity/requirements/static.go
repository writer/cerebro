package requirements

import (
	"path"
	"sort"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// ExtractStatic deterministically and independently extracts the closed
// subset of direct cloud SDK call sites documented in the package comment.
// It never trusts a model: this is the ground truth Validate cross-checks
// model claims against, and the source of Requirements the model never even
// needs to see in order for them to be promoted.
//
// Only Go source, parsed and closed-world-analyzed with go/parser, can mark
// a file fully covered. Python/JS/TS use bounded single-line regex pattern
// matching: they can still prove a real call exists (so their findings are
// promotable), but they can never prove a file has nothing else hiding in
// it, so those files never count toward CoveredFiles. Any file outside the
// four supported extensions is classified either as an inert asset (no gap,
// does not affect ScopeComplete) or as an unreviewed dependency/config/
// runtime path (gap, blocks ScopeComplete), per requirementsPathClass.
func ExtractStatic(files []ci.SourceFile) StaticFindings {
	findings := StaticFindings{}
	covered := map[string]bool{}
	sorted := make([]ci.SourceFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, file := range sorted {
		if path.Base(file.Path) == "go.mod" {
			if gaps := requirementsExtractGoModFile(file.Path, file.Content); len(gaps) == 0 {
				covered[file.Path] = true
			} else {
				findings.Gaps = append(findings.Gaps, gaps...)
			}
			continue
		}
		switch requirementsLanguageOf(file.Path) {
		case requirementsLanguageGo:
			included, hasSDKUsage := requirementsGoBuildProfileCheck(file.Path, file.Content)
			if !included {
				if hasSDKUsage {
					findings.Gaps = append(findings.Gaps, ci.Gap{
						Code:    GapBuildProfileExcluded,
						Scope:   file.Path,
						Message: "file is excluded by the documented deployed build profile (linux/amd64, linux/arm64, no custom tags; _test.go/testdata always excluded) but imports a recognized cloud SDK package; it was not analyzed and may hide calls a different build variant or similarly-shaped production code actually makes",
					})
				}
				continue
			}
			ops, fileGaps, ok := requirementsExtractGoFile(file.Path, file.Content)
			findings.Operations = append(findings.Operations, ops...)
			findings.Gaps = append(findings.Gaps, fileGaps...)
			if ok {
				covered[file.Path] = true
			}
		case requirementsLanguagePython:
			ops, fileGaps := requirementsExtractPythonFile(file.Path, file.Content)
			findings.Operations = append(findings.Operations, ops...)
			findings.Gaps = append(findings.Gaps, fileGaps...)
		case requirementsLanguageJSOrTS:
			ops, fileGaps := requirementsExtractJSFile(file.Path, file.Content)
			findings.Operations = append(findings.Operations, ops...)
			findings.Gaps = append(findings.Gaps, fileGaps...)
		default:
			if requirementsPathClassOf(file.Path) == requirementsPathDependencyConfig {
				findings.Gaps = append(findings.Gaps, ci.Gap{
					Code:    GapUnreviewedPath,
					Scope:   file.Path,
					Message: "dependency/config/runtime path is outside the documented static-extraction subset and was not analyzed; it may itself introduce or alter cloud calls",
				})
			}
			// requirementsPathInert: a doc/asset file cannot itself make a
			// cloud call, so it is silently out of scope without affecting
			// ScopeComplete.
		}
	}
	for p := range covered {
		findings.CoveredFiles = append(findings.CoveredFiles, p)
	}
	sort.Strings(findings.CoveredFiles)
	return findings
}

type requirementsLanguage int

const (
	requirementsLanguageUnsupported requirementsLanguage = iota
	requirementsLanguageGo
	requirementsLanguagePython
	requirementsLanguageJSOrTS
)

func requirementsLanguageOf(filePath string) requirementsLanguage {
	switch strings.ToLower(path.Ext(filePath)) {
	case ".go":
		return requirementsLanguageGo
	case ".py":
		return requirementsLanguagePython
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return requirementsLanguageJSOrTS
	default:
		return requirementsLanguageUnsupported
	}
}

type requirementsPathClass int

const (
	requirementsPathInert requirementsPathClass = iota
	requirementsPathDependencyConfig
)

// requirementsInertExtensions are asset/documentation files that cannot
// themselves perform a cloud call.
var requirementsInertExtensions = map[string]bool{
	".md": true, ".markdown": true, ".txt": true, ".rst": true, ".adoc": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".pdf": true, ".editorconfig": true, ".gitattributes": true,
	".gitignore": true,
}

// requirementsInertBasenames are well-known inert files with no (or an
// ambiguous) extension.
var requirementsInertBasenames = map[string]bool{
	"LICENSE": true, "LICENSE.txt": true, "NOTICE": true, "AUTHORS": true,
	"CODEOWNERS": true, "README": true, "CONTRIBUTING": true,
}

// requirementsPathClassOf classifies a file outside the four supported
// source extensions. Dependency manifests, lockfiles, build/runtime
// descriptors, and shell/config scripts can all alter or introduce cloud
// calls (a Dockerfile RUN step, a postinstall script, a Helm values file
// wiring a different role) so they always block ScopeComplete rather than
// being silently assumed irrelevant.
func requirementsPathClassOf(filePath string) requirementsPathClass {
	base := path.Base(filePath)
	if requirementsInertBasenames[base] {
		return requirementsPathInert
	}
	ext := strings.ToLower(path.Ext(filePath))
	if requirementsInertExtensions[ext] {
		return requirementsPathInert
	}
	return requirementsPathDependencyConfig
}

// requirementsFileLines splits file content into 1-indexed lines without
// trailing newline characters, matching the convention used for both AST
// token.Position line numbers and regexp line scanning.
func requirementsFileLines(content []byte) []string {
	normalized := strings.ReplaceAll(string(content), "\r\n", "\n")
	return strings.Split(normalized, "\n")
}

// requirementsQuoteLines renders the exact text spanning [startLine,endLine]
// (1-indexed, inclusive) for use as a citation quote.
func requirementsQuoteLines(lines []string, startLine, endLine int) (string, bool) {
	if startLine < 1 || endLine < startLine || endLine > len(lines) {
		return "", false
	}
	return strings.Join(lines[startLine-1:endLine], "\n"), true
}

// requirementsNormalizeToken maps a literal source token (Go method name,
// python snake_case method name, or an AWS SDK v3 `XCommand` class name)
// onto the PascalCase operation-name convention used by
// ci.OperationDefinition.Operation.
func requirementsNormalizeToken(token string) string {
	token = strings.TrimSuffix(token, "Command")
	if !strings.Contains(token, "_") {
		return token
	}
	parts := strings.Split(token, "_")
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			b.WriteString(part[1:])
		}
	}
	return b.String()
}
