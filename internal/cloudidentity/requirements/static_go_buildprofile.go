package requirements

import (
	"go/build/constraint"
	"go/parser"
	"go/token"
	"path"
	"strings"
)

// requirementsGoKnownGOOS/GOARCH are the recognized filename-suffix and
// build-constraint target tokens this package understands when evaluating
// a Go file against the documented deployed build profile (see
// requirementsGoBuildTargets). They mirror Go's own recognized GOOS/GOARCH
// values; an unrecognized trailing filename segment is never mistaken for
// one.
var requirementsGoKnownGOOS = map[string]bool{
	"linux": true, "darwin": true, "windows": true, "freebsd": true,
	"netbsd": true, "openbsd": true, "plan9": true, "solaris": true,
	"android": true, "ios": true, "js": true, "wasip1": true,
	"aix": true, "dragonfly": true, "illumos": true, "zos": true,
}

var requirementsGoKnownGOARCH = map[string]bool{
	"amd64": true, "386": true, "arm": true, "arm64": true, "wasm": true,
	"mips": true, "mipsle": true, "mips64": true, "mips64le": true,
	"ppc64": true, "ppc64le": true, "riscv64": true, "s390x": true,
	"loong64": true,
}

// requirementsGoUnixGOOS are the GOOS values Go's "unix" build-constraint
// meta-tag implies, needed to correctly evaluate a `//go:build unix` file
// against the linux targets below.
var requirementsGoUnixGOOS = map[string]bool{
	"linux": true, "darwin": true, "freebsd": true, "netbsd": true,
	"openbsd": true, "solaris": true, "dragonfly": true, "illumos": true,
	"aix": true,
}

// requirementsGoBuildTargets are the two deployed workload build variants
// this package certifies coverage against (ci-impl-context's "Build
// profile" bound): plain linux/amd64 and linux/arm64, with no custom build
// tags recognized. A file reachable on EITHER variant is in scope (a
// multi-arch image ships both), so a file is excluded only when it matches
// neither.
var requirementsGoBuildTargets = [][2]string{{"linux", "amd64"}, {"linux", "arm64"}}

// requirementsGoFilenameGOOSGOARCH derives the implicit GOOS/GOARCH
// filename-suffix constraint Go itself recognizes (`foo_linux.go`,
// `foo_amd64.go`, `foo_linux_amd64.go`); an empty string means that
// position is unconstrained by the filename.
func requirementsGoFilenameGOOSGOARCH(base string) (goos, goarch string) {
	name := strings.TrimSuffix(base, ".go")
	parts := strings.Split(name, "_")
	if len(parts) < 2 {
		return "", ""
	}
	last := parts[len(parts)-1]
	if requirementsGoKnownGOARCH[last] {
		goarch = last
		if len(parts) >= 3 && requirementsGoKnownGOOS[parts[len(parts)-2]] {
			goos = parts[len(parts)-2]
		}
		return goos, goarch
	}
	if requirementsGoKnownGOOS[last] {
		goos = last
	}
	return goos, goarch
}

// requirementsGoParseBuildConstraints collects every `//go:build ...` /
// `// +build ...` constraint comment from the file's leading comment block
// (bounded: it stops at the first non-comment, non-blank line, exactly
// where Go itself requires build constraints to live).
func requirementsGoParseBuildConstraints(content []byte) []constraint.Expr {
	var exprs []constraint.Expr
	for _, line := range requirementsFileLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "//") {
			break
		}
		if strings.HasPrefix(trimmed, "//go:build") || strings.HasPrefix(trimmed, "// +build") {
			if expr, err := constraint.Parse(trimmed); err == nil {
				exprs = append(exprs, expr)
			}
		}
	}
	return exprs
}

// requirementsGoFileMatchesLinuxProfile reports whether a Go source file is
// reachable on at least one of the two documented deployed build targets,
// evaluating both the filename GOOS/GOARCH suffix convention and any
// //go:build / // +build constraint comments. No custom build tags are
// recognized beyond the target GOOS/GOARCH themselves and the "unix"
// meta-tag (per the documented bound: "no custom tags"); a constraint
// requiring any other tag (e.g. `//go:build tools`) can never be satisfied
// and excludes the file from every target.
func requirementsGoFileMatchesLinuxProfile(base string, content []byte) bool {
	goos, goarch := requirementsGoFilenameGOOSGOARCH(base)
	exprs := requirementsGoParseBuildConstraints(content)
	for _, target := range requirementsGoBuildTargets {
		if goos != "" && goos != target[0] {
			continue
		}
		if goarch != "" && goarch != target[1] {
			continue
		}
		matched := true
		for _, expr := range exprs {
			if !expr.Eval(func(tag string) bool {
				return tag == target[0] || tag == target[1] || (tag == "unix" && requirementsGoUnixGOOS[target[0]])
			}) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// requirementsPathInTestdata reports whether any path segment is literally
// "testdata", matching Go's own build-system exclusion rule for that
// directory.
func requirementsPathInTestdata(filePath string) bool {
	for _, seg := range strings.Split(filePath, "/") {
		if seg == "testdata" {
			return true
		}
	}
	return false
}

// requirementsGoFileImportsSDK reports whether a Go file imports a
// recognized AWS/GCP SDK package, using a bounded imports-only parse (no
// full-body analysis — this is only ever used to decide whether a file the
// build profile has already excluded still deserves a scope-blocking gap).
func requirementsGoFileImportsSDK(content []byte) bool {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", content, parser.ImportsOnly)
	if err != nil {
		// Unparseable even for imports alone: conservatively assume it
		// might carry cloud SDK usage rather than silently vanishing.
		return true
	}
	for _, imp := range file.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		if _, _, isSDK := requirementsGoImportService(importPath); isSDK {
			return true
		}
	}
	return false
}

// requirementsGoBuildProfileCheck decides whether a Go file is in scope for
// full closed-world analysis under the documented deployed build profile
// (linux/amd64, linux/arm64, no custom tags). `_test.go` files, anything
// under a `testdata/` directory, and any file whose base name starts with
// "_" or "." are HARD-excluded exactly like Go's own build system: the go
// tool never compiles these regardless of GOOS/GOARCH or build-constraint
// comments, so their content can never become a real requirement and their
// exclusion is never itself a scope-blocking gap, no matter what they
// import. Anything else the documented build profile excludes (a genuine
// build-constrained production variant — e.g. a windows-only or
// unsupported-arch file) is different: the deployed binary provably never
// contains it either, so it is still never analyzed, but hasSDKUsage
// reports whether it imports a recognized cloud SDK package — in which
// case the exclusion itself becomes a scope-blocking gap (the file could
// hide real, unreviewed cloud calls a different build variant or copy of
// similar code DOES ship) — rather than being silently ignored.
func requirementsGoBuildProfileCheck(filePath string, content []byte) (included bool, hasSDKUsage bool) {
	base := path.Base(filePath)
	if strings.HasSuffix(base, "_test.go") || requirementsPathInTestdata(filePath) ||
		strings.HasPrefix(base, "_") || strings.HasPrefix(base, ".") {
		return false, false
	}
	if requirementsGoFileMatchesLinuxProfile(base, content) {
		return true, false
	}
	return false, requirementsGoFileImportsSDK(content)
}
