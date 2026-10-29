package requirements

import (
	"regexp"
	"sort"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// requirementsGoModApprovedPrefixes are module path prefixes a go.mod file
// may require without blocking ScopeComplete: the official AWS/GCP SDK
// families this package already statically reviews call sites for, plus
// their well-known required transitive dependencies. A go.mod requiring
// anything outside this documented, explicit list stays an
// unapproved_dependency gap — a realistic app with other dependencies is
// still a legitimate "candidate" state, never silently treated as reviewed.
var requirementsGoModApprovedPrefixes = []string{
	"github.com/aws/aws-sdk-go-v2",
	"github.com/aws/smithy-go",
	"cloud.google.com/go",
	"google.golang.org/api",
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
	"google.golang.org/genproto",
	"golang.org/x/oauth2",
	"golang.org/x/net",
	"golang.org/x/sync",
	"golang.org/x/time",
	"github.com/googleapis/gax-go",
	"github.com/golang/protobuf",
}

var requirementsGoModRequireLine = regexp.MustCompile(`^([^\s]+)\s+v[0-9][^\s]*`)

// requirementsGoModReplaceLine matches one `OLD [OLDVERSION] => NEW
// [NEWVERSION]` replace directive body (the part after the leading
// "replace " keyword, or one line inside a `replace ( ... )` block),
// capturing only the module path being replaced: that is the one whose
// approval status matters, since the replacement's own source is never
// analyzed by this bounded, dependency-free scanner.
var requirementsGoModReplaceLine = regexp.MustCompile(`^([^\s]+)(?:\s+v[0-9][^\s]*)?\s*=>\s*\S+`)

// requirementsExtractGoModFile parses a go.mod file's require and replace
// directives (both the single-line form and the parenthesized block form)
// with a bounded, dependency-free line scanner — never a full module-graph
// resolution — and reports whether every required module is on the
// approved list, and whether any approved module is replaced.
//
// A `replace` directive targeting an already-approved module (e.g.
// replacing `github.com/aws/aws-sdk-go-v2/service/s3` with an unreviewed
// fork) means the runtime implementation this package statically reviewed
// call sites for is not actually what gets compiled in: the replacement
// source is never pinned or analyzed here, so it always keeps the file an
// unapproved_dependency gap too, exactly like requiring an unapproved
// module directly.
func requirementsExtractGoModFile(path string, content []byte) []ci.Gap {
	lines := requirementsFileLines(content)
	inRequireBlock := false
	inReplaceBlock := false
	var modules []string
	var replaced []string
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		switch {
		case trimmed == "require (":
			inRequireBlock = true
		case inRequireBlock && trimmed == ")":
			inRequireBlock = false
		case inRequireBlock:
			if m := requirementsGoModRequireLine.FindStringSubmatch(trimmed); m != nil {
				modules = append(modules, m[1])
			}
		case trimmed == "replace (":
			inReplaceBlock = true
		case inReplaceBlock && trimmed == ")":
			inReplaceBlock = false
		case inReplaceBlock:
			if m := requirementsGoModReplaceLine.FindStringSubmatch(trimmed); m != nil {
				replaced = append(replaced, m[1])
			}
		case strings.HasPrefix(trimmed, "require "):
			if m := requirementsGoModRequireLine.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(trimmed, "require "))); m != nil {
				modules = append(modules, m[1])
			}
		case strings.HasPrefix(trimmed, "replace "):
			if m := requirementsGoModReplaceLine.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(trimmed, "replace "))); m != nil {
				replaced = append(replaced, m[1])
			}
		}
	}

	var gaps []ci.Gap

	var unapproved []string
	for _, module := range modules {
		if !requirementsGoModApproved(module) {
			unapproved = append(unapproved, module)
		}
	}
	if len(unapproved) > 0 {
		sort.Strings(unapproved)
		gaps = append(gaps, ci.Gap{
			Code:    GapUnapprovedDependency,
			Scope:   path,
			Message: "go.mod declares dependencies outside the documented approved SDK/stdlib-adjacent allowlist: " + strings.Join(unapproved, ", "),
		})
	}

	var unapprovedReplaced []string
	for _, module := range replaced {
		if requirementsGoModApproved(module) {
			unapprovedReplaced = append(unapprovedReplaced, module)
		}
	}
	if len(unapprovedReplaced) > 0 {
		sort.Strings(unapprovedReplaced)
		gaps = append(gaps, ci.Gap{
			Code:    GapUnapprovedDependency,
			Scope:   path,
			Message: "go.mod replaces an approved SDK/stdlib-adjacent module with an unreviewed replacement source, which the pinned repository never actually provides for analysis and can itself perform additional cloud calls: " + strings.Join(unapprovedReplaced, ", "),
		})
	}

	return gaps
}

func requirementsGoModApproved(module string) bool {
	for _, prefix := range requirementsGoModApprovedPrefixes {
		if module == prefix || strings.HasPrefix(module, prefix+"/") {
			return true
		}
	}
	return false
}
