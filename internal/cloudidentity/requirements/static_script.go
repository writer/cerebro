package requirements

import (
	"regexp"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// Python and JavaScript/TypeScript extraction is deliberately regex-based,
// single-line, and conservative: it proves real, literal call sites exist
// (and those findings are promotable, exactly like a Go AST finding, once
// mapped through Definitions), but it can never prove a file has no other,
// unrecognized cloud call hiding in a multi-line, computed, or wrapped
// construct. Every file processed here therefore always gets an explicit
// completeness gap and is never added to CoveredFiles; ScopeComplete can
// only be true for a repository containing none of these files, or whose
// Go files are closed-world-complete and whose script files additionally
// carry no cloud SDK indicators.

var requirementsPythonBotoAssign = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*boto3\.client\(\s*["']([a-zA-Z0-9_\-]+)["']`)
var requirementsPythonMethodCall = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\.([a-z][a-z0-9_]*)\(`)
var requirementsPythonResourceUnsupported = []*regexp.Regexp{
	regexp.MustCompile(`boto3\.resource\(`),
	regexp.MustCompile(`getattr\(`),
	regexp.MustCompile(`\(\*\*`),
}

func requirementsExtractPythonFile(path string, content []byte) (ops []StaticOperation, gaps []ci.Gap) {
	lines := requirementsFileLines(content)
	digest := ci.DigestBytes(content)
	clientVars := map[string]string{} // var name -> boto3 service slug
	for lineNo, line := range lines {
		if m := requirementsPythonBotoAssign.FindStringSubmatch(line); m != nil {
			clientVars[m[1]] = m[2]
		}
		for _, unsupported := range requirementsPythonResourceUnsupported {
			if unsupported.MatchString(line) {
				gaps = append(gaps, ci.Gap{
					Code: GapUnsupportedPattern, Scope: path,
					Message:    "python construct cannot be statically resolved to a direct boto3 client call",
					References: []ci.Reference{{Path: path, StartLine: lineNo + 1, EndLine: lineNo + 1, Digest: digest}},
				})
			}
		}
		for _, m := range requirementsPythonMethodCall.FindAllStringSubmatch(line, -1) {
			service, bound := clientVars[m[1]]
			if !bound {
				continue
			}
			quote, ok := requirementsQuoteLines(lines, lineNo+1, lineNo+1)
			if !ok {
				continue
			}
			ops = append(ops, StaticOperation{
				Provider: ci.AWS, Service: service, Token: m[2],
				Path: path, StartLine: lineNo + 1, EndLine: lineNo + 1, Quote: quote,
			})
		}
	}
	gaps = append(gaps, ci.Gap{
		Code: GapUnsupportedPattern, Scope: path,
		Message: "python source is reviewed via bounded single-line boto3.client(...) pattern matching only; absence of additional dynamic, multi-line, or wrapped cloud calls cannot be proven, so this file is never marked fully covered",
	})
	return ops, gaps
}

var requirementsJSImport = regexp.MustCompile(`import\s*\{([^}]+)\}\s*from\s*["']@aws-sdk/client-([a-z0-9-]+)["']`)
var requirementsJSCommand = regexp.MustCompile(`new\s+([A-Za-z0-9_]+)Command\(`)
var requirementsJSUnsupported = []*regexp.Regexp{
	regexp.MustCompile(`\[[^\]]*\]\s*\(`), // computed member call: client[method](...)
	regexp.MustCompile(`\beval\(`),
	regexp.MustCompile(`\bnew\s+Function\(`),
	regexp.MustCompile(`@google-cloud/`),
}

func requirementsExtractJSFile(path string, content []byte) (ops []StaticOperation, gaps []ci.Gap) {
	lines := requirementsFileLines(content)
	digest := ci.DigestBytes(content)
	importedCommands := map[string]string{} // CommandName (without suffix) -> service slug
	for _, line := range lines {
		if m := requirementsJSImport.FindStringSubmatch(line); m != nil {
			service := m[2]
			for _, symbol := range strings.Split(m[1], ",") {
				symbol = strings.TrimSpace(symbol)
				if idx := strings.Index(symbol, " as "); idx >= 0 {
					symbol = strings.TrimSpace(symbol[:idx])
				}
				if strings.HasSuffix(symbol, "Command") {
					importedCommands[strings.TrimSuffix(symbol, "Command")] = service
				}
			}
		}
	}
	for lineNo, line := range lines {
		for _, unsupported := range requirementsJSUnsupported {
			if unsupported.MatchString(line) {
				gaps = append(gaps, ci.Gap{
					Code: GapUnsupportedPattern, Scope: path,
					Message:    "javascript/typescript construct cannot be statically resolved to a direct, supported cloud SDK call",
					References: []ci.Reference{{Path: path, StartLine: lineNo + 1, EndLine: lineNo + 1, Digest: digest}},
				})
			}
		}
		for _, m := range requirementsJSCommand.FindAllStringSubmatch(line, -1) {
			service, bound := importedCommands[m[1]]
			if !bound {
				continue
			}
			quote, ok := requirementsQuoteLines(lines, lineNo+1, lineNo+1)
			if !ok {
				continue
			}
			ops = append(ops, StaticOperation{
				Provider: ci.AWS, Service: service, Token: m[1],
				Path: path, StartLine: lineNo + 1, EndLine: lineNo + 1, Quote: quote,
			})
		}
	}
	gaps = append(gaps, ci.Gap{
		Code: GapUnsupportedPattern, Scope: path,
		Message: "javascript/typescript source is reviewed via bounded single-line `new XCommand(...)` pattern matching only; absence of additional dynamic, multi-line, or wrapped cloud calls cannot be proven, so this file is never marked fully covered",
	})
	return ops, gaps
}
