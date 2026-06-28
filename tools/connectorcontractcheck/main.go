package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/connectorvalidation"
	"github.com/writer/cerebro/internal/connectorvalidation/contracttest"
)

type issue struct {
	path    string
	message string
	warning bool
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	issues, err := run(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connector-contract-check: %v\n", err)
		os.Exit(1)
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].warning != issues[j].warning {
			return !issues[i].warning
		}
		if issues[i].path != issues[j].path {
			return issues[i].path < issues[j].path
		}
		return issues[i].message < issues[j].message
	})
	failed := false
	warningsPrinted := 0
	warningsSuppressed := 0
	for _, issue := range issues {
		prefix := "ERROR"
		out := os.Stderr
		if issue.warning {
			if warningsPrinted >= 10 {
				warningsSuppressed++
				continue
			}
			warningsPrinted++
			prefix = "WARN"
			out = os.Stdout
		} else {
			failed = true
		}
		fmt.Fprintf(out, "%s %s: %s\n", prefix, issue.path, issue.message)
	}
	if warningsSuppressed > 0 {
		fmt.Fprintf(os.Stdout, "WARN connector-contract-check: suppressed %d additional projection warnings\n", warningsSuppressed)
	}
	if failed {
		os.Exit(1)
	}
}

func run(root string) ([]issue, error) {
	root = filepath.Clean(root)
	catalogRoot := filepath.Join(root, "internal", "connectorcatalog", "catalog")
	analysis, err := connectorcatalog.AnalyzeDir(catalogRoot, connectorcatalog.Options{DryRunSourcegen: true})
	if err != nil {
		return nil, err
	}
	entries := map[string]connectorcatalog.Entry{}
	var issues []issue
	for _, catalogIssue := range analysis.Issues {
		issues = append(issues, issue{path: filepath.ToSlash(filepath.Join("internal", "connectorcatalog", "catalog", catalogIssue.Path)), message: catalogIssue.Message})
	}
	for _, entry := range analysis.Entries {
		entries[entry.Definition.SourceID] = entry
		issues = append(issues, projectionLint(entry)...)
		issues = append(issues, scopeLint(entry)...)
	}
	registryPath := filepath.Join(root, "internal", "connectorvalidation", "registry.yaml")
	payload, err := os.ReadFile(registryPath)
	if err != nil {
		return nil, err
	}
	registry, err := connectorvalidation.LoadRegistry(payload)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, validation := range registry.Entries {
		entry, ok := entries[validation.SourceID]
		if !ok {
			issues = append(issues, issue{path: "internal/connectorvalidation/registry.yaml", message: fmt.Sprintf("validation references unknown connector %q", validation.SourceID)})
			continue
		}
		for _, err := range connectorvalidation.ValidateClaim(entry.Definition, validation) {
			issues = append(issues, issue{path: "internal/connectorvalidation/registry.yaml", message: err.Error()})
		}
		for _, evidence := range validation.Evidence {
			if strings.TrimSpace(evidence.Type) != "fixture" {
				continue
			}
			ref := strings.TrimSpace(evidence.Ref)
			if ref == "" {
				issues = append(issues, issue{path: "internal/connectorvalidation/registry.yaml", message: fmt.Sprintf("%s fixture evidence ref is required", validation.SourceID)})
				continue
			}
			body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ref)))
			if err != nil {
				issues = append(issues, issue{path: ref, message: "read fixture: " + err.Error()})
				continue
			}
			_, err = contracttest.ValidateFixture(ctx, entry.Definition, contracttest.Fixture{
				SourceID:       validation.SourceID,
				ResourceFamily: evidence.ResourceFamily,
				Ref:            ref,
				Body:           body,
			})
			if err != nil {
				issues = append(issues, issue{path: ref, message: err.Error()})
			}
		}
	}
	if len(issues) == 0 {
		fmt.Fprintln(os.Stdout, "connector-contract-check: ok")
	}
	return dedupe(issues), nil
}

func projectionLint(entry connectorcatalog.Entry) []issue {
	var issues []issue
	path := filepath.ToSlash(filepath.Join("internal", "connectorcatalog", "catalog", entry.Path))
	for _, family := range entry.Definition.ResourceFamilies {
		if family.Projection == nil {
			continue
		}
		bySource := map[string][]string{}
		for target, source := range family.Projection.Fields {
			target = strings.TrimSpace(target)
			source = strings.TrimSpace(source)
			if target == "" || source == "" {
				continue
			}
			bySource[source] = append(bySource[source], target)
			if requiredProjectionTarget(family.Projection.Template, target) && source == "" {
				issues = append(issues, issue{path: path, warning: true, message: fmt.Sprintf("%s %s required projection target %q is unmapped", entry.Definition.SourceID, family.ID, target)})
			}
			if enumLikeTarget(target) && source == target {
				issues = append(issues, issue{path: path, warning: true, message: fmt.Sprintf("%s %s projection target %q identity-copies an enum-like field", entry.Definition.SourceID, family.ID, target)})
			}
		}
		for source, targets := range bySource {
			targets = unique(targets)
			if len(targets) < 2 {
				continue
			}
			if semanticallyDistinct(targets) {
				issues = append(issues, issue{path: path, warning: true, message: fmt.Sprintf("%s %s maps source field %q to distinct targets %s", entry.Definition.SourceID, family.ID, source, strings.Join(targets, ","))})
			}
		}
	}
	return issues
}

func scopeLint(entry connectorcatalog.Entry) []issue {
	if !readOnlyPullDefinition(entry.Definition) {
		return nil
	}
	var offenders []string
	for _, scope := range entry.Definition.Auth.Scopes {
		if writeScope(scope) {
			offenders = append(offenders, scope)
		}
	}
	for _, family := range entry.Definition.ResourceFamilies {
		for _, scope := range family.PermissionsNeeded {
			if writeScope(scope) {
				offenders = append(offenders, family.ID+":"+scope)
			}
		}
	}
	if len(offenders) == 0 {
		return nil
	}
	return []issue{{
		path:    filepath.ToSlash(filepath.Join("internal", "connectorcatalog", "catalog", entry.Path)),
		message: fmt.Sprintf("%s read-only pull connector requests write/admin scopes: %s", entry.Definition.SourceID, strings.Join(unique(offenders), ", ")),
	}}
}

func readOnlyPullDefinition(definition connectordefinitions.Definition) bool {
	if mode := strings.TrimSpace(definition.Ingest.Mode); mode != "" && mode != connectordefinitions.IngestModePull {
		return false
	}
	for _, family := range definition.ResourceFamilies {
		method := strings.ToUpper(strings.TrimSpace(family.Method))
		if method != "" && method != "GET" {
			return false
		}
	}
	return true
}

func writeScope(scope string) bool {
	normalized := strings.ToLower(strings.TrimSpace(scope))
	if normalized == "" {
		return false
	}
	if (strings.HasPrefix(normalized, "admin.") || strings.Contains(normalized, "/admin.")) && (strings.HasSuffix(normalized, ":read") || strings.HasSuffix(normalized, ".readonly")) {
		return false
	}
	tokens := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == ':' || r == '/' || r == '.' || r == '_' || r == '-' || r == ' '
	})
	for _, token := range tokens {
		switch token {
		case "write", "admin", "manage", "delete", "update", "modify", "create":
			return true
		}
	}
	return strings.Contains(normalized, "*")
}

func requiredProjectionTarget(template string, target string) bool {
	switch strings.TrimSpace(template) {
	case "finding":
		return target == "finding_id" || target == "title" || target == "status" || target == "severity"
	case "identity_user":
		return target == "user_id" || target == "email"
	default:
		return target == "id" || target == "resource_id"
	}
}

func enumLikeTarget(target string) bool {
	switch strings.TrimSpace(target) {
	case "severity", "status", "state", "priority":
		return true
	default:
		return false
	}
}

func semanticallyDistinct(targets []string) bool {
	groups := map[string]struct{}{}
	for _, target := range targets {
		switch target {
		case "id", "resource_id", "finding_id", "user_id", "group_id", "provider_id":
			groups["identity"] = struct{}{}
		case "name", "title", "resource_name", "display_name":
			groups["label"] = struct{}{}
		case "severity", "status", "state", "priority":
			groups[target] = struct{}{}
		default:
			groups[target] = struct{}{}
		}
	}
	return len(groups) > 1
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func dedupe(values []issue) []issue {
	seen := map[issue]struct{}{}
	out := make([]issue, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
