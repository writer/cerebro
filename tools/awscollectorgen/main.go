// Command awscollectorgen wires an implemented AWS resource collector into the
// central source, fixture, projection, catalog, and deploy registries.
package main

import (
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

type filePlan struct {
	path  string
	gofmt bool
	apply []func(string) (string, error)
}

type fileUpdate struct {
	path    string
	content []byte
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "awscollectorgen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("awscollectorgen", flag.ContinueOnError)
	family := flags.String("family", "", "lower_snake_case family id, e.g. ec2_transit_gateway")
	title := flags.String("title", "", "human-readable coverage title")
	label := flags.String("label", "", "sourcecdk family label")
	constName := flags.String("const-name", "", "Go family constant name; defaults to family + PascalCase")
	recordType := flags.String("record-type", "", "record type used by awsFamilyOptions[T]")
	listFunc := flags.String("list-func", "", "implemented list function name")
	eventFunc := flags.String("event-func", "", "implemented event function name")
	urnExpr := flags.String("urn-expr", "", "Go expression that returns the record resource id string, evaluated with record/settings in scope")
	cursorExpr := flags.String("cursor-expr", "", "Go expression for CursorFallback; defaults to --urn-expr")
	projector := flags.String("projector", "awsCloudResourceProjections", "sourceprojection projector function")
	root := flags.String("root", ".", "repository root containing sources/aws")
	dryRun := flags.Bool("dry-run", false, "validate and print changed files without writing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	n, err := deriveNames(*family, *title, *constName, *recordType, *listFunc, *eventFunc, *label, *urnExpr, *cursorExpr, *projector)
	if err != nil {
		return err
	}
	awsDir := filepath.Join(*root, "sources", "aws")
	if err := validateReadyCollector(*root, awsDir, n); err != nil {
		return err
	}
	updates, err := prepareUpdates(*root, awsDir, n)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("would wire aws collector %q into %d files:\n", n.Family, len(updates))
		for _, update := range updates {
			fmt.Printf("  - %s\n", update.path)
		}
		return nil
	}
	for _, update := range updates {
		if err := os.WriteFile(update.path, update.content, 0o644); err != nil { // #nosec G306 -- generated source/catalog files use normal repository permissions.
			return fmt.Errorf("write %s: %w", update.path, err)
		}
	}
	fmt.Printf("wired aws collector %q\n", n.Family)
	return nil
}

func validateReadyCollector(root, awsDir string, n names) error {
	if err := ensureNotAlreadyWired(root, awsDir, n); err != nil {
		return err
	}
	body, err := readAWSImplementationFiles(awsDir)
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`func\s+` + regexp.QuoteMeta(n.ListFunc) + `\s*\(`).MatchString(body) {
		return fmt.Errorf("sources/aws implementation must define %s", n.ListFunc)
	}
	if !regexp.MustCompile(`func\s+` + regexp.QuoteMeta(n.EventFunc) + `\s*\(`).MatchString(body) {
		return fmt.Errorf("sources/aws implementation must define %s", n.EventFunc)
	}
	if !strings.Contains(n.RecordType, ".") && !regexp.MustCompile(`type\s+`+regexp.QuoteMeta(n.RecordType)+`\b`).MatchString(body) {
		return fmt.Errorf("sources/aws implementation must define type %s", n.RecordType)
	}
	return validateFixtures(root, n)
}

func readAWSImplementationFiles(awsDir string) (string, error) {
	entries, err := os.ReadDir(awsDir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", awsDir, err)
	}
	var b strings.Builder
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path, err := safeChildPath(awsDir, name)
		if err != nil {
			return "", err
		}
		body, err := os.ReadFile(path) // #nosec G304,G703 -- name comes from os.ReadDir and safeChildPath rejects escapes.
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		b.Write(body)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func safeChildPath(dir, name string) (string, error) {
	if name == "" || name != filepath.Base(name) || filepath.IsAbs(name) {
		return "", fmt.Errorf("unsafe child path %q", name)
	}
	path := filepath.Join(dir, name)
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return "", fmt.Errorf("relativize %s: %w", path, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe child path %q", name)
	}
	return path, nil
}

func ensureNotAlreadyWired(root, awsDir string, n names) error {
	checks := []struct {
		path string
		want string
	}{
		{filepath.Join(awsDir, "source.go"), "= " + strconv.Quote(n.Family)},
		{filepath.Join(awsDir, "source.go"), n.FamilyConst},
		{filepath.Join(awsDir, "fixture.go"), n.FamilyConst},
		{filepath.Join(root, "internal", "sourceprojection", "registry.go"), strconv.Quote(n.Kind) + ":"},
		{filepath.Join(awsDir, "catalog.yaml"), "- " + n.Kind},
		{filepath.Join(awsDir, "catalog.yaml"), "- " + n.Family},
		{filepath.Join(awsDir, "deploy.yaml"), "family: " + n.Family},
	}
	for _, check := range checks {
		body, err := os.ReadFile(check.path)
		if err != nil {
			return fmt.Errorf("read %s: %w", check.path, err)
		}
		if strings.Contains(string(body), check.want) {
			return fmt.Errorf("family %q already appears in %s", n.Family, check.path)
		}
	}
	return nil
}

func validateFixtures(root string, n names) error {
	fsys := os.DirFS(root)
	discoverPath := filepath.ToSlash(filepath.Join("sources", "aws", "testdata", "discover_"+n.Family+".json"))
	readPath := filepath.ToSlash(filepath.Join("sources", "aws", "testdata", "read_"+n.Family+".json"))
	urns, err := sourcecdk.LoadFixtureURNs(fsys, discoverPath)
	if err != nil {
		return err
	}
	if len(urns) == 0 {
		return fmt.Errorf("%s must contain at least one URN", discoverPath)
	}
	events, err := sourcecdk.LoadFixtureEvents(fsys, readPath)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("%s must contain at least one event", readPath)
	}
	for _, event := range events {
		if event.GetKind() != n.Kind {
			return fmt.Errorf("%s event %q kind = %q, want %q", readPath, event.GetId(), event.GetKind(), n.Kind)
		}
		if event.GetSchemaRef() != n.SchemaRef {
			return fmt.Errorf("%s event %q schema_ref = %q, want %q", readPath, event.GetId(), event.GetSchemaRef(), n.SchemaRef)
		}
	}
	return nil
}

func prepareUpdates(root, awsDir string, n names) ([]fileUpdate, error) {
	registerSnippet, err := renderTemplate(registerTemplate, n)
	if err != nil {
		return nil, err
	}
	dimensionSnippet, err := renderTemplate(dimensionTemplate, n)
	if err != nil {
		return nil, err
	}
	deploySnippet, err := renderTemplate(deployTemplate, n)
	if err != nil {
		return nil, err
	}
	plans := []filePlan{
		{
			path:  filepath.Join(awsDir, "source.go"),
			gofmt: true,
			apply: []func(string) (string, error){
				func(content string) (string, error) {
					return insertBeforeLineSentinel(content, sentinelFamilyConst, "\t"+n.FamilyConst+" = "+strconv.Quote(n.Family))
				},
				func(content string) (string, error) {
					return insertBeforeLineSentinel(content, sentinelFamilyRegister, registerSnippet)
				},
				func(content string) (string, error) {
					return insertBeforeInlineTarget(content, sentinelNormalize, "familyRedshiftCluster:", n.FamilyConst+", ")
				},
			},
		},
		{
			path:  filepath.Join(awsDir, "fixture.go"),
			gofmt: true,
			apply: []func(string) (string, error){
				func(content string) (string, error) {
					return insertBeforeInlineTarget(content, sentinelFixture, "familyRedshiftCluster} {", n.FamilyConst+", ")
				},
			},
		},
		{
			path:  filepath.Join(root, "internal", "sourceprojection", "registry.go"),
			gofmt: true,
			apply: []func(string) (string, error){
				func(content string) (string, error) {
					return insertBeforeLineSentinel(content, sentinelProjector, "\t"+strconv.Quote(n.Kind)+": "+n.Projector+",")
				},
			},
		},
		{
			path: filepath.Join(awsDir, "catalog.yaml"),
			apply: []func(string) (string, error){
				func(content string) (string, error) {
					return insertBeforeLineSentinel(content, sentinelEmittedKinds, "  - "+n.Kind)
				},
				func(content string) (string, error) {
					return insertBeforeLineSentinel(content, sentinelRuntimeFamilies, "  - "+n.Family)
				},
				func(content string) (string, error) {
					return insertBeforeLineSentinel(content, sentinelDimensions, dimensionSnippet)
				},
			},
		},
		{
			path: filepath.Join(awsDir, "deploy.yaml"),
			apply: []func(string) (string, error){
				func(content string) (string, error) {
					return insertBeforeLineSentinel(content, sentinelDeployRuntimes, deploySnippet)
				},
			},
		},
	}
	updates := make([]fileUpdate, 0, len(plans))
	for _, plan := range plans {
		body, err := os.ReadFile(plan.path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", plan.path, err)
		}
		content := string(body)
		for _, apply := range plan.apply {
			content, err = apply(content)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", plan.path, err)
			}
		}
		out := []byte(content)
		if plan.gofmt {
			out, err = format.Source(out)
			if err != nil {
				return nil, fmt.Errorf("gofmt %s: %w", plan.path, err)
			}
		}
		updates = append(updates, fileUpdate{path: plan.path, content: out})
	}
	return updates, nil
}
