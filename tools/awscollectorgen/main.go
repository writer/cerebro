// Command awscollectorgen scaffolds a new AWS resource collector family and
// wires it into the central source, fixture, projection, catalog, and deploy
// files through deterministic sentinel markers.
package main

import (
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type edit struct {
	sentinel string
	snippet  string
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
	title := flags.String("title", "", "human-readable coverage title (defaults to a derived title)")
	root := flags.String("root", ".", "repository root containing sources/aws")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*family) == "" {
		return fmt.Errorf("--family is required")
	}
	n, err := deriveNames(*family, *title)
	if err != nil {
		return err
	}
	awsDir := filepath.Join(*root, "sources", "aws")
	if err := ensureNotExisting(awsDir, n); err != nil {
		return err
	}

	registerSnippet, err := renderTemplate(registerTemplate, n)
	if err != nil {
		return err
	}
	dimensionSnippet, err := renderTemplate(dimensionTemplate, n)
	if err != nil {
		return err
	}
	deploySnippet, err := renderTemplate(deployTemplate, n)
	if err != nil {
		return err
	}

	if err := wireGoFile(filepath.Join(awsDir, "source.go"), []edit{
		{sentinelFamilyConst, "\t" + n.FamilyConst + " = " + strconv.Quote(n.Family)},
		{sentinelFamilyRegister, registerSnippet},
		{sentinelNormalize, "\t\t" + n.FamilyConst + ","},
	}); err != nil {
		return err
	}
	if err := wireGoFile(filepath.Join(awsDir, "fixture.go"), []edit{
		{sentinelFixture, "\t\t" + n.FamilyConst + ","},
	}); err != nil {
		return err
	}
	if err := wireGoFile(filepath.Join(*root, "internal", "sourceprojection", "registry.go"), []edit{
		{sentinelProjector, "\t" + strconv.Quote(n.Kind) + ": awsCloudResourceProjections,"},
	}); err != nil {
		return err
	}
	if err := wireTextFile(filepath.Join(awsDir, "catalog.yaml"), []edit{
		{sentinelEmittedKinds, "  - " + n.Kind},
		{sentinelRuntimeFamilies, "  - " + n.Family},
		{sentinelDimensions, dimensionSnippet},
	}); err != nil {
		return err
	}
	if err := wireTextFile(filepath.Join(awsDir, "deploy.yaml"), []edit{
		{sentinelDeployRuntimes, deploySnippet},
	}); err != nil {
		return err
	}

	collector, err := renderCollector(n)
	if err != nil {
		return err
	}
	test, err := renderTest(n)
	if err != nil {
		return err
	}
	discover, err := renderDiscoverFixture(n)
	if err != nil {
		return err
	}
	read, err := renderReadFixture(n)
	if err != nil {
		return err
	}
	writes := map[string]string{
		filepath.Join(awsDir, n.Family+".go"):                          collector,
		filepath.Join(awsDir, n.Family+"_test.go"):                     test,
		filepath.Join(awsDir, "testdata", "discover_"+n.Family+".json"): discover,
		filepath.Join(awsDir, "testdata", "read_"+n.Family+".json"):     read,
	}
	for path, content := range writes {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	fmt.Printf("scaffolded aws collector %q\n", n.Family)
	fmt.Println("next steps:")
	fmt.Printf("  - implement %s in sources/aws/%s.go using the AWS SDK\n", n.ListFunc, n.Family)
	fmt.Printf("  - flesh out %s and the testdata fixtures, then add a real case to the kind table test\n", n.EventFunc)
	return nil
}

func ensureNotExisting(awsDir string, n names) error {
	collectorPath := filepath.Join(awsDir, n.Family+".go")
	if _, err := os.Stat(collectorPath); err == nil {
		return fmt.Errorf("collector %s already exists", collectorPath)
	}
	source, err := os.ReadFile(filepath.Join(awsDir, "source.go"))
	if err != nil {
		return fmt.Errorf("read source.go: %w", err)
	}
	if strings.Contains(string(source), n.FamilyConst+" =") {
		return fmt.Errorf("family constant %s already declared", n.FamilyConst)
	}
	return nil
}

func wireGoFile(path string, edits []edit) error {
	content, err := applyEdits(path, edits)
	if err != nil {
		return err
	}
	formatted, err := format.Source([]byte(content))
	if err != nil {
		return fmt.Errorf("gofmt %s: %w", path, err)
	}
	return os.WriteFile(path, formatted, 0o644)
}

func wireTextFile(path string, edits []edit) error {
	content, err := applyEdits(path, edits)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func applyEdits(path string, edits []edit) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	content := string(raw)
	for _, e := range edits {
		content, err = insertBeforeSentinel(content, e.sentinel, e.snippet)
		if err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
	}
	return content, nil
}
