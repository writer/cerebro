package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "validate checked-in finding DSL files")
	migratePolicies := flag.Bool("migrate-policies", false, "convert legacy policy JSON files into PolicyFindingRule DSL YAML")
	write := flag.Bool("write", false, "write migration output")
	flag.Parse()

	if !*check && !*migratePolicies {
		fmt.Fprintln(os.Stderr, "findingdsl: one of --check or --migrate-policies is required")
		os.Exit(2)
	}
	if *migratePolicies {
		if err := migratePolicyFiles(filepath.Clean(*root), *write); err != nil {
			fmt.Fprintf(os.Stderr, "findingdsl: %v\n", err)
			os.Exit(1)
		}
	}
	if *check {
		if err := checkPolicyRules(filepath.Clean(*root)); err != nil {
			fmt.Fprintf(os.Stderr, "findingdsl: %v\n", err)
			os.Exit(1)
		}
	}
}

func checkPolicyRules(root string) error {
	rules, issues, err := findingdsl.LoadPolicyRules(root)
	if err != nil {
		return err
	}
	for _, issue := range issues {
		fmt.Fprintf(os.Stderr, "%s: %s\n", issue.Path, issue.Message)
	}
	if len(issues) != 0 {
		return fmt.Errorf("policy DSL validation failed with %d issue(s)", len(issues))
	}
	if len(rules) == 0 {
		return errors.New("no PolicyFindingRule DSL files found under policies/")
	}
	return nil
}

func migratePolicyFiles(root string, write bool) error {
	policiesRoot := filepath.Join(root, "policies")
	converted := 0
	err := filepath.WalkDir(policiesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		rel := slashRel(root, path)
		if rel == findingdsl.ControlMappingRelPath {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlinked policy files are not allowed", rel)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		legacy, err := findingdsl.DecodeLegacyPolicy(content)
		if err != nil {
			return fmt.Errorf("decode %s: %w", rel, err)
		}
		rule := findingdsl.FromLegacyPolicy(strings.TrimSuffix(rel, ".json")+".yaml", legacy)
		if issues := findingdsl.ValidatePolicyRule(rule); len(issues) != 0 {
			messages := make([]string, 0, len(issues))
			for _, issue := range issues {
				messages = append(messages, issue.Message)
			}
			return fmt.Errorf("validate migrated %s: %s", rel, strings.Join(messages, "; "))
		}
		yamlContent, err := findingdsl.MarshalPolicyRuleYAML(rule)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", rel, err)
		}
		target := strings.TrimSuffix(path, ".json") + ".yaml"
		targetRel := slashRel(root, target)
		if !write {
			fmt.Fprintf(os.Stdout, "would convert %s -> %s\n", rel, targetRel)
			converted++
			return nil
		}
		if err := rejectSymlink(target); err != nil {
			return fmt.Errorf("write %s: %w", targetRel, err)
		}
		if err := os.WriteFile(target, yamlContent, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", targetRel, err)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove %s: %w", rel, err)
		}
		converted++
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("policies directory not found")
		}
		return err
	}
	if converted == 0 {
		fmt.Fprintln(os.Stdout, "findingdsl: no legacy policy JSON files to migrate")
		return nil
	}
	if write {
		fmt.Fprintf(os.Stdout, "findingdsl: converted %d legacy policy file(s)\n", converted)
	} else {
		fmt.Fprintf(os.Stdout, "findingdsl: %d legacy policy file(s) would be converted; rerun with --write\n", converted)
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlinked generated files are not allowed")
	}
	return nil
}

func slashRel(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
