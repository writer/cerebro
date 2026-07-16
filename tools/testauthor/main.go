package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
	"gopkg.in/yaml.v3"
)

type gap struct {
	Policy    string `json:"policy"`
	Test      string `json:"test"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("command is required: scan, author-policy, author-tests, or prove-policy"))
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "author-policy":
		err = runAuthorPolicy(os.Args[2:])
	case "author-tests":
		err = runAuthorTests(os.Args[2:])
	case "prove-policy":
		err = runProvePolicy(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func runScan(args []string) error {
	flags := flag.NewFlagSet("testauthor scan", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	gaps, err := findGaps(*root)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(gaps)
}

func runAuthorPolicy(args []string) error {
	flags := flag.NewFlagSet("testauthor author-policy", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	intentPath := flags.String("intent", "", "policy intent YAML")
	write := flags.Bool("write", false, "write policy and test files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*intentPath) == "" {
		return errors.New("--intent is required")
	}
	intent, err := loadIntent(*intentPath)
	if err != nil {
		return err
	}
	artifacts, err := policyauthor.Author(intent)
	if err != nil {
		return err
	}
	if !*write {
		_, err = fmt.Fprintf(os.Stdout, "# %s\n%s---\n# %s\n%s", artifacts.PolicyPath, artifacts.PolicyYAML, artifacts.TestPath, artifacts.TestYAML)
		return err
	}
	if err := writeNew(*root, artifacts.PolicyPath, artifacts.PolicyYAML); err != nil {
		return err
	}
	if err := writeNew(*root, artifacts.TestPath, artifacts.TestYAML); err != nil {
		_ = os.Remove(filepath.Join(*root, filepath.FromSlash(artifacts.PolicyPath)))
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "testauthor: wrote %s and %s; finding and passing cases proved\n", artifacts.PolicyPath, artifacts.TestPath)
	return err
}

func runProvePolicy(args []string) error {
	flags := flag.NewFlagSet("testauthor prove-policy", flag.ContinueOnError)
	intentPath := flags.String("intent", "", "policy intent YAML")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*intentPath) == "" {
		return errors.New("--intent is required")
	}
	intent, err := loadIntent(*intentPath)
	if err != nil {
		return err
	}
	artifacts, err := policyauthor.Author(intent)
	if err != nil {
		return err
	}
	result, err := policyauthor.Prove(context.Background(), artifacts)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(result); encodeErr != nil {
		return errors.Join(err, encodeErr)
	}
	return err
}

func loadIntent(path string) (policyauthor.Intent, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return policyauthor.Intent{}, err
	}
	var intent policyauthor.Intent
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&intent); err != nil {
		return intent, fmt.Errorf("decode policy intent: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return intent, errors.New("policy intent must contain one YAML document")
	}
	return intent, nil
}

func runAuthorTests(args []string) error {
	flags := flag.NewFlagSet("testauthor author-tests", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	write := flags.Bool("write", false, "write supported missing test suites")
	if err := flags.Parse(args); err != nil {
		return err
	}
	gaps, rules, err := gapsAndRules(*root)
	if err != nil {
		return err
	}
	authored := 0
	for _, item := range gaps {
		if !item.Supported {
			continue
		}
		rule := rules[item.Policy]
		suite, err := policyauthor.SuiteForRule(rule)
		if err != nil {
			return err
		}
		content, err := findingdsl.FormatPolicyRuleTestSuiteYAML(suite)
		if err != nil {
			return err
		}
		if *write {
			if err := writeNew(*root, item.Test, content); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(os.Stdout, "# %s\n%s", item.Test, content); err != nil {
				return err
			}
		}
		authored++
	}
	_, err = fmt.Fprintf(os.Stdout, "testauthor: authored %d supported test suite(s); %d gap(s) require explicit intent\n", authored, len(gaps)-authored)
	return err
}

func findGaps(root string) ([]gap, error) { gaps, _, err := gapsAndRules(root); return gaps, err }

func gapsAndRules(root string) ([]gap, map[string]findingdsl.PolicyFindingRule, error) {
	rules, issues, err := findingdsl.LoadPolicyRules(filepath.Clean(root))
	if err != nil {
		return nil, nil, err
	}
	if len(issues) != 0 {
		return nil, nil, fmt.Errorf("policy repository has %d validation issue(s)", len(issues))
	}
	result := []gap{}
	byPath := map[string]findingdsl.PolicyFindingRule{}
	for _, rule := range rules {
		testPath := strings.TrimSuffix(rule.RelPath, filepath.Ext(rule.RelPath)) + ".test.yaml"
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(testPath))); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return nil, nil, err
		}
		item := gap{Policy: rule.RelPath, Test: testPath}
		if _, _, synthErr := findingdsl.SynthesizeEqualityConditionFixtures(rule.Spec.Match.Conditions); synthErr == nil {
			item.Supported = true
		} else {
			item.Reason = synthErr.Error()
		}
		result = append(result, item)
		byPath[rule.RelPath] = rule
	}
	return result, byPath, nil
}

func writeNew(root, rel string, content []byte) error {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("unsafe repository path %q", rel)
	}
	repo, err := os.OpenRoot(filepath.Clean(root))
	if err != nil {
		return err
	}
	defer repo.Close()
	if dir := filepath.ToSlash(filepath.Dir(rel)); dir != "." {
		if err := repo.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	file, err := repo.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("refusing to overwrite %s", rel)
		}
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = repo.Remove(rel)
		return err
	}
	return file.Close()
}

func fail(err error) { fmt.Fprintln(os.Stderr, "testauthor:", err); os.Exit(1) }
