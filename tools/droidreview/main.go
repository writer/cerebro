package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/tools/droidreview/bodyread"
)

func main() {
	var base string
	var head string
	var repo string
	flag.StringVar(&base, "base", "origin/main", "base git revision for changed-file preflight")
	flag.StringVar(&head, "head", "HEAD", "head git revision for changed-file preflight")
	flag.StringVar(&repo, "repo", ".", "repository root")
	flag.Parse()

	if err := run(base, head, repo); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(base, head, repo string) error {
	files, err := changedFiles(base, head, repo)
	if err != nil {
		return err
	}
	var findings []bodyread.Finding
	for _, file := range files {
		if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		switch {
		case strings.HasPrefix(file, "vendor/"),
			strings.HasPrefix(file, "gen/"),
			strings.HasPrefix(file, "sdk/"),
			strings.Contains(file, "/testdata/"):
			continue
		}
		path := filepath.Join(repo, filepath.FromSlash(file))
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}
		fileFindings, err := bodyread.FindUnboundedReadAll(file, body)
		if err != nil {
			return fmt.Errorf("scan %s: %w", file, err)
		}
		findings = append(findings, fileFindings...)
	}
	if len(findings) > 0 {
		var message strings.Builder
		message.WriteString("Droid review preflight found unbounded io.ReadAll calls:\n")
		for _, finding := range findings {
			fmt.Fprintf(&message, "- %s:%d\n", finding.File, finding.Line)
		}
		message.WriteString("\nWrap external/body reads in io.LimitReader or stream them instead.\n")
		return fmt.Errorf("%s", strings.TrimRight(message.String(), "\n"))
	}
	fmt.Printf("Droid review preflight passed for %d changed files.\n", len(files))
	return nil
}

func changedFiles(base, head, repo string) ([]string, error) {
	files := map[string]struct{}{}
	for _, args := range [][]string{
		{"diff", "--name-only", "--diff-filter=ACMR", base + "..." + head},
		{"diff", "--name-only", "--diff-filter=ACMR"},
		{"diff", "--cached", "--name-only", "--diff-filter=ACMR"},
		{"ls-files", "--others", "--exclude-standard"},
	} {
		output, err := gitOutput(repo, args...)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				files[filepath.ToSlash(line)] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(files))
	for file := range files {
		ordered = append(ordered, file)
	}
	sort.Strings(ordered)
	return ordered, nil
}

func gitOutput(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
