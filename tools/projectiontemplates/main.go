// Command projectiontemplates validates that projection template specs in
// internal/sourcegen/projectionspec/templates/ are well-formed and consistent
// with the existing classifier grammar.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen/projectionspec"
)

func main() {
	var check bool
	flag.BoolVar(&check, "check", false, "check consistency with classifier grammar")
	flag.Parse()

	registry, err := projectionspec.Load()
	if err != nil {
		fail(err)
	}

	ids := registry.IDs()
	fmt.Fprintf(os.Stderr, "projectiontemplates: loaded %d templates: %s\n", len(ids), strings.Join(ids, ", "))

	if check {
		grammar := connectordefinitions.DefaultGrammar()
		var issues []string

		// Verify every grammar projection template has a spec.
		for _, grammarTemplate := range grammar.ProjectionTemplates {
			if _, ok := registry.Get(grammarTemplate); !ok {
				issues = append(issues, fmt.Sprintf("grammar projection template %q has no spec YAML", grammarTemplate))
			}
		}

		// Verify every spec exists in the grammar.
		grammarSet := map[string]bool{}
		for _, t := range grammar.ProjectionTemplates {
			grammarSet[t] = true
		}
		for _, id := range ids {
			if !grammarSet[id] {
				issues = append(issues, fmt.Sprintf("spec %q exists but is not in the classifier grammar's ProjectionTemplates", id))
			}
		}

		sort.Strings(issues)
		if len(issues) > 0 {
			for _, issue := range issues {
				fmt.Fprintf(os.Stderr, "  issue: %s\n", issue)
			}
			fail(fmt.Errorf("%d consistency issue(s) found", len(issues)))
		}
		fmt.Fprintf(os.Stderr, "projectiontemplates: all %d templates consistent with classifier grammar\n", len(ids))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
