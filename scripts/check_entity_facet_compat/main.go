package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

const contractsPath = "docs/GRAPH_ENTITY_FACETS.json"

var gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/\-^~]+$`)

func main() {
	baseRefFlag := flag.String("base-ref", strings.TrimSpace(os.Getenv("ENTITY_FACET_BASE_REF")), "git ref used as compatibility baseline (for example origin/main)")
	requireBaseline := flag.Bool("require-baseline", false, "fail when no baseline entity facet catalog can be loaded")
	flag.Parse()

	currentCatalog := graph.BuildEntityFacetContractCatalog(time.Time{})
	baselineCatalog, baselineRef, err := loadBaselineCatalog(strings.TrimSpace(*baseRefFlag))
	if err != nil {
		if *requireBaseline {
			fatalf("load baseline entity facet catalog failed: %v", err)
		}
		fmt.Printf("entity facet compatibility check skipped: %v\n", err)
		return
	}
	report := graph.CompareEntityFacetContractCatalogs(baselineCatalog, currentCatalog, time.Now().UTC())
	fmt.Printf("baseline_ref=%s baseline_facets=%d current_facets=%d added=%d removed=%d breaking=%d violations=%d diffs=%d\n",
		baselineRef,
		report.BaselineFacets,
		report.CurrentFacets,
		len(report.AddedFacets),
		len(report.RemovedFacets),
		len(report.BreakingChanges),
		len(report.VersioningViolations),
		len(report.DiffSummaries),
	)
	for _, issue := range report.BreakingChanges {
		fmt.Printf("breaking_change facet_id=%s type=%s detail=%s prev=%s curr=%s\n",
			issue.FacetID,
			issue.ChangeType,
			issue.Detail,
			issue.PreviousVersion,
			issue.CurrentVersion,
		)
	}
	for _, diff := range report.DiffSummaries {
		fmt.Printf("diff_summary facet_id=%s prev=%s curr=%s added=%s removed=%s changed=%s\n",
			diff.FacetID,
			diff.PreviousVersion,
			diff.CurrentVersion,
			strings.Join(diff.AddedPaths, ","),
			strings.Join(diff.RemovedPaths, ","),
			strings.Join(diff.ChangedPaths, ","),
		)
	}
	if !report.Compatible {
		fatalf(
			"entity facet compatibility failed: %d breaking change(s), %d versioning violation(s) detected",
			len(report.BreakingChanges),
			len(report.VersioningViolations),
		)
	}
	fmt.Println("entity facet compatibility check passed")
}

func loadBaselineCatalog(baseRef string) (graph.EntityFacetContractCatalog, string, error) {
	candidates := make([]string, 0, 4)
	if baseRef != "" {
		candidates = append(candidates, baseRef)
	}
	candidates = append(candidates, "HEAD^1", "HEAD^", "origin/main")
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		payload, err := gitShowFile(candidate, contractsPath)
		if err != nil {
			continue
		}
		var catalog graph.EntityFacetContractCatalog
		if err := json.Unmarshal(payload, &catalog); err != nil {
			continue
		}
		return catalog, candidate, nil
	}
	if _, err := os.Stat(contractsPath); err == nil {
		return graph.EntityFacetContractCatalog{}, "bootstrap:none", nil
	}
	return graph.EntityFacetContractCatalog{}, "", fmt.Errorf("no readable baseline entity facet catalog found for refs %v", candidates)
}

func gitShowFile(ref, filePath string) ([]byte, error) {
	if !isSafeGitRef(ref) {
		return nil, fmt.Errorf("unsafe git ref %q", ref)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "show", fmt.Sprintf("%s:%s", ref, filePath)) // #nosec G204,G702 -- ref is strictly validated and file path is a repository constant.
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func isSafeGitRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.Contains(ref, ":") || strings.Contains(ref, "..") || strings.HasPrefix(ref, "-") {
		return false
	}
	return gitRefPattern.MatchString(ref)
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
