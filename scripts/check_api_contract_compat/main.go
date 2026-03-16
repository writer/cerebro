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

	"github.com/writer/cerebro/internal/apicontractcompat"
)

const contractsPath = "docs/API_CONTRACTS.json"

var gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/\-^~]+$`)

func main() {
	baseRefFlag := flag.String("base-ref", strings.TrimSpace(os.Getenv("API_CONTRACT_BASE_REF")), "git ref used as compatibility baseline (for example origin/main)")
	requireBaseline := flag.Bool("require-baseline", false, "fail when no baseline API contract catalog can be loaded")
	flag.Parse()

	currentCatalog, err := apicontractcompat.BuildCatalogFromFile("api/openapi.yaml", time.Time{})
	if err != nil {
		fatalf("build current api contract catalog failed: %v", err)
	}
	baselineCatalog, baselineRef, err := loadBaselineCatalog(strings.TrimSpace(*baseRefFlag))
	if err != nil {
		if *requireBaseline {
			fatalf("load baseline api contracts failed: %v", err)
		}
		fmt.Printf("api contract compatibility check skipped: %v\n", err)
		return
	}

	report := apicontractcompat.CompareCatalogs(baselineCatalog, currentCatalog, time.Now().UTC())
	fmt.Printf("baseline_ref=%s baseline_endpoints=%d current_endpoints=%d added=%d removed=%d breaking=%d\n",
		baselineRef,
		report.BaselineEndpoints,
		report.CurrentEndpoints,
		len(report.AddedEndpoints),
		len(report.RemovedEndpoints),
		len(report.BreakingChanges),
	)
	for _, issue := range report.BreakingChanges {
		fmt.Printf("breaking_change endpoint=%s type=%s detail=%s status=%s field=%s param=%s prev=%s curr=%s\n",
			issue.EndpointID,
			issue.ChangeType,
			issue.Detail,
			issue.StatusCode,
			issue.FieldPath,
			issue.ParameterName,
			issue.PreviousType,
			issue.CurrentType,
		)
	}
	if len(report.BreakingChanges) > 0 {
		fatalf("api contract compatibility failed: %d breaking change(s) detected", len(report.BreakingChanges))
	}
	fmt.Println("api contract compatibility check passed")
}

func loadBaselineCatalog(baseRef string) (apicontractcompat.Catalog, string, error) {
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
		var catalog apicontractcompat.Catalog
		if err := json.Unmarshal(payload, &catalog); err != nil {
			continue
		}
		return catalog, candidate, nil
	}
	if _, err := os.Stat(contractsPath); err == nil {
		return apicontractcompat.Catalog{}, "bootstrap:none", nil
	}
	return apicontractcompat.Catalog{}, "", fmt.Errorf("no readable baseline api contract catalog found for refs %v", candidates)
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
