package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphingest"
)

const mappingsPath = "internal/graphingest/mappings.yaml"

var gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/\-^~]+$`)

func main() {
	baseRefFlag := flag.String("base-ref", strings.TrimSpace(os.Getenv("MAPPER_CONTRACT_BASE_REF")), "git ref used as compatibility baseline (for example origin/main)")
	requireBaseline := flag.Bool("require-baseline", false, "fail when no baseline mapping config can be loaded")
	flag.Parse()

	currentConfig, err := graphingest.LoadDefaultConfig()
	if err != nil {
		fatalf("load current mappings failed: %v", err)
	}

	baselineConfig, baselineRef, err := loadBaselineConfig(strings.TrimSpace(*baseRefFlag))
	if err != nil {
		if *requireBaseline {
			fatalf("load baseline mappings failed: %v", err)
		}
		fmt.Printf("contract compatibility check skipped: %v\n", err)
		return
	}

	baselineCatalog := graphingest.BuildContractCatalog(baselineConfig, time.Time{})
	currentCatalog := graphingest.BuildContractCatalog(currentConfig, time.Time{})
	report := graphingest.CompareContractCatalogs(baselineCatalog, currentCatalog, time.Now().UTC())

	fmt.Printf("baseline_ref=%s baseline_mappings=%d current_mappings=%d baseline_lifecycle_events=%d current_lifecycle_events=%d added=%d removed=%d added_lifecycle=%d removed_lifecycle=%d breaking=%d violations=%d\n",
		baselineRef,
		report.BaselineMappings,
		report.CurrentMappings,
		report.BaselineLifecycleEvents,
		report.CurrentLifecycleEvents,
		len(report.AddedMappings),
		len(report.RemovedMappings),
		len(report.AddedLifecycleEvents),
		len(report.RemovedLifecycleEvents),
		len(report.BreakingChanges),
		len(report.VersioningViolations),
	)
	for _, issue := range report.BreakingChanges {
		fmt.Printf("breaking_change contract_type=%s contract=%s type=%s detail=%s prev=%s curr=%s\n",
			issue.ContractType,
			firstNonEmpty(issue.ContractName, issue.MappingName),
			issue.ChangeType,
			issue.Detail,
			issue.PreviousContractVersion,
			issue.CurrentContractVersion,
		)
	}
	if len(report.VersioningViolations) > 0 {
		fatalf("contract compatibility failed: %d versioning violation(s) detected", len(report.VersioningViolations))
	}
	fmt.Println("contract compatibility check passed")
}

func loadBaselineConfig(baseRef string) (graphingest.MappingConfig, string, error) {
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

		payload, err := gitShowFile(candidate, mappingsPath)
		if err != nil {
			continue
		}
		config, err := graphingest.ParseConfig(payload)
		if err != nil {
			continue
		}
		return config, candidate, nil
	}
	return graphingest.MappingConfig{}, "", fmt.Errorf("no readable baseline mappings found for refs %v", candidates)
}

func gitShowFile(ref, filePath string) ([]byte, error) {
	if !isSafeGitRef(ref) {
		return nil, fmt.Errorf("unsafe git ref %q", ref)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "show", fmt.Sprintf("%s:%s", ref, filePath)) // #nosec G204,G702 -- ref is strictly validated by isSafeGitRef and filePath is a repository constant.
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
