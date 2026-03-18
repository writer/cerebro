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

	reports "github.com/writer/cerebro/internal/graph/reports"
)

const contractsPath = "docs/GRAPH_REPORT_CONTRACTS.json"

var gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/\-^~]+$`)

func main() {
	baseRefFlag := flag.String("base-ref", strings.TrimSpace(os.Getenv("REPORT_CONTRACT_BASE_REF")), "git ref used as compatibility baseline (for example origin/main)")
	requireBaseline := flag.Bool("require-baseline", false, "fail when no baseline report contract catalog can be loaded")
	flag.Parse()

	currentCatalog := reports.BuildReportContractCatalog(time.Time{})
	baselineCatalog, baselineRef, err := loadBaselineCatalog(strings.TrimSpace(*baseRefFlag))
	if err != nil {
		if *requireBaseline {
			fatalf("load baseline report contracts failed: %v", err)
		}
		fmt.Printf("report contract compatibility check skipped: %v\n", err)
		return
	}

	report := reports.CompareReportContractCatalogs(baselineCatalog, currentCatalog, time.Now().UTC())
	fmt.Printf("baseline_ref=%s baseline_section_envelopes=%d current_section_envelopes=%d baseline_section_fragments=%d current_section_fragments=%d baseline_benchmark_packs=%d current_benchmark_packs=%d added_envelopes=%d removed_envelopes=%d added_fragments=%d removed_fragments=%d added_packs=%d removed_packs=%d breaking=%d violations=%d diffs=%d\n",
		baselineRef,
		report.BaselineSectionEnvelopes,
		report.CurrentSectionEnvelopes,
		report.BaselineSectionFragments,
		report.CurrentSectionFragments,
		report.BaselineBenchmarkPacks,
		report.CurrentBenchmarkPacks,
		len(report.AddedSectionEnvelopes),
		len(report.RemovedSectionEnvelopes),
		len(report.AddedSectionFragments),
		len(report.RemovedSectionFragments),
		len(report.AddedBenchmarkPacks),
		len(report.RemovedBenchmarkPacks),
		len(report.BreakingChanges),
		len(report.VersioningViolations),
		len(report.DiffSummaries),
	)
	for _, issue := range report.BreakingChanges {
		fmt.Printf("breaking_change contract_type=%s contract_id=%s type=%s detail=%s prev=%s curr=%s\n",
			issue.ContractType,
			issue.ContractID,
			issue.ChangeType,
			issue.Detail,
			issue.PreviousVersion,
			issue.CurrentVersion,
		)
	}
	for _, diff := range report.DiffSummaries {
		fmt.Printf("diff_summary contract_type=%s contract_id=%s prev=%s curr=%s added=%s removed=%s changed=%s\n",
			diff.ContractType,
			diff.ContractID,
			diff.PreviousVersion,
			diff.CurrentVersion,
			strings.Join(diff.AddedPaths, ","),
			strings.Join(diff.RemovedPaths, ","),
			strings.Join(diff.ChangedPaths, ","),
		)
	}
	if len(report.VersioningViolations) > 0 {
		fatalf("report contract compatibility failed: %d versioning violation(s) detected", len(report.VersioningViolations))
	}
	fmt.Println("report contract compatibility check passed")
}

func loadBaselineCatalog(baseRef string) (reports.ReportContractCatalog, string, error) {
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
		var catalog reports.ReportContractCatalog
		if err := json.Unmarshal(payload, &catalog); err != nil {
			continue
		}
		return catalog, candidate, nil
	}
	if _, err := os.Stat(contractsPath); err == nil {
		return reports.ReportContractCatalog{}, "bootstrap:none", nil
	}
	return reports.ReportContractCatalog{}, "", fmt.Errorf("no readable baseline report contract catalog found for refs %v", candidates)
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
