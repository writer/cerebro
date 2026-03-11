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

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/agentsdk"
	"github.com/writer/cerebro/internal/app"
)

const contractsPath = "docs/AGENT_SDK_CONTRACTS.json"

var gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/\-^~]+$`)

func main() {
	baseRefFlag := flag.String("base-ref", strings.TrimSpace(os.Getenv("AGENT_SDK_CONTRACT_BASE_REF")), "git ref used as compatibility baseline (for example origin/main)")
	requireBaseline := flag.Bool("require-baseline", false, "fail when no baseline Agent SDK contract catalog can be loaded")
	flag.Parse()

	currentCatalog := agentsdk.BuildCatalog(agentSDKTools(), time.Time{})
	baselineCatalog, baselineRef, err := loadBaselineCatalog(strings.TrimSpace(*baseRefFlag))
	if err != nil {
		if *requireBaseline {
			fatalf("load baseline agent sdk contracts failed: %v", err)
		}
		fmt.Printf("agent sdk contract compatibility check skipped: %v\n", err)
		return
	}

	report := agentsdk.CompareCatalogs(baselineCatalog, currentCatalog, time.Now().UTC())
	fmt.Printf("baseline_ref=%s baseline_tools=%d current_tools=%d baseline_resources=%d current_resources=%d added_tools=%d removed_tools=%d added_resources=%d removed_resources=%d breaking=%d violations=%d\n",
		baselineRef,
		report.BaselineTools,
		report.CurrentTools,
		report.BaselineResources,
		report.CurrentResources,
		len(report.AddedTools),
		len(report.RemovedTools),
		len(report.AddedResources),
		len(report.RemovedResources),
		len(report.BreakingChanges),
		len(report.VersioningViolations),
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
	if len(report.VersioningViolations) > 0 {
		fatalf("agent sdk contract compatibility failed: %d versioning violation(s) detected", len(report.VersioningViolations))
	}
	fmt.Println("agent sdk contract compatibility check passed")
}

func agentSDKTools() []agents.Tool {
	application := &app.App{Config: &app.Config{}}
	return application.AgentSDKTools()
}

func loadBaselineCatalog(baseRef string) (agentsdk.Catalog, string, error) {
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
		var catalog agentsdk.Catalog
		if err := json.Unmarshal(payload, &catalog); err != nil {
			continue
		}
		return catalog, candidate, nil
	}
	if _, err := os.Stat(contractsPath); err == nil {
		return agentsdk.Catalog{}, "bootstrap:none", nil
	}
	return agentsdk.Catalog{}, "", fmt.Errorf("no readable baseline agent sdk contract catalog found for refs %v", candidates)
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
