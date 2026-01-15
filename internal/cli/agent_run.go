package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/agents"
	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/scm"
)

var agentRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Deep Research Agent end-to-end",
	Long: `Run a deterministic code-to-cloud investigation using repository analysis
and live cloud inspections.

Examples:
  cerebro agent run --repo-url https://github.com/org/repo
  cerebro agent run --repo-url https://github.com/org/repo --gcp-project my-project
  cerebro agent run --resource arn:aws:s3:::my-bucket --aws-region us-east-1`,
	RunE: runAgentFlow,
}

var (
	agentRunRepoURL      string
	agentRunResource     string
	agentRunMaxResources int
	agentRunAWSRegion    string
	agentRunGCPProject   string
	agentRunGCPZone      string
	agentRunOutput       string
)

func init() {
	agentCmd.AddCommand(agentRunCmd)

	agentRunCmd.Flags().StringVar(&agentRunRepoURL, "repo-url", "", "Repository URL to analyze")
	agentRunCmd.Flags().StringVar(&agentRunResource, "resource", "", "Single resource identifier to inspect (optional)")
	agentRunCmd.Flags().IntVar(&agentRunMaxResources, "max-resources", 25, "Maximum resources to inspect from repo scan (0 for all)")
	agentRunCmd.Flags().StringVar(&agentRunAWSRegion, "aws-region", "", "AWS region override")
	agentRunCmd.Flags().StringVar(&agentRunGCPProject, "gcp-project", "", "GCP project ID for inspections")
	agentRunCmd.Flags().StringVar(&agentRunGCPZone, "gcp-zone", "", "GCP zone for compute instance inspections")
	agentRunCmd.Flags().StringVarP(&agentRunOutput, "output", "o", "table", "Output format (table,json)")
}

func runAgentFlow(cmd *cobra.Command, args []string) error {
	if agentRunRepoURL == "" && agentRunResource == "" {
		return fmt.Errorf("repo-url or resource is required")
	}

	ctx := context.Background()
	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer application.Close()

	scmClient := scm.NewGitHubClient(os.Getenv("GITHUB_TOKEN"))
	tools := agents.NewSecurityTools(application.Snowflake, application.Findings, application.Policy, scmClient)

	report, err := agents.RunCodeToCloudFlow(ctx, tools, agents.CodeToCloudOptions{
		RepoURL:      agentRunRepoURL,
		Resource:     agentRunResource,
		MaxResources: agentRunMaxResources,
		AWSRegion:    agentRunAWSRegion,
		GCPProject:   agentRunGCPProject,
		GCPZone:      agentRunGCPZone,
	})
	if err != nil {
		return err
	}

	if agentRunOutput == FormatJSON {
		return JSONOutput(report)
	}

	if report.Analysis != nil {
		Info("Repo: %s", report.RepoURL)
		Info("Files scanned: %d", report.Analysis.FilesScanned)
		Info("Resources found: %d", report.Analysis.TotalResources)
	}
	if report.Truncated {
		Warning("Results truncated; adjust --max-resources or use --output json for full details")
	}
	if len(report.Inspections) == 0 {
		Warning("No resources inspected")
		return nil
	}

	fmt.Println()
	tw := NewTableWriter(os.Stdout, "Resource", "Provider", "Service", "Status")
	for _, inspection := range report.Inspections {
		status := statusColor("ok")
		if inspection.Error != "" {
			status = statusColor("failed")
		}
		resource := inspection.Resource.Resource
		if resource == "" {
			resource = inspection.Resource.Identifier
		}
		tw.AddRow(resource, inspection.Provider, inspection.Service, status)
	}
	tw.Render()

	if report.Failed > 0 {
		fmt.Println()
		Warning("%d resources failed inspection; use --output json for details", report.Failed)
	}

	return nil
}
