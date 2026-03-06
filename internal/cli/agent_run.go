package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/jobs"
	"github.com/evalops/cerebro/internal/scm"
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
	agentRunDistributed  bool
	agentRunWait         bool
	agentRunPollInterval time.Duration
	agentRunTimeout      time.Duration
	agentRunMaxAttempts  int
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
	agentRunCmd.Flags().BoolVar(&agentRunDistributed, "distributed", false, "Use distributed job execution when configured")
	agentRunCmd.Flags().BoolVar(&agentRunWait, "wait", false, "Wait for distributed jobs to complete")
	agentRunCmd.Flags().DurationVar(&agentRunPollInterval, "poll-interval", 5*time.Second, "Polling interval for distributed jobs")
	agentRunCmd.Flags().DurationVar(&agentRunTimeout, "timeout", 0, "Maximum time to wait for jobs (0 for no limit)")
	agentRunCmd.Flags().IntVar(&agentRunMaxAttempts, "max-attempts", 0, "Maximum attempts per distributed job")
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
	defer func() { _ = application.Close() }()

	scmClient := scm.NewConfiguredClient(
		application.Config.GitHubToken,
		application.Config.GitLabToken,
		application.Config.GitLabBaseURL,
	)
	tools := agents.NewSecurityTools(application.Snowflake, application.Findings, application.Policy, scmClient)
	useDistributed := agentRunDistributed || (application.Config.JobQueueURL != "" && application.Config.JobTableName != "")
	if useDistributed {
		return runDistributedAgentFlow(ctx, application, tools)
	}

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

func runDistributedAgentFlow(ctx context.Context, application *app.App, tools *agents.SecurityTools) error {
	if application.Config.JobQueueURL == "" || application.Config.JobTableName == "" {
		return fmt.Errorf("JOB_QUEUE_URL and JOB_TABLE_NAME are required for distributed execution")
	}

	resources, analysis, err := buildDistributedResources(ctx, tools)
	if err != nil {
		return err
	}
	if len(resources) == 0 {
		return fmt.Errorf("no resources to enqueue")
	}

	awsCfg, err := jobs.LoadAWSConfig(ctx, application.Config.JobRegion)
	if err != nil {
		return err
	}

	queue := jobs.NewSQSQueue(awsCfg, application.Config.JobQueueURL)
	store := jobs.NewDynamoStore(awsCfg, application.Config.JobTableName)
	manager := jobs.NewManager(queue, store, application.Logger)

	maxAttempts := agentRunMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = application.Config.JobMaxAttempts
	}

	filesScanned := 0
	truncated := false
	if analysis != nil {
		filesScanned = analysis.FilesScanned
		truncated = analysis.Truncated
	}

	batch, err := manager.EnqueueInspectResources(ctx, resources, jobs.EnqueueOptions{
		MaxAttempts:  maxAttempts,
		Overrides:    jobs.InspectOverrides{AWSRegion: agentRunAWSRegion, GCPProject: agentRunGCPProject, GCPZone: agentRunGCPZone},
		RepoURL:      agentRunRepoURL,
		FilesScanned: filesScanned,
		Truncated:    truncated,
	})
	if err != nil {
		return err
	}

	if agentRunOutput == FormatJSON {
		if agentRunWait {
			jobsResult, waitErr := waitForJobs(ctx, manager, batch.JobIDs)
			if waitErr != nil {
				return waitErr
			}
			return JSONOutput(map[string]interface{}{"batch": batch, "analysis": analysis, "jobs": jobsResult})
		}
		return JSONOutput(map[string]interface{}{"batch": batch, "analysis": analysis})
	}

	Info("Enqueued %d jobs", len(batch.JobIDs))
	Info("Job group: %s", batch.GroupID)
	if analysis != nil {
		Info("Files scanned: %d", analysis.FilesScanned)
		Info("Resources found: %d", analysis.TotalResources)
	}
	if batch.Truncated {
		Warning("Results truncated; adjust --max-resources or use --output json for full details")
	}
	if !agentRunWait {
		return nil
	}

	jobsResult, err := waitForJobs(ctx, manager, batch.JobIDs)
	if err != nil {
		return err
	}

	printJobResults(jobsResult)
	return nil
}

func buildDistributedResources(ctx context.Context, tools *agents.SecurityTools) ([]jobs.ResourceRef, *agents.RepoAnalysis, error) {
	if agentRunRepoURL == "" && agentRunResource == "" {
		return nil, nil, fmt.Errorf("repo-url or resource is required")
	}

	var analysis *agents.RepoAnalysis
	resources := make([]jobs.ResourceRef, 0)

	if agentRunRepoURL != "" {
		repoAnalysis, err := tools.AnalyzeRepository(ctx, agentRunRepoURL)
		if err != nil {
			return nil, nil, err
		}
		analysis = repoAnalysis
		for _, res := range repoAnalysis.Resources {
			resources = append(resources, jobs.ResourceRef{
				Provider:     res.Provider,
				Service:      res.Service,
				ResourceType: res.ResourceType,
				Identifier:   res.Identifier,
				Resource:     res.Resource,
				File:         res.File,
				Line:         res.Line,
				Snippet:      res.Snippet,
				Confidence:   res.Confidence,
			})
		}
	}

	if agentRunResource != "" {
		resources = []jobs.ResourceRef{{Resource: agentRunResource, Identifier: agentRunResource}}
	}

	if agentRunMaxResources > 0 && len(resources) > agentRunMaxResources {
		resources = resources[:agentRunMaxResources]
		if analysis != nil {
			analysis.Truncated = true
		}
	}

	return resources, analysis, nil
}

func waitForJobs(ctx context.Context, manager *jobs.Manager, jobIDs []string) ([]*jobs.Job, error) {
	waitCtx := ctx
	if agentRunTimeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, agentRunTimeout)
		defer cancel()
	}
	return manager.WaitForJobs(waitCtx, jobIDs, agentRunPollInterval)
}

func printJobResults(results []*jobs.Job) {
	if len(results) == 0 {
		Warning("No jobs completed")
		return
	}

	fmt.Println()
	tw := NewTableWriter(os.Stdout, "Resource", "Status", "Error")
	failed := 0
	for _, job := range results {
		resource := job.ID
		var payload jobs.InspectResourcePayload
		if err := json.Unmarshal([]byte(job.Payload), &payload); err == nil {
			resource = payload.Resource.Resource
			if resource == "" {
				resource = payload.Resource.Identifier
			}
		}
		var statusLabel string
		switch job.Status {
		case jobs.StatusSucceeded:
			statusLabel = statusColor("passed")
		case jobs.StatusFailed:
			statusLabel = statusColor("failed")
			failed++
		default:
			statusLabel = string(job.Status)
		}
		tw.AddRow(resource, statusLabel, job.Error)
	}
	tw.Render()
	if failed > 0 {
		fmt.Println()
		Warning("%d jobs failed; use --output json for details", failed)
	}
}
