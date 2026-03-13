package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/graph"
)

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Inspect graph scale characteristics and planning guidance",
}

var graphProfileScaleCmd = &cobra.Command{
	Use:   "profile-scale",
	Short: "Benchmark synthetic graph tiers and recommend the next scale path",
	Long: `Benchmark synthetic graph tiers and summarize the persistence/multi-worker
recommendation for the current graph architecture.

This command uses a deterministic synthetic estate so runs are comparable across
branches and over time. It is intended to gate architectural changes such as
distributed graph persistence, tenant partitioning, and multi-worker graph
mutation.`,
	RunE: runGraphProfileScale,
}

var (
	graphProfileOutput          string
	graphProfileTiers           []int
	graphProfileQueryIterations int

	graphProfileSyntheticScaleFn = graph.ProfileSyntheticScale
)

func init() {
	graphProfileScaleCmd.Flags().StringVarP(&graphProfileOutput, "output", "o", FormatTable, "Output format (table,json)")
	graphProfileScaleCmd.Flags().IntSliceVar(&graphProfileTiers, "tiers", nil, "Synthetic resource tiers to benchmark (for example 1000,10000,50000,100000)")
	graphProfileScaleCmd.Flags().IntVar(&graphProfileQueryIterations, "query-iterations", 0, "Number of query iterations per tier (defaults to the graph profiler default)")

	graphCmd.AddCommand(graphProfileScaleCmd)
	rootCmd.AddCommand(graphCmd)
}

func runGraphProfileScale(cmd *cobra.Command, _ []string) error {
	if err := validateGraphProfileOutputFormat(); err != nil {
		return err
	}
	report, err := graphProfileSyntheticScaleFn(graph.ScaleProfileSpec{
		Tiers:           append([]int(nil), graphProfileTiers...),
		QueryIterations: graphProfileQueryIterations,
	})
	if err != nil {
		return err
	}
	if graphProfileOutput == FormatJSON {
		return JSONOutput(report)
	}
	return renderGraphScaleProfileReport(report)
}

func validateGraphProfileOutputFormat() error {
	if graphProfileOutput != FormatTable && graphProfileOutput != FormatJSON {
		return fmt.Errorf("--output must be one of: %s, %s", FormatTable, FormatJSON)
	}
	return nil
}

func renderGraphScaleProfileReport(report *graph.ScaleProfileReport) error {
	if report == nil {
		return fmt.Errorf("profile report is required")
	}
	fmt.Println("Graph Scale Profile")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05Z07:00"))
	fmt.Printf("Workload: %s\n", report.Workload)
	fmt.Printf("Query iterations: %d\n\n", report.QueryIterations)

	tw := NewTableWriter(os.Stdout, "Tier", "Accounts", "Nodes", "Edges", "Heap MB", "Index ms", "Search ms", "Blast Cold ms", "COW ms", "Snapshot MB")
	for _, measurement := range report.Measurements {
		tw.AddRow(
			fmt.Sprintf("%d", measurement.ResourceCount),
			fmt.Sprintf("%d", measurement.AccountCount),
			fmt.Sprintf("%d", measurement.NodeCount),
			fmt.Sprintf("%d", measurement.EdgeCount),
			fmt.Sprintf("%.1f", bytesToMiB(measurement.HeapAllocBytes)),
			fmt.Sprintf("%.1f", measurement.IndexDurationMS),
			fmt.Sprintf("%.1f", measurement.SearchDurationMS),
			fmt.Sprintf("%.1f", measurement.BlastRadiusColdDurationMS),
			fmt.Sprintf("%.1f", measurement.CopyOnWriteDurationMS),
			fmt.Sprintf("%.1f", int64BytesToMiB(measurement.SnapshotCompressedBytes)),
		)
	}
	tw.Render()
	if strings.TrimSpace(report.RecommendedPath) != "" {
		fmt.Printf("\nRecommended path: %s\n", report.RecommendedPath)
	}
	if strings.TrimSpace(report.Recommendation) != "" {
		fmt.Printf("Recommendation: %s\n", report.Recommendation)
	}
	return nil
}

func bytesToMiB(size uint64) float64 {
	return float64(size) / (1024.0 * 1024.0)
}

func int64BytesToMiB(size int64) float64 {
	if size <= 0 {
		return 0
	}
	return float64(size) / (1024.0 * 1024.0)
}
