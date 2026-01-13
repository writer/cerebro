package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cerebro",
	Short: "Security data platform",
	Long:  `Cerebro - Security posture management powered by CloudQuery + Snowflake + Cedar`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(queryCmd)
}
