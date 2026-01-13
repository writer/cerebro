package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync cloud assets to Snowflake via CloudQuery",
	RunE:  runSync,
}

var (
	syncConfigPath string
	syncSource     string
)

func init() {
	syncCmd.Flags().StringVarP(&syncConfigPath, "config", "c", "config/cloudquery.yml", "CloudQuery config file")
	syncCmd.Flags().StringVarP(&syncSource, "source", "s", "", "Sync only specific source (aws, gcp, azure)")
}

func runSync(cmd *cobra.Command, args []string) error {
	if _, err := exec.LookPath("cloudquery"); err != nil {
		return fmt.Errorf("cloudquery CLI not found. Install: brew install cloudquery/tap/cloudquery")
	}

	cqArgs := []string{"sync", syncConfigPath}
	if syncSource != "" {
		cqArgs = append(cqArgs, "--source", syncSource)
	}

	fmt.Printf("Running: cloudquery %v\n", cqArgs)
	
	cqCmd := exec.Command("cloudquery", cqArgs...)
	cqCmd.Stdout = os.Stdout
	cqCmd.Stderr = os.Stderr
	cqCmd.Env = os.Environ()

	return cqCmd.Run()
}
