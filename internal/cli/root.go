package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "cerebro",
	Short: "Security data platform",
	Long: `Cerebro - Security posture management powered by Snowflake + CEL-backed policy evaluation

Cerebro scans cloud assets with native collectors and evaluates them against security policies.
It integrates with Snowflake for data storage and CEL-backed policy-as-code.

Get started:
  cerebro status              Check system health
  cerebro scan                Scan assets against policies
  cerebro findings list       View security findings
  cerebro policy list         List loaded policies

Documentation: https://github.com/writer/cerebro`,
	SilenceUsage: true,
}

var versionOutput string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		if versionOutput == FormatJSON {
			return JSONOutput(map[string]string{
				"version": Version,
				"commit":  Commit,
				"built":   BuildDate,
			})
		}
		fmt.Printf("cerebro %s\n", Version)
		fmt.Printf("  commit:  %s\n", Commit)
		fmt.Printf("  built:   %s\n", BuildDate)
		return nil
	},
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for cerebro.

To load completions:

Bash:
  $ source <(cerebro completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ cerebro completion bash > /etc/bash_completion.d/cerebro
  # macOS:
  $ cerebro completion bash > $(brew --prefix)/etc/bash_completion.d/cerebro

Zsh:
  $ source <(cerebro completion zsh)
  # To load completions for each session, execute once:
  $ cerebro completion zsh > "${fpath[1]}/_cerebro"

Fish:
  $ cerebro completion fish | source
  # To load completions for each session, execute once:
  $ cerebro completion fish > ~/.config/fish/completions/cerebro.fish

PowerShell:
  PS> cerebro completion powershell | Out-String | Invoke-Expression
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	versionCmd.Flags().StringVarP(&versionOutput, "output", "o", "text", "Output format (text,json)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(completionCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(bootstrapCmd)
	rootCmd.AddCommand(findingsCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(notificationsCmd)
	rootCmd.AddCommand(ingestCmd)
	rootCmd.AddCommand(workloadScanCmd)
	rootCmd.AddCommand(imageScanCmd)
	rootCmd.AddCommand(functionScanCmd)
	rootCmd.AddCommand(vulndbCmd)
}
