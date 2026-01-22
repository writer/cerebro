package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

var snowflakeDSNCmd = &cobra.Command{
	Use:    "snowflake-dsn",
	Short:  "Generate Snowflake DSN from key-pair env vars",
	Hidden: true, // Internal use only
	Long: `Generate a Snowflake DSN string from key-pair authentication environment variables.

This command is used internally by wrapper scripts to generate the DSN for CloudQuery.
It reads SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_PRIVATE_KEY and outputs a DSN.

The DSN is printed to stdout with no trailing newline for easy capture.`,
	RunE: runSnowflakeDSN,
}

func init() {
	rootCmd.AddCommand(snowflakeDSNCmd)
}

func runSnowflakeDSN(cmd *cobra.Command, args []string) error {
	cfg := snowflake.DSNConfigFromEnv()
	if missing := cfg.MissingFields(); len(missing) > 0 {
		return fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	dsn, ok, err := snowflake.BuildDSN(cfg)
	if err != nil {
		return fmt.Errorf("failed to build DSN: %w", err)
	}
	if !ok {
		return fmt.Errorf("incomplete configuration")
	}

	// Print DSN to stdout (no newline for easier capture)
	_, err = fmt.Fprint(os.Stdout, dsn)
	return err
}
