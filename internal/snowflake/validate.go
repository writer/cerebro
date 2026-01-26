package snowflake

import (
	"fmt"
	"regexp"
	"strings"
)

// validTableNameRegex matches valid Snowflake identifiers
var validTableNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// knownTablePrefixes are CloudQuery and Cerebro table prefixes
var knownTablePrefixes = []string{
	"aws_", "gcp_", "azure_", "k8s_", "okta_", "github_",
	"snyk_", "crowdstrike_", "sentinelone_", "tenable_",
	"datadog_", "qualys_", "semgrep_", "gitlab_", "cloudflare_",
	"auth0_", "slack_", "splunk_", "terraform_",
	"cerebro_",
}

// ValidateTableName ensures a table name is safe for SQL queries.
// Returns an error if the table name contains invalid characters or patterns.
func ValidateTableName(table string) error {
	if table == "" {
		return fmt.Errorf("table name cannot be empty")
	}

	// Check for SQL injection patterns
	lower := strings.ToLower(table)
	dangerous := []string{
		";", "--", "/*", "*/", "'", "\"", "\\",
		" or ", " and ", " union ", " select ", " drop ", " delete ",
		" insert ", " update ", " exec ", " execute ",
	}
	for _, pattern := range dangerous {
		if strings.Contains(lower, pattern) {
			return fmt.Errorf("table name contains dangerous pattern: %s", pattern)
		}
	}

	// Must match valid identifier pattern
	if !validTableNameRegex.MatchString(table) {
		return fmt.Errorf("table name contains invalid characters: %s", table)
	}

	// Check length (Snowflake limit is 255)
	if len(table) > 255 {
		return fmt.Errorf("table name too long: %d chars (max 255)", len(table))
	}

	return nil
}

// ValidateColumnName ensures a column name is safe for SQL queries.
// Returns an error if the column name contains invalid characters or patterns.
func ValidateColumnName(column string) error {
	if err := ValidateTableName(column); err != nil {
		return fmt.Errorf("column name invalid: %w", err)
	}

	return nil
}

// ValidateTableNameStrict validates and also checks against known prefixes.
// Use this when the table should be a known CloudQuery or Cerebro table.
func ValidateTableNameStrict(table string) error {
	if err := ValidateTableName(table); err != nil {
		return err
	}

	// Check if it matches a known prefix
	lower := strings.ToLower(table)
	for _, prefix := range knownTablePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return nil
		}
	}

	return fmt.Errorf("unknown table prefix: %s (not a known CloudQuery/Cerebro table)", table)
}

// QuoteIdentifier safely quotes a Snowflake identifier
func QuoteIdentifier(name string) string {
	// Escape any double quotes in the name
	escaped := strings.ReplaceAll(name, "\"", "\"\"")
	return "\"" + escaped + "\""
}

// SafeTableRef returns a safe table reference for SQL queries.
// It validates and normalizes identifiers to uppercase (Snowflake convention).
func SafeTableRef(database, schema, table string) (string, error) {
	if err := ValidateTableName(database); err != nil {
		return "", fmt.Errorf("invalid database name: %w", err)
	}
	if err := ValidateTableName(schema); err != nil {
		return "", fmt.Errorf("invalid schema name: %w", err)
	}
	if err := ValidateTableName(table); err != nil {
		return "", fmt.Errorf("invalid table name: %w", err)
	}

	// Normalize to uppercase for Snowflake (tables are stored as uppercase)
	return fmt.Sprintf("%s.%s.%s",
		strings.ToUpper(database),
		strings.ToUpper(schema),
		strings.ToUpper(table)), nil
}
