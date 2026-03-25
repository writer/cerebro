package postgres

import (
	"fmt"
	"regexp"
	"strings"
)

// validTableNameRegex matches valid SQL identifiers.
var validTableNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// knownTablePrefixes are supported asset table prefixes.
var knownTablePrefixes = []string{
	"aws_", "gcp_", "azure_", "k8s_", "okta_", "github_",
	"snyk_", "crowdstrike_", "sentinelone_", "tenable_",
	"datadog_", "qualys_", "semgrep_", "gitlab_", "cloudflare_",
	"auth0_", "slack_", "splunk_", "terraform_", "servicenow_", "workday_", "bamboohr_", "onelogin_", "jumpcloud_", "duo_", "pingidentity_", "cyberark_", "sailpoint_", "saviynt_", "forgerock_", "oracle_idcs_",
	"ai_", "ml_", "entra_", "m365_", "identity_", "hris_",
	"mdm_", "jamf_", "intune_", "kandji_", "edr_",
	"network_", "dns_", "firewall_", "container_", "vulnerability_",
	"compliance_", "infrastructure_", "log_", "password_", "penetration_", "policy_",
	"tls_", "user_", "cross_provider_", "telemetry_", "tailscale_",
	"google_", "security_",
	"cerebro_",
}

var knownTableNames = []string{
	"backups",
	"certificates",
	"containers",
	"databases",
	"employees",
	"endpoints",
	"firewalls",
	"secrets",
	"servers",
	"systems",
	"vendors",
	"vulnerabilities",
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

	// Postgres identifier limit is 63 bytes
	if len(table) > 63 {
		return fmt.Errorf("table name too long: %d chars (max 63)", len(table))
	}

	return nil
}

// ValidateColumnName ensures a column name is safe for SQL queries.
func ValidateColumnName(column string) error {
	if err := ValidateTableName(column); err != nil {
		return fmt.Errorf("column name invalid: %w", err)
	}
	return nil
}

// ValidateTableNameStrict validates and also checks against known prefixes.
// Use this when the table should be a known asset table.
func ValidateTableNameStrict(table string) error {
	if err := ValidateTableName(table); err != nil {
		return err
	}

	lower := strings.ToLower(table)
	for _, prefix := range knownTablePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return nil
		}
	}
	for _, name := range knownTableNames {
		if lower == name {
			return nil
		}
	}

	return fmt.Errorf("unknown table prefix: %s (not a known asset table)", table)
}

// QuoteIdentifier safely quotes a Postgres identifier.
func QuoteIdentifier(name string) string {
	escaped := strings.ReplaceAll(name, "\"", "\"\"")
	return "\"" + escaped + "\""
}

// SafeTableRef returns a safe two-part schema.table reference for SQL queries.
// Unlike Snowflake's three-part database.schema.table, Postgres uses schema.table.
func SafeTableRef(schema, table string) (string, error) {
	if err := ValidateTableName(schema); err != nil {
		return "", fmt.Errorf("invalid schema name: %w", err)
	}
	if err := ValidateTableName(table); err != nil {
		return "", fmt.Errorf("invalid table name: %w", err)
	}

	return fmt.Sprintf("%s.%s",
		strings.ToLower(schema),
		strings.ToLower(table)), nil
}

// SafeQualifiedTableRef validates a schema reference plus table name
// and returns a normalized lowercase fully-qualified table reference.
// In Postgres this is schema.table (two-part), unlike Snowflake's database.schema.table.
func SafeQualifiedTableRef(schema, table string) (string, error) {
	if err := ValidateTableName(schema); err != nil {
		return "", fmt.Errorf("invalid schema name: %w", err)
	}
	if err := ValidateTableName(table); err != nil {
		return "", fmt.Errorf("invalid table name: %w", err)
	}

	return strings.ToLower(schema) + "." + strings.ToLower(table), nil
}
