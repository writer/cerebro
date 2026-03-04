package snowflake

import (
	"fmt"
	"regexp"
	"strings"
)

// validTableNameRegex matches valid Snowflake identifiers
var validTableNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// knownTablePrefixes are supported asset table prefixes
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
// Use this when the table should be a known asset table.
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
	for _, name := range knownTableNames {
		if lower == name {
			return nil
		}
	}

	return fmt.Errorf("unknown table prefix: %s (not a known asset table)", table)
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

// ValidateQualifiedSchemaRef validates a DATABASE.SCHEMA reference and returns
// a normalized uppercase value for SQL identifier usage.
func ValidateQualifiedSchemaRef(schemaRef string) (string, error) {
	parts := strings.Split(strings.TrimSpace(schemaRef), ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid schema reference %q: expected DATABASE.SCHEMA", schemaRef)
	}

	database := strings.TrimSpace(parts[0])
	schema := strings.TrimSpace(parts[1])
	if err := ValidateTableName(database); err != nil {
		return "", fmt.Errorf("invalid database name: %w", err)
	}
	if err := ValidateTableName(schema); err != nil {
		return "", fmt.Errorf("invalid schema name: %w", err)
	}

	return strings.ToUpper(database) + "." + strings.ToUpper(schema), nil
}

// SafeQualifiedTableRef validates a DATABASE.SCHEMA reference plus table name
// and returns a normalized uppercase fully-qualified table reference.
func SafeQualifiedTableRef(schemaRef, table string) (string, error) {
	normalizedSchema, err := ValidateQualifiedSchemaRef(schemaRef)
	if err != nil {
		return "", err
	}
	if err := ValidateTableName(table); err != nil {
		return "", fmt.Errorf("invalid table name: %w", err)
	}

	return normalizedSchema + "." + strings.ToUpper(table), nil
}
