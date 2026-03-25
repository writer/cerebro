package warehouse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// QueryResult holds query results in a structured format.
// This type is backend-agnostic and can be produced by any warehouse implementation.
type QueryResult struct {
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
	Count   int                      `json:"count"`
}

// AssetFilter specifies filtering options for asset retrieval.
type AssetFilter struct {
	Provider       string
	Type           string
	Account        string
	Region         string
	Limit          int
	Offset         int // Deprecated: use cursor fields instead
	Since          time.Time
	SinceID        string
	Columns        []string  // If set, only SELECT these columns instead of *
	CursorSyncTime time.Time // Keyset cursor: sync time of last seen row
	CursorID       string    // Keyset cursor: _cq_id of last seen row
}

// CDCEvent represents a change data capture event for an asset table.
type CDCEvent struct {
	EventID     string
	TableName   string
	ResourceID  string
	ChangeType  string
	Provider    string
	Region      string
	AccountID   string
	Payload     interface{}
	PayloadHash string
	EventTime   time.Time
}

// BuildCDCEventID builds a deterministic CDC event identifier.
func BuildCDCEventID(table, resourceID, changeType, payloadHash string, eventTime time.Time) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%s", table, resourceID, changeType, payloadHash, eventTime.UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

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
	"backups", "certificates", "containers", "databases", "employees",
	"endpoints", "firewalls", "secrets", "servers", "systems",
	"vendors", "vulnerabilities",
}

// ValidateTableName ensures a table name is safe for SQL queries.
func ValidateTableName(table string) error {
	if table == "" {
		return fmt.Errorf("table name cannot be empty")
	}
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
	if !validTableNameRegex.MatchString(table) {
		return fmt.Errorf("table name contains invalid characters: %s", table)
	}
	if len(table) > 255 {
		return fmt.Errorf("table name too long: %d chars (max 255)", len(table))
	}
	return nil
}

// ValidateTableNameStrict validates and also checks against known prefixes.
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
