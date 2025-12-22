"""
Common parameter descriptions used across compliance operations.

Provides centralized, consistent descriptions for commonly used parameters
across all compliance operations, ensuring uniformity and maintainability.

Based on Vanta MCP server patterns.
"""

# Compliance Framework Descriptions
FRAMEWORK_ID_DESCRIPTION = (
    "Framework identifier to operate on, e.g. 'soc2', 'iso27001', or 'pci_dss'"
)

FRAMEWORK_NAME_DESCRIPTION = "Framework name for compliance operations, e.g. 'SOC 2 Type II', 'ISO 27001', or 'PCI DSS'"

# Control Descriptions
CONTROL_ID_DESCRIPTION = (
    "Control identifier to operate on, e.g. 'CC6.1', 'A.9.1.1', or '7.1.1'"
)

CONTROL_CATEGORY_DESCRIPTION = "Control category filter, e.g. 'Access Controls', 'System Monitoring', or 'Configuration Management'"

# Organization and Tenant Descriptions
ORGANIZATION_ID_DESCRIPTION = (
    "Organization ID to operate on, e.g. 'org-123' or specific organization identifier"
)

TENANT_ID_DESCRIPTION = "Tenant ID to operate on for multi-tenant operations"

# Evidence and Assessment Descriptions
EVIDENCE_TYPE_DESCRIPTION = "Evidence type filter, e.g. 'configuration', 'access_log', 'audit_log', or 'system_report'"

ASSESSMENT_PERIOD_DESCRIPTION = "Assessment period for evidence collection in ISO format, e.g. '2024-01-01' to '2024-12-31'"

PERIOD_START_DESCRIPTION = "Start date for evidence collection period in ISO format, e.g. '2024-01-01T00:00:00Z'"

PERIOD_END_DESCRIPTION = (
    "End date for evidence collection period in ISO format, e.g. '2024-12-31T23:59:59Z'"
)

# Pagination Descriptions
PAGE_SIZE_DESCRIPTION = (
    "Controls the maximum number of items returned in a single response. "
    "Allowed values: 1-100. Default is 10."
)

PAGE_CURSOR_DESCRIPTION = (
    "A marker or pointer telling the API where to start fetching items for the "
    "subsequent page in a paginated response. Leave blank to start from the first page."
)

OFFSET_DESCRIPTION = (
    "Number of items to skip before starting to return results. Default is 0."
)

LIMIT_DESCRIPTION = "Maximum number of items to return. Default is 25, maximum is 100."

# Status and Filter Descriptions
COMPLIANCE_STATUS_DESCRIPTION = "Filter by compliance status, e.g. 'compliant', 'non-compliant', 'partial', or 'unknown'"

AUTOMATION_LEVEL_DESCRIPTION = (
    "Filter by automation level, e.g. 'automated', 'semi-automated', or 'manual'"
)

RISK_LEVEL_DESCRIPTION = (
    "Filter by risk level, e.g. 'low', 'medium', 'high', or 'critical'"
)

# Query and Analysis Descriptions
SQL_QUERY_DESCRIPTION = (
    "SQL query to execute for evidence collection against security tables"
)

ANALYSIS_TYPE_DESCRIPTION = "Type of analysis to perform, e.g. 'gap_analysis', 'trend_analysis', or 'risk_assessment'"

# Report Generation Descriptions
REPORT_FORMAT_DESCRIPTION = (
    "Output format for compliance reports, e.g. 'json', 'pdf', 'csv', or 'xlsx'"
)

INCLUDE_EVIDENCE_DESCRIPTION = "Whether to include detailed evidence in the report response. Default is false for performance."

INCLUDE_REMEDIATION_DESCRIPTION = (
    "Whether to include remediation guidance in control results. Default is true."
)
