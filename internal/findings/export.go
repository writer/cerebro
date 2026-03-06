package findings

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/policy"
)

// CSVExporter exports findings in CSV format
type CSVExporter struct{}

// NewCSVExporter creates a new CSV exporter
func NewCSVExporter() *CSVExporter {
	return &CSVExporter{}
}

// Export exports findings to CSV format
func (e *CSVExporter) Export(findings []*Finding) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header row
	headers := []string{
		"Created At",
		"Title",
		"Severity",
		"Status",
		"Description",
		"Resource Type",
		"Resource ID",
		"Resource external ID",
		"Subscription ID",
		"Project IDs",
		"Project Names",
		"Resolved Time",
		"Resolution",
		"Control ID",
		"Resource Name",
		"Resource Region",
		"Resource Status",
		"Resource Platform",
		"Resource original JSON",
		"Issue ID",
		"Ticket URLs",
		"Note",
		"Due At",
		"Remediation Recommendation",
		"Subscription Name",
		"Cloud Provider URL",
		"Resource Tags",
		"Kubernetes Cluster",
		"Kubernetes Namespace",
		"Container Service",
		"Risks",
		"Threats",
		"MITRE ATT&CK",
		"Status Changed At",
		"Updated At",
		"Assignee Name",
		"Ticket Names",
		"Ticket External IDs",
		"Security Frameworks",
		"Security Categories",
		"Compliance Mappings",
		"Evidence",
	}

	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("write headers: %w", err)
	}

	// Write each finding
	for _, f := range findings {
		row := []string{
			formatTime(f.CreatedAt),
			f.Title,
			f.Severity,
			f.Status,
			f.Description,
			f.ResourceType,
			f.ResourceID,
			f.ResourceExternalID,
			f.SubscriptionID,
			strings.Join(f.ProjectIDs, "|"),
			strings.Join(f.ProjectNames, "|"),
			formatTimePtr(f.ResolvedAt),
			f.Resolution,
			f.ControlID,
			f.ResourceName,
			f.ResourceRegion,
			f.ResourceStatus,
			f.ResourcePlatform,
			formatJSON(f.ResourceJSON),
			f.IssueID,
			strings.Join(f.TicketURLs, "|"),
			f.Notes,
			formatTimePtr(f.DueAt),
			f.Remediation,
			f.SubscriptionName,
			f.CloudProviderURL,
			formatTags(f.ResourceTags),
			f.KubernetesCluster,
			f.KubernetesNamespace,
			f.ContainerService,
			strings.Join(f.RiskCategories, "|"),
			strings.Join(f.Threats, "|"),
			formatMitreAttack(f.MitreAttack),
			formatTimePtr(f.StatusChangedAt),
			formatTime(f.UpdatedAt),
			f.AssigneeName,
			strings.Join(f.TicketNames, "|"),
			strings.Join(f.TicketExternalIDs, "|"),
			strings.Join(f.SecurityFrameworks, "|"),
			strings.Join(f.SecurityCategories, "|"),
			formatComplianceMappings(f.ComplianceMappings),
			formatEvidence(f.Evidence),
		}
		for i := range row {
			row[i] = sanitizeCSVCell(row[i])
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("write row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}

	return buf.Bytes(), nil
}

// JSONExporter exports findings in JSON format
type JSONExporter struct {
	Pretty bool
}

// NewJSONExporter creates a new JSON exporter
func NewJSONExporter(pretty bool) *JSONExporter {
	return &JSONExporter{Pretty: pretty}
}

// Export exports findings to JSON format
func (e *JSONExporter) Export(findings []*Finding) ([]byte, error) {
	if e.Pretty {
		return json.MarshalIndent(findings, "", "  ")
	}
	return json.Marshal(findings)
}

// Helper functions

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func formatJSON(data map[string]interface{}) string {
	if data == nil {
		return ""
	}
	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func formatTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(tags))
	for k, v := range tags {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(pairs, "|")
}

func formatEvidence(evidence []Evidence) string {
	if len(evidence) == 0 {
		return ""
	}
	b, err := json.Marshal(evidence)
	if err != nil {
		return ""
	}
	return string(b)
}

func formatComplianceMappings(mappings []policy.FrameworkMapping) string {
	if len(mappings) == 0 {
		return ""
	}

	parts := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		if len(mapping.Controls) == 0 {
			continue
		}
		controls := append([]string{}, mapping.Controls...)
		sort.Strings(controls)
		parts = append(parts, fmt.Sprintf("%s:%s", mapping.Name, strings.Join(controls, ",")))
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func formatMitreAttack(mappings []policy.MitreMapping) string {
	if len(mappings) == 0 {
		return ""
	}
	parts := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		if mapping.Tactic == "" && mapping.Technique == "" {
			continue
		}
		if mapping.Tactic != "" && mapping.Technique != "" {
			parts = append(parts, fmt.Sprintf("%s:%s", mapping.Tactic, mapping.Technique))
			continue
		}
		if mapping.Tactic != "" {
			parts = append(parts, mapping.Tactic)
			continue
		}
		parts = append(parts, mapping.Technique)
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func sanitizeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}
