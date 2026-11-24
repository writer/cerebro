package mcpoperations

// ScopeVulnerabilitiesIngest lets a principal deliver vulnerability payloads
// to an existing profile without being able to reconfigure profiles.
const ScopeVulnerabilitiesIngest = "cerebro.vulnerabilities.ingest"

// VulnerabilityToolDefinition describes one vulnerability pipeline MCP tool.
type VulnerabilityToolDefinition struct {
	Name         string
	Title        string
	Description  string
	InputSchema  InputSchema
	OutputSchema OutputSchema
	Idempotent   bool
}

// VulnerabilityToolDefinitions returns the vulnerability pipeline tools.
func VulnerabilityToolDefinitions() []VulnerabilityToolDefinition {
	tenant := map[string]any{"type": "string", "description": "Tenant scope. Omit only when the authenticated principal is bound to one tenant."}
	text := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	list := func(description string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": description}
	}
	output := func(properties map[string]any) OutputSchema { return ResponseSchema(Properties(properties)) }
	return []VulnerabilityToolDefinition{
		{
			Name: "cerebro.vulnerabilities.list", Title: "List Vulnerability Observations",
			Description: "List normalized vulnerability observations from every connected scanner. Each record carries the source tag that reported it.",
			InputSchema: objectSchema(map[string]any{
				"tenant_id":        tenant,
				"source_id":        list("Only observations reported by these source tags."),
				"profile_id":       text("Only observations ingested through this profile."),
				"severity":         list("Severity filter: critical, high, medium, low, info, unknown."),
				"status":           list("Status filter: open, resolved, suppressed."),
				"class":            list("Class filter, for example package, code, web, container_image."),
				"vulnerability_id": text("CVE, GHSA, or other advisory identifier."),
				"asset":            text("Asset identifier substring."),
				"q":                text("Free-text search over title and identifiers."),
				"limit":            limitSchema(200, "observations"),
				"cursor":           text("Cursor from a previous page."),
			}, nil),
			OutputSchema: output(map[string]any{"observations": map[string]any{"type": "array"}, "next_cursor": map[string]any{"type": "string"}}),
			Idempotent:   true,
		},
		{
			Name: "cerebro.vulnerabilities.summary", Title: "Summarize Vulnerabilities",
			Description:  "Count open vulnerability observations by severity, source, and class, and report how many ingestion profiles need attention.",
			InputSchema:  objectSchema(map[string]any{"tenant_id": tenant}, nil),
			OutputSchema: output(map[string]any{"open": map[string]any{"type": "integer"}, "by_severity": map[string]any{"type": "object"}, "by_source": map[string]any{"type": "array"}, "profiles_needing_attention": map[string]any{"type": "integer"}}),
			Idempotent:   true,
		},
		{
			Name: "cerebro.vulnerabilities.ingest", Title: "Ingest Vulnerability Payload",
			Description: "Deliver one scanner payload to an existing ingestion profile. Known formats are normalized immediately; unknown formats are held until a learned mapping is reviewed. Reusing an idempotency key returns the original result. Requires " + ScopeVulnerabilitiesIngest + ".",
			InputSchema: objectSchema(map[string]any{
				"tenant_id":       tenant,
				"profile_id":      text("Ingestion profile ID; its source tag is stamped on every observation."),
				"payload":         map[string]any{"description": "Scanner output as a JSON object, JSON array, or NDJSON string."},
				"format":          text("Optional format override, for example strix, sarif, cyclonedx, osv, trivy, grype, generic."),
				"full_snapshot":   map[string]any{"type": "boolean", "description": "The payload is the complete current set; open observations absent from it are resolved."},
				"idempotency_key": text("Caller-owned retry key."),
			}, []string{"profile_id", "payload"}),
			OutputSchema: output(map[string]any{"batch_id": map[string]any{"type": "string"}, "status": map[string]any{"type": "string"}, "accepted": map[string]any{"type": "integer"}, "quarantined": map[string]any{"type": "integer"}}),
			Idempotent:   true,
		},
	}
}
