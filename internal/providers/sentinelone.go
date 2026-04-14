package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SentinelOneProvider syncs endpoint security data from SentinelOne
type SentinelOneProvider struct {
	*BaseProvider
	apiToken string
	baseURL  string
	client   *http.Client
}

func NewSentinelOneProvider() *SentinelOneProvider {
	return &SentinelOneProvider{
		BaseProvider: NewBaseProvider("sentinelone", ProviderTypeEndpoint),
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (s *SentinelOneProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := s.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	s.apiToken = s.GetConfigString("api_token")
	s.baseURL = s.GetConfigString("base_url") // e.g., https://usea1-partners.sentinelone.net

	return nil
}

func (s *SentinelOneProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, "/web/api/v2.1/system/info")
	return err
}

func (s *SentinelOneProvider) Schema() []TableSchema {
	// Endpoint software/CVE correlation in SentinelOne typically uses:
	//   - sentinelone_agents: canonical endpoint rows keyed by id
	//   - sentinelone_applications: installed application inventory keyed by agent_id
	//   - sentinelone_vulnerabilities: provider-reported CVEs keyed by agent_id
	//
	// A patch-target query usually joins sentinelone_agents -> sentinelone_applications
	// on id/agent_id, then joins sentinelone_vulnerabilities on agent_id and
	// matches application_name/application_version back to the installed app row.
	// Names are intentionally preserved from the provider API, so cross-provider
	// deduplication may require additional normalization.
	return []TableSchema{
		{
			Name:        "sentinelone_agents",
			Description: "SentinelOne endpoint agents",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "uuid", Type: "string"},
				{Name: "computer_name", Type: "string"},
				{Name: "external_ip", Type: "string"},
				{Name: "internal_ip", Type: "string"},
				{Name: "os_name", Type: "string"},
				{Name: "os_type", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "agent_version", Type: "string"},
				{Name: "is_active", Type: "boolean"},
				{Name: "is_infected", Type: "boolean"},
				{Name: "is_up_to_date", Type: "boolean"},
				{Name: "network_status", Type: "string"},
				{Name: "scan_status", Type: "string"},
				{Name: "threat_reboot_required", Type: "boolean"},
				{Name: "last_active_date", Type: "timestamp"},
				{Name: "registered_at", Type: "timestamp"},
				{Name: "site_id", Type: "string"},
				{Name: "site_name", Type: "string"},
				{Name: "group_id", Type: "string"},
				{Name: "group_name", Type: "string"},
				{Name: "machine_type", Type: "string"},
				{Name: "domain", Type: "string"},
				{Name: "encrypted_applications", Type: "boolean"},
				{Name: "firewall_enabled", Type: "boolean"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_threats",
			Description: "SentinelOne threat detections",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "agent_id", Type: "string"},
				{Name: "agent_computer_name", Type: "string"},
				{Name: "threat_name", Type: "string"},
				{Name: "classification", Type: "string"},
				{Name: "classification_source", Type: "string"},
				{Name: "confidence_level", Type: "string"},
				{Name: "analyst_verdict", Type: "string"},
				{Name: "incident_status", Type: "string"},
				{Name: "mitigation_status", Type: "string"},
				{Name: "initiated_by", Type: "string"},
				{Name: "file_path", Type: "string"},
				{Name: "file_sha256", Type: "string"},
				{Name: "file_sha1", Type: "string"},
				{Name: "file_md5", Type: "string"},
				{Name: "mitre_tactics", Type: "array"},
				{Name: "mitre_techniques", Type: "array"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_activities",
			Description: "SentinelOne activity log",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "activity_type", Type: "integer"},
				{Name: "activity_description", Type: "string"},
				{Name: "primary_description", Type: "string"},
				{Name: "secondary_description", Type: "string"},
				{Name: "user_id", Type: "string"},
				{Name: "agent_id", Type: "string"},
				{Name: "site_id", Type: "string"},
				{Name: "threat_id", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_sites",
			Description: "SentinelOne sites/accounts",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
				{Name: "state", Type: "string"},
				{Name: "account_id", Type: "string"},
				{Name: "account_name", Type: "string"},
				{Name: "license_type", Type: "string"},
				{Name: "total_licenses", Type: "integer"},
				{Name: "active_licenses", Type: "integer"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_applications",
			Description: "Applications installed on endpoints",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "agent_id", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "publisher", Type: "string"},
				{Name: "size", Type: "integer"},
				{Name: "installed_date", Type: "timestamp"},
				{Name: "type", Type: "string"},
				{Name: "risk_level", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "sentinelone_vulnerabilities",
			Description: "Vulnerabilities detected on endpoints",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "cve_id", Type: "string"},
				{Name: "agent_id", Type: "string"},
				{Name: "application_name", Type: "string"},
				{Name: "application_version", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "exploited_in_wild", Type: "boolean"},
				{Name: "days_since_detection", Type: "integer"},
				{Name: "remediation_action", Type: "string"},
				{Name: "detected_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (s *SentinelOneProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  s.Name(),
		StartedAt: start,
	}

	syncTable := func(name string, fn func(context.Context) (*TableResult, error)) {
		table, err := fn(ctx)
		if err != nil {
			result.Errors = append(result.Errors, name+": "+err.Error())
			return
		}
		result.Tables = append(result.Tables, *table)
		result.TotalRows += table.Rows
	}

	syncTable("sites", s.syncSites)
	syncTable("agents", s.syncAgents)
	syncTable("threats", s.syncThreats)
	syncTable("activities", s.syncActivities)
	syncTable("applications", s.syncApplications)
	syncTable("vulnerabilities", s.syncVulnerabilities)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (s *SentinelOneProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(s.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (s *SentinelOneProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := s.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "APIToken "+s.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sentinelone API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (s *SentinelOneProvider) syncSites(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_sites")
	result := &TableResult{Name: "sentinelone_sites"}
	if err != nil {
		return result, err
	}

	sites, err := s.listCollection(ctx, "/web/api/v2.1/sites?limit=200", "sites")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(sites))
	for _, site := range sites {
		row := normalizeSentinelOneRow(site)
		ensureSentinelOneRowID(row, "name")
		rows = append(rows, row)
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SentinelOneProvider) syncAgents(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_agents")
	result := &TableResult{Name: "sentinelone_agents"}
	if err != nil {
		return result, err
	}

	agents, err := s.listCollection(ctx, "/web/api/v2.1/agents?limit=1000", "")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(agents))
	for _, agent := range agents {
		row := normalizeSentinelOneRow(agent)
		ensureSentinelOneRowID(row, "uuid", "computer_name")
		rows = append(rows, row)
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SentinelOneProvider) syncThreats(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_threats")
	result := &TableResult{Name: "sentinelone_threats"}
	if err != nil {
		return result, err
	}

	// Get threats from last 30 days
	createdAfter := time.Now().AddDate(0, 0, -30).Format(time.RFC3339)
	path := fmt.Sprintf("/web/api/v2.1/threats?limit=1000&createdAt__gt=%s", createdAfter)

	threats, err := s.listCollection(ctx, path, "")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(threats))
	for _, threat := range threats {
		row := normalizeSentinelOneRow(threat)
		ensureSentinelOneRowID(row, "agent_id", "file_sha256", "threat_name")
		rows = append(rows, row)
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SentinelOneProvider) syncActivities(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_activities")
	result := &TableResult{Name: "sentinelone_activities"}
	if err != nil {
		return result, err
	}

	// Get activities from last 7 days
	createdAfter := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	path := fmt.Sprintf("/web/api/v2.1/activities?limit=1000&createdAt__gt=%s", createdAfter)

	activities, err := s.listCollection(ctx, path, "")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(activities))
	for _, activity := range activities {
		row := normalizeSentinelOneRow(activity)
		ensureSentinelOneRowID(row, "activity_type", "created_at", "agent_id", "site_id")
		rows = append(rows, row)
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SentinelOneProvider) syncApplications(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_applications")
	result := &TableResult{Name: "sentinelone_applications"}
	if err != nil {
		return result, err
	}

	// Installed applications are synced independently from vulnerability rows so
	// callers can choose how to reconcile provider-native names, versions, and
	// publishers when building patching and exposure reports.
	applications, err := s.listCollection(ctx, "/web/api/v2.1/installed-applications?limit=1000", "")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(applications))
	for _, application := range applications {
		row := normalizeSentinelOneRow(application)
		if row["name"] == nil {
			row["name"] = firstSentinelOneValue(row, "application_name", "app_name")
		}
		if row["version"] == nil {
			row["version"] = firstSentinelOneValue(row, "application_version", "app_version")
		}
		ensureSentinelOneRowID(row, "agent_id", "name", "version", "publisher")
		rows = append(rows, row)
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SentinelOneProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_vulnerabilities")
	result := &TableResult{Name: "sentinelone_vulnerabilities"}
	if err != nil {
		return result, err
	}

	// Vulnerabilities are preserved as reported so downstream queries can decide
	// whether to trust SentinelOne's application linkage directly or normalize it
	// against sentinelone_applications for stricter patch-target correlation.
	vulnerabilities, err := s.listCollection(ctx, "/web/api/v2.1/vulnerabilities?limit=1000", "")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		row := normalizeSentinelOneRow(vulnerability)
		if row["application_name"] == nil {
			row["application_name"] = firstSentinelOneValue(row, "name", "app_name")
		}
		if row["application_version"] == nil {
			row["application_version"] = firstSentinelOneValue(row, "version", "app_version")
		}
		ensureSentinelOneRowID(row, "agent_id", "cve_id", "application_name", "application_version")
		rows = append(rows, row)
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SentinelOneProvider) listCollection(ctx context.Context, path string, nestedKey string) ([]map[string]interface{}, error) {
	currentPath := path
	seenCursors := make(map[string]struct{})
	allItems := make([]map[string]interface{}, 0)

	for {
		body, err := s.request(ctx, currentPath)
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}

		allItems = append(allItems, sentinelOneExtractItems(payload, nestedKey)...)

		nextCursor := sentinelOneNextCursor(payload)
		if nextCursor == "" {
			break
		}
		if _, seen := seenCursors[nextCursor]; seen {
			break
		}
		seenCursors[nextCursor] = struct{}{}
		currentPath = addQueryParams(path, map[string]string{"cursor": nextCursor})
	}

	return allItems, nil
}

func sentinelOneExtractItems(payload map[string]interface{}, nestedKey string) []map[string]interface{} {
	if data, ok := payload["data"]; ok {
		if items := sentinelOneMapSlice(data); len(items) > 0 {
			return items
		}
		if dataMap, ok := data.(map[string]interface{}); ok {
			if nestedKey != "" {
				if items := sentinelOneMapSlice(dataMap[nestedKey]); len(items) > 0 {
					return items
				}
			}
			for _, value := range dataMap {
				if items := sentinelOneMapSlice(value); len(items) > 0 {
					return items
				}
			}
		}
	}

	if nestedKey != "" {
		if items := sentinelOneMapSlice(payload[nestedKey]); len(items) > 0 {
			return items
		}
	}

	return nil
}

func sentinelOneMapSlice(value interface{}) []map[string]interface{} {
	raw, ok := value.([]interface{})
	if !ok {
		return nil
	}
	items := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		asMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		items = append(items, asMap)
	}
	return items
}

func sentinelOneNextCursor(payload map[string]interface{}) string {
	if pagination, ok := payload["pagination"].(map[string]interface{}); ok {
		if cursor := strings.TrimSpace(providerStringValue(pagination["nextCursor"])); cursor != "" {
			return cursor
		}
		if cursor := strings.TrimSpace(providerStringValue(pagination["next_cursor"])); cursor != "" {
			return cursor
		}
	}

	if cursor := strings.TrimSpace(providerStringValue(payload["nextCursor"])); cursor != "" {
		return cursor
	}
	if cursor := strings.TrimSpace(providerStringValue(payload["next_cursor"])); cursor != "" {
		return cursor
	}

	return ""
}

func normalizeSentinelOneRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func ensureSentinelOneRowID(row map[string]interface{}, fallbackKeys ...string) {
	id := strings.TrimSpace(providerStringValue(row["id"]))
	if id != "" {
		row["id"] = id
		return
	}

	parts := make([]string, 0, len(fallbackKeys))
	for _, key := range fallbackKeys {
		value := strings.TrimSpace(providerStringValue(row[key]))
		if value == "" {
			continue
		}
		parts = append(parts, value)
	}
	if len(parts) == 0 {
		return
	}

	row["id"] = strings.Join(parts, "|")
}

func firstSentinelOneValue(row map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := row[key]; ok && value != nil && strings.TrimSpace(providerStringValue(value)) != "" {
			return value
		}
	}
	return nil
}
