package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	s.apiToken = strings.TrimSpace(s.GetConfigString("api_token"))
	if s.apiToken == "" {
		return fmt.Errorf("sentinelone api_token is required")
	}

	s.baseURL = strings.TrimRight(strings.TrimSpace(s.GetConfigString("base_url")), "/")
	if s.baseURL == "" {
		return fmt.Errorf("sentinelone base_url is required")
	}
	parsed, err := url.Parse(s.baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("sentinelone base_url must be an http(s) URL")
	}

	s.client = newProviderHTTPClientWithOptions(ProviderHTTPClientOptions{
		Provider: "sentinelone",
		Timeout:  30 * time.Second,
	})

	return nil
}

func (s *SentinelOneProvider) Test(ctx context.Context) error {
	_, err := s.request(ctx, "/web/api/v2.1/system/info")
	return err
}

func (s *SentinelOneProvider) Schema() []TableSchema {
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
				{Name: "threat_info", Type: "object"},
				{Name: "agent_realtime_info", Type: "object"},
				{Name: "agent_detection_info", Type: "object"},
				{Name: "indicators", Type: "object"},
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
				{Name: "site_id", Type: "string"},
				{Name: "endpoint_name", Type: "string"},
				{Name: "application_name", Type: "string"},
				{Name: "application_version", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
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

	type syncPlan struct {
		name string
		fn   func(context.Context) (*TableResult, error)
	}
	plans := []syncPlan{
		{name: "sentinelone_sites", fn: s.syncSites},
		{name: "sentinelone_agents", fn: s.syncAgents},
		{name: "sentinelone_threats", fn: func(ctx context.Context) (*TableResult, error) {
			return s.syncThreats(ctx, opts.Since)
		}},
		{name: "sentinelone_activities", fn: func(ctx context.Context) (*TableResult, error) {
			return s.syncActivities(ctx, opts.Since)
		}},
		{name: "sentinelone_applications", fn: s.syncApplications},
		{name: "sentinelone_vulnerabilities", fn: s.syncVulnerabilities},
	}

	if len(opts.Tables) > 0 {
		anySelected := false
		for _, plan := range plans {
			if tableRequested(opts.Tables, plan.name) {
				anySelected = true
				break
			}
		}
		if !anySelected {
			return result, fmt.Errorf("no matching SentinelOne tables in filter: %s", strings.Join(opts.Tables, ", "))
		}
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

	for _, plan := range plans {
		if !tableRequested(opts.Tables, plan.name) {
			continue
		}
		syncTable(plan.name, plan.fn)
	}

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

func (s *SentinelOneProvider) syncThreats(ctx context.Context, since *time.Time) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_threats")
	result := &TableResult{Name: "sentinelone_threats"}
	if err != nil {
		return result, err
	}

	createdAfter := sentinelOneSince(since, 30).Format(time.RFC3339)
	path := addQueryParams("/web/api/v2.1/threats?limit=1000", map[string]string{"createdAt__gt": createdAfter})

	threats, err := s.listCollection(ctx, path, "")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(threats))
	for _, threat := range threats {
		row := normalizeSentinelOneThreat(threat)
		ensureSentinelOneRowID(row, "agent_id", "file_sha256", "threat_name")
		rows = append(rows, row)
	}

	return s.syncTable(ctx, schema, rows)
}

func (s *SentinelOneProvider) syncActivities(ctx context.Context, since *time.Time) (*TableResult, error) {
	schema, err := s.schemaFor("sentinelone_activities")
	result := &TableResult{Name: "sentinelone_activities"}
	if err != nil {
		return result, err
	}

	createdAfter := sentinelOneSince(since, 7).Format(time.RFC3339)
	path := addQueryParams("/web/api/v2.1/activities?limit=1000", map[string]string{"createdAt__gt": createdAfter})

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

	sites, err := s.listCollection(ctx, "/web/api/v2.1/sites?limit=200", "sites")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	for _, site := range sites {
		siteID := strings.TrimSpace(providerStringValue(site["id"]))
		if siteID == "" {
			continue
		}

		path := addQueryParams("/web/api/v2.1/application-management/risks?limit=1000", map[string]string{"siteIds": siteID})
		vulnerabilities, err := s.listCollection(ctx, path, "")
		if err != nil {
			return result, err
		}

		for _, vulnerability := range vulnerabilities {
			row := normalizeSentinelOneVulnerability(vulnerability, siteID)
			ensureSentinelOneRowID(row, "agent_id", "cve_id", "application_name", "application_version")
			rows = append(rows, row)
		}
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

func normalizeSentinelOneThreat(threat map[string]interface{}) map[string]interface{} {
	row := normalizeSentinelOneRow(threat)
	threatInfo := sentinelOneMapValue(row, "threat_info")
	agentRealtime := sentinelOneMapValue(row, "agent_realtime_info")
	agentDetection := sentinelOneMapValue(row, "agent_detection_info")
	indicators := sentinelOneMapValue(row, "indicators")

	fillSentinelOneValue(row, "id", threatInfo, "threat_id", "id")
	fillSentinelOneValue(row, "agent_id", agentRealtime, "agent_id", "id")
	fillSentinelOneValue(row, "agent_id", agentDetection, "agent_id", "id")
	fillSentinelOneValue(row, "agent_computer_name", agentRealtime, "agent_computer_name", "computer_name")
	fillSentinelOneValue(row, "agent_computer_name", agentDetection, "agent_computer_name", "computer_name")
	fillSentinelOneValue(row, "threat_name", threatInfo, "threat_name", "name")
	fillSentinelOneValue(row, "classification", threatInfo, "classification")
	fillSentinelOneValue(row, "classification_source", threatInfo, "classification_source")
	fillSentinelOneValue(row, "confidence_level", threatInfo, "confidence_level")
	fillSentinelOneValue(row, "analyst_verdict", threatInfo, "analyst_verdict")
	fillSentinelOneValue(row, "incident_status", threatInfo, "incident_status")
	fillSentinelOneValue(row, "mitigation_status", threatInfo, "mitigation_status")
	fillSentinelOneValue(row, "initiated_by", threatInfo, "initiated_by")
	fillSentinelOneValue(row, "file_path", threatInfo, "file_path")
	fillSentinelOneValue(row, "file_sha256", threatInfo, "sha256", "file_sha256")
	fillSentinelOneValue(row, "file_sha1", threatInfo, "sha1", "file_sha1")
	fillSentinelOneValue(row, "file_md5", threatInfo, "md5", "file_md5")
	fillSentinelOneValue(row, "mitre_tactics", indicators, "mitre_tactics")
	fillSentinelOneValue(row, "mitre_techniques", indicators, "mitre_techniques")
	fillSentinelOneValue(row, "created_at", threatInfo, "created_at")
	fillSentinelOneValue(row, "updated_at", threatInfo, "updated_at")

	return row
}

func normalizeSentinelOneVulnerability(vulnerability map[string]interface{}, siteID string) map[string]interface{} {
	row := normalizeSentinelOneRow(vulnerability)
	if strings.TrimSpace(providerStringValue(row["site_id"])) == "" {
		row["site_id"] = siteID
	}
	if row["agent_id"] == nil {
		row["agent_id"] = firstSentinelOneValue(row, "endpoint_id")
	}
	if row["application_name"] == nil {
		row["application_name"] = firstSentinelOneValue(row, "application", "name", "app_name")
	}
	if row["application_version"] == nil {
		row["application_version"] = firstSentinelOneValue(row, "version", "app_version")
	}
	if row["cvss_score"] == nil {
		row["cvss_score"] = firstSentinelOneValue(row, "base_score")
	}
	if row["days_since_detection"] == nil {
		row["days_since_detection"] = firstSentinelOneValue(row, "days_detected")
	}
	if row["detected_at"] == nil {
		row["detected_at"] = firstSentinelOneValue(row, "detection_date")
	}
	if row["remediation_action"] == nil {
		row["remediation_action"] = firstSentinelOneValue(row, "reason", "last_scan_result")
	}
	return row
}

func sentinelOneSince(since *time.Time, defaultDays int) time.Time {
	if since != nil && !since.IsZero() {
		return since.UTC()
	}
	return time.Now().AddDate(0, 0, -defaultDays).UTC()
}

func sentinelOneMapValue(row map[string]interface{}, key string) map[string]interface{} {
	value, ok := row[key]
	if !ok || value == nil {
		return nil
	}
	asMap, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	return asMap
}

func fillSentinelOneValue(row map[string]interface{}, target string, source map[string]interface{}, keys ...string) {
	if row == nil || source == nil {
		return
	}
	if value, ok := row[target]; ok && value != nil && strings.TrimSpace(providerStringValue(value)) != "" {
		return
	}
	value := firstSentinelOneValue(source, keys...)
	if value != nil {
		row[target] = value
	}
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
