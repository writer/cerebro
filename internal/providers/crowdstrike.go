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

// CrowdStrikeProvider syncs endpoint data from CrowdStrike Falcon
type CrowdStrikeProvider struct {
	*BaseProvider
	clientID     string
	clientSecret string
	baseURL      string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

type CrowdStrikeConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	BaseURL      string `json:"base_url"` // e.g., https://api.crowdstrike.com
}

func NewCrowdStrikeProvider() *CrowdStrikeProvider {
	return &CrowdStrikeProvider{
		BaseProvider: NewBaseProvider("crowdstrike", ProviderTypeEndpoint),
		baseURL:      "https://api.crowdstrike.com",
		client:       newProviderHTTPClient(30 * time.Second),
	}
}

func (c *CrowdStrikeProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := c.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	c.clientID = c.GetConfigString("client_id")
	c.clientSecret = c.GetConfigString("client_secret")

	if baseURL := c.GetConfigString("base_url"); baseURL != "" {
		c.baseURL = baseURL
	}
	c.client = c.NewHTTPClient(30 * time.Second)

	return nil
}

func (c *CrowdStrikeProvider) Test(ctx context.Context) error {
	_, err := c.authenticate(ctx)
	return err
}

func (c *CrowdStrikeProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "crowdstrike_hosts",
			Description: "CrowdStrike Falcon managed hosts",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "hostname", Type: "string"},
				{Name: "platform_name", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "agent_version", Type: "string"},
				{Name: "last_seen", Type: "timestamp"},
				{Name: "status", Type: "string"},
				{Name: "tags", Type: "array"},
			},
			PrimaryKey: []string{"device_id"},
		},
		{
			Name:        "crowdstrike_detections",
			Description: "CrowdStrike Falcon detections",
			Columns: []ColumnSchema{
				{Name: "detection_id", Type: "string", Required: true},
				{Name: "device_id", Type: "string"},
				{Name: "severity", Type: "integer"},
				{Name: "status", Type: "string"},
				{Name: "tactic", Type: "string"},
				{Name: "technique", Type: "string"},
				{Name: "description", Type: "string"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"detection_id"},
		},
		{
			Name:        "crowdstrike_vulnerabilities",
			Description: "CrowdStrike Spotlight vulnerabilities",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "cve_id", Type: "string"},
				{Name: "host_id", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "app_name", Type: "string"},
				{Name: "app_version", Type: "string"},
				{Name: "exploit_available", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
				{Name: "updated_at", Type: "timestamp"},
				{Name: "remediation_action", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (c *CrowdStrikeProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(c.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (c *CrowdStrikeProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  c.Name(),
		StartedAt: start,
	}

	token, err := c.authenticate(ctx)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	c.token = token

	// Sync hosts
	hosts, err := c.syncHosts(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "hosts: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *hosts)
		result.TotalRows += hosts.Rows
	}

	// Sync detections
	detections, err := c.syncDetections(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "detections: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *detections)
		result.TotalRows += detections.Rows
	}

	// Sync vulnerabilities
	vulnerabilities, err := c.syncVulnerabilities(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "vulnerabilities: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *vulnerabilities)
		result.TotalRows += vulnerabilities.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (c *CrowdStrikeProvider) authenticate(ctx context.Context) (string, error) {
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return c.token, nil
	}

	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth2/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed: %s", string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	c.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, nil
}

func (c *CrowdStrikeProvider) syncHosts(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("crowdstrike_hosts")
	result := &TableResult{Name: "crowdstrike_hosts"}
	if err != nil {
		return result, err
	}

	ids, err := c.queryResources(ctx, "/devices/queries/devices/v1")
	if err != nil {
		return result, err
	}
	hosts, err := c.fetchEntities(ctx, "/devices/entities/devices/v2", ids)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(hosts))
	for _, host := range hosts {
		row := normalizeCrowdStrikeRow(host)
		deviceID := firstCrowdStrikeString(row, "device_id", "device_id.id", "aid", "id")
		if deviceID == "" {
			continue
		}
		rows = append(rows, map[string]interface{}{
			"device_id":     deviceID,
			"hostname":      firstCrowdStrikeValue(row, "hostname", "device_name", "local_hostname"),
			"platform_name": firstCrowdStrikeValue(row, "platform_name", "platform", "os.platform", "os_name"),
			"os_version":    firstCrowdStrikeValue(row, "os_version", "os.version", "os_build"),
			"agent_version": firstCrowdStrikeValue(row, "agent_version", "product_type_desc", "agent_version_major"),
			"last_seen":     firstCrowdStrikeValue(row, "last_seen", "modified_timestamp", "first_seen"),
			"status":        firstCrowdStrikeValue(row, "status", "sensor_status", "device_status"),
			"tags":          firstCrowdStrikeValue(row, "tags", "groups"),
		})
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *CrowdStrikeProvider) syncDetections(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("crowdstrike_detections")
	result := &TableResult{Name: "crowdstrike_detections"}
	if err != nil {
		return result, err
	}

	ids, err := c.queryResources(ctx, "/detects/queries/detects/v1")
	if err != nil {
		return result, err
	}
	detections, err := c.fetchEntities(ctx, "/detects/entities/summaries/GET/v1", ids)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(detections))
	for _, detection := range detections {
		row := normalizeCrowdStrikeRow(detection)
		detectionID := firstCrowdStrikeString(row, "detection_id", "id")
		if detectionID == "" {
			continue
		}
		rows = append(rows, map[string]interface{}{
			"detection_id": detectionID,
			"device_id":    firstCrowdStrikeValue(row, "device_id", "aid"),
			"severity":     firstCrowdStrikeValue(row, "severity", "max_severity"),
			"status":       firstCrowdStrikeValue(row, "status"),
			"tactic":       firstCrowdStrikeValue(row, "tactic", "tactics"),
			"technique":    firstCrowdStrikeValue(row, "technique", "techniques"),
			"description":  firstCrowdStrikeValue(row, "description", "name"),
			"created_at":   firstCrowdStrikeValue(row, "created_at", "first_behavior", "behaviors.0.timestamp"),
		})
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *CrowdStrikeProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	schema, err := c.schemaFor("crowdstrike_vulnerabilities")
	result := &TableResult{Name: "crowdstrike_vulnerabilities"}
	if err != nil {
		return result, err
	}

	vulnerabilities, err := c.listCombinedVulnerabilities(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		row := normalizeCrowdStrikeRow(vulnerability)
		hostID := firstCrowdStrikeString(row, "host_id", "aid", "device_id")
		cveID := firstCrowdStrikeString(row, "cve_id", "cve", "cve.id")
		appName := firstCrowdStrikeString(row, "app_name", "application_name", "app.name", "product_name")
		appVersion := firstCrowdStrikeString(row, "app_version", "application_version", "app.version", "version")
		if hostID == "" || cveID == "" {
			continue
		}
		rows = append(rows, map[string]interface{}{
			"id":                 buildCrowdStrikeVulnerabilityID(hostID, cveID, appName, appVersion),
			"cve_id":             cveID,
			"host_id":            hostID,
			"severity":           firstCrowdStrikeValue(row, "severity", "severity_name"),
			"status":             firstCrowdStrikeValue(row, "status"),
			"app_name":           nullableCrowdStrikeValue(appName),
			"app_version":        nullableCrowdStrikeValue(appVersion),
			"exploit_available":  firstCrowdStrikeValue(row, "exploit_available", "public_exploit"),
			"created_at":         firstCrowdStrikeValue(row, "created_at", "first_found", "first_seen"),
			"updated_at":         firstCrowdStrikeValue(row, "updated_at", "last_found", "last_seen"),
			"remediation_action": firstCrowdStrikeValue(row, "remediation_action", "remediation", "solution"),
		})
	}

	return c.syncTable(ctx, schema, rows)
}

func (c *CrowdStrikeProvider) request(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("crowdstrike API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (c *CrowdStrikeProvider) queryResources(ctx context.Context, path string) ([]string, error) {
	body, err := c.request(ctx, path)
	if err != nil {
		return nil, err
	}

	var queryResult struct {
		Resources []string `json:"resources"`
	}
	if err := json.Unmarshal(body, &queryResult); err != nil {
		return nil, err
	}
	return queryResult.Resources, nil
}

func (c *CrowdStrikeProvider) fetchEntities(ctx context.Context, path string, ids []string) ([]map[string]interface{}, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	const batchSize = 100

	rows := make([]map[string]interface{}, 0, len(ids))
	for start := 0; start < len(ids); start += batchSize {
		end := start + batchSize
		if end > len(ids) {
			end = len(ids)
		}
		params := url.Values{}
		for _, id := range ids[start:end] {
			if strings.TrimSpace(id) != "" {
				params.Add("ids", id)
			}
		}
		if len(params) == 0 {
			continue
		}

		body, err := c.request(ctx, path+"?"+params.Encode())
		if err != nil {
			return nil, err
		}
		var response struct {
			Resources []map[string]interface{} `json:"resources"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, err
		}
		rows = append(rows, response.Resources...)
	}

	return rows, nil
}

func (c *CrowdStrikeProvider) listCombinedVulnerabilities(ctx context.Context) ([]map[string]interface{}, error) {
	rows := make([]map[string]interface{}, 0)
	seenAfter := make(map[string]struct{})
	after := ""

	for {
		params := url.Values{}
		params.Set("limit", "5000")
		if after != "" {
			params.Set("after", after)
		}

		body, err := c.request(ctx, "/spotlight/combined/vulnerabilities/v1?"+params.Encode())
		if err != nil {
			return nil, err
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		rows = append(rows, crowdStrikeMapSlice(payload["resources"])...)

		nextAfter := extractCrowdStrikeAfter(payload)
		if nextAfter == "" {
			break
		}
		if _, seen := seenAfter[nextAfter]; seen {
			break
		}
		seenAfter[nextAfter] = struct{}{}
		after = nextAfter
	}

	return rows, nil
}

func (c *CrowdStrikeProvider) setAuth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
}

func normalizeCrowdStrikeRow(row map[string]interface{}) map[string]interface{} {
	normalized, _ := normalizeMapKeys(row).(map[string]interface{})
	if normalized == nil {
		return map[string]interface{}{}
	}
	return normalized
}

func firstCrowdStrikeValue(row map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := crowdStrikeValue(row, key); ok && value != nil {
			return value
		}
	}
	return nil
}

func firstCrowdStrikeString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := crowdStrikeValue(row, key); ok {
			switch typed := value.(type) {
			case string:
				if trimmed := strings.TrimSpace(typed); trimmed != "" {
					return trimmed
				}
			case []byte:
				if trimmed := strings.TrimSpace(string(typed)); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

func crowdStrikeValue(row map[string]interface{}, key string) (interface{}, bool) {
	current := interface{}(row)
	for _, part := range strings.Split(key, ".") {
		currentMap, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		value, ok := currentMap[part]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func crowdStrikeMapSlice(value interface{}) []map[string]interface{} {
	items, ok := value.([]interface{})
	if !ok {
		if typed, ok := value.([]map[string]interface{}); ok {
			return typed
		}
		return nil
	}
	rows := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		if row, ok := item.(map[string]interface{}); ok {
			rows = append(rows, row)
		}
	}
	return rows
}

func extractCrowdStrikeAfter(payload map[string]interface{}) string {
	for _, key := range []string{"meta", "pagination"} {
		value, ok := payload[key]
		if !ok {
			continue
		}
		if nested, ok := value.(map[string]interface{}); ok {
			if after := firstCrowdStrikeString(nested, "pagination.after", "after", "offset"); after != "" {
				return after
			}
		}
	}
	return firstCrowdStrikeString(payload, "after", "offset")
}

func buildCrowdStrikeVulnerabilityID(hostID, cveID, appName, appVersion string) string {
	parts := []string{strings.TrimSpace(hostID), strings.TrimSpace(cveID), strings.TrimSpace(appName), strings.TrimSpace(appVersion)}
	return strings.Join(parts, "|")
}

func nullableCrowdStrikeValue(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
