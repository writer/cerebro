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

// KandjiProvider syncs device data from Kandji MDM
type KandjiProvider struct {
	*BaseProvider
	apiURL   string
	apiToken string
	client   *http.Client
}

func NewKandjiProvider() *KandjiProvider {
	return &KandjiProvider{
		BaseProvider: NewBaseProvider("kandji", ProviderTypeEndpoint),
		client:       newProviderHTTPClient(60 * time.Second),
	}
}

func (k *KandjiProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := k.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	k.apiURL = k.GetConfigString("api_url")
	if k.apiURL == "" {
		k.apiURL = "https://api.kandji.io/api/v1"
	}

	k.apiToken = k.GetConfigString("api_token")
	if k.apiToken == "" {
		return fmt.Errorf("kandji api_token required")
	}

	return nil
}

func (k *KandjiProvider) Test(ctx context.Context) error {
	_, err := k.request(ctx, "/devices?limit=1")
	return err
}

func (k *KandjiProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "kandji_devices",
			Description: "Kandji managed devices",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "device_name", Type: "string"},
				{Name: "serial_number", Type: "string"},
				{Name: "platform", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "last_check_in", Type: "timestamp"},
				{Name: "user_name", Type: "string"},
				{Name: "user_email", Type: "string"},
				{Name: "asset_tag", Type: "string"},
				{Name: "blueprint_name", Type: "string"},
				{Name: "mdm_enabled", Type: "boolean"},
				{Name: "agent_installed", Type: "boolean"},
				{Name: "is_supervised", Type: "boolean"},
				{Name: "filevault_enabled", Type: "boolean"},
				{Name: "firewall_enabled", Type: "boolean"},
				{Name: "remote_desktop_enabled", Type: "boolean"},
				{Name: "screen_sharing_enabled", Type: "boolean"},
				{Name: "gatekeeper_enabled", Type: "boolean"},
				{Name: "sip_enabled", Type: "boolean"},
			},
			PrimaryKey: []string{"device_id"},
		},
		{
			Name:        "kandji_device_apps",
			Description: "Applications installed on Kandji devices",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "app_name", Type: "string", Required: true},
				{Name: "bundle_id", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "path", Type: "string"},
			},
			PrimaryKey: []string{"device_id", "app_name"},
		},
		{
			Name:        "kandji_device_profiles",
			Description: "Configuration profiles on Kandji devices",
			Columns: []ColumnSchema{
				{Name: "device_id", Type: "string", Required: true},
				{Name: "profile_id", Type: "string", Required: true},
				{Name: "profile_name", Type: "string"},
				{Name: "profile_uuid", Type: "string"},
				{Name: "installed", Type: "boolean"},
			},
			PrimaryKey: []string{"device_id", "profile_id"},
		},
		{
			Name:        "kandji_users",
			Description: "Kandji users",
			Columns: []ColumnSchema{
				{Name: "user_id", Type: "string", Required: true},
				{Name: "email", Type: "string"},
				{Name: "name", Type: "string"},
				{Name: "role", Type: "string"},
				{Name: "is_active", Type: "boolean"},
				{Name: "created_at", Type: "timestamp"},
			},
			PrimaryKey: []string{"user_id"},
		},
		{
			Name:        "kandji_vulnerabilities",
			Description: "Kandji vulnerability detections",
			Columns: []ColumnSchema{
				{Name: "cve_id", Type: "string", Required: true},
				{Name: "device_id", Type: "string"},
				{Name: "device_name", Type: "string"},
				{Name: "device_serial_number", Type: "string"},
				{Name: "software_name", Type: "string"},
				{Name: "software_version", Type: "string"},
				{Name: "cvss_score", Type: "float"},
				{Name: "cvss_severity", Type: "string"},
				{Name: "first_detection_date", Type: "timestamp"},
				{Name: "latest_detection_date", Type: "timestamp"},
				{Name: "cve_link", Type: "string"},
			},
			PrimaryKey: []string{"cve_id", "device_id"},
		},
		{
			Name:        "kandji_audit_events",
			Description: "Kandji audit log events",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "action", Type: "string"},
				{Name: "actor_id", Type: "string"},
				{Name: "actor_type", Type: "string"},
				{Name: "target_id", Type: "string"},
				{Name: "target_type", Type: "string"},
				{Name: "occurred_at", Type: "timestamp"},
				{Name: "new_state", Type: "json"},
				{Name: "metadata", Type: "json"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func (k *KandjiProvider) schemaFor(name string) (TableSchema, error) {
	schema, ok := schemaByName(k.Schema(), name)
	if !ok {
		return TableSchema{}, fmt.Errorf("schema not found: %s", name)
	}
	return schema, nil
}

func (k *KandjiProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  k.Name(),
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

	syncTable("devices", k.syncDevices)
	syncTable("device_apps", k.syncDeviceApps)
	syncTable("device_profiles", k.syncDeviceProfiles)
	syncTable("users", k.syncUsers)
	syncTable("vulnerabilities", k.syncVulnerabilities)
	syncTable("audit_events", k.syncAuditEvents)

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (k *KandjiProvider) syncDevices(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kandji_devices")
	result := &TableResult{Name: "kandji_devices"}
	if err != nil {
		return result, err
	}

	devices, err := k.listAllDevices(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(devices))
	for _, device := range devices {
		row := normalizeKandjiRow(device)
		if deviceID := firstKandjiString(row, "device_id", "id", "device_uuid", "serial_number"); deviceID != "" {
			row["device_id"] = deviceID
		}
		if row["device_name"] == nil {
			row["device_name"] = firstKandjiValue(row, "device_name", "name", "display_name")
		}
		if user := kandjiMap(row["user"]); len(user) > 0 {
			if row["user_name"] == nil {
				row["user_name"] = firstKandjiValue(user, "name", "display_name", "full_name")
			}
			if row["user_email"] == nil {
				row["user_email"] = firstKandjiValue(user, "email", "email_address")
			}
		}
		rows = append(rows, row)
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KandjiProvider) syncDeviceApps(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kandji_device_apps")
	result := &TableResult{Name: "kandji_device_apps"}
	if err != nil {
		return result, err
	}

	devices, err := k.listAllDevices(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, device := range devices {
		normalizedDevice := normalizeKandjiRow(device)
		deviceID := firstKandjiString(normalizedDevice, "device_id", "id", "device_uuid", "serial_number")
		if deviceID == "" {
			continue
		}

		for _, app := range kandjiMapSlice(firstKandjiValue(normalizedDevice, "applications", "installed_apps", "apps")) {
			row := normalizeKandjiRow(app)
			appName := firstKandjiString(row, "app_name", "name", "application_name", "display_name", "bundle_id")
			if appName == "" {
				continue
			}

			id := deviceID + "|" + appName
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}

			row["device_id"] = deviceID
			row["app_name"] = appName
			if row["bundle_id"] == nil {
				row["bundle_id"] = firstKandjiValue(row, "bundle_id", "bundleid", "identifier")
			}
			if row["version"] == nil {
				row["version"] = firstKandjiValue(row, "version", "app_version")
			}

			rows = append(rows, row)
		}
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KandjiProvider) syncDeviceProfiles(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kandji_device_profiles")
	result := &TableResult{Name: "kandji_device_profiles"}
	if err != nil {
		return result, err
	}

	devices, err := k.listAllDevices(ctx)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	for _, device := range devices {
		normalizedDevice := normalizeKandjiRow(device)
		deviceID := firstKandjiString(normalizedDevice, "device_id", "id", "device_uuid", "serial_number")
		if deviceID == "" {
			continue
		}

		for _, profile := range kandjiMapSlice(firstKandjiValue(normalizedDevice, "profiles", "configuration_profiles", "installed_profiles")) {
			row := normalizeKandjiRow(profile)
			profileID := firstKandjiString(row, "profile_id", "id", "uuid", "profile_uuid", "identifier")
			if profileID == "" {
				continue
			}

			id := deviceID + "|" + profileID
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}

			row["device_id"] = deviceID
			row["profile_id"] = profileID
			if row["profile_name"] == nil {
				row["profile_name"] = firstKandjiValue(row, "profile_name", "name", "display_name")
			}
			if row["profile_uuid"] == nil {
				row["profile_uuid"] = firstKandjiValue(row, "profile_uuid", "uuid")
			}
			if installed, ok := kandjiBoolFromKeys(row, "installed", "is_installed"); ok {
				row["installed"] = installed
			}

			rows = append(rows, row)
		}
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KandjiProvider) syncUsers(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kandji_users")
	result := &TableResult{Name: "kandji_users"}
	if err != nil {
		return result, err
	}

	body, err := k.request(ctx, "/users")
	if err != nil {
		return result, err
	}

	users, err := kandjiDecodeItems(body)
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		row := normalizeKandjiRow(user)
		if userID := firstKandjiString(row, "user_id", "id", "email"); userID != "" {
			row["user_id"] = userID
		}
		rows = append(rows, row)
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KandjiProvider) syncVulnerabilities(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kandji_vulnerabilities")
	result := &TableResult{Name: "kandji_vulnerabilities"}
	if err != nil {
		return result, err
	}

	detections, err := k.listAllResults(ctx, "/vulnerability-management/detections?size=300")
	if err != nil {
		if isKandjiIgnorableError(err) {
			return result, nil
		}
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(detections))
	for _, detection := range detections {
		row := normalizeKandjiRow(detection)
		if cveID := firstKandjiString(row, "cve_id", "cve", "id", "cveid"); cveID != "" {
			row["cve_id"] = cveID
		}
		if row["device_id"] == nil {
			row["device_id"] = firstKandjiValue(row, "device_id", "asset_id")
		}

		if device := kandjiMap(row["device"]); len(device) > 0 {
			if row["device_id"] == nil {
				row["device_id"] = firstKandjiValue(device, "device_id", "id", "asset_id", "serial_number")
			}
			if row["device_name"] == nil {
				row["device_name"] = firstKandjiValue(device, "device_name", "name", "display_name")
			}
			if row["device_serial_number"] == nil {
				row["device_serial_number"] = firstKandjiValue(device, "serial_number")
			}
		}

		if software := kandjiMap(row["software"]); len(software) > 0 {
			if row["software_name"] == nil {
				row["software_name"] = firstKandjiValue(software, "name", "software_name", "app_name")
			}
			if row["software_version"] == nil {
				row["software_version"] = firstKandjiValue(software, "version", "software_version", "app_version")
			}
		}

		if row["software_name"] == nil {
			row["software_name"] = firstKandjiValue(row, "software_name", "name", "app_name")
		}
		if row["software_version"] == nil {
			row["software_version"] = firstKandjiValue(row, "software_version", "version", "app_version")
		}

		rows = append(rows, row)
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KandjiProvider) syncAuditEvents(ctx context.Context) (*TableResult, error) {
	schema, err := k.schemaFor("kandji_audit_events")
	result := &TableResult{Name: "kandji_audit_events"}
	if err != nil {
		return result, err
	}

	events, err := k.listAllResults(ctx, "/audit/events?limit=500&sort_by=-occurred_at")
	if err != nil {
		return result, err
	}

	rows := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		row := normalizeKandjiRow(event)

		id := firstKandjiString(row, "id", "event_id", "uuid")
		if id == "" {
			id = buildKandjiFallbackID(
				firstKandjiString(row, "action"),
				firstKandjiString(row, "occurred_at"),
				firstKandjiString(row, "actor_id"),
				firstKandjiString(row, "target_id"),
			)
		}
		if id != "" {
			row["id"] = id
		}

		if row["metadata"] == nil {
			row["metadata"] = firstKandjiValue(row, "metadata", "details", "payload", "attributes")
		}

		rows = append(rows, row)
	}

	return k.syncTable(ctx, schema, rows)
}

func (k *KandjiProvider) listAllDevices(ctx context.Context) ([]map[string]interface{}, error) {
	var allDevices []map[string]interface{}
	offset := 0
	limit := 300
	guard := newPaginationGuard("kandji", "/devices")

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := guard.nextPage(); err != nil {
			return nil, err
		}

		body, err := k.request(ctx, fmt.Sprintf("/devices?limit=%d&offset=%d", limit, offset))
		if err != nil {
			return nil, err
		}

		devices, err := kandjiDecodeItems(body)
		if err != nil {
			return nil, err
		}

		allDevices = append(allDevices, devices...)

		if len(devices) < limit {
			break
		}
		offset += limit
		if err := guard.nextOffset(offset); err != nil {
			return nil, err
		}
	}

	return allDevices, nil
}

func (k *KandjiProvider) listAllResults(ctx context.Context, path string) ([]map[string]interface{}, error) {
	currentPath := path
	guard := newPaginationGuard("kandji", path)
	allItems := make([]map[string]interface{}, 0)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := guard.nextPage(); err != nil {
			return nil, err
		}

		body, err := k.request(ctx, currentPath)
		if err != nil {
			return nil, err
		}

		items, next, err := kandjiDecodePage(body)
		if err != nil {
			return nil, err
		}
		allItems = append(allItems, items...)

		if strings.TrimSpace(next) == "" {
			break
		}

		nextPath, err := k.resolveKandjiNextPath(currentPath, next)
		if err != nil {
			return nil, err
		}
		if err := guard.nextToken(nextPath); err != nil {
			return nil, err
		}
		currentPath = nextPath
	}

	return allItems, nil
}

func kandjiDecodePage(body []byte) ([]map[string]interface{}, string, error) {
	var direct []map[string]interface{}
	if err := json.Unmarshal(body, &direct); err == nil {
		return direct, "", nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}

	normalized := normalizeKandjiRow(payload)
	return kandjiExtractItems(normalized), kandjiExtractNext(normalized), nil
}

func kandjiDecodeItems(body []byte) ([]map[string]interface{}, error) {
	items, _, err := kandjiDecodePage(body)
	return items, err
}

func kandjiExtractItems(payload map[string]interface{}) []map[string]interface{} {
	for _, key := range []string{"results", "data", "items", "devices", "events"} {
		if items := kandjiMapSlice(payload[key]); len(items) > 0 {
			return items
		}
		if nested := kandjiMap(payload[key]); len(nested) > 0 {
			for _, nestedKey := range []string{"results", "data", "items", "devices", "events"} {
				if items := kandjiMapSlice(nested[nestedKey]); len(items) > 0 {
					return items
				}
			}
		}
	}

	return nil
}

func kandjiExtractNext(payload map[string]interface{}) string {
	for _, key := range []string{"next", "next_url", "next_page", "next_cursor", "cursor"} {
		if next := strings.TrimSpace(providerStringValue(payload[key])); next != "" {
			return next
		}
	}

	if pagination := kandjiMap(payload["pagination"]); len(pagination) > 0 {
		for _, key := range []string{"next", "next_url", "next_page", "next_cursor", "cursor"} {
			if next := strings.TrimSpace(providerStringValue(pagination[key])); next != "" {
				return next
			}
		}
	}

	return ""
}

func (k *KandjiProvider) resolveKandjiNextPath(currentPath string, next string) (string, error) {
	next = strings.TrimSpace(next)
	if next == "" {
		return "", nil
	}

	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		nextURL, err := url.Parse(next)
		if err != nil {
			return "", err
		}
		baseURL, err := url.Parse(k.apiURL)
		if err != nil {
			return "", err
		}
		if nextURL.Host != "" && !strings.EqualFold(nextURL.Host, baseURL.Host) {
			return "", fmt.Errorf("unexpected kandji pagination host %q", nextURL.Host)
		}
		if nextURL.Scheme != "" && !strings.EqualFold(nextURL.Scheme, baseURL.Scheme) {
			return "", fmt.Errorf("unexpected kandji pagination scheme %q", nextURL.Scheme)
		}
		resolved := nextURL.Path
		if resolved == "" {
			resolved = "/"
		}
		if nextURL.RawQuery != "" {
			resolved += "?" + nextURL.RawQuery
		}
		return resolved, nil
	}

	if strings.HasPrefix(next, "/") {
		return next, nil
	}

	if strings.HasPrefix(next, "?") {
		basePath := currentPath
		if idx := strings.Index(basePath, "?"); idx >= 0 {
			basePath = basePath[:idx]
		}
		return basePath + next, nil
	}

	return addQueryParams(currentPath, map[string]string{"cursor": next}), nil
}

func (k *KandjiProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := k.apiURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+k.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kandji API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func normalizeKandjiRow(row map[string]interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(row).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return normalized
}

func kandjiMap(value interface{}) map[string]interface{} {
	normalized, ok := normalizeMapKeys(value).(map[string]interface{})
	if !ok {
		return nil
	}
	return normalized
}

func kandjiMapSlice(value interface{}) []map[string]interface{} {
	normalized := normalizeMapKeys(value)
	raw, ok := normalized.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		asMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, asMap)
	}
	return out
}

func firstKandjiString(row map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text != "" {
			return text
		}
	}
	return ""
}

func firstKandjiValue(row map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		value, ok := row[key]
		if !ok || value == nil {
			continue
		}
		if text := strings.TrimSpace(providerStringValue(value)); text == "" {
			continue
		}
		return value
	}
	return nil
}

func kandjiBoolFromKeys(row map[string]interface{}, keys ...string) (bool, bool) {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		if parsed, ok := kandjiBool(value); ok {
			return parsed, true
		}
	}
	return false, false
}

func kandjiBool(value interface{}) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		normalized := strings.ToLower(strings.TrimSpace(typed))
		switch normalized {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

func buildKandjiFallbackID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return strings.Join(values, "|")
}

func isKandjiIgnorableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api error 403") || strings.Contains(message, "api error 404")
}

// DeviceCompliance returns compliance information for a device
func (k *KandjiProvider) DeviceCompliance(device map[string]interface{}) map[string]bool {
	return map[string]bool{
		"filevault_enabled":  getBool(device, "filevault_enabled"),
		"firewall_enabled":   getBool(device, "firewall_enabled"),
		"gatekeeper_enabled": getBool(device, "gatekeeper_enabled"),
		"sip_enabled":        getBool(device, "sip_enabled"),
		"mdm_enabled":        getBool(device, "mdm_enabled"),
		"agent_installed":    getBool(device, "agent_installed"),
	}
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}
