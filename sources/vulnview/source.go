package vulnview

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID = "vulnview"

	familySite          = "site"
	familyScan          = "scan"
	familyVulnerability = "vulnerability"
	familyAsset         = "asset"
	familyDNSAlert      = "dns_alert"
)

// Source reads VulnView attack-surface and vulnerability data.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	mu                   sync.Mutex
	tokenKey             string
	accessToken          string
	tokenExpiresAt       time.Time
}

type record struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

type listResponse struct {
	Items      []json.RawMessage `json:"items"`
	NextCursor string            `json:"nextCursor"`
}

// New constructs the VulnView source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:          spec,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Spec returns static VulnView source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured VulnView family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns canonical VulnView URNs for one configured page.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages VulnView records and emits vulnview.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string {
		return settings.family
	},
		s.family(familySite, "/sites"),
		s.family(familyScan, "/scans"),
		s.family(familyVulnerability, "/vulnerabilities"),
		s.family(familyAsset, "/assets"),
		s.dnsAlertFamily(),
	)
}

func (s *Source) family(name string, path string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: name,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.list(ctx, settings, path, "", 1)
			if err != nil {
				return fmt.Errorf("vulnview %s: %w", name, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.list(ctx, settings, path, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("vulnview %s: %w", name, err)
			}
			return urnsFor(settings, name, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.list(ctx, settings, path, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("vulnview %s: %w", name, err)
			}
			return pullFromRecords(settings, name, records, next)
		},
	}
}

func (s *Source) list(ctx context.Context, settings settings, path string, cursor string, pageSize int) ([]record, string, error) {
	var response listResponse
	query := settings.query()
	query.Set("limit", strconv.Itoa(pageSize))
	sourcecdk.AddQueryParam(query, "cursor", cursor)
	if err := s.getJSON(ctx, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	records := make([]record, 0, len(response.Items))
	for _, item := range response.Items {
		rec, err := recordFromRaw(settings.family, item)
		if err != nil {
			return nil, "", err
		}
		if rec.ID == "" {
			continue
		}
		records = append(records, rec)
	}
	if serverPaged(cursor, pageSize, len(records), response.NextCursor) {
		return records, strings.TrimSpace(response.NextCursor), nil
	}
	return sourcecdk.PageByOffset(records, cursor, pageSize)
}

func recordFromRaw(family string, raw json.RawMessage) (record, error) {
	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return record{}, fmt.Errorf("decode VulnView %s record: %w", family, err)
	}
	return record{Raw: cloneRaw(raw), Values: values, ID: recordID(family, values)}, nil
}

func recordID(family string, values map[string]any) string {
	switch family {
	case familySite:
		return firstValueString(values, "siteId", "id", "name")
	case familyScan:
		return firstValueString(values, "scanId", "id", "name")
	case familyVulnerability:
		return stableID(
			firstValueString(values, "scanId"),
			firstValueString(values, "templateId", "template-id", "id", "name"),
			firstValueString(values, "matchedAt", "matched-at", "host"),
		)
	case familyAsset:
		return firstValueString(values, "asset", "host", "matchedAt", "matched-at")
	default:
		return firstValueString(values, "id", "name")
	}
}

func urnsFor(settings settings, family string, records []record) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:vulnview_%s:%s", settings.tenantID, family, normalizeID(record.ID)))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(settings settings, family string, records []record, next string) (sourcecdk.Pull, error) {
	return sourcecdk.PullFromRecords(records, next,
		func(rec record) (*primitives.Event, error) {
			return eventFromRecord(settings, family, rec), nil
		},
		func(rec record) string { return strings.TrimSpace(rec.ID) },
	)
}

func eventFromRecord(settings settings, family string, record record) *primitives.Event {
	occurredAt := occurredAtFor(record.Values)
	return &primitives.Event{
		Id:         eventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       sourceID + "." + family,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  sourceID + "/" + family + "/v1",
		Payload:    cloneRaw(record.Raw),
		Attributes: attributesFor(family, record),
	}
}

func eventID(settings settings, family string, recordID string) string {
	return strings.Join([]string{
		sourceID,
		normalizeID(settings.tenantID),
		runtimeScope(settings),
		normalizeID(family),
		normalizeID(recordID),
	}, "-")
}

func runtimeScope(settings settings) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		settings.baseURL,
		settings.clientID,
		settings.scope,
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

func attributesFor(family string, record record) map[string]string {
	values := record.Values
	attrs := map[string]string{
		"external_id":     record.ID,
		"family":          family,
		"provider":        sourceID,
		"source_provider": sourceID,
	}
	switch family {
	case familySite:
		copyFields(attrs, values, map[string]string{
			"site_id": "siteId",
			"name":    "name",
		})
	case familyScan:
		copyFields(attrs, values, map[string]string{
			"scan_id":          "scanId",
			"site_id":          "siteId",
			"name":             "name",
			"scan_type":        "scanType",
			"target":           "target",
			"status":           "status",
			"findings_count":   "findingsCount",
			"results_key":      "resultsKey",
			"created_at":       "createdAt",
			"started_at":       "startedAt",
			"completed_at":     "completedAt",
			"cloud_account_id": "cloudAccountId",
		})
	case familyVulnerability:
		copyFields(attrs, values, map[string]string{
			"vulnerability_id": "templateId",
			"template_id":      "templateId",
			"name":             "name",
			"severity":         "severity",
			"type":             "type",
			"target_id":        "host",
			"target_name":      "host",
			"host":             "host",
			"matched_at":       "matchedAt",
			"description":      "description",
			"remediation":      "remediation",
			"scan_id":          "scanId",
			"scan_name":        "scanName",
			"site_id":          "siteId",
			"site_name":        "siteName",
			"timestamp":        "timestamp",
		})
		addVulnViewFindingStateAttributes(attrs, values)
		if attrs["template_id"] == "" {
			copyFields(attrs, values, map[string]string{"template_id": "template-id", "vulnerability_id": "template-id"})
		}
		if attrs["matched_at"] == "" {
			copyFields(attrs, values, map[string]string{"matched_at": "matched-at"})
		}
		attrs["target_type"] = "external_asset"
		attrs["vulnerability_type"] = firstNonEmpty(attrs["type"], "vulnview")
	case familyAsset:
		copyFields(attrs, values, map[string]string{
			"asset_id":          "asset",
			"asset_name":        "asset",
			"target_id":         "asset",
			"target_name":       "asset",
			"highest_severity":  "highestSeverity",
			"findings_count":    "findingsCount",
			"sites":             "sites",
			"scan_names":        "scanNames",
			"critical_count":    "severityCounts.critical",
			"high_count":        "severityCounts.high",
			"medium_count":      "severityCounts.medium",
			"low_count":         "severityCounts.low",
			"info_count":        "severityCounts.info",
			"dns_alerts_count":  "dnsAlertSummary.total",
			"dns_highest_alert": "dnsAlertSummary.highestSeverity",
		})
		attrs["target_type"] = "external_asset"
	case familyDNSAlert:
		copyFields(attrs, values, map[string]string{
			"asset_id":     "asset",
			"asset_name":   "asset",
			"target_id":    "asset",
			"target_name":  "asset",
			"alert":        "alert",
			"name":         "alert",
			"severity":     "severity",
			"description":  "description",
			"record_type":  "recordType",
			"record_value": "recordValue",
			"sites":        "siteNames",
			"scan_names":   "scanNames",
		})
		addVulnViewFindingStateAttributes(attrs, values)
		attrs["target_type"] = "external_asset"
	}
	trimEmptyAttributes(attrs)
	return attrs
}

func addVulnViewFindingStateAttributes(attrs map[string]string, values map[string]any) {
	stateFields := map[string][]string{
		"vulnview_status":            {"status"},
		"vulnview_state":             {"state"},
		"vulnview_finding_status":    {"findingStatus", "finding_status"},
		"vulnview_remediation_state": {"remediationState", "remediation_state"},
		"vulnview_lifecycle_state":   {"lifecycleState", "lifecycle_state"},
	}
	for attr, fields := range stateFields {
		if value := firstValueString(values, fields...); value != "" {
			attrs[attr] = value
		}
	}
	attrs["vulnview_finding_state"] = firstNonEmpty(
		attrs["vulnview_status"],
		attrs["vulnview_state"],
		attrs["vulnview_finding_status"],
		attrs["vulnview_remediation_state"],
		attrs["vulnview_lifecycle_state"],
	)
}

func occurredAtFor(values map[string]any) time.Time {
	for _, key := range []string{"timestamp", "completedAt", "startedAt", "createdAt", "matchedAt", "matched-at"} {
		if parsed, ok := parseTime(valueString(valueAt(values, key))); ok {
			return parsed
		}
	}
	return time.Now().UTC()
}

func parseTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func copyFields(attrs map[string]string, values map[string]any, fields map[string]string) {
	for attr, field := range fields {
		if value := valueString(valueAt(values, field)); value != "" {
			attrs[attr] = value
		}
	}
}

func firstValueString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := valueString(valueAt(values, key)); value != "" {
			return value
		}
	}
	return ""
}

func valueAt(values map[string]any, path string) any {
	current := any(values)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

func valueString(value any) string {
	return sourcecdk.JSONScalar{Value: value}.Flattened()
}

func stableID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ":")
}

func normalizeID(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", ":", "-", "\n", "-", "\t", "-")
	return replacer.Replace(normalized)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func trimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(value) == "" {
			delete(attrs, key)
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}
