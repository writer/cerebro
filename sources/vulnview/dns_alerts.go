package vulnview

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const dnsAlertDiscoverPages = 10

type dnsAlertCursor struct {
	AssetCursor string `json:"assetCursor,omitempty"`
	AlertOffset int    `json:"alertOffset,omitempty"`
}

func (s *Source) dnsAlertFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familyDNSAlert,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.listDNSAlerts(ctx, settings, "", 1)
			if err != nil {
				return fmt.Errorf("vulnview dns_alert: %w", err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, err := s.discoverDNSAlerts(ctx, settings)
			if err != nil {
				return nil, fmt.Errorf("vulnview dns_alert: %w", err)
			}
			return urnsFor(settings, familyDNSAlert, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.listDNSAlerts(ctx, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("vulnview dns_alert: %w", err)
			}
			return pullFromRecords(settings, familyDNSAlert, records, next)
		},
	}
}

func (s *Source) listDNSAlerts(ctx context.Context, settings settings, cursor string, pageSize int) ([]record, string, error) {
	assetCursor, alertOffset, err := parseDNSAlertCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	familySettings := settings
	familySettings.family = familyAsset
	var response listResponse
	query := familySettings.query()
	query.Set("limit", strconv.Itoa(familySettings.perPage))
	sourcecdk.AddQueryParam(query, "cursor", assetCursor)
	if err := s.getJSON(ctx, familySettings, "/assets", query, &response); err != nil {
		return nil, "", err
	}
	records := []record{}
	for _, item := range response.Items {
		var asset map[string]any
		if err := json.Unmarshal(item, &asset); err != nil {
			return nil, "", fmt.Errorf("decode VulnView asset: %w", err)
		}
		alerts, _ := asset["dnsAlerts"].([]any)
		for index, rawAlert := range alerts {
			alert, ok := rawAlert.(map[string]any)
			if !ok {
				continue
			}
			values := map[string]any{
				"asset":     asset["asset"],
				"siteNames": asset["sites"],
				"scanNames": asset["scanNames"],
			}
			maps.Copy(values, alert)
			raw, err := json.Marshal(values)
			if err != nil {
				return nil, "", fmt.Errorf("marshal VulnView DNS alert: %w", err)
			}
			id := firstValueString(values, "id", "alert", "name", "type")
			assetID := valueString(asset["asset"])
			records = append(records, record{
				Raw:    raw,
				Values: values,
				ID:     stableID(assetID, id, strconv.Itoa(index)),
			})
		}
	}
	page, nextAlertOffset, err := sourcecdk.PageByOffset(records, strconv.Itoa(alertOffset), pageSize)
	if err != nil {
		return nil, "", err
	}
	if nextAlertOffset != "" {
		return page, encodeDNSAlertCursor(assetCursor, nextAlertOffset), nil
	}
	if strings.TrimSpace(response.NextCursor) != "" {
		return page, encodeDNSAlertCursor(response.NextCursor, "0"), nil
	}
	return page, "", nil
}

func (s *Source) discoverDNSAlerts(ctx context.Context, settings settings) ([]record, error) {
	cursor := ""
	for page := 0; page < dnsAlertDiscoverPages; page++ {
		records, next, err := s.listDNSAlerts(ctx, settings, cursor, settings.perPage)
		if err != nil {
			return nil, err
		}
		if len(records) > 0 || strings.TrimSpace(next) == "" {
			return records, nil
		}
		cursor = next
	}
	return nil, nil
}

func serverPaged(cursor string, pageSize int, recordCount int, nextCursor string) bool {
	return strings.TrimSpace(nextCursor) != "" || (strings.TrimSpace(cursor) != "" && recordCount <= pageSize)
}

func parseDNSAlertCursor(cursor string) (string, int, error) {
	trimmed := strings.TrimSpace(cursor)
	if trimmed == "" {
		return "", 0, nil
	}
	if !strings.HasPrefix(trimmed, "dns:") {
		return trimmed, 0, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(trimmed, "dns:"))
	if err != nil {
		return "", 0, fmt.Errorf("invalid VulnView DNS alert cursor")
	}
	var decoded dnsAlertCursor
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "", 0, fmt.Errorf("invalid VulnView DNS alert cursor")
	}
	if decoded.AlertOffset < 0 {
		return "", 0, fmt.Errorf("invalid VulnView DNS alert cursor")
	}
	return strings.TrimSpace(decoded.AssetCursor), decoded.AlertOffset, nil
}

func encodeDNSAlertCursor(assetCursor string, alertOffset string) string {
	offset, err := strconv.Atoi(strings.TrimSpace(alertOffset))
	if err != nil || offset < 0 {
		offset = 0
	}
	payload, err := json.Marshal(dnsAlertCursor{AssetCursor: strings.TrimSpace(assetCursor), AlertOffset: offset})
	if err != nil {
		return ""
	}
	return "dns:" + base64.RawURLEncoding.EncodeToString(payload)
}
