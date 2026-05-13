package sourceprojection

import (
	"net"
	"net/url"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func internetHostURN(tenantID string, raw string) (string, string) {
	host := internetHost(raw)
	if host == "" {
		return "", ""
	}
	return projectionURN(tenantID, "internet_host", host), host
}

func internetHost(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return normalizeInternetHost(parsed.Hostname())
	}
	if parsed, err := url.Parse("https://" + value); err == nil && parsed.Hostname() != "" {
		return normalizeInternetHost(parsed.Hostname())
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return normalizeInternetHost(host)
	}
	return normalizeInternetHost(strings.Trim(value, "/"))
}

func internetHostIfLikely(raw string) string {
	host := internetHost(raw)
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil || strings.Contains(host, ".") {
		return host
	}
	return ""
}

func internetIPURN(tenantID string, raw string) (string, string) {
	ip := internetIP(raw)
	if ip == "" {
		return "", ""
	}
	return projectionURN(tenantID, "internet_ip", ip), ip
}

func internetIP(raw string) string {
	host := internetHost(raw)
	if host == "" {
		return ""
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func normalizeInternetHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.Trim(host, ".")))
	if normalized == "" || strings.ContainsAny(normalized, " /?#,;@") {
		return ""
	}
	return normalized
}

func addInternetHostEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urn string, host string) {
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "internet.host",
		Label:      host,
		Attributes: map[string]string{
			"host": host,
		},
	})
}

func addInternetIPEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urn string, ip string) {
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "internet.ip",
		Label:      ip,
		Attributes: map[string]string{
			"ip": ip,
		},
	})
}

func addInternetHostLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, rawHost string, matchType string, confidence string) {
	hostURN, host := internetHostURN(tenantID, rawHost)
	if hostURN == "" || fromURN == "" {
		return
	}
	addInternetHostEntity(entities, tenantID, sourceID, hostURN, host)
	addLink(links, projectedLink(tenantID, sourceID, fromURN, hostURN, relation, map[string]string{
		"confidence": confidence,
		"event_id":   event.GetId(),
		"host":       host,
		"match_type": matchType,
	}))
}
