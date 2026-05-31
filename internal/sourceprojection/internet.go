package sourceprojection

import (
	"net"
	"net/url"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"golang.org/x/net/publicsuffix"
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

func internetDomainURN(tenantID string, raw string) (string, string) {
	domain := internetDomain(raw)
	if domain == "" {
		return "", ""
	}
	return projectionURN(tenantID, "internet_domain", domain), domain
}

func internetDomain(raw string) string {
	host := internetHost(raw)
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return domain
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

func addInternetDomainEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urn string, domain string) {
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "internet.domain",
		Label:      domain,
		Attributes: map[string]string{
			"domain": domain,
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

func addInternetHostDomainLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, rawHost string, matchType string, confidence string) {
	hostURN, host := internetHostURN(tenantID, rawHost)
	domainURN, domain := internetDomainURN(tenantID, host)
	if hostURN == "" || domainURN == "" {
		return
	}
	addInternetHostEntity(entities, tenantID, sourceID, hostURN, host)
	addInternetDomainEntity(entities, tenantID, sourceID, domainURN, domain)
	addLink(links, projectedLink(tenantID, sourceID, hostURN, domainURN, relationBelongsTo, map[string]string{
		"confidence": confidence,
		"domain":     domain,
		"event_id":   event.GetId(),
		"host":       host,
		"match_type": matchType,
	}))
}

func addInternetHostResolvesToIPLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, rawHost string, rawIP string, matchType string, confidence string) {
	hostURN, host := internetHostURN(tenantID, rawHost)
	ipURN, ip := internetIPURN(tenantID, rawIP)
	if hostURN == "" || ipURN == "" || host == ip {
		return
	}
	addInternetHostEntity(entities, tenantID, sourceID, hostURN, host)
	addInternetIPEntity(entities, tenantID, sourceID, ipURN, ip)
	addLink(links, projectedLink(tenantID, sourceID, hostURN, ipURN, relationResolvesTo, map[string]string{
		"confidence": confidence,
		"event_id":   event.GetId(),
		"host":       host,
		"ip":         ip,
		"match_type": matchType,
	}))
}

func dnsRecordURN(tenantID string, host string, recordType string, recordValue string) string {
	host = internetHost(host)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	recordValue = dnsRecordValue(recordType, recordValue)
	if host == "" || recordType == "" || recordValue == "" {
		return ""
	}
	return projectionURN(tenantID, "dns_record", host+"|"+recordType+"|"+recordValue)
}

func dnsRecordValue(recordType string, raw string) string {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "A", "AAAA":
		return internetIP(raw)
	case "CNAME":
		if host := internetHost(raw); host != "" {
			return host
		}
	}
	return strings.TrimSpace(raw)
}

func addDNSRecordEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, urn string, host string, recordType string, recordValue string) {
	normalizedRecordType := strings.ToUpper(strings.TrimSpace(recordType))
	normalizedRecordValue := dnsRecordValue(normalizedRecordType, recordValue)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "dns.record",
		Label:      normalizedRecordType + " " + internetHost(host),
		Attributes: map[string]string{
			"host":         internetHost(host),
			"record_type":  normalizedRecordType,
			"record_value": normalizedRecordValue,
		},
	})
}
